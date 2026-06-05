# Enumerates all loaded kernel drivers via Win32_SystemDriver (WMI), hashes each .sys binary, checks against a local LOLDrivers JSON DB, and checks Authenticode signatures.

"""
Security design decisions:
   - LOLDrivers DB loaded once at startup from a local file only. No network calls at runtime — the scanner is fully offline-capable.
   - WMI output treated as untrusted: every field has a safe fallback.
   - SHA-256 computed in 64KB chunks (same as process_watcher).
   - Signature check reuses _batch_check_signatures from process_watcher so the PowerShell subprocess cost is shared across both modules.
   - Hash lookup is O(1) via a pre-built set — no linear scan of DB.
   - Parameterized path validation before any file read.
   - No shell=True anywhere.
   - All timestamps UTC.

Threat model:
   - Attacker loads a vulnerable signed driver (LOLDriver) to kill EDR
   - Attacker loads an unsigned driver bypassing HVCI (older systems)
   - Attacker loads a driver not present at baseline
   - Defender detects all three within one poll cycle (default 30s)

Detection opportunities:
   - Hash match in LOLDrivers DB -> immediate HIGH alert
   - Unsigned driver -> MEDIUM alert
   - New driver since baseline -> flag for analyst review
   - Driver loaded from non-standard path (not System32\\drivers\\) -> flag

"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .alert_scorer import score_driver as _score_alert
from .models import AlertLevel, DriverRecord
from .process_watcher import _batch_check_signatures, _signature_cache, _validate_path_for_ps, _get_cached_signature

logger = logging.getLogger("winspector.driver_scanner")


# Loldriver Database

# Default location — can be overridden in DriverScanner.__init__
_DEFAULT_DB_PATH = Path("data") / "loldrivers" / "drivers.json"

def _load_loldrivers_db(db_path: Path) -> dict[str, dict]:
    """
    Load the LOLDrivers JSON snapshot and build a hash-to-entry index.

    Returns a dict keyed by lowercase SHA256 hex string. Value is a
    minimal dict with 'id' and 'tags' for alert output.

    Design: we index only SHA256 (not MD5) — SHA256 collision resistance is sufficient for this threat model.
    MD5 is kept as a secondary cross-check in the alert output but not used for primary detection.

    Failure modes:
      - File missing: returns empty dict, logs WARNING. Scanner continues with no LOLDriver detection capability — degraded but not crashed.
      - JSON malformed: same — log and return empty.
      - Entry missing expected fields: skip that entry, log DEBUG.
    """
    if not db_path.is_file():
        logger.warning(
            "loldrivers_db_missing",
            extra={"path": str(db_path)},
        )
        return {}

    try:
        raw = db_path.read_text(encoding="utf-8")
        entries: list[dict] = json.loads(raw)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning(
            "loldrivers_db_load_failed",
            extra={"path": str(db_path), "error": str(exc)},
        )
        return {}

    index: dict[str, dict] = {}
    skipped = 0

    for entry in entries:
        entry_id   = entry.get("Id", "")
        tags       = entry.get("Tags", [])
        tags_str   = " ".join(tags) if isinstance(tags, list) else ""
        samples    = entry.get("KnownVulnerableSamples", [])

        if not isinstance(samples, list):
            skipped += 1
            continue

        for sample in samples:
            sha256 = sample.get("SHA256", "")
            if not sha256 or not isinstance(sha256, str):
                continue

            sha256_lower = sha256.lower().strip()

            # Skip obviously invalid hashes
            if len(sha256_lower) != 64:
                skipped += 1
                continue

            index[sha256_lower] = {
                "id":   entry_id,
                "tags": tags_str,
            }

    logger.info(
        "loldrivers_db_loaded",
        extra={
            "entries":    len(index),
            "db_path":    str(db_path),
            "skipped":    skipped,
        },
    )
    return index


def _verify_loldrivers_integrity(
    db_path: Path,
    manifest_path: Path,
) -> bool:
    """
    Verify the LOLDrivers DB file matches the stored SHA-256 manifest.

    Returns True if integrity check passes or manifest doesn't exist
    (first run). Returns False and logs a WARNING if the file has been
    modified since the manifest was written — this indicates either
    tampering or an untracked update.

    Security rationale: an attacker who can write to the data directory
    could remove entries from drivers.json to hide a LOLDriver they
    intend to load. This check detects that scenario.
    """
    if not manifest_path.is_file():
        logger.warning(
            "loldrivers_no_manifest",
            extra={"manifest": str(manifest_path)},
        )
        return True  # First run — no baseline yet, proceed but warn

    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
        expected_sha256 = manifest.get("sha256", "")
        if not expected_sha256:
            logger.warning("loldrivers_manifest_missing_hash")
            return True

        actual_sha256 = hashlib.sha256(
            db_path.read_bytes()
        ).hexdigest()

        if actual_sha256 != expected_sha256:
            logger.error(
                "loldrivers_integrity_failure",
                extra={
                    "expected": expected_sha256[:16] + "...",
                    "actual":   actual_sha256[:16] + "...",
                    "path":     str(db_path),
                },
            )
            return False

        # Check staleness — warn if DB is older than 7 days
        downloaded_at_str = manifest.get("downloaded_at", "")
        if downloaded_at_str:
            from datetime import datetime, timezone, timedelta
            downloaded_at = datetime.fromisoformat(downloaded_at_str)
            age = datetime.now(timezone.utc) - downloaded_at
            if age.days > 7:
                logger.warning(
                    "loldrivers_db_stale",
                    extra={"age_days": age.days},
                )

        return True

    except (json.JSONDecodeError, OSError, KeyError) as exc:
        logger.warning(
            "loldrivers_manifest_read_failed",
            extra={"error": str(exc)},
        )
        return True  # Degrade gracefully — don't block startup


# Hashing — identical to process_watcher but kept local for module clarity

_HASH_CHUNK = 65_536


def _sha256_file(path: Path) -> str:
    """SHA-256 a file in 64KB chunks. Returns '' on any read failure."""
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            while chunk := fh.read(_HASH_CHUNK):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        logger.debug("driver_hash_unavailable", extra={"path": str(path)})
        return ""


# WMI driver enumeration via PowerShell

"""
 We use PowerShell Get-WmiObject Win32_SystemDriver rather than pywin32.
 
 WMI directly for two reasons:
  1. Consistent with our signature check approach — one PowerShell subprocess call returns all driver metadata as structured JSON.
  2. Win32_SystemDriver via pywin32 sometimes requires elevated COM marshalling that is fragile across Python versions.

 The PowerShell call is non-interactive, uses -LiteralPath for all path operations, and outputs compact JSON for deterministic parsing.
"""

_PS_ENUM_DRIVERS = """
$drivers = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue
$results = @()
foreach ($d in $drivers) {
    $results += [PSCustomObject]@{
        name         = $d.Name
        display_name = $d.DisplayName
        path_name    = $d.PathName
        state        = $d.State
        start_mode   = $d.StartMode
    }
}
$results | ConvertTo-Json -Compress
"""


def _enumerate_drivers() -> list[dict]:
    """
    Call Win32_SystemDriver via PowerShell and return a list of raw driver dicts. Returns empty list on any failure.

    Each dict has keys: name, display_name, path_name, state, start_mode.
    All values are strings — empty string if WMI returned null.
    """
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command", _PS_ENUM_DRIVERS,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        if result.returncode != 0 or not result.stdout.strip():
            logger.warning(
                "driver_enum_failed",
                extra={"stderr": result.stderr.strip()[:300]},
            )
            return []

        raw = result.stdout.strip()
        parsed = json.loads(raw)

        # PowerShell returns a dict (not list) for single-item results
        if isinstance(parsed, dict):
            parsed = [parsed]

        # Normalise: ensure all expected fields exist and are strings
        normalised = []
        for d in parsed:
            normalised.append({
                "name":         str(d.get("name",         "") or ""),
                "display_name": str(d.get("display_name", "") or ""),
                "path_name":    str(d.get("path_name",    "") or ""),
                "state":        str(d.get("state",        "") or ""),
                "start_mode":   str(d.get("start_mode",   "") or ""),
            })

        return normalised

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        logger.warning(
            "driver_enum_exception",
            extra={"error": str(exc)},
        )
        return []

# Path cleaning

def _clean_driver_path(raw_path: str) -> str:
    """
    Win32_SystemDriver PathName values use several formats:
      1. \\SystemRoot\\System32\\drivers\\ntfs.sys
      2. system32\\drivers\\disk.sys
      3. C:\\Windows\\System32\\drivers\\tcpip.sys

    Normalise all of them to absolute paths. Returns '' if the path cannot be resolved or the resulting file does not exist.
    """
    if not raw_path:
        return ""

    p = raw_path.strip()

    # \SystemRoot\ → C:\Windows\ (or wherever Windows is installed)
    if p.startswith("\\SystemRoot\\"):
        windir = Path("C:\\Windows")  # safe default for lab VM
        p = str(windir / p[len("\\SystemRoot\\"):])

    # Relative paths → assume System32
    if not Path(p).is_absolute():
        p = str(Path("C:\\Windows\\System32") / p)

    resolved = Path(p)
    if not resolved.is_file():
        logger.debug("driver_path_not_found", extra={"path": p})
        return ""

    return str(resolved)


# Driver Scanner

_DEFAULT_MANIFEST_PATH = Path("data") / "loldrivers" / "manifest.json"

class DriverScanner:
    """
    Enumerates loaded kernel drivers, hashes each, checks LOLDrivers DB, checks signatures, scores each for suspiciousness.
    """

    def __init__(
        self,
        db_path: Path = _DEFAULT_DB_PATH,
        manifest_path: Path = _DEFAULT_MANIFEST_PATH,
    ) -> None:
        # Integrity check before loading — warn if tampered or stale
        _verify_loldrivers_integrity(db_path, manifest_path)
        self._loldrivers: dict[str, dict] = _load_loldrivers_db(db_path)
        self._baseline: set[str] = set()
        self._initialized = False
        logger.info(
            "driver_scanner_init",
            extra={"loldrivers_entries": len(self._loldrivers)},
        )

    def scan(self) -> list[DriverRecord]:
        """
        Enumerate all loaded drivers, hash, check, score.

        First call establishes baseline (list of driver names at startup).
        Subsequent calls flag any driver name not in the baseline as new.

        Returns the full list of DriverRecords, scored. Callers filter by alert_level for their own purposes.
        """
        raw_drivers = _enumerate_drivers()

        if not raw_drivers:
            logger.warning("driver_scan_empty")
            return []

        # Batch signature check — one PowerShell call for all unique paths.
        # _validate_path_for_ps applied here: WMI PathName output is untrusted
        # and must be validated before reaching the PowerShell subprocess.
        unique_paths = []
        for d in raw_drivers:
            cleaned = _clean_driver_path(d["path_name"])
            if cleaned and cleaned not in _signature_cache:
                if _validate_path_for_ps(cleaned):
                    unique_paths.append(cleaned)
                else:
                    logger.warning(
                        "driver_path_rejected_unsafe",
                        extra={"path": cleaned[:200]},
                    )
                    _signature_cache[cleaned] = False

        if unique_paths:
            _batch_check_signatures(unique_paths)

        records: list[DriverRecord] = []
        current_names: set[str] = set()

        for d in raw_drivers:
            name        = d["name"]
            exe_path    = _clean_driver_path(d["path_name"])
            current_names.add(name)

            # Hash the binary
            sha256 = ""
            if exe_path:
                sha256 = _sha256_file(Path(exe_path))

            # LOLDrivers check — O(1) set lookup
            lol_match = False
            lol_id    = ""
            lol_tags  = ""
            if sha256:
                lol_entry = self._loldrivers.get(sha256.lower())
                if lol_entry:
                    lol_match = True
                    lol_id    = lol_entry["id"]
                    lol_tags  = lol_entry["tags"]
                    logger.warning(
                        "loldrivers_match",
                        extra={
                            "driver":  name,
                            "path":    exe_path,
                            "sha256":  sha256,
                            "lol_id":  lol_id,
                            "lol_tags": lol_tags,
                        },
                    )

            # Signature from warm cache
            is_signed = (_get_cached_signature(exe_path) or False) if exe_path else False

            record = DriverRecord(
                name             = name,
                display_name     = d["display_name"],
                exe_path         = exe_path,
                state            = d["state"],
                start_mode       = d["start_mode"],
                sha256           = sha256,
                is_signed        = is_signed,
                loldrivers_match = lol_match,
                loldrivers_id    = lol_id,
                loldrivers_tags  = lol_tags,
            )

            alert = _score_alert(record)
            record = replace(record, alert_level=alert.alert_level)
            records.append(record)

        # Baseline tracking — flag new drivers on subsequent scans
        if not self._initialized:
            self._baseline   = current_names
            self._initialized = True
            logger.info(
                "driver_baseline_established",
                extra={"driver_count": len(records)},
            )
        else:
            new_drivers = current_names - self._baseline
            for rec in records:
                if rec.name in new_drivers:
                    logger.warning(
                        "new_driver_since_baseline",
                        extra={
                            "driver":  rec.name,
                            "path":    rec.exe_path,
                            "sha256":  rec.sha256,
                            "signed":  rec.is_signed,
                        },
                    )

        alert_count = sum(
            1 for r in records if r.alert_level != AlertLevel.INFO
        )
        logger.info(
            "driver_scan_complete",
            extra={
                "total":  len(records),
                "alerts": alert_count,
            },
        )

        return records
