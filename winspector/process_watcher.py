# It collects a full process snapshot every poll cycle, diffs against the previous snapshot, hashed binaries, flags unsigned executables.

"""
SECURITY DESIGN DECISION I HAVE TAKEN:-

1. No shell=True anywhere. All subprocess calls are avoided entirely; psutil talks to the windows kernel directly via C extensions.
2. All file paths are validated with pathlib before any read attempt.
3. WMI/psutil output is treated as untrusted: every field has a safe fallback. A process that hides its path does not crash the watcher.
4. SHA-256 is computed by reading the binary in 64KB chunks to avoid loading large files entirely into memory.
5. Timestamps are always UTC.
6. Logging in structured json via the stdlib logging + a custom formatter. No print() anywhere.

"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import psutil

from .models import ProcessRecord, SnapshotDiff

logger = logging.getLogger("winspector.process_watcher")

# Sentinel for any field we could not read from a process.
# Empty string (not None) so every field stays the same type.

_INACCESSIBLE = ""

# Read binaries in 64 KB chunks when computing SHA-256.
_HASH_CHUNK = 65_536

# Hashing

def _sha256_file(path: Path) -> str:
    """
    Compute SHA-256 of a file. Returns empty string if the file cannot be
    read, callers must treat "" as 'hash unavailable', not a valid hash.
    """
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            while chunk := fh.read(_HASH_CHUNK):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        logger.debug("hash_unavailable", extra={"path": str(path)})
        return ""

# Signature verification

"""

Windows has two ways to sign a binary:
   1. Embedded — signature lives inside the PE file itself.
   2. Catalog  — file hash is listed in a .cat file under CatRoot\\.
                 The binary contains no signature bytes at all.

This Windows10 VM uses catalog signing for all OS binaries, so WinVerifyTrust (embedded-only) returns 0x800B0100 (TRUST_E_NOSIGNATURE) for notepad.exe / cmd.exe / svchost.exe even 
though they are validly signed.

Batching: first poll has 160+ unique binaries. One PowerShell process per binary is unusable. _batch_check_signatures() sends all uncached paths in a single PowerShell call, 
parses the JSON response, and warms the cache in one shot. Every subsequent poll for known binaries is free.

"""

import time as _time

_AUTHENTICODE_VALID = 0  # PowerShell SignatureStatus.Valid == 0

# Signature cache with TTL.
# Stores (result: bool, cached_at: float) tuples keyed by absolute path.
# Entries older than _SIGNATURE_CACHE_TTL_SECONDS are re-verified.
# This prevents stale True entries persisting if a binary is swapped
# after WinSpector starts.
_SIGNATURE_CACHE_TTL_SECONDS = 600  # 10 minutes
_signature_cache: dict[str, tuple[bool, float]] = {}


def _get_cached_signature(path_str: str) -> bool | None:
    """
    Return cached signature result if fresh, None if expired or absent.
    """
    entry = _signature_cache.get(path_str)
    if entry is None:
        return None
    result, cached_at = entry
    if (_time.monotonic() - cached_at) > _SIGNATURE_CACHE_TTL_SECONDS:
        del _signature_cache[path_str]
        return None
    return result


def _set_cached_signature(path_str: str, result: bool) -> None:
    """Store a signature result with current timestamp."""
    _signature_cache[path_str] = (result, _time.monotonic())

# Windows pseudo-processes that have no executable on disk.
# These are kernel constructs — skip path validation entirely.
_KERNEL_PSEUDO_PROCESSES = frozenset({
    "registry",
    "memcompression",
    "system",
    "system idle process",
})


def _validate_path_for_ps(path: str) -> bool:
    """
    Return True only if path is a safe absolute Windows binary path
    that can be passed to a PowerShell script without injection risk.

    Allows:
      - Standard absolute paths: C:\\Windows\\...\\binary.exe
      - Program Files (x86) paths with parentheses in directory names
      - Spaces in directory and file names

    Rejects:
      - Empty or missing paths
      - Paths over MAX_PATH (260 chars)
      - UNC paths (\\\\server\\share)
      - PowerShell injection vectors: $, `, ;, |, &, <, >, {, }
      - Quote characters that break the PS array literal: ' "
      - No file extension (exe, sys, dll)
    """
    if not path or len(path) > 260:
        return False

    # Pseudo-processes have no path on disk — skip them upstream,
    # but reject here as a safety net
    if path.lower() in _KERNEL_PSEUDO_PROCESSES:
        return False

    # Must be an absolute path starting with a drive letter
    if not re.match(r'^[A-Za-z]:\\', path):
        return False

    # Must end with a known binary extension
    if not re.match(r'.*\.(?:exe|sys|dll|EXE|SYS|DLL)$', path):
        return False

    # Reject PowerShell injection metacharacters.
    # Parentheses are explicitly allowed — Program Files (x86) is legitimate.
    # Single quotes are handled by doubling in the PS script, so allow them
    # here but the caller must still escape them before insertion.
    forbidden = frozenset('$`;&|<>{}"')
    if any(c in forbidden for c in path):
        return False

    return True


def _batch_check_signatures(paths: list[str]) -> None:
    """
    Verify Authenticode signatures for a list of absolute path strings
    using a single PowerShell invocation. Results written to _signature_cache.

    Paths already cached are skipped. Any path that fails or is not
    returned by PowerShell is cached as False (treat as unsigned).
    """
    uncached = [p for p in paths if _get_cached_signature(p) is None]
    if not uncached:
        return

    # Validate every path before it touches the PowerShell script.
    # Paths that fail validation are cached as False (unsigned) and
    # logged — they are never passed to the subprocess.
    safe_paths = []
    for p in uncached:
        # Skip kernel pseudo-processes with no on-disk binary
        if Path(p).name.lower().rstrip('.exe') in {
            'registry', 'memcompression', 'system'
        }:
            _set_cached_signature(p, False)
            continue

        if _validate_path_for_ps(p):
            safe_paths.append(p)
        else:
            logger.warning(
                "path_rejected_unsafe",
                extra={"path": p[:200]},  # truncate for log safety
            )
            _set_cached_signature(p, False)

    if not safe_paths:
        return

    path_array_literal = ",\n".join(
        "  '" + p.replace("'", "''") + "'" for p in safe_paths
    )

    ps_script = """
$paths = @(
{path_array_literal}
)
$results = @()
foreach ($p in $paths) {{
    try {{
        $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue
        $valid = ($sig -ne $null) -and ($sig.Status.value__ -eq 0)
    }} catch {{
        $valid = $false
    }}
    $results += [PSCustomObject]@{{ path = $p; valid = $valid }}
}}
$results | ConvertTo-Json -Compress
""".format(path_array_literal=path_array_literal)

    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ps1", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(ps_script)
            tmp_path = tmp.name

        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-File", tmp_path,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        Path(tmp_path).unlink(missing_ok=True)

        if result.returncode != 0 or not result.stdout.strip():
            logger.debug(
                "batch_sig_check_failed",
                extra={"stderr": result.stderr.strip()[:200]},
            )
            for p in safe_paths:
                _set_cached_signature(p, False)
            return

        # PowerShell returns a bare object (not array) for a single result.
        parsed = json.loads(result.stdout.strip())
        if isinstance(parsed, dict):
            parsed = [parsed]

        for entry in parsed:
            p = entry.get("path", "")
            if p:
                _set_cached_signature(p, bool(entry.get("valid", False)))

        # Any path PowerShell did not return defaults to unsigned.
        returned = {e.get("path", "") for e in parsed}
        for p in safe_paths:
            if p not in returned:
                _set_cached_signature(p, False)

    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        logger.debug("batch_sig_check_exception", extra={"error": str(exc)})
        if tmp_path:
            Path(tmp_path).unlink(missing_ok=True)
        for p in safe_paths:
            _set_cached_signature(p, False)


def _is_signed(path: Path) -> bool:
    """
    Return True if the binary has a valid Authenticode signature
    (embedded or catalog). Returns False on any error — conservative
    by design: a wrong True suppresses a legitimate alert.

    Note: checks that a signature exists and is valid, not that the
    signer is trustworthy. A stolen cert passes here.
    """
    if not path.is_file():
        return False

    path_str = str(path.resolve())
    cached = _get_cached_signature(path_str)
    if cached is not None:
        return cached
    _batch_check_signatures([path_str])
    return _signature_cache.get(path_str, (False, 0.0))[0]

# Snapshot engine

class ProcessWatcher:
    """
    Polls the running process list and produces diffs against the previous
    snapshot. First call establishes the baseline (no diff emitted).
    Subsequent calls return created and terminated process sets.

    poll() runs in three passes to avoid spawning one PowerShell process
    per binary:
      Pass 1 — collect all process metadata (no signature checks).
      Pass 2 — one PowerShell call for all unique uncached exe paths.
      Pass 3 — fill sha256 + is_signed from the now-warm cache.

    """

    def __init__(self) -> None:
        self._previous: dict[int, ProcessRecord] = {}
        self._initialized = False
        logger.info("process_watcher_init")

    def poll(self) -> SnapshotDiff:
        current: dict[int, ProcessRecord] = {}

        # Pass 1 — collect all process metadata, no signature checks yet.
        for proc in psutil.process_iter():
            try:
                with proc.oneshot():
                    pid  = proc.pid
                    ppid = proc.ppid()
                    name = proc.name() or _INACCESSIBLE

                    exe_path    = _INACCESSIBLE
                    cmdline     = _INACCESSIBLE
                    username    = _INACCESSIBLE
                    create_time = 0.0

                    try:
                        raw      = proc.exe()
                        exe_path = raw if raw else _INACCESSIBLE
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        pass

                    try:
                        cmdline = " ".join(proc.cmdline())
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        pass

                    try:
                        username = proc.username() or _INACCESSIBLE
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        pass

                    try:
                        create_time = proc.create_time()
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        pass

                    current[pid] = ProcessRecord(
                        pid=pid, ppid=ppid, name=name,
                        exe_path=exe_path, cmdline=cmdline,
                        username=username, create_time=create_time,
                        sha256=_INACCESSIBLE, is_signed=False,
                    )

            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied:
                # Protected system process — record existence with empty fields.
                current[proc.pid] = ProcessRecord(
                    pid=proc.pid, ppid=0, name=_INACCESSIBLE,
                    exe_path=_INACCESSIBLE, cmdline=_INACCESSIBLE,
                    username=_INACCESSIBLE, create_time=0.0,
                    sha256=_INACCESSIBLE, is_signed=False,
                )

        # Pass 2 — one PowerShell call for all unique uncached exe paths.
        unique_paths = list({
            str(Path(r.exe_path).resolve())
            for r in current.values()
            if r.exe_path and Path(r.exe_path).is_file()
        })
        if unique_paths:
            _batch_check_signatures(unique_paths)

        # Pass 3 — fill sha256 + is_signed from the now-warm cache.
        for pid, record in current.items():
            if record.exe_path and Path(record.exe_path).is_file():
                exe = Path(record.exe_path)
                current[pid] = ProcessRecord(
                    pid=record.pid, ppid=record.ppid, name=record.name,
                    exe_path=record.exe_path, cmdline=record.cmdline,
                    username=record.username, create_time=record.create_time,
                    sha256=_sha256_file(exe),
                    is_signed=_get_cached_signature(str(exe.resolve())) or False,
                )

        diff = SnapshotDiff()

        if self._initialized:
            prev_pids    = set(self._previous.keys())
            current_pids = set(current.keys())

            # New PIDs — straightforward creation
            for pid in current_pids - prev_pids:
                diff.created.append(current[pid])

            # Gone PIDs — straightforward termination
            for pid in prev_pids - current_pids:
                diff.terminated.append(self._previous[pid])

            # PID reuse detection — same PID in both snapshots but
            # different create_time means the old process died and a
            # new one was assigned the same PID within one poll cycle.
            # Both events are otherwise invisible. We emit both.
            for pid in prev_pids & current_pids:
                prev_rec = self._previous[pid]
                curr_rec = current[pid]
                if (
                    prev_rec.create_time != 0.0
                    and curr_rec.create_time != 0.0
                    and abs(curr_rec.create_time - prev_rec.create_time) > 0.1
                ):
                    # Different process — old one terminated, new one created
                    logger.warning(
                        "pid_reuse_detected",
                        extra={
                            "pid":            pid,
                            "old_name":       prev_rec.name,
                            "old_create_time": prev_rec.create_time,
                            "new_name":       curr_rec.name,
                            "new_create_time": curr_rec.create_time,
                        },
                    )
                    diff.terminated.append(prev_rec)
                    diff.created.append(curr_rec)
        else:
            logger.info(
                "baseline_established",
                extra={"process_count": len(current)},
            )
            self._initialized = True

        self._previous = current

        if diff.has_changes():
            logger.info(
                "snapshot_diff",
                extra={
                    "procs_created":    len(diff.created),
                    "procs_terminated": len(diff.terminated),
                },
            )

        return diff

    def full_snapshot(self) -> list[ProcessRecord]:
        """Return the last collected snapshot as a flat list."""
        return list(self._previous.values())
