# Module 4: Alert Scorer - Applies detection rules to ProcessRecord, DriverRecord, and EventRecord objects and produces ScoredAlert output.

"""
 Design principles:
   - Rules are static Python constants — no dynamic loading, no eval
   - Scoring is additive and deterministic — same input always produces same score
   - Each rule is independently testable
   - Whitelists suppress known-good false positives explicitly
   - WinSpector's own process chain is suppressed by default
   - All scoring logic is in pure functions — no side effects
   - Score is capped at 100. CRITICAL (LOLDriver match) bypasses
     the normal threshold entirely

 Threat model:
   - Attacker renames malware to a known-good process name
     -> path-based rules catch this (wrong location)
   - Attacker uses signed binary from legitimate path
     -> parent chain and network rules still apply
   - Attacker loads a LOLDriver
     -> RULE-012 fires immediately at score 100
   - Attacker exploits high poll interval (PID reuse)
     -> create_time comparison in Module 1 already handles this
"""

from __future__ import annotations

import logging
from dataclasses import replace

from .models import AlertLevel, DriverRecord, EventRecord, ProcessRecord, ScoredAlert

logger = logging.getLogger("winspector.alert_scorer")

# Whitelists — suppress known-good false positives

# Processes that legitimately spawn cmd.exe or powershell.exe
_KNOWN_SHELL_PARENTS = frozenset({
    "explorer.exe", "services.exe", "svchost.exe",
    "taskhostw.exe", "msiexec.exe", "wininit.exe",
    "winlogon.exe", "csrss.exe", "smss.exe",
    # powershell.exe retained — user-interactive shells legitimately spawn child shells (e.g. powershell -> cmd /c whoami).
    # Malicious chains are caught by RULE-007 (suspicious parent path) and RULE-008 (blank PE metadata) instead.
    "powershell.exe", "pwsh.exe",
    # python.exe retained for lab — WinSpector spawns PowerShell
    # for signature checks. Remove in production deployment.
    "python.exe",
})

# Processes that legitimately make outbound network connections
_KNOWN_NETWORK_PROCESSES = frozenset({
    "msedge.exe", "msedgewebview2.exe", "chrome.exe", "firefox.exe",
    "iexplore.exe", "MsMpEng.exe", "svchost.exe", "lsass.exe",
    "OneDrive.exe", "Teams.exe", "SearchApp.exe", "backgroundTaskHost.exe",
    "WinStore.App.exe", "SkypeHelper.exe", "YourPhone.exe",
    "splunkd.exe", "splunk-winevtlog.exe", "nessusd.exe",
    "wireguard.exe", "ruby.exe",
})

# WinSpector's own process chain — score zero to avoid self-flagging
_WINSPECTOR_PROCESSES = frozenset({
    "python.exe", "pythonw.exe",
})

# Path fragments that identify WinSpector's own process chain
# Used to suppress self-generated telemetry from scoring
_WINSPECTOR_PATH_FRAGMENTS = frozenset({
    "\\projects\\winspector\\",
    "\\.venv\\scripts\\",
})

# Kernel pseudo-processes with no real exe path
_PSEUDO_PROCESSES = frozenset({
    "registry", "memcompression", "system",
    "system idle process", "",
})

# Ports that are normal for outbound connections
_COMMON_PORTS = frozenset({
    80, 443, 8080, 8443,      # HTTP/HTTPS
    1433, 3306, 5432, 27017,  # Databases
    9200, 5601,               # Elastic
    53, 123,                  # DNS, NTP
})


# Score -> AlertLevel mapping

def _score_to_level(score: int) -> AlertLevel:
    if score >= 100:
        return AlertLevel.HIGH    # CRITICAL maps to HIGH for display
    if score >= 75:
        return AlertLevel.HIGH
    if score >= 50:
        return AlertLevel.MEDIUM
    if score >= 30:
        return AlertLevel.LOW
    return AlertLevel.INFO


# Helper — path analysis


def _in_suspicious_path(path: str) -> bool:
    """Return True if path is in a user-writable temp/appdata location."""
    p = path.lower()
    return (
        "\\temp\\"     in p or
        "\\tmp\\"      in p or
        "appdata\\local\\temp" in p or
        "appdata\\roaming" in p or
        "\\downloads\\" in p or
        "\\desktop\\"   in p
    )


def _in_standard_system_path(path: str) -> bool:
    """Return True if path is a standard Windows system location."""
    p = path.lower()
    return (
        "\\windows\\system32\\" in p or
        "\\windows\\syswow64\\" in p or
        "\\windows\\sysnat\\"   in p or
        "\\program files\\"     in p or
        "\\program files (x86)\\" in p
    )


# Process scoring


def score_process(record: ProcessRecord) -> ScoredAlert:
    """
    Apply all process detection rules to a ProcessRecord.
    Returns a ScoredAlert with score, level, and rule hits.
    """
    score     = 0
    rule_hits: list[str] = []
    details:   list[str] = []

    name       = record.name.lower()
    exe_path   = record.exe_path.lower()
    cmdline    = record.cmdline.lower()
    username   = record.username.lower()
    ppid_name  = ""  # populated below if available

    # Skip pseudo-processes entirely
    if name.rstrip(".exe") in _PSEUDO_PROCESSES or not record.exe_path:
        return ScoredAlert(
            source="process", rule_hits=[], score=0,
            alert_level=AlertLevel.INFO,
            entity_name=record.name, entity_path=record.exe_path,
            detail="pseudo-process or no path", raw=record.to_dict(),
        )

    # RULE-001: svchost.exe with non-services.exe parent
    if name == "svchost.exe":
        # We don't have ppid_name in ProcessRecord directly, we use PPID and check if it matches known services.exe PIDs.
        # Conservative: flag if cmdline has no -k flag (RULE-002 covers this)
        pass

    # RULE-002: svchost.exe with no -k flag
    if name == "svchost.exe" and "-k" not in cmdline:
        score += 60
        rule_hits.append("RULE-002")
        details.append("svchost.exe has no -k flag in cmdline")

    # RULE-003: powershell.exe spawned — check if parent is cmd.exe
    # (parent name not available in ProcessRecord; scored in event rules)

    # RULE-004: unsigned binary in suspicious path
    if not record.is_signed and _in_suspicious_path(exe_path):
        score += 55
        rule_hits.append("RULE-004")
        details.append(f"unsigned binary in suspicious path: {record.exe_path}")

    # RULE-005: unsigned binary (any location)
    elif not record.is_signed and record.exe_path:
        score += 30
        rule_hits.append("RULE-005")
        details.append("unsigned binary")

    # RULE-008: blank PE metadata (no FileVersion/Description/Company)
    # Not available from psutil — applied in event scorer for Sysmon EID 1

    # Suppress WinSpector's own processes from high scores
    if name in _WINSPECTOR_PROCESSES and _in_standard_system_path(exe_path):
        score = max(0, score - 30)
        details.append("score reduced: WinSpector own process")

    # Cap at 100
    score = min(score, 100)
    level = _score_to_level(score)

    if rule_hits:
        logger.debug(
            "process_scored",
            extra={
                "entity": record.name,
                "score":  score,
                "rules":  rule_hits,
            },
        )

    return ScoredAlert(
        source      = "process",
        rule_hits   = rule_hits,
        score       = score,
        alert_level = level,
        entity_name = record.name,
        entity_path = record.exe_path,
        detail      = "; ".join(details) if details else "clean",
        raw         = record.to_dict(),
    )


# Driver scoring

def score_driver(record: DriverRecord) -> ScoredAlert:
    """
    Apply driver detection rules to a DriverRecord.
    LOLDrivers match immediately returns CRITICAL (score 100).
    """
    score     = 0
    rule_hits: list[str] = []
    details:   list[str] = []

    # RULE-012: LOLDrivers hash match — immediate critical
    if record.loldrivers_match:
        score = 100
        rule_hits.append("RULE-012")
        details.append(
            f"LOLDrivers match: {record.loldrivers_id} "
            f"tags=[{record.loldrivers_tags}]"
        )
        logger.warning(
            "loldrivers_alert",
            extra={
                "driver":  record.name,
                "path":    record.exe_path,
                "lol_id":  record.loldrivers_id,
                "score":   score,
            },
        )
        return ScoredAlert(
            source      = "driver",
            rule_hits   = rule_hits,
            score       = score,
            alert_level = AlertLevel.HIGH,
            entity_name = record.name,
            entity_path = record.exe_path,
            detail      = "; ".join(details),
            raw         = record.to_dict(),
        )

    # RULE-013: unsigned driver
    if not record.is_signed and record.exe_path:
        score += 60
        rule_hits.append("RULE-013")
        details.append("unsigned driver")

    # RULE-014: driver in non-standard path
    exe_lower = record.exe_path.lower()
    if record.exe_path and "system32" not in exe_lower:
        score += 50
        rule_hits.append("RULE-014")
        details.append(f"non-standard driver path: {record.exe_path}")

    score = min(score, 100)
    level = _score_to_level(score)

    if rule_hits:
        logger.info(
            "driver_scored",
            extra={
                "entity": record.name,
                "score":  score,
                "rules":  rule_hits,
            },
        )

    return ScoredAlert(
        source      = "driver",
        rule_hits   = rule_hits,
        score       = score,
        alert_level = level,
        entity_name = record.name,
        entity_path = record.exe_path,
        detail      = "; ".join(details) if details else "clean",
        raw         = record.to_dict(),
    )


# Event scoring

def score_event(record: EventRecord) -> ScoredAlert:
    """
    Apply event detection rules to an EventRecord.
    Different rules apply based on event_id.
    """
    score     = 0
    rule_hits: list[str] = []
    details:   list[str] = []
    f         = record.fields

    eid = record.event_id

    # ── Sysmon EID 1 — Process Create ──
    if eid == 1:
        image       = f.get("Image", "")
        image_name  = image.split("\\")[-1].lower()
        parent_img  = f.get("ParentImage", "")
        parent_name = parent_img.split("\\")[-1].lower()
        cmdline     = f.get("CommandLine", "").lower()

        # Suppress WinSpector's own chain
        if (image_name in _WINSPECTOR_PROCESSES and
                any(frag in image.lower() for frag in _WINSPECTOR_PATH_FRAGMENTS)):
            return ScoredAlert(
                source="event", rule_hits=[], score=0,
                alert_level=AlertLevel.INFO,
                entity_name=image_name, entity_path=image,
                detail="WinSpector own process suppressed",
                raw=record.to_dict(),
            )

        # Suppress WinSpector's signature-check powershell subprocesses, parent is our own python.exe in the venv, cmdline is our known pattern
        if (image_name == "powershell.exe"
                and parent_name in _WINSPECTOR_PROCESSES
                and any(frag in parent_img.lower()
                        for frag in _WINSPECTOR_PATH_FRAGMENTS)):
            return ScoredAlert(
                source="event", rule_hits=[], score=0,
                alert_level=AlertLevel.INFO,
                entity_name=image_name, entity_path=image,
                detail="WinSpector signature-check subprocess suppressed",
                raw=record.to_dict(),
            )

        # RULE-003: powershell.exe or cmd.exe spawned by cmd.exe
        if (image_name in {"powershell.exe", "cmd.exe"}
                and parent_name == "cmd.exe"):
            score += 35
            rule_hits.append("RULE-003")
            details.append(f"shell spawned by cmd.exe: {image_name}")

        # RULE-006: shell spawned by non-standard parent
        if (image_name in {"powershell.exe", "cmd.exe"}
                and parent_name not in _KNOWN_SHELL_PARENTS):
            score += 40
            rule_hits.append("RULE-006")
            details.append(
                f"shell {image_name} spawned by "
                f"non-standard parent: {parent_name}"
            )

        # RULE-007: cmd.exe spawned by %TEMP%/%APPDATA% executable
        if image_name == "cmd.exe" and _in_suspicious_path(parent_img):
            score += 60
            rule_hits.append("RULE-007")
            details.append(
                f"cmd.exe spawned by suspicious-path binary: {parent_img}"
            )

        # RULE-008: blank PE metadata
        file_ver = f.get("FileVersion", "").strip()
        desc     = f.get("Description", "").strip()
        company  = f.get("Company", "").strip()
        if (not file_ver and not desc and not company
                and image_name not in _PSEUDO_PROCESSES):
            score += 35
            rule_hits.append("RULE-008")
            details.append("blank PE metadata (FileVersion/Description/Company)")

        # RULE-004 variant: unsigned binary in suspicious path
        # (Sysmon EID 1 doesn't give signed status directly, we check the image path as a proxy)
        if _in_suspicious_path(image):
            score += 40
            rule_hits.append("RULE-004-EID1")
            details.append(f"process image in suspicious path: {image}")

    # ── Sysmon EID 3 — Network Connection ──
    elif eid == 3:
        image      = f.get("Image", "")
        image_name = image.split("\\")[-1].lower()
        dst_port_s = f.get("DestinationPort", "0")
        dst_ip     = f.get("DestinationIp", "")
        initiated  = f.get("Initiated", "").lower() == "true"

        if not initiated:
            # Only score outbound connections
            pass
        else:
            try:
                dst_port = int(dst_port_s)
            except ValueError:
                dst_port = 0

            # RULE-010: outbound connection from suspicious path
            if _in_suspicious_path(image):
                score += 70
                rule_hits.append("RULE-010")
                details.append(
                    f"outbound TCP from suspicious-path binary "
                    f"to {dst_ip}:{dst_port}"
                )

            # RULE-011: non-standard high port from unknown process
            if (dst_port > 1024
                    and dst_port not in _COMMON_PORTS
                    and image_name not in _KNOWN_NETWORK_PROCESSES):
                score += 25
                rule_hits.append("RULE-011")
                details.append(
                    f"outbound to non-standard port {dst_port} "
                    f"from {image_name}"
                )

    # ── Sysmon EID 11 — File Create ──
    elif eid == 11:
        image       = f.get("Image", "")
        image_name  = image.split("\\")[-1].lower()
        target      = f.get("TargetFilename", "").lower()

        # RULE-009: EXE dropped to %TEMP% by a shell
        if (target.endswith(".exe")
                and "temp" in target
                and image_name in {"powershell.exe", "cmd.exe",
                                   "wscript.exe", "cscript.exe"}):
            score += 55
            rule_hits.append("RULE-009")
            details.append(
                f"executable dropped to temp by {image_name}: "
                f"{f.get('TargetFilename','')}"
            )

    # ── Security EID 4688 — Process Creation ──
    elif eid == 4688:
        new_proc    = f.get("NewProcessName", "")
        new_name    = new_proc.split("\\")[-1].lower()
        parent_proc = f.get("ParentProcessName", "")
        parent_name = parent_proc.split("\\")[-1].lower()
        cmdline     = f.get("CommandLine", "").lower()

        # Suppress WinSpector own chain
        if (new_name in _WINSPECTOR_PROCESSES and
                any(frag in new_proc.lower()
                    for frag in _WINSPECTOR_PATH_FRAGMENTS)):
            return ScoredAlert(
                source="event", rule_hits=[], score=0,
                alert_level=AlertLevel.INFO,
                entity_name=new_name, entity_path=new_proc,
                detail="WinSpector own process suppressed",
                raw=record.to_dict(),
            )

        # Suppress WinSpector's signature-check powershell subprocesses
        if (new_name == "powershell.exe"
                and parent_name in _WINSPECTOR_PROCESSES
                and any(frag in parent_proc.lower()
                        for frag in _WINSPECTOR_PATH_FRAGMENTS)):
            return ScoredAlert(
                source="event", rule_hits=[], score=0,
                alert_level=AlertLevel.INFO,
                entity_name=new_name, entity_path=new_proc,
                detail="WinSpector signature-check subprocess suppressed",
                raw=record.to_dict(),
            )

        # RULE-003: shell spawned by cmd.exe
        if (new_name in {"powershell.exe", "cmd.exe"}
                and parent_name == "cmd.exe"):
            score += 35
            rule_hits.append("RULE-003")
            details.append(f"shell spawned by cmd.exe")

        # RULE-006: shell from non-standard parent
        if (new_name in {"powershell.exe", "cmd.exe"}
                and parent_name not in _KNOWN_SHELL_PARENTS):
            score += 40
            rule_hits.append("RULE-006")
            details.append(
                f"shell {new_name} from non-standard "
                f"parent: {parent_name}"
            )

        # RULE-007: cmd.exe spawned by %TEMP%/%APPDATA% executable
        if new_name == "cmd.exe" and _in_suspicious_path(parent_proc):
            score += 60
            rule_hits.append("RULE-007")
            details.append(
                f"cmd.exe from suspicious-path parent: {parent_proc}"
            )

        # RULE-002: svchost with no -k flag
        if new_name == "svchost.exe" and "-k" not in cmdline:
            score += 60
            rule_hits.append("RULE-002")
            details.append("svchost.exe has no -k flag")

        # RULE-004 variant: new process in suspicious path
        if _in_suspicious_path(new_proc):
            score += 40
            rule_hits.append("RULE-004-EID4688")
            details.append(f"new process in suspicious path: {new_proc}")

    # ── System EID 7045 — New Service ──
    elif eid == 7045:
        svc_name = f.get("ServiceName", "")
        img_path = f.get("ImagePath", "").lower()

        # Any new service install is worth flagging at LOW minimum
        score += 30
        rule_hits.append("RULE-SVCINSTALL")
        details.append(f"new service installed: {svc_name}")

        # Higher score if service binary is in suspicious path
        if _in_suspicious_path(img_path):
            score += 45
            rule_hits.append("RULE-SVCINSTALL-SUSPPATH")
            details.append(f"service binary in suspicious path: {img_path}")

    score = min(score, 100)
    level = _score_to_level(score)

    entity_name = (
        f.get("Image", f.get("NewProcessName", "unknown"))
        .split("\\")[-1]
    )
    entity_path = f.get("Image", f.get("NewProcessName", ""))

    if rule_hits:
        logger.info(
            "event_scored",
            extra={
                "eid":    eid,
                "entity": entity_name,
                "score":  score,
                "rules":  rule_hits,
            },
        )

    return ScoredAlert(
        source      = "event",
        rule_hits   = rule_hits,
        score       = score,
        alert_level = level,
        entity_name = entity_name,
        entity_path = entity_path,
        detail      = "; ".join(details) if details else "clean",
        raw         = record.to_dict(),
    )
