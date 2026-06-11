# Alert Scorer - Applies detection rules to ProcessRecord, DriverRecord, and EventRecord objects and produces ScoredAlert output.

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
    "powershell.exe", "pwsh.exe","python.exe",
    "ruby.exe", "rubyinstaller.exe", "splunkd.exe", "run.exe",
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
# Used to suppress self-generated telemetry from scoring.
# WINSPECTOR_INSTALL_DIR is computed dynamically from the install location
# so this works regardless of where the repo is cloned.
from .config import WINSPECTOR_INSTALL_DIR

_WINSPECTOR_PATH_FRAGMENTS = frozenset({
    WINSPECTOR_INSTALL_DIR,
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

# Reconnaissance tools commonly used post-exploitation
_RECON_TOOLS = frozenset({
    "whoami.exe", "ipconfig.exe", "hostname.exe", "net.exe",
    "netstat.exe", "tasklist.exe", "systeminfo.exe", "nltest.exe",
    "nslookup.exe", "ping.exe", "arp.exe", "route.exe",
})

# LOLBins commonly abused for download/execute
_LOLBIN_DOWNLOAD_TOOLS = frozenset({
    "certutil.exe", "bitsadmin.exe", "mshta.exe",
    "wscript.exe", "cscript.exe", "regsvr32.exe",
    "rundll32.exe", "msiexec.exe", "installutil.exe",
})

# Certutil-specific suspicious flags
_CERTUTIL_SUSPICIOUS_ARGS = frozenset({
    "-urlcache", "-decode", "-encode", "-decodehex",
})

# PowerShell obfuscation/download indicators
_PS_ENCODED_FLAGS = frozenset({
    "-encodedcommand", "-enc", "-enco",
})

_PS_DOWNLOAD_CRADLES = frozenset({
    "invoke-expression", "iex", "downloadstring", "downloadfile",
    "webclient", "net.webclient", "invoke-webrequest", "wget", "curl",
})

# WMI process parents — legitimate WMI spawns shells
_WMI_PARENTS = frozenset({
    "wmiprvse.exe", "wbem\\wmiprvse.exe",
})

# Persistence mechanisms
_SCHTASKS_CREATE = frozenset({"/create", "-create"})
_REG_RUN_KEYS = frozenset({
    "software\\microsoft\\windows\\currentversion\\run",
    "software\\microsoft\\windows\\currentversion\\runonce",
    "software\\microsoft\\windows nt\\currentversion\\winlogon",
})

# RULE-019: Processes that legitimately access LSASS
# taskmgr.exe reads LSASS for memory display in Task Manager
# MsMpEng.exe is Windows Defender — legitimate LSASS access
# svchost.exe hosts many system services that access LSASS
_LSASS_ACCESS_WHITELIST = frozenset({
    "taskmgr.exe", "msmpeng.exe", "svchost.exe",
    "mssense.exe", "csrss.exe", "wininit.exe",
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
        pass

    # RULE-002: svchost.exe with no -k flag
    if name == "svchost.exe" and "-k" not in cmdline:
        score += 60
        rule_hits.append("RULE-002")
        details.append("svchost.exe has no -k flag in cmdline")

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

    # -- Sysmon EID 1 -- Process Create --
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

        # Suppress WinSpector's signature-check powershell subprocesses
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

        # RULE-004 variant: process image in suspicious path
        if _in_suspicious_path(image):
            score += 40
            rule_hits.append("RULE-004-EID1")
            details.append(f"process image in suspicious path: {image}")

        # RULE-015: recon tool spawned by suspicious-path binary
        if (image_name in _RECON_TOOLS
                and _in_suspicious_path(parent_img)):
            score += 50
            rule_hits.append("RULE-015")
            details.append(
                f"recon tool {image_name} spawned by "
                f"suspicious-path binary: {parent_img.split(chr(92))[-1]}"
            )

        # RULE-016: LOLBin download/execute abuse
        if image_name in _LOLBIN_DOWNLOAD_TOOLS:
            cmdline_lower = f.get("CommandLine", "").lower()
            if any(arg in cmdline_lower for arg in _CERTUTIL_SUSPICIOUS_ARGS):
                score += 60
                rule_hits.append("RULE-016")
                details.append(
                    f"LOLBin abuse: {image_name} with suspicious args"
                )
            elif image_name in {"mshta.exe", "wscript.exe", "cscript.exe",
                                "regsvr32.exe", "rundll32.exe"}:
                score += 35
                rule_hits.append("RULE-016")
                details.append(f"LOLBin execution: {image_name}")

        # RULE-017: PowerShell encoded command (T1027)
        if image_name in {"powershell.exe", "pwsh.exe"}:
            cmdline_lower = f.get("CommandLine", "").lower()
            if any(flag in cmdline_lower for flag in _PS_ENCODED_FLAGS):
                score += 65
                rule_hits.append("RULE-017")
                details.append("PowerShell encoded command (-EncodedCommand)")

        # RULE-018: PowerShell download cradle (T1059.001)
        if image_name in {"powershell.exe", "pwsh.exe"}:
            cmdline_lower = f.get("CommandLine", "").lower()
            if any(cradle in cmdline_lower for cradle in _PS_DOWNLOAD_CRADLES):
                score += 70
                rule_hits.append("RULE-018")
                details.append("PowerShell download cradle detected")

        # RULE-023: WMI spawning child process (T1047)
        if parent_img and any(
            wmi in parent_img.lower() for wmi in _WMI_PARENTS
        ):
            score += 65
            rule_hits.append("RULE-023")
            details.append(f"process spawned by WMI: {image_name}")

        # RULE-025: Scheduled task creation (T1053.005)
        if image_name == "schtasks.exe":
            cmdline_lower = f.get("CommandLine", "").lower()
            if any(flag in cmdline_lower for flag in _SCHTASKS_CREATE):
                score += 60
                rule_hits.append("RULE-025")
                details.append("scheduled task creation via schtasks.exe")

        # RULE-026: Registry run key modification (T1547.001)
        if image_name in {"reg.exe", "regedit.exe"}:
            cmdline_lower = f.get("CommandLine", "").lower()
            if ("add" in cmdline_lower and
                    any(key in cmdline_lower for key in _REG_RUN_KEYS)):
                score += 55
                rule_hits.append("RULE-026")
                details.append("registry run key modification detected")

    # -- Sysmon EID 3 -- Network Connection --
    elif eid == 3:
        image      = f.get("Image", "")
        image_name = image.split("\\")[-1].lower()
        dst_port_s = f.get("DestinationPort", "0")
        dst_ip     = f.get("DestinationIp", "")
        initiated  = f.get("Initiated", "").lower() == "true"

        if not initiated:
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

    # -- Sysmon EID 7 -- Image Load --
    elif eid == 7:
        image      = f.get("Image", "")
        image_name = image.split("\\")[-1].lower()
        img_loaded = f.get("ImageLoaded", "").lower()
        signed     = f.get("Signed", "").lower()

        # RULE-021: DLL loaded from suspicious path (T1574)
        if _in_suspicious_path(img_loaded):
            score += 55
            rule_hits.append("RULE-021")
            details.append(f"DLL loaded from suspicious path: {img_loaded}")

    # -- Sysmon EID 8 -- CreateRemoteThread --
    elif eid == 8:
        source_image = f.get("SourceImage", "")
        target_image = f.get("TargetImage", "")
        source_name  = source_image.split("\\")[-1].lower()
        target_name  = target_image.split("\\")[-1].lower()

        # RULE-020: Remote thread injection (T1055)
        score += 75
        rule_hits.append("RULE-020")
        details.append(
            f"remote thread created by {source_name} "
            f"in target {target_name}"
        )

    # -- Sysmon EID 10 -- Process Access --
    elif eid == 10:
        source_image = f.get("SourceImage", "")
        target_image = f.get("TargetImage", "")
        source_name  = source_image.split("\\")[-1].lower()
        target_name  = target_image.split("\\")[-1].lower()
        granted_access = f.get("GrantedAccess", "")

        # RULE-019: LSASS access (T1003.001 - OS Credential Dumping)
        # Whitelist: processes that legitimately access LSASS
        if (target_name == "lsass.exe"
                and source_name not in _LSASS_ACCESS_WHITELIST):
            score += 80
            rule_hits.append("RULE-019")
            details.append(
                f"LSASS accessed by {source_name} "
                f"(GrantedAccess={granted_access})"
            )

    # -- Sysmon EID 11 -- File Create --
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

    # -- Security EID 4688 -- Process Creation --
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
            details.append(f"cmd.exe from suspicious-path parent: {parent_proc}")

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

        # RULE-015: recon tool spawned by suspicious-path binary
        if (new_name in _RECON_TOOLS
                and _in_suspicious_path(parent_proc)):
            score += 50
            rule_hits.append("RULE-015")
            details.append(
                f"recon tool {new_name} spawned by "
                f"suspicious-path binary: {parent_proc.split(chr(92))[-1]}"
            )

        # RULE-016: LOLBin download/execute abuse
        if new_name in _LOLBIN_DOWNLOAD_TOOLS:
            cmdline_lower = f.get("CommandLine", "").lower()
            if any(arg in cmdline_lower for arg in _CERTUTIL_SUSPICIOUS_ARGS):
                score += 60
                rule_hits.append("RULE-016")
                details.append(f"LOLBin abuse: {new_name} with suspicious args")
            elif new_name in {"mshta.exe", "wscript.exe", "cscript.exe",
                              "regsvr32.exe", "rundll32.exe"}:
                score += 35
                rule_hits.append("RULE-016")
                details.append(f"LOLBin execution: {new_name}")

        # RULE-017: PowerShell encoded command (T1027)
        if new_name in {"powershell.exe", "pwsh.exe"}:
            cmdline_lower = f.get("CommandLine", "").lower()
            if any(flag in cmdline_lower for flag in _PS_ENCODED_FLAGS):
                score += 65
                rule_hits.append("RULE-017")
                details.append("PowerShell encoded command (-EncodedCommand)")

        # RULE-018: PowerShell download cradle (T1059.001)
        if new_name in {"powershell.exe", "pwsh.exe"}:
            cmdline_lower = f.get("CommandLine", "").lower()
            if any(cradle in cmdline_lower for cradle in _PS_DOWNLOAD_CRADLES):
                score += 70
                rule_hits.append("RULE-018")
                details.append("PowerShell download cradle detected")

        # RULE-023: WMI spawning child process (T1047)
        if parent_proc and any(
            wmi in parent_proc.lower() for wmi in _WMI_PARENTS
        ):
            score += 65
            rule_hits.append("RULE-023")
            details.append(f"process spawned by WMI: {new_name}")

        # RULE-024: Base64 string in command line (T1027)
        cmdline_lower = f.get("CommandLine", "").lower()
        if ("base64" in cmdline_lower or
                "-e " in cmdline_lower and
                len(f.get("CommandLine", "")) > 100):
            score += 45
            rule_hits.append("RULE-024")
            details.append("base64/encoded content in command line")

        # RULE-025: Scheduled task creation (T1053.005)
        if new_name == "schtasks.exe":
            if any(flag in cmdline_lower for flag in _SCHTASKS_CREATE):
                score += 60
                rule_hits.append("RULE-025")
                details.append("scheduled task creation via schtasks.exe")

        # RULE-026: Registry run key modification (T1547.001)
        if new_name in {"reg.exe", "regedit.exe"}:
            if ("add" in cmdline_lower and
                    any(key in cmdline_lower for key in _REG_RUN_KEYS)):
                score += 55
                rule_hits.append("RULE-026")
                details.append("registry run key modification detected")

    # -- System EID 7045 -- New Service --
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
