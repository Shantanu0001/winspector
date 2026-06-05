from __future__ import annotations

import hashlib
import json
import logging
import logging.config
import time
from datetime import datetime, timezone
from pathlib import Path

from winspector.alert_scorer import score_process, score_driver, score_event
from winspector.driver_scanner import DriverScanner
from winspector.event_log_miner import EventLogMiner
from winspector.models import AlertLevel
from winspector.process_watcher import ProcessWatcher

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "logging.Formatter",
            "fmt": '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
            "datefmt": "%Y-%m-%dT%H:%M:%S+00:00",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "stream": "ext://sys.stdout",
        },
        "file": {
            "class": "logging.FileHandler",
            "formatter": "json",
            "filename": str(LOG_DIR / "winspector.log"),
            "encoding": "utf-8",
        },
    },
    "root": {"level": "INFO", "handlers": ["console", "file"]},
}

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("winspector.main")

SNAPSHOT_DIR = Path("data") / "snapshots"
SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

DRIVER_REPORT_DIR = Path("data") / "drivers"
DRIVER_REPORT_DIR.mkdir(parents=True, exist_ok=True)

PROCESS_POLL_INTERVAL = 5   # seconds
DRIVER_POLL_INTERVAL  = 30  # seconds

# Append-only integrity manifest for snapshot files.
# Each entry records the filename and its SHA-256 so any
# post-write tampering is detectable on next run.
_MANIFEST_FILE = SNAPSHOT_DIR / "manifest.jsonl"


def _sha256_file(path: Path) -> str:
    """SHA-256 a file in 64KB chunks."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65_536):
            h.update(chunk)
    return h.hexdigest()


def _save_diff(diff_dict: dict) -> None:
    ts  = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = SNAPSHOT_DIR / f"diff_{ts}.json"
    out.write_text(json.dumps(diff_dict, indent=2), encoding="utf-8")

    # Compute hash after write and append to manifest
    sha256 = _sha256_file(out)
    manifest_entry = json.dumps({
        "file":   out.name,
        "sha256": sha256,
        "ts":     datetime.now(timezone.utc).isoformat(),
    })
    with _MANIFEST_FILE.open("a", encoding="utf-8") as mf:
        mf.write(manifest_entry + "\n")


_DRIVER_MANIFEST_FILE = DRIVER_REPORT_DIR / "manifest.jsonl"


def _save_driver_report(records: list, ts: str) -> None:
    out = DRIVER_REPORT_DIR / f"drivers_{ts}.json"
    out.write_text(
        json.dumps([r.to_dict() for r in records], indent=2),
        encoding="utf-8",
    )
    sha256 = _sha256_file(out)
    manifest_entry = json.dumps({
        "file":   out.name,
        "sha256": sha256,
        "ts":     datetime.now(timezone.utc).isoformat(),
    })
    with _DRIVER_MANIFEST_FILE.open("a", encoding="utf-8") as mf:
        mf.write(manifest_entry + "\n")


def _print_process_diff(diff) -> None:
    for proc in diff.created:
        alert = score_process(proc)
        signed = "signed" if proc.is_signed else "UNSIGNED"

        # Build alert indicator
        if alert.score >= 75:
            indicator = f"  *** HIGH [{alert.score}] {alert.detail}"
        elif alert.score >= 50:
            indicator = f"  !! MEDIUM [{alert.score}] {alert.detail}"
        elif alert.score >= 30:
            indicator = f"  ! LOW [{alert.score}] {alert.detail}"
        else:
            indicator = ""

        print(
            f"  [+] {proc.name:<30} PID:{proc.pid:<6} "
            f"PPID:{proc.ppid:<6} USER:{proc.username:<30} {signed}"
        )
        if indicator:
            print(indicator)

    for proc in diff.terminated:
        print(f"  [-] {proc.name:<30} PID:{proc.pid:<6} exited")


def _print_driver_report(records: list) -> None:
    alerts = [r for r in records if r.alert_level != AlertLevel.INFO]
    total  = len(records)

    print(f"\n  [DRIVERS] {total} loaded — {len(alerts)} flagged\n")

    # Always print alerts first
    for r in alerts:
        level = r.alert_level.value
        lol   = " *** LOLDriver MATCH ***" if r.loldrivers_match else ""
        sig   = "signed" if r.is_signed else "UNSIGNED"
        print(
            f"  [!] {r.name:<30} {sig:<10} "
            f"{level:<8} {r.exe_path}{lol}"
        )
        if r.loldrivers_match:
            print(f"      ID: {r.loldrivers_id}  Tags: {r.loldrivers_tags}")

    # Print a summary of clean drivers (count only, not full list)
    clean = [r for r in records if r.alert_level == AlertLevel.INFO]
    if clean:
        print(f"  [OK] {len(clean)} drivers clean (signed, no LOLDrivers match)")


def _print_events(events: list) -> None:
    for evt in events:
        eid = evt.event_id
        f   = evt.fields
        alert = score_event(evt)

        # Build prefix based on score
        if alert.score >= 75:
            prefix = f"*** HIGH [{alert.score}]"
        elif alert.score >= 50:
            prefix = f" !! MED  [{alert.score}]"
        elif alert.score >= 30:
            prefix = f"  ! LOW  [{alert.score}]"
        else:
            prefix = "       "

        if eid == 1:
            image   = f.get("Image", "?").split("\\")[-1]
            parent  = f.get("ParentImage", "?").split("\\")[-1]
            cmdline = f.get("CommandLine", "")[:60]
            print(f"  {prefix} [EID:1 ] {image:<28} parent={parent:<22} cmd={cmdline}")
            if alert.rule_hits:
                print(f"           rules={alert.rule_hits} — {alert.detail[:80]}")

        elif eid == 3:
            image = f.get("Image", "?").split("\\")[-1]
            dst   = f.get("DestinationIp", "?")
            dport = f.get("DestinationPort", "?")
            print(f"  {prefix} [EID:3 ] {image:<28} → {dst}:{dport}")
            if alert.rule_hits:
                print(f"           rules={alert.rule_hits} — {alert.detail[:80]}")

        elif eid == 11:
            image  = f.get("Image", "?").split("\\")[-1]
            target = f.get("TargetFilename", "?")
            print(f"  {prefix} [EID:11] {image:<28} created {target[:60]}")
            if alert.rule_hits:
                print(f"           rules={alert.rule_hits} — {alert.detail[:80]}")

        elif eid == 4688:
            new_proc = f.get("NewProcessName", "?").split("\\")[-1]
            creator  = f.get("ParentProcessName", "?").split("\\")[-1]
            cmdline  = f.get("CommandLine", "")[:50]
            print(f"  {prefix} [EID:4688] {new_proc:<26} creator={creator:<22} cmd={cmdline}")
            if alert.rule_hits:
                print(f"           rules={alert.rule_hits} — {alert.detail[:80]}")

        elif eid == 7045:
            svc_name = f.get("ServiceName", "?")
            svc_file = f.get("ImagePath", "?")
            print(f"  {prefix} [EID:7045] NEW SERVICE: {svc_name} → {svc_file[:50]}")
            if alert.rule_hits:
                print(f"           rules={alert.rule_hits} — {alert.detail[:80]}")

        elif eid in {7, 8, 10}:
            image = f.get("Image", "?").split("\\")[-1]
            print(f"  {prefix} [EID:{eid:<3}] {image}")
            if alert.rule_hits:
                print(f"           rules={alert.rule_hits} — {alert.detail[:80]}")


def main() -> None:
    logger.info("winspector_start", extra={
        "process_poll": PROCESS_POLL_INTERVAL,
        "driver_poll":  DRIVER_POLL_INTERVAL,
    })
    print("\n  WinSpector — Process + Driver Monitor  (Ctrl+C to stop)\n")

    watcher = ProcessWatcher()
    scanner = DriverScanner()
    miner   = EventLogMiner(db_path=Path("data") / "winspector.db")

    # Establish baselines
    watcher.poll()
    print(f"  Process baseline: {len(watcher.full_snapshot())} processes.\n")

    print("  Running initial driver scan (this takes ~20 seconds)...")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    initial_drivers = scanner.scan()
    _save_driver_report(initial_drivers, ts)
    _print_driver_report(initial_drivers)

    print("\n  Watching for changes...\n")

    last_driver_scan = time.monotonic()

    try:
        while True:
            time.sleep(PROCESS_POLL_INTERVAL)

            # Process diff
            diff = watcher.poll()
            if diff.has_changes():
                print(f"\n  [{datetime.now(timezone.utc).isoformat()}]")
                _print_process_diff(diff)
                _save_diff(diff.to_dict())

            # Event log poll — every cycle
            new_events = miner.poll()
            if new_events:
                detection_eids = {1, 3, 7, 8, 10, 11, 4688, 7045}
                relevant = [e for e in new_events
                            if e.event_id in detection_eids]
                if relevant:
                    print(f"\n  [EVENTS — {datetime.now(timezone.utc).isoformat()}]")
                    _print_events(relevant)

            # Driver scan every 30 seconds
            elapsed = time.monotonic() - last_driver_scan
            if elapsed >= DRIVER_POLL_INTERVAL:
                ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                driver_records = scanner.scan()
                _save_driver_report(driver_records, ts)
                alerts = [r for r in driver_records
                          if r.alert_level != AlertLevel.INFO]
                if alerts:
                    print(f"\n  [DRIVER ALERT — {datetime.now(timezone.utc).isoformat()}]")
                    _print_driver_report(driver_records)
                last_driver_scan = time.monotonic()

    except KeyboardInterrupt:
        logger.info("winspector_stop")
        miner.close()
        print("\n  Stopped.")


if __name__ == "__main__":
    main()
