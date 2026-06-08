from __future__ import annotations

import hashlib
import json
import logging
import logging.config
import time
from datetime import datetime, timezone
from pathlib import Path

from winspector.alert_scorer import score_driver, score_event, score_process
from winspector.dashboard import Dashboard
from winspector.driver_scanner import DriverScanner
from winspector.elastic_exporter import ElasticExporter
from winspector.event_log_miner import EventLogMiner
from winspector.models import AlertLevel
from winspector.process_watcher import ProcessWatcher

# Structured JSON logging — file only, console goes to dashboard

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "logging.Formatter",
            "fmt": '{"ts":"%(asctime)s","level":"%(levelname)s",'
                   '"logger":"%(name)s","msg":"%(message)s"}',
            "datefmt": "%Y-%m-%dT%H:%M:%S+00:00",
        }
    },
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "formatter": "json",
            "filename": str(LOG_DIR / "winspector.log"),
            "encoding": "utf-8",
        },
    },
    "root": {"level": "INFO", "handlers": ["file"]},
}

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("winspector.main")

# Snapshot persistence

SNAPSHOT_DIR = Path("data") / "snapshots"
SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
DRIVER_REPORT_DIR = Path("data") / "drivers"
DRIVER_REPORT_DIR.mkdir(parents=True, exist_ok=True)

_MANIFEST_FILE        = SNAPSHOT_DIR / "manifest.jsonl"
_DRIVER_MANIFEST_FILE = DRIVER_REPORT_DIR / "manifest.jsonl"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65_536):
            h.update(chunk)
    return h.hexdigest()


def _save_diff(diff_dict: dict) -> None:
    ts  = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = SNAPSHOT_DIR / f"diff_{ts}.json"
    out.write_text(json.dumps(diff_dict, indent=2), encoding="utf-8")
    sha256 = _sha256_file(out)
    with _MANIFEST_FILE.open("a", encoding="utf-8") as mf:
        mf.write(json.dumps({
            "file": out.name, "sha256": sha256,
            "ts": datetime.now(timezone.utc).isoformat(),
        }) + "\n")


def _save_driver_report(records: list, ts: str) -> None:
    out = DRIVER_REPORT_DIR / f"drivers_{ts}.json"
    out.write_text(
        json.dumps([r.to_dict() for r in records], indent=2),
        encoding="utf-8",
    )
    sha256 = _sha256_file(out)
    with _DRIVER_MANIFEST_FILE.open("a", encoding="utf-8") as mf:
        mf.write(json.dumps({
            "file": out.name, "sha256": sha256,
            "ts": datetime.now(timezone.utc).isoformat(),
        }) + "\n")


# Poll intervals

PROCESS_POLL_INTERVAL = 5
DRIVER_POLL_INTERVAL  = 30


# Main

def main() -> None:
    logger.info("winspector_start", extra={
        "process_poll": PROCESS_POLL_INTERVAL,
        "driver_poll":  DRIVER_POLL_INTERVAL,
    })

    watcher = ProcessWatcher()
    scanner = DriverScanner()
    miner   = EventLogMiner(db_path=Path("data") / "winspector.db")

    exporter = ElasticExporter(
        elastic_url="http://192.168.91.129:9200",
        index="winspector-alerts",
        batch_size=10,
    )

    dashboard = Dashboard()

    with dashboard:
        # Baselines
        watcher.poll()
        dashboard.state.process_count   = len(watcher.full_snapshot())
        dashboard.state.last_process_poll = _now()
        dashboard.update()

        # Initial driver scan
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        initial_drivers = scanner.scan()
        _save_driver_report(initial_drivers, ts)
        flagged = [r for r in initial_drivers
                   if r.alert_level != AlertLevel.INFO]
        dashboard.state.update_drivers(initial_drivers, flagged)
        dashboard.state.last_driver_scan = _now()
        dashboard.update()

        last_driver_scan = time.monotonic()

        try:
            while True:
                time.sleep(PROCESS_POLL_INTERVAL)

                # Process diff
                diff = watcher.poll()
                dashboard.state.process_count   = len(watcher.full_snapshot())
                dashboard.state.last_process_poll = _now()

                if diff.has_changes():
                    _save_diff(diff.to_dict())
                    for proc in diff.created:
                        alert = score_process(proc)
                        dashboard.state.add_process_created(proc, alert)
                        if alert.score >= 30:
                            exporter.add(alert)
                    for proc in diff.terminated:
                        dashboard.state.add_process_terminated(proc)

                # Event log
                new_events = miner.poll()
                dashboard.state.last_event_poll = _now()
                if new_events:
                    for evt in new_events:
                        alert = score_event(evt)
                        dashboard.state.add_event(evt, alert)
                        if alert.score >= 30:
                            exporter.add(alert)

                # Driver scan
                if time.monotonic() - last_driver_scan >= DRIVER_POLL_INTERVAL:
                    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    driver_records = scanner.scan()
                    _save_driver_report(driver_records, ts)
                    flagged = [r for r in driver_records
                               if r.alert_level != AlertLevel.INFO]
                    dashboard.state.update_drivers(driver_records, flagged)
                    dashboard.state.last_driver_scan = _now()
                    last_driver_scan = time.monotonic()

                # Flush any pending alerts to Elastic
                exporter.flush()

                # Redraw dashboard
                dashboard.update()

        except KeyboardInterrupt:
            exporter.flush()  # flush remaining before exit
            miner.close()
            logger.info("winspector_stop")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


if __name__ == "__main__":
    main()
