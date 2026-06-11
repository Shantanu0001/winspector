from __future__ import annotations

import os
import sys
import time
import threading
import logging
from pathlib import Path

import win32service
import win32serviceutil
import win32event
import servicemanager

# Project directory — everything resolves relative to this
_PROJECT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_PROJECT_DIR))
os.chdir(str(_PROJECT_DIR))

# Point pythonservice.exe at the venv Python so it can find all packages
_PYTHON_EXE = str(_PROJECT_DIR / ".venv" / "Scripts" / "python.exe")


class WinSpectorService(win32serviceutil.ServiceFramework):
    _svc_name_         = "WinSpector"
    _svc_display_name_ = "WinSpector EDR Monitor"
    _svc_description_  = (
        "Windows process and driver activity monitor. "
        "Collects telemetry, scores alerts, exports to Elasticsearch."
    )
    _svc_start_type_   = win32service.SERVICE_AUTO_START
    _exe_name_         = _PYTHON_EXE
    _exe_args_         = f'"{__file__}"'

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._thread     = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self._stop_event)
        if self._thread:
            self._thread.join(timeout=15)

    def SvcDoRun(self):
        # Report running immediately so SCM does not time out
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )

        self._thread = threading.Thread(
            target=self._run_winspector,
            daemon=True,
        )
        self._thread.start()

        win32event.WaitForSingleObject(
            self._stop_event,
            win32event.INFINITE,
        )

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ""),
        )

    def _run_winspector(self):
        try:
            from winspector.config import ELASTIC_URL
            from winspector.alert_scorer import score_event, score_process
            from winspector.driver_scanner import DriverScanner
            from winspector.elastic_exporter import ElasticExporter
            from winspector.event_log_miner import EventLogMiner
            from winspector.models import AlertLevel
            from winspector.process_watcher import ProcessWatcher

            import hashlib
            import logging.config
            from datetime import datetime, timezone

            LOG_DIR = Path("logs")
            LOG_DIR.mkdir(exist_ok=True)

            logging.config.dictConfig({
                "version": 1,
                "disable_existing_loggers": False,
                "formatters": {
                    "json": {
                        "()": "logging.Formatter",
                        "fmt": (
                            '{"ts":"%(asctime)s","level":"%(levelname)s",'
                            '"logger":"%(name)s","msg":"%(message)s"}'
                        ),
                        "datefmt": "%Y-%m-%dT%H:%M:%S+00:00",
                    }
                },
                "handlers": {
                    "file": {
                        "class": "logging.FileHandler",
                        "formatter": "json",
                        "filename": str(LOG_DIR / "winspector.log"),
                        "encoding": "utf-8",
                    }
                },
                "root": {"level": "INFO", "handlers": ["file"]},
            })

            logger = logging.getLogger("winspector.service")
            logger.info("service_loop_start")

            watcher  = ProcessWatcher()
            scanner  = DriverScanner()
            miner    = EventLogMiner(db_path=Path("data") / "winspector.db")
            exporter = ElasticExporter(
                elastic_url=ELASTIC_URL,
                index="winspector-alerts",
                batch_size=10,
            )

            PROCESS_POLL_INTERVAL = 5
            DRIVER_POLL_INTERVAL  = 30

            Path("data/snapshots").mkdir(parents=True, exist_ok=True)
            Path("data/drivers").mkdir(parents=True, exist_ok=True)

            watcher.poll()
            scanner.scan()
            last_driver_scan = time.monotonic()

            while not self._is_stopping():
                time.sleep(PROCESS_POLL_INTERVAL)
                if self._is_stopping():
                    break

                diff = watcher.poll()
                if diff.has_changes():
                    for proc in diff.created:
                        alert = score_process(proc)
                        if alert.score >= 30:
                            exporter.add(alert)

                new_events = miner.poll()
                if new_events:
                    for evt in new_events:
                        alert = score_event(evt)
                        if alert.score >= 30:
                            exporter.add(alert)

                if time.monotonic() - last_driver_scan >= DRIVER_POLL_INTERVAL:
                    scanner.scan()
                    last_driver_scan = time.monotonic()

                exporter.flush()

            exporter.flush()
            miner.close()
            logger.info("service_loop_stop")

        except Exception as exc:
            servicemanager.LogErrorMsg(f"WinSpector crashed: {exc}")
            raise

    def _is_stopping(self) -> bool:
        return win32event.WaitForSingleObject(
            self._stop_event, 0
        ) == win32event.WAIT_OBJECT_0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(WinSpectorService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(WinSpectorService)
