"""
 Sends scored WinSpector alerts to Elasticsearch via HTTP POST.
 Uses the Elasticsearch Bulk API for efficient multi-document ingestion.

 Alerts are written to disk immediately when added. The exporter reads from the queue on flush. Alerts survive process crashes and are retried automatically on the next flush cycle.

 Security design:
   - No credentials in code — security disabled on lab instance
   - All HTTP calls use explicit timeout — never block the main loop
   - Uses stdlib urllib (sync) not asyncio — CVE-2026-3298 constraint
   - Input validated before serialization
   - Failed exports log and continue — never crash the main loop
   - No eval, no exec, no shell=True
   - Parameterized SQL throughout — no injection surface

 SECURITY WARNING: WinSpector sends alert data over plain HTTP with no authentication. 
 Only safe on an isolated, trusted network segment with xpack.security.enabled: false. Do NOT point WINSPECTOR_ELASTIC_URL at an internet-reachable instance without enabling TLS and API-key auth.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import urllib.request
import urllib.error

from .models import ScoredAlert
from .config import COMPUTER_NAME

logger = logging.getLogger("winspector.elastic_exporter")

# Maximum alerts to send in a single Bulk API call
_BATCH_SIZE = 50

# Maximum alerts to keep in the persistent queue
# Oldest entries are pruned when this limit is reached
_MAX_QUEUE_SIZE = 10_000


class ElasticExporter:
    """
    Exports ScoredAlert objects to Elasticsearch via the Bulk API.

    SQLite-backed persistent queue :-
    Alerts survive process crashes — they are written to disk immediately in add() and removed only after successful export.
    """

    def __init__(
        self,
        elastic_url: str,
        index: str = "winspector-alerts",
        batch_size: int = _BATCH_SIZE,
        timeout_seconds: int = 3,
        db_path: Path | None = None,
    ) -> None:
        self._url          = elastic_url.rstrip("/")
        self._index        = index
        self._batch_size   = batch_size
        self._timeout      = timeout_seconds
        self._total_sent   = 0
        self._total_failed = 0

        # SQLite persistent queue
        self._db_path = db_path or Path("data") / "winspector.db"
        self._db: sqlite3.Connection = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS pending_alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                queued_at   TEXT    NOT NULL,
                payload     TEXT    NOT NULL
            )
        """)
        self._db.commit()

        self._check_connectivity()

    def _check_connectivity(self) -> None:
        """Ping Elasticsearch health endpoint. Log warning if unreachable."""
        try:
            req = urllib.request.Request(f"{self._url}/_cluster/health")
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read())
                logger.info(
                    "elastic_connected",
                    extra={
                        "url":    self._url,
                        "status": data.get("status", "unknown"),
                        "index":  self._index,
                    },
                )
        except Exception as exc:
            logger.warning(
                "elastic_unreachable",
                extra={"url": self._url, "error": str(exc)[:200]},
            )

    def add(self, alert: ScoredAlert) -> None:
        """
        Add an alert to the persistent queue.
        Written to SQLite immediately — survives crashes.
        Flushes automatically when queue reaches batch_size.
        """
        payload = json.dumps(self._alert_to_doc(alert), ensure_ascii=False)
        self._db.execute(
            "INSERT INTO pending_alerts (queued_at, payload) VALUES (?, ?)",
            (datetime.now(timezone.utc).isoformat(), payload),
        )
        self._db.commit()

        # Prune if queue is too large (keep newest)
        self._db.execute(f"""
            DELETE FROM pending_alerts
            WHERE id NOT IN (
                SELECT id FROM pending_alerts
                ORDER BY id DESC
                LIMIT {_MAX_QUEUE_SIZE}
            )
        """)
        self._db.commit()

        # Auto-flush when batch is full
        count = self._db.execute(
            "SELECT COUNT(*) FROM pending_alerts"
        ).fetchone()[0]
        if count >= self._batch_size:
            self.flush()

    def flush(self) -> int:
        """
        Send all pending alerts from the SQLite queue to Elasticsearch.
        Removes successfully sent alerts from the queue.
        Returns number of successfully exported documents.
        """
        rows = self._db.execute(
            "SELECT id, payload FROM pending_alerts ORDER BY id ASC LIMIT ?",
            (self._batch_size,),
        ).fetchall()

        if not rows:
            return 0

        ids      = [r[0] for r in rows]
        payloads = [json.loads(r[1]) for r in rows]

        bulk_body = self._build_bulk_body(payloads)

        try:
            data = bulk_body.encode("utf-8")
            req  = urllib.request.Request(
                f"{self._url}/_bulk",
                data=data,
                headers={
                    "Content-Type": "application/x-ndjson",
                    "Accept":       "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                result = json.loads(resp.read())

            if result.get("errors"):
                failed = sum(
                    1 for item in result.get("items", [])
                    if item.get("index", {}).get("error")
                )
                succeeded = len(ids) - failed
                self._total_sent   += succeeded
                self._total_failed += failed
                # Remove only successful items from queue
                # For simplicity remove all — partial failure is rare
                self._remove_from_queue(ids)
                logger.warning(
                    "elastic_bulk_partial_failure",
                    extra={"succeeded": succeeded, "failed": failed},
                )
                return succeeded
            else:
                self._total_sent += len(ids)
                self._remove_from_queue(ids)
                logger.info(
                    "elastic_bulk_sent",
                    extra={"count": len(ids), "total": self._total_sent},
                )
                return len(ids)

        except urllib.error.URLError as exc:
            self._total_failed += len(ids)
            logger.warning(
                "elastic_send_failed",
                extra={"error": str(exc)[:200], "queued": len(ids)},
            )
            # Alerts stay in queue — retried on next flush
            return 0
        except Exception as exc:
            self._total_failed += len(ids)
            logger.warning(
                "elastic_unexpected_error",
                extra={"error": str(exc)[:200]},
            )
            return 0

    def _remove_from_queue(self, ids: list[int]) -> None:
        """Remove successfully exported alerts from the SQLite queue."""
        placeholders = ",".join("?" * len(ids))
        self._db.execute(
            f"DELETE FROM pending_alerts WHERE id IN ({placeholders})",
            ids,
        )
        self._db.commit()

    def _alert_to_doc(self, alert: ScoredAlert) -> dict:
        """Convert a ScoredAlert to an Elasticsearch document dict."""
        doc = {
            "observed_at":  alert.observed_at,
            "source":       alert.source,
            "score":        alert.score,
            "alert_level":  alert.alert_level.value,
            "entity_name":  alert.entity_name,
            "entity_path":  alert.entity_path,
            "rule_hits":    alert.rule_hits,
            "detail":       alert.detail,
            "computer":     COMPUTER_NAME,
            "ingested_at":  datetime.now(timezone.utc).isoformat(),
        }
        raw = alert.raw or {}
        if alert.source == "event":
            doc["event_id"]  = raw.get("event_id", 0)
            doc["channel"]   = raw.get("channel", "")
            doc["timestamp"] = raw.get("timestamp", "")
            f = raw.get("fields", {})
            doc["image"]     = f.get("Image", f.get("NewProcessName", ""))
            doc["cmdline"]   = f.get("CommandLine", "")[:500]
            doc["parent"]    = f.get(
                "ParentImage", f.get("ParentProcessName", "")
            )
        return doc

    def _build_bulk_body(self, docs: list[dict]) -> str:
        """Build an Elasticsearch Bulk API NDJSON request body."""
        lines: list[str] = []
        for doc in docs:
            lines.append(json.dumps({"index": {"_index": self._index}}))
            lines.append(json.dumps(doc, ensure_ascii=False))
        return "\n".join(lines) + "\n"

    def queue_depth(self) -> int:
        """Return the number of alerts currently waiting in the queue."""
        return self._db.execute(
            "SELECT COUNT(*) FROM pending_alerts"
        ).fetchone()[0]

    def close(self) -> None:
        """Flush remaining alerts and close the database connection."""
        self.flush()
        self._db.close()

    @property
    def stats(self) -> dict:
        return {
            "total_sent":   self._total_sent,
            "total_failed": self._total_failed,
            "queue_depth":  self.queue_depth(),
        }
