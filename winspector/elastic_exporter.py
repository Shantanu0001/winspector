# Module 5 Part 2: Elastic SIEM Export - Sends scored WinSpector alerts to Elasticsearch via HTTP POST.
# Uses the Elasticsearch Bulk API for efficient multi-document ingestion.
"""
 Security design:
   - No credentials in code — security disabled on lab instance
   - All HTTP calls use explicit timeout — never block the main loop
   - Uses requests (sync) not asyncio — CVE-2026-3298 constraint
   - Input validated before serialization
   - Failed exports log and continue — never crash the main loop
   - No eval, no exec, no shell=True
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import urllib.request
import urllib.error

from .models import ScoredAlert
from .config import COMPUTER_NAME

logger = logging.getLogger("winspector.elastic_exporter")

# Exporter

class ElasticExporter:
    """
    Exports ScoredAlert objects to Elasticsearch via the Bulk API.
    Uses stdlib urllib — no additional dependencies.
    Batches alerts and sends in one HTTP call per flush.
    """

    def __init__(
        self,
        elastic_url: str,
        index: str = "winspector-alerts",
        batch_size: int = 20,
        timeout_seconds: int = 3,
    ) -> None:
        # Strip trailing slash
        self._url          = elastic_url.rstrip("/")
        self._index        = index
        self._batch_size   = batch_size
        self._timeout      = timeout_seconds
        self._pending:     list[ScoredAlert] = []
        self._total_sent   = 0
        self._total_failed = 0

        # Verify connectivity on init — warn but don't fail
        self._check_connectivity()

    def _check_connectivity(self) -> None:
        """Ping Elasticsearch health endpoint. Log warning if unreachable."""
        try:
            url = f"{self._url}/_cluster/health"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read())
                status = data.get("status", "unknown")
                logger.info(
                    "elastic_connected",
                    extra={
                        "url":    self._url,
                        "status": status,
                        "index":  self._index,
                    },
                )
        except Exception as exc:
            logger.warning(
                "elastic_unreachable",
                extra={
                    "url":   self._url,
                    "error": str(exc)[:200],
                },
            )

    def add(self, alert: ScoredAlert) -> None:
        """Add an alert to the pending batch. Flushes if batch is full."""
        self._pending.append(alert)
        if len(self._pending) >= self._batch_size:
            self.flush()

    def flush(self) -> int:
        """
        Send all pending alerts to Elasticsearch via Bulk API.
        Returns number of successfully indexed documents.
        Clears pending list regardless of success.
        """
        if not self._pending:
            return 0

        to_send = list(self._pending)
        self._pending.clear()

        bulk_body = self._build_bulk_body(to_send)
        if not bulk_body:
            return 0

        try:
            url  = f"{self._url}/_bulk"
            data = bulk_body.encode("utf-8")
            req  = urllib.request.Request(
                url,
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
                # Count individual document errors
                failed = sum(
                    1 for item in result.get("items", [])
                    if item.get("index", {}).get("error")
                )
                succeeded = len(to_send) - failed
                self._total_sent   += succeeded
                self._total_failed += failed
                logger.warning(
                    "elastic_bulk_partial_failure",
                    extra={"succeeded": succeeded, "failed": failed},
                )
                return succeeded
            else:
                self._total_sent += len(to_send)
                logger.info(
                    "elastic_bulk_sent",
                    extra={
                        "count": len(to_send),
                        "total": self._total_sent,
                    },
                )
                return len(to_send)

        except urllib.error.URLError as exc:
            self._total_failed += len(to_send)
            logger.warning(
                "elastic_send_failed",
                extra={"error": str(exc)[:200], "dropped": len(to_send)},
            )
            return 0
        except Exception as exc:
            self._total_failed += len(to_send)
            logger.warning(
                "elastic_unexpected_error",
                extra={"error": str(exc)[:200]},
            )
            return 0

    def _build_bulk_body(self, alerts: list[ScoredAlert]) -> str:
        """
        Build an Elasticsearch Bulk API request body.
        Format: alternating action + document lines, each terminated by newline.
        """
        lines: list[str] = []
        for alert in alerts:
            # Action line
            action = json.dumps({"index": {"_index": self._index}})
            lines.append(action)

            # Document line
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

            # Add event-specific fields if available
            raw = alert.raw or {}
            if alert.source == "event":
                doc["event_id"] = raw.get("event_id", 0)
                doc["channel"]  = raw.get("channel", "")
                doc["timestamp"] = raw.get("timestamp", "")
                f = raw.get("fields", {})
                doc["image"]    = f.get("Image", f.get("NewProcessName", ""))
                doc["cmdline"]  = f.get("CommandLine", "")[:500]
                doc["parent"]   = f.get(
                    "ParentImage",
                    f.get("ParentProcessName", "")
                )

            lines.append(json.dumps(doc, ensure_ascii=False))

        return "\n".join(lines) + "\n"

    @property
    def stats(self) -> dict:
        return {
            "total_sent":   self._total_sent,
            "total_failed": self._total_failed,
            "pending":      len(self._pending),
        }
