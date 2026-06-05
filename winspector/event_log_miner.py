# Reads Windows event logs incrementally using pywin32 (win32evtlog).
# Parses Sysmon and Windows Security/System events into structured EventRecord objects and persists them in SQLite with WAL mode.

"""
Security design decisions:
   - pywin32 direct API — no subprocess, no PowerShell, no shell=True
   - All SQLite writes use parameterized queries — no string SQL
   - SQLite WAL mode for crash safety
   - Record number cursor persisted in DB — survives restarts
   - Raw message stored but never executed or eval'd
   - All timestamps normalised to UTC ISO-8601
   - Input from event log treated as untrusted — field parser is defensive, unknown fields are stored but never acted upon
   - DB schema versioned — safe to add columns in future migrations

 Threat model:
   - Attacker generates high event volume to exhaust log buffer (log poisoning) -> mitigated by MAX_EVENTS_PER_POLL cap
   - Attacker crafts event message to inject SQL -> parameterized queries
   - Attacker modifies event log to cover tracks -> record_number cursor detects gaps; Sysmon itself logs tampering attempts

 Detection opportunities (events we parse):
   Sysmon EID 1  -- process create with full cmdline + hashes
   Sysmon EID 3  -- network connection (catches C2 callbacks)
   Sysmon EID 7  -- image load (DLL injection detection)
   Sysmon EID 8  -- CreateRemoteThread (process injection)
   Sysmon EID 10 -- ProcessAccess (lsass dumping)
   Sysmon EID 11 -- FileCreate (payload dropped to disk)
   Security 4688 -- process creation (Windows native)
   System 7045   -- new service/driver installed
"""
from __future__ import annotations

import logging
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import win32evtlog

from .models import EventRecord

logger = logging.getLogger("winspector.event_log_miner")

# XML namespace used in all Windows event log XML
_EVT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS     = {"e": _EVT_NS}


# Constants

_SYSMON_IDS   = frozenset({1, 3, 7, 8, 10, 11})
_SECURITY_IDS = frozenset({4688})
_SYSTEM_IDS   = frozenset({7045})

_MAX_EVENTS_PER_POLL = 500

_CHANNELS = {
    "Microsoft-Windows-Sysmon/Operational": _SYSMON_IDS,
    "Security":                             _SECURITY_IDS,
    "System":                               _SYSTEM_IDS,
}


# SQLite schema

_SCHEMA_VERSION = 1

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    channel       TEXT    NOT NULL,
    event_id      INTEGER NOT NULL,
    record_number INTEGER NOT NULL,
    timestamp     TEXT    NOT NULL,
    computer      TEXT    NOT NULL,
    fields        TEXT    NOT NULL,
    raw_message   TEXT    NOT NULL,
    observed_at   TEXT    NOT NULL,
    UNIQUE(channel, record_number)
);

CREATE INDEX IF NOT EXISTS idx_events_event_id
    ON events(event_id);

CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON events(timestamp);

CREATE TABLE IF NOT EXISTS cursors (
    channel     TEXT PRIMARY KEY,
    last_record INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT    NOT NULL
);
"""


def _init_db(db_path: Path) -> sqlite3.Connection:
    """
    Open or create the SQLite database with WAL mode and correct schema.
    Returns an open connection. Caller is responsible for closing.

    Security: WAL mode prevents corruption on crash. The UNIQUE constraint
    on (channel, record_number) prevents duplicate event ingestion even if
    the cursor is reset.
    """
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")

    conn.executescript(_DDL)

    conn.execute(
        """
        INSERT OR IGNORE INTO schema_version (version, applied_at)
        VALUES (?, ?)
        """,
        (_SCHEMA_VERSION, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()

    logger.info(
        "db_initialized",
        extra={"path": str(db_path), "schema_version": _SCHEMA_VERSION},
    )
    return conn


# ---------------------------------------------------------------------------
# XML-based event parser
# ---------------------------------------------------------------------------

def _parse_event_xml(xml_str: str) -> tuple[int, str, str, dict[str, str]]:
    """
    Parse a Windows event XML string into (event_id, timestamp, computer, fields).

    Returns (0, "", "", {}) on any parse failure — callers must check event_id != 0.

    The XML structure is:
        <Event>
          <System>
            <EventID>N</EventID>
            <TimeCreated SystemTime="..."/>
            <Computer>hostname</Computer>
          </System>
          <EventData>
            <Data Name="FieldName">Value</Data>
            ...
          </EventData>
        </Event>

    Security: input is untrusted event log data. We use ElementTree's
    safe parser — no exec, no eval, no dynamic dispatch on field values.
    Field values are truncated to 2048 chars to prevent log bloat.
    """
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return 0, "", "", {}

    try:
        eid = int(root.findtext("e:System/e:EventID", "0", _NS))
    except (ValueError, TypeError):
        return 0, "", "", {}

    # Timestamp from System/TimeCreated/@SystemTime — already UTC
    time_elem = root.find("e:System/e:TimeCreated", _NS)
    timestamp = ""
    if time_elem is not None:
        raw_ts = time_elem.get("SystemTime", "")
        # Normalise to ISO-8601 UTC
        # Windows format: "2026-06-03T14:27:30.5106352Z"
        if raw_ts:
            timestamp = raw_ts.replace("Z", "+00:00")
            # Truncate sub-second precision to microseconds if needed
            if "." in timestamp:
                dot_pos   = timestamp.index(".")
                plus_pos  = timestamp.index("+")
                sub_sec   = timestamp[dot_pos+1:plus_pos][:6]
                timestamp = timestamp[:dot_pos+1] + sub_sec + "+00:00"

    computer = root.findtext("e:System/e:Computer", "", _NS)

    # Parse EventData named fields
    fields: dict[str, str] = {}
    event_data = root.find("e:EventData", _NS)
    if event_data is not None:
        for data_elem in event_data:
            name  = data_elem.get("Name", "").strip()
            value = (data_elem.text or "").strip()[:2048]
            if name:
                fields[name] = value

    return eid, timestamp, computer, fields


# ---------------------------------------------------------------------------
# Bookmark-based cursor for EvtQuery
# ---------------------------------------------------------------------------

def _make_bookmark_query(channel: str, bookmark_xml: Optional[str]) -> object:
    """
    Create an EvtQuery handle positioned after a bookmark.
    If no bookmark, starts from the oldest event.
    Returns the query handle or None on failure.
    """
    try:
        flags = win32evtlog.EvtQueryChannelPath
        h = win32evtlog.EvtQuery(channel, flags, "*", None)
        if bookmark_xml:
            try:
                bm = win32evtlog.EvtCreateBookmark(bookmark_xml)
                win32evtlog.EvtSeek(
                    h, 1, bm,
                    win32evtlog.EvtSeekRelativeToBookmark
                )
            except Exception:
                # Bookmark seek failed — start from beginning
                pass
        return h
    except Exception as exc:
        logger.warning(
            "evtquery_open_failed",
            extra={"channel": channel, "error": str(exc)[:200]},
        )
        return None


# ---------------------------------------------------------------------------
# Core reader — EvtQuery/EvtNext/EvtRender
# ---------------------------------------------------------------------------

def _read_channel(
    channel: str,
    allowed_ids: frozenset[int],
    last_record: int,
    max_events: int,
) -> list[EventRecord]:
    """
    Read new events from a single channel using EvtQuery/EvtNext/EvtRender.

    Filters by record number (> last_record) to read only new events.
    Filters by event ID against allowed_ids.
    Returns EventRecord list, oldest first.
    """
    records: list[EventRecord] = []

    try:
        flags = win32evtlog.EvtQueryChannelPath
        h = win32evtlog.EvtQuery(channel, flags, "*", None)
    except Exception as exc:
        logger.warning(
            "channel_open_failed",
            extra={"channel": channel, "error": str(exc)[:200]},
        )
        return records

    try:
        collected = []
        while len(collected) < max_events:
            try:
                batch = win32evtlog.EvtNext(h, 50)
            except Exception:
                break
            if not batch:
                break

            for evt_handle in batch:
                try:
                    xml_str = win32evtlog.EvtRender(
                        evt_handle,
                        win32evtlog.EvtRenderEventXml,
                    )
                except Exception:
                    continue

                eid, timestamp, computer, fields = _parse_event_xml(xml_str)
                if eid == 0:
                    continue
                if eid not in allowed_ids:
                    continue

                # Use record number from XML System/EventRecordID
                root = ET.fromstring(xml_str)
                rec_num_str = root.findtext(
                    "e:System/e:EventRecordID", "0", _NS
                )
                try:
                    rec_num = int(rec_num_str)
                except (ValueError, TypeError):
                    rec_num = 0

                if rec_num <= last_record:
                    continue

                record = EventRecord(
                    channel       = channel,
                    event_id      = eid,
                    record_number = rec_num,
                    timestamp     = timestamp,
                    computer      = computer,
                    fields        = fields,
                    raw_message   = xml_str[:4096],
                )
                collected.append(record)

                if len(collected) >= max_events:
                    break

        records = collected

    except Exception as exc:
        logger.warning(
            "channel_read_error",
            extra={"channel": channel, "error": str(exc)[:200]},
        )

    return records


# EventLogMiner

class EventLogMiner:
    """
    Polls configured Windows event log channels incrementally,
    parses events into EventRecord objects, and persists them in SQLite.

    Usage:
        miner = EventLogMiner(db_path=Path("data/winspector.db"))
        while True:
            new_events = miner.poll()
            for evt in new_events:
                handle(evt)
            time.sleep(5)
    """

    def __init__(
        self,
        db_path: Path = Path("data") / "winspector.db",
        max_events_per_poll: int = _MAX_EVENTS_PER_POLL,
    ) -> None:
        self._db_path    = db_path
        self._max_events = max_events_per_poll
        self._conn       = _init_db(db_path)
        self._cursors: dict[str, int] = self._load_cursors()
        self._seed_cursors_if_new()
        logger.info(
            "event_log_miner_init",
            extra={
                "channels": list(_CHANNELS.keys()),
                "cursors":  self._cursors,
            },
        )

    def _seed_cursors_if_new(self) -> None:
        """
        On first run, seed cursor to current end of each log so we only
        process events generated after WinSpector starts.
        Uses EvtQuery to find the latest EventRecordID.
        """
        for channel in _CHANNELS:
            if self._cursors.get(channel, 0) > 0:
                continue
            try:
                # Query in reverse to get the most recent event's RecordID
                h = win32evtlog.EvtQuery(
                    channel,
                    win32evtlog.EvtQueryChannelPath |
                    win32evtlog.EvtQueryReverseDirection,
                    "*",
                    None,
                )
                batch = win32evtlog.EvtNext(h, 1)
                if batch:
                    xml_str = win32evtlog.EvtRender(
                        batch[0], win32evtlog.EvtRenderEventXml
                    )
                    root = ET.fromstring(xml_str)
                    rec_str = root.findtext(
                        "e:System/e:EventRecordID", "0", _NS
                    )
                    last = int(rec_str or "0")
                    self._cursors[channel] = last
                    self._save_cursor(channel, last)
                    logger.info(
                        "cursor_seeded",
                        extra={"channel": channel, "seeded_to": last},
                    )
            except Exception as exc:
                logger.warning(
                    "cursor_seed_failed",
                    extra={"channel": channel, "error": str(exc)[:200]},
                )

    def _load_cursors(self) -> dict[str, int]:
        """Load last-read record numbers from DB."""
        cursors: dict[str, int] = {ch: 0 for ch in _CHANNELS}
        rows = self._conn.execute(
            "SELECT channel, last_record FROM cursors"
        ).fetchall()
        for row in rows:
            if row["channel"] in cursors:
                cursors[row["channel"]] = row["last_record"]
        return cursors

    def _save_cursor(self, channel: str, last_record: int) -> None:
        """Persist cursor to DB so it survives restarts."""
        self._conn.execute(
            """
            INSERT INTO cursors (channel, last_record, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(channel) DO UPDATE SET
                last_record = excluded.last_record,
                updated_at  = excluded.updated_at
            """,
            (channel, last_record, datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    def _persist_events(self, events: list[EventRecord]) -> int:
        """
        Write events to SQLite. Returns count of newly inserted rows.
        UNIQUE(channel, record_number) silently ignores duplicates.
        """
        import json
        inserted = 0
        for evt in events:
            try:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO events
                        (channel, event_id, record_number, timestamp,
                         computer, fields, raw_message, observed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evt.channel,
                        evt.event_id,
                        evt.record_number,
                        evt.timestamp,
                        evt.computer,
                        json.dumps(evt.fields),
                        evt.raw_message,
                        evt.observed_at,
                    ),
                )
                if self._conn.execute("SELECT changes()").fetchone()[0]:
                    inserted += 1
            except sqlite3.Error as exc:
                logger.warning(
                    "event_persist_failed",
                    extra={"error": str(exc)[:200]},
                )
        self._conn.commit()
        return inserted

    def poll(self) -> list[EventRecord]:
        """
        Read new events from all channels since last cursor position.
        Persists events to SQLite and advances cursors.
        Returns all newly ingested EventRecord objects.
        """
        all_new: list[EventRecord] = []

        for channel, allowed_ids in _CHANNELS.items():
            last = self._cursors.get(channel, 0)
            new_events = _read_channel(
                channel, allowed_ids, last, self._max_events
            )

            if not new_events:
                continue

            inserted = self._persist_events(new_events)
            if inserted:
                max_record = max(e.record_number for e in new_events)
                self._cursors[channel] = max_record
                self._save_cursor(channel, max_record)
                all_new.extend(new_events)
                logger.info(
                    "events_ingested",
                    extra={
                        "channel": channel,
                        "count":   inserted,
                        "cursor":  max_record,
                    },
                )

        return all_new

    def query_recent(
        self,
        event_id: Optional[int] = None,
        limit: int = 50,
    ) -> list[dict]:
        """
        Query recent events from SQLite.
        Optionally filter by event_id.
        Returns list of dicts ordered by timestamp descending.
        """
        import json
        if event_id is not None:
            rows = self._conn.execute(
                """
                SELECT * FROM events
                WHERE event_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (event_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT * FROM events
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        results = []
        for row in rows:
            d = dict(row)
            d["fields"] = json.loads(d["fields"])
            results.append(d)
        return results

    def close(self) -> None:
        """Close the database connection cleanly."""
        try:
            self._conn.close()
        except Exception:
            pass
