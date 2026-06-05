# It is data contatiners for winspector telemetry.
# I have used dataclasses that gives me type safety, repr and easy json serialization without external dependencies.

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

class EventType(str,Enum):
    CREATE = "PROCESS_CREATE"
    TERMINATE = "PROCESS_TERMINATE"
    SNAPSHOT = "SNAPSHOT"

class AlertLevel(str,Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

@dataclass
class ProcessRecord:
    """
    Immutable snapshot of a single process at a point in time.
    All fields are collected once and never mutated after construction.
    """

    pid:int
    ppid:int
    name:str
    exe_path:str
    cmdline:str
    username:str
    create_time:float
    sha256:str
    is_signed:bool
    score:int=0
    alert_level:AlertLevel=AlertLevel.INFO
    observed_at:str=field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SnapshotDiff:
    """
    Result of comparing two consecutive process snapshots.
    Created processes appeared in new but not old.
    Terminated processes appeared in old but not new.
    """

    observed_at:str=field(default_factory=lambda:datetime.now(timezone.utc).isoformat())
    created:list[ProcessRecord]=field(default_factory=list)
    terminated:list[ProcessRecord]=field(default_factory=list)

    def has_changes(self) -> bool:
        return bool(self.created or self.terminated)

    def to_dict(self) -> dict:
        return {
            "observed_at": self.observed_at,
            "created": [p.to_dict() for p in self.created],
            "terminated": [p.to_dict() for p in self.terminated],
            }


@dataclass
class DriverRecord:
    """
    Immutable snapshot of a single loaded kernel driver.

    Fields follow the same conservative design as ProcessRecord:
    empty string for unavailable fields, False for unverifiable booleans.
    Never None — callers don't need None checks.

    loldrivers_match: True if SHA256 found in local LOLDrivers DB.
    loldrivers_id:    The LOLDrivers entry Id if matched, else "".
    loldrivers_tags:  Space-joined tags from the matched entry, else "".
    """
    name:             str
    display_name:     str
    exe_path:         str
    state:            str        # Running, Stopped, etc.
    start_mode:       str        # Boot, System, Auto, Manual, Disabled
    sha256:           str
    is_signed:        bool
    loldrivers_match: bool
    loldrivers_id:    str
    loldrivers_tags:  str
    alert_level:      AlertLevel = AlertLevel.INFO
    observed_at:      str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EventRecord:
    """
    Normalised representation of a single Windows event log entry.

    Raw event log messages are key-value strings. We parse them into structured fields at ingest time so downstream consumers (alert scorer, SIEM export)
    never need to touch raw strings.

    channel:      source log channel name
    event_id:     numeric event ID (e.g. 1, 4688, 7045)
    record_number: position in the log — used as cursor for incremental reads
    timestamp:    UTC ISO-8601 string
    computer:     hostname that generated the event
    fields:       parsed key-value pairs from the Message field
                  keys vary by event_id — callers check before accessing
    raw_message:  original unparsed message — retained for forensic completeness
    """
    channel:       str
    event_id:      int
    record_number: int
    timestamp:     str
    computer:      str
    fields:        dict[str, str]
    raw_message:   str
    observed_at:   str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)



@dataclass
class ScoredAlert:
    """
    Output of the alert scorer for a single process or event.

    source:      which module produced the input (process/driver/event)
    rule_hits:   list of rule IDs that fired, e.g. ["RULE-004","RULE-005"]
    score:       additive total, capped at 100
    alert_level: INFO/LOW/MEDIUM/HIGH/CRITICAL
    entity_name: process name, driver name, or event image name
    entity_path: full exe path or driver path
    detail:      human-readable summary of why this scored as it did
    raw:         the original record as a dict for JSON export
    """
    source:      str
    rule_hits:   list[str]
    score:       int
    alert_level: AlertLevel
    entity_name: str
    entity_path: str
    detail:      str
    raw:         dict
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)
