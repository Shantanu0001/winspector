# Module 5 Part 1: Terminal Dashboard - A Rich TUI that displays live WinSpector telemetry in a single terminal window. 

# Replaces the ad-hoc print() calls in main.py with a structured, colour-coded live display.
# Security: no user input accepted, no exec, no eval.
# Display only — all data comes from the existing module pipeline.

from __future__ import annotations

import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from .models import AlertLevel, DriverRecord, EventRecord, ProcessRecord, ScoredAlert

# Colour scheme

_LEVEL_STYLE = {
    AlertLevel.INFO:     "dim white",
    AlertLevel.LOW:      "yellow",
    AlertLevel.MEDIUM:   "orange1",
    AlertLevel.HIGH:     "bold red",
}

_LEVEL_LABEL = {
    AlertLevel.INFO:     "INFO  ",
    AlertLevel.LOW:      "LOW   ",
    AlertLevel.MEDIUM:   "MEDIUM",
    AlertLevel.HIGH:     "HIGH  ",
}

_EID_LABEL = {
    1:    "[cyan]PROC CREATE [/cyan]",
    3:    "[magenta]NET CONNECT [/magenta]",
    7:    "[yellow]IMAGE LOAD  [/yellow]",
    8:    "[red]REMOTE THRD [/red]",
    10:   "[red]PROC ACCESS [/red]",
    11:   "[blue]FILE CREATE [/blue]",
    4688: "[cyan]WIN PROC    [/cyan]",
    7045: "[yellow]SVC INSTALL [/yellow]",
}


# Dashboard state — all deques are bounded to prevent unbounded memory growth


class DashboardState:
    """
    Shared mutable state between the polling loop and the renderer.
    All collections are bounded deques — oldest entries drop off automatically when capacity is exceeded.
    """

    def __init__(self) -> None:
        self.start_time        = time.monotonic()
        self.process_count     = 0
        self.driver_count      = 0
        self.driver_alerts     = 0
        self.total_alerts      = 0

        # Recent process events — (symbol, name, pid, ppid, user, signed)
        self.process_events: deque[tuple] = deque(maxlen=12)

        # Recent scored alerts — ScoredAlert objects
        self.alerts: deque[ScoredAlert] = deque(maxlen=10)

        # Recent event log entries — (eid, entity_name, detail, score, level)
        self.event_log: deque[tuple] = deque(maxlen=15)

        # Driver status line
        self.driver_status     = "Scanning..."
        self.flagged_drivers:  list[DriverRecord] = []

        # Last poll timestamps
        self.last_process_poll = "never"
        self.last_driver_scan  = "never"
        self.last_event_poll   = "never"

    def add_process_created(self, proc: ProcessRecord, alert: ScoredAlert) -> None:
        signed = "Y" if proc.is_signed else "N"
        style  = "green" if proc.is_signed else "red"
        self.process_events.appendleft((
            "[green]+[/green]", proc.name, proc.pid,
            proc.ppid, proc.username, signed, style, alert,
        ))
        if alert.score >= 30:
            self.alerts.appendleft(alert)
            self.total_alerts += 1

    def add_process_terminated(self, proc: ProcessRecord) -> None:
        self.process_events.appendleft((
            "[dim]-[/dim]", proc.name, proc.pid,
            proc.ppid, "", "", "dim", None,
        ))

    def add_event(self, evt: EventRecord, alert: ScoredAlert) -> None:
        eid_label = _EID_LABEL.get(evt.event_id, f"EID:{evt.event_id}")
        f = evt.fields
        entity = (
            f.get("Image", f.get("NewProcessName", ""))
            .split("\\")[-1]
        )[:28]
        detail = alert.detail[:50] if alert.detail != "clean" else ""
        self.event_log.appendleft((
            eid_label, entity, detail,
            alert.score, alert.alert_level,
        ))
        if alert.score >= 30:
            self.alerts.appendleft(alert)
            self.total_alerts += 1

    def update_drivers(
        self,
        records: list[DriverRecord],
        flagged: list[DriverRecord],
    ) -> None:
        self.driver_count  = len(records)
        self.driver_alerts = len(flagged)
        self.flagged_drivers = flagged
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        if flagged:
            self.driver_status = f"[red]{len(flagged)} FLAGGED[/red] @ {ts}"
        else:
            self.driver_status = f"[green]{len(records)} clean[/green] @ {ts}"


# Renderers — each returns a Rich renderable

def _render_header(state: DashboardState) -> Panel:
    elapsed  = int(time.monotonic() - state.start_time)
    hours    = elapsed // 3600
    minutes  = (elapsed % 3600) // 60
    seconds  = elapsed % 60
    uptime   = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    now_utc  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    alert_style = "bold red" if state.total_alerts > 0 else "green"

    t = Table.grid(padding=(0, 4))
    t.add_column(style="bold cyan",   justify="left")
    t.add_column(style="dim white",   justify="left")
    t.add_column(style="dim white",   justify="left")
    t.add_column(style=alert_style,   justify="left")
    t.add_column(style="dim white",   justify="right")
    t.add_row(
        "WinSpector",
        f"uptime {uptime}",
        f"processes {state.process_count}",
        f"alerts {state.total_alerts}",
        now_utc,
    )
    return Panel(t, style="bold cyan", box=box.HEAVY_HEAD, padding=(0, 1))


def _render_alerts(state: DashboardState) -> Panel:
    if not state.alerts:
        return Panel(
            Text("No alerts — system clean", style="dim green"),
            title="[bold]Recent Alerts[/bold]",
            border_style="green",
            box=box.ROUNDED,
        )

    t = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold white",
        padding=(0, 1),
        expand=True,
    )
    t.add_column("Level",   width=8)
    t.add_column("Score",   width=6)
    t.add_column("Source",  width=8)
    t.add_column("Entity",  width=28)
    t.add_column("Rules",   width=22)
    t.add_column("Detail",  ratio=1)

    for alert in list(state.alerts)[:8]:
        style    = _LEVEL_STYLE.get(alert.alert_level, "white")
        label    = _LEVEL_LABEL.get(alert.alert_level, "?")
        rules_str = ",".join(alert.rule_hits)[:20]
        detail   = alert.detail[:50]
        t.add_row(
            Text(label, style=style),
            Text(str(alert.score), style=style),
            alert.source[:7],
            alert.entity_name[:27],
            rules_str,
            detail,
            style=style if alert.alert_level != AlertLevel.INFO else "",
        )

    border = "red" if any(
        a.alert_level == AlertLevel.HIGH for a in state.alerts
    ) else "yellow"

    return Panel(
        t,
        title=f"[bold]Alerts ({len(state.alerts)})[/bold]",
        border_style=border,
        box=box.ROUNDED,
    )


def _render_processes(state: DashboardState) -> Panel:
    t = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold white",
        padding=(0, 1),
        expand=True,
    )
    t.add_column("",       width=3)
    t.add_column("Name",   width=24)
    t.add_column("PID",    width=7)
    t.add_column("PPID",   width=7)
    t.add_column("Sig",    width=3)
    t.add_column("Score",  width=5)

    for entry in list(state.process_events)[:10]:
        sym, name, pid, ppid, user, signed, style, alert = entry
        score_str = str(alert.score) if alert and alert.score > 0 else ""
        score_style = (
            "red" if alert and alert.score >= 75 else
            "yellow" if alert and alert.score >= 30 else
            "dim"
        )
        t.add_row(
            Text.from_markup(sym),
            name[:23],
            str(pid),
            str(ppid) if ppid else "",
            Text(signed, style=style),
            Text(score_str, style=score_style),
        )

    return Panel(
        t,
        title=f"[bold]Processes[/bold] (baseline {state.process_count})",
        border_style="cyan",
        box=box.ROUNDED,
    )


def _render_events(state: DashboardState) -> Panel:
    t = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold white",
        padding=(0, 1),
        expand=True,
    )
    t.add_column("Type",    width=13)
    t.add_column("Entity",  width=24)
    t.add_column("Score",   width=6)
    t.add_column("Detail",  ratio=1)

    for eid_label, entity, detail, score, level in list(state.event_log)[:12]:
        style = _LEVEL_STYLE.get(level, "dim white") if score >= 30 else "dim white"
        t.add_row(
            Text.from_markup(eid_label),
            entity[:23],
            Text(str(score) if score > 0 else "", style=style),
            Text(detail[:40], style=style),
        )

    return Panel(
        t,
        title="[bold]Event Stream[/bold]",
        border_style="blue",
        box=box.ROUNDED,
    )


def _render_drivers(state: DashboardState) -> Panel:
    content: list = []

    status_line = Text.from_markup(
        f"Drivers: {state.driver_status}   "
        f"LOLDrivers DB: [cyan]active[/cyan]"
    )
    content.append(status_line)

    if state.flagged_drivers:
        content.append(Text(""))
        for drv in state.flagged_drivers[:4]:
            style = "bold red" if drv.loldrivers_match else "yellow"
            flag  = "*** LOLDriver MATCH" if drv.loldrivers_match else "UNSIGNED"
            content.append(
                Text(f"  [!] {drv.name:<30} {flag}", style=style)
            )

    from rich.console import Group
    border = "red" if state.flagged_drivers else "dim white"
    return Panel(
        Group(*content),
        title="[bold]Driver Scanner[/bold]",
        border_style=border,
        box=box.ROUNDED,
        padding=(0, 1),
    )


def _render_statusbar(state: DashboardState) -> Panel:
    t = Table.grid(padding=(0, 3))
    t.add_column(style="dim")
    t.add_column(style="dim")
    t.add_column(style="dim")
    t.add_column(style="dim", justify="right")
    t.add_row(
        f"proc poll: {state.last_process_poll}",
        f"driver scan: {state.last_driver_scan}",
        f"event poll: {state.last_event_poll}",
        "Ctrl+C to stop",
    )
    return Panel(t, style="dim", box=box.HORIZONTALS, padding=(0, 1))


# Layout builder

def build_layout(state: DashboardState) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header",    size=3),
        Layout(name="alerts",    size=13),
        Layout(name="middle",    ratio=1),
        Layout(name="drivers",   size=5),
        Layout(name="statusbar", size=3),
    )
    layout["middle"].split_row(
        Layout(name="processes", ratio=1),
        Layout(name="events",    ratio=1),
    )
    layout["header"].update(_render_header(state))
    layout["alerts"].update(_render_alerts(state))
    layout["middle"]["processes"].update(_render_processes(state))
    layout["middle"]["events"].update(_render_events(state))
    layout["drivers"].update(_render_drivers(state))
    layout["statusbar"].update(_render_statusbar(state))
    return layout


# Public interface

class Dashboard:
    """ Wraps Rich Live display. Call update() each poll cycle to refresh."""

    def __init__(self) -> None:
        self.state   = DashboardState()
        self._console = Console()
        self._live   = Live(
            build_layout(self.state),
            console=self._console,
            refresh_per_second=1,
            screen=True,
        )

    def __enter__(self) -> "Dashboard":
        self._live.__enter__()
        return self

    def __exit__(self, *args) -> None:
        self._live.__exit__(*args)

    def update(self) -> None:
        """Rebuild and push the layout to the terminal."""
        self._live.update(build_layout(self.state))
