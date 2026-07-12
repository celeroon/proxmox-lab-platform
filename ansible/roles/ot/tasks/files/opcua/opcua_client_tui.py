"""Live htop-style status view for opcua-client, run directly on the VM.

Tails /var/log/opcua-client.log — the same file the systemd service already
writes — and renders the SCADA historian's view of the machine as a
live-updating terminal dashboard. Read-only: parses the existing log stream,
opens no OPC-UA connection of its own beyond what opcua-client is already
doing.

opcua-client's subscription pushes Speed/Status separately (one tag per log
line, unlike every other protocol's combined-state line) — this TUI merges
successive partial updates into a persisted state, so FaultCode never shows
here (the historian doesn't subscribe to it, matching real behavior).

Run:
    /opt/opcua/venv/bin/python3 /opt/opcua/opcua_client_tui.py
"""

from __future__ import annotations

import argparse
import time
from collections import deque
from datetime import datetime
from typing import Deque, Iterator, Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from opcua_tui_common import Reading, parse_log_line, sparkline

HISTORY_LEN = 60
STALE_AFTER_SECONDS = 30.0  # push-driven, not polled -- Status can be genuinely static for a while


def follow(path: str) -> Iterator[Optional[str]]:
    """Yield new lines appended to path, like `tail -f`; yields None on each idle
    poll (no new line yet) so callers can still re-render on a wall-clock cadence.
    Waits if the file doesn't exist yet.
    """
    f = None
    while f is None:
        try:
            f = open(path, "r")
        except FileNotFoundError:
            time.sleep(0.5)
    f.seek(0, 2)  # start at end of file
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.25)
            yield None
            continue
        yield line


def render(state: Reading, speeds: Deque[float], last_update: Optional[datetime]) -> Panel:
    table = Table.grid(padding=(0, 2))
    stale = last_update is not None and (datetime.now() - last_update).total_seconds() > STALE_AFTER_SECONDS

    if state.status is None and state.speed is None:
        table.add_row("[dim]waiting for opcua-client log activity...[/dim]")
    else:
        status_text = {
            "Running": "[bold green]RUNNING[/bold green]",
            "Stopped": "[dim]STOPPED[/dim]",
            "Fault": "[bold red]FAULT[/bold red]",
        }.get(state.status, state.status or "-")
        table.add_row("STATUS (as seen by historian)", status_text)
        table.add_row("SPEED", f"[bold cyan]{state.speed:.1f}[/bold cyan]" if state.speed is not None else "-")
        table.add_row("SPEED TREND", sparkline(speeds, lo=0, hi=2000) or "[dim](collecting...)[/dim]")

    if stale:
        table.add_row("", "[bold white on red] NO UPDATES — opcua-client may have crashed/disconnected [/bold white on red]")

    footer = f"last push: {last_update.strftime('%H:%M:%S') if last_update else '-'}  |  Ctrl+C to exit"
    border = "red" if stale else "white"
    return Panel(table, title="opcua-client — SCADA historian simulator", subtitle=footer, border_style=border)


def main() -> None:
    parser = argparse.ArgumentParser(description="Live TUI for opcua-client")
    parser.add_argument("--log-file", default="/var/log/opcua-client.log")
    args = parser.parse_args()

    console = Console()
    speeds: Deque[float] = deque(maxlen=HISTORY_LEN)
    state = Reading()
    last_update: Optional[datetime] = None

    try:
        with Live(render(state, speeds, last_update), console=console, refresh_per_second=4, screen=True) as live:
            for line in follow(args.log_file):
                if line is not None:
                    parsed = parse_log_line(line)
                    if parsed is not None:
                        if parsed.speed is not None:
                            state.speed = parsed.speed
                            speeds.append(parsed.speed)
                        if parsed.status is not None:
                            state.status = parsed.status
                        last_update = datetime.now()
                live.update(render(state, speeds, last_update))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
