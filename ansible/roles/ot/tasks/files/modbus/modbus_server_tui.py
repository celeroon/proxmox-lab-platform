"""Live htop-style status view for modbus-server, run directly on the VM.

Tails /var/log/modbus-server.log — the same file the systemd service already
writes — and renders the tank/pump/alarm state as a live-updating terminal
dashboard. Read-only: opens no Modbus connection of its own, so it can't be
mistaken for a second Modbus master and never appears in a Malcolm/Zeek
capture.

Run:
    /opt/modbus/venv/bin/python3 /opt/modbus/modbus_server_tui.py
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

from modbus_tui_common import Reading, bar, parse_log_line, sparkline

HISTORY_LEN = 60
STALE_AFTER_SECONDS = 5.0


def follow(path: str) -> Iterator[Optional[str]]:
    """Yield new lines appended to path, like `tail -f`; yields None on each idle
    poll (no new line yet) so callers can still re-render on a wall-clock cadence —
    e.g. to notice "no updates in N seconds" even while nothing new arrives.
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


def render(reading: Optional[Reading], history: Deque[float], last_update: Optional[datetime]) -> Panel:
    table = Table.grid(padding=(0, 2))
    stale = last_update is not None and (datetime.now() - last_update).total_seconds() > STALE_AFTER_SECONDS

    if reading is None:
        table.add_row("[dim]waiting for modbus-server log activity...[/dim]")
    else:
        level_color = "red" if reading.high_alarm else ("yellow" if reading.level >= 70 else "green")
        table.add_row("LEVEL", f"[bold {level_color}]{reading.level:5.1f}%[/bold {level_color}]  {bar(reading.level)}")
        pump_text = "[bold green]ON[/bold green]" if reading.pump_on else "[dim]OFF[/dim]"
        alarm_text = "[bold red]ALARM[/bold red]" if reading.high_alarm else "[green]OK[/green]"
        table.add_row("PUMP", pump_text)
        table.add_row("ALARM", alarm_text)
        if reading.threshold is not None:
            table.add_row("THRESHOLD", f"{reading.threshold:.1f}%")
        table.add_row("HISTORY", sparkline(history) or "[dim](collecting...)[/dim]")

    if stale:
        table.add_row("", "[bold white on red] NO UPDATES — modbus-server may have crashed [/bold white on red]")

    footer = f"last update: {last_update.strftime('%H:%M:%S') if last_update else '-'}  |  Ctrl+C to exit"
    border = "red" if stale else "white"
    return Panel(table, title="modbus-server — tank + pump simulator", subtitle=footer, border_style=border)


def main() -> None:
    parser = argparse.ArgumentParser(description="Live TUI for modbus-server")
    parser.add_argument("--log-file", default="/var/log/modbus-server.log")
    args = parser.parse_args()

    console = Console()
    history: Deque[float] = deque(maxlen=HISTORY_LEN)
    reading: Optional[Reading] = None
    last_update: Optional[datetime] = None

    try:
        with Live(render(reading, history, last_update), console=console, refresh_per_second=4, screen=True) as live:
            for line in follow(args.log_file):
                if line is not None:
                    parsed = parse_log_line(line)
                    if parsed is not None:
                        reading = parsed
                        history.append(parsed.level)
                        last_update = datetime.now()
                live.update(render(reading, history, last_update))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
