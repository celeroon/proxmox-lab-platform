"""Live htop-style status view for dnp3-server, run directly on the VM.

Tails /var/log/dnp3-server.log — the same file the systemd service already
writes — and renders the breaker/line-current state as a live-updating
terminal dashboard. Read-only: opens no DNP3 connection of its own, so it
can't be mistaken for a second master and never appears in a Malcolm/Zeek
capture.

Run:
    /opt/dnp3/venv/bin/python3 /opt/dnp3/dnp3_server_tui.py
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

from dnp3_tui_common import Reading, parse_log_line, sparkline

HISTORY_LEN = 60
STALE_AFTER_SECONDS = 5.0  # server ticks every 1s by default


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


def render(reading: Optional[Reading], currents: Deque[float], last_update: Optional[datetime]) -> Panel:
    table = Table.grid(padding=(0, 2))
    stale = last_update is not None and (datetime.now() - last_update).total_seconds() > STALE_AFTER_SECONDS

    if reading is None:
        table.add_row("[dim]waiting for dnp3-server log activity...[/dim]")
    else:
        breaker_text = "[bold green]CLOSED[/bold green]" if reading.breaker_closed else "[dim]OPEN[/dim]"
        table.add_row("BREAKER", breaker_text)
        table.add_row("LINE CURRENT", f"[bold cyan]{reading.line_current:.1f}A[/bold cyan]")
        table.add_row("CURRENT TREND", sparkline(currents, lo=0, hi=45) or "[dim](collecting...)[/dim]")
        if reading.in_outage:
            table.add_row("", "[bold white on red] SIMULATED OUTAGE — silently dropping all requests [/bold white on red]")

    if stale:
        table.add_row("", "[bold white on red] NO UPDATES — dnp3-server may have crashed [/bold white on red]")

    footer = f"last update: {last_update.strftime('%H:%M:%S') if last_update else '-'}  |  Ctrl+C to exit"
    border = "red" if stale else "white"
    return Panel(table, title="dnp3-server — substation breaker outstation", subtitle=footer, border_style=border)


def main() -> None:
    parser = argparse.ArgumentParser(description="Live TUI for dnp3-server")
    parser.add_argument("--log-file", default="/var/log/dnp3-server.log")
    args = parser.parse_args()

    console = Console()
    currents: Deque[float] = deque(maxlen=HISTORY_LEN)
    reading: Optional[Reading] = None
    last_update: Optional[datetime] = None

    try:
        with Live(render(reading, currents, last_update), console=console, refresh_per_second=4, screen=True) as live:
            for line in follow(args.log_file):
                if line is not None:
                    parsed = parse_log_line(line)
                    if parsed is not None:
                        reading = parsed
                        currents.append(parsed.line_current)
                        last_update = datetime.now()
                live.update(render(reading, currents, last_update))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
