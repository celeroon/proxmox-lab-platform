"""Live htop-style status view for bacnet-client, run directly on the VM.

Tails /var/log/bacnet-client.log — the same file the systemd service already
writes — and renders the supervisory BAS's view of the HVAC zone as a
live-updating terminal dashboard. Read-only: parses the existing log stream,
opens no BACnet connection of its own beyond what bacnet-client is already
doing.

Run:
    /opt/bacnet/venv/bin/python3 /opt/bacnet/bacnet_client_tui.py
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

from bacnet_tui_common import Reading, bar, parse_log_line, sparkline

HISTORY_LEN = 60
STALE_AFTER_SECONDS = 15.0  # client polls every 3s by default; ~5 missed polls = stale
TEMP_LO, TEMP_HI = 10.0, 35.0  # typical HVAC band -- bar just pins at 100% above this (e.g. a runaway attack)


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


def render(reading: Optional[Reading], history: Deque[float], last_update: Optional[datetime]) -> Panel:
    table = Table.grid(padding=(0, 2))
    stale = last_update is not None and (datetime.now() - last_update).total_seconds() > STALE_AFTER_SECONDS

    if reading is None:
        table.add_row("[dim]waiting for bacnet-client log activity...[/dim]")
    else:
        temp_color = "red" if reading.temperature >= TEMP_HI else ("yellow" if reading.temperature >= 26 else "green")
        table.add_row(
            "TEMPERATURE (as seen by BAS)",
            f"[bold {temp_color}]{reading.temperature:5.1f}°C[/bold {temp_color}]  {bar(reading.temperature, lo=TEMP_LO, hi=TEMP_HI)}",
        )
        commanded_text = f"{reading.commanded_setpoint:.1f}°C" if reading.commanded_setpoint is not None else "[dim](none yet)[/dim]"
        table.add_row("LAST COMMANDED SETPOINT", commanded_text)
        table.add_row("HISTORY", sparkline(history, lo=TEMP_LO, hi=TEMP_HI) or "[dim](collecting...)[/dim]")

    if stale:
        table.add_row("", "[bold white on red] NO UPDATES — bacnet-client may have crashed/disconnected [/bold white on red]")

    footer = f"last poll: {last_update.strftime('%H:%M:%S') if last_update else '-'}  |  Ctrl+C to exit"
    border = "red" if stale else "white"
    return Panel(table, title="bacnet-client — supervisory BAS simulator", subtitle=footer, border_style=border)


def main() -> None:
    parser = argparse.ArgumentParser(description="Live TUI for bacnet-client")
    parser.add_argument("--log-file", default="/var/log/bacnet-client.log")
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
                        history.append(parsed.temperature)
                        last_update = datetime.now()
                live.update(render(reading, history, last_update))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
