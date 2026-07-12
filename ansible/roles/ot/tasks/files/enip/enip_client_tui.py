"""Live htop-style status view for enip-client, run directly on the VM.

Tails /var/log/enip-client.log — the same file the systemd service already
writes — and renders the HMI's view of the sensor+solenoid rack as a
live-updating terminal dashboard. Read-only: parses the existing log stream,
opens no EtherNet/IP connection of its own beyond what enip-client is already
doing.

Run:
    /opt/enip/venv/bin/python3 /opt/enip/enip_client_tui.py
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

from enip_tui_common import Reading, parse_log_line, sparkline

HISTORY_LEN = 60
STALE_AFTER_SECONDS = 15.0  # client polls every 3s by default; ~5 missed polls = stale


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
        table.add_row("[dim]waiting for enip-client log activity...[/dim]")
    else:
        sensor_text = "[bold green]ON[/bold green]" if reading.sensor_active else "[dim]OFF[/dim]"
        solenoid_text = "[bold green]ON[/bold green]" if reading.solenoid_on else "[dim]OFF[/dim]"
        table.add_row("SENSOR1 (as read by HMI)", sensor_text)
        table.add_row("SOLENOID1 (last commanded by HMI)", solenoid_text)
        interlock_ok = reading.solenoid_on == reading.sensor_active
        interlock_text = (
            "[green]OK (mirrors sensor)[/green]"
            if interlock_ok
            else "[bold red]VIOLATED — solenoid ignoring sensor![/bold red]"
        )
        table.add_row("INTERLOCK", interlock_text)
        table.add_row("SENSOR1 HISTORY", sparkline(history) or "[dim](collecting...)[/dim]")

    if stale:
        table.add_row("", "[bold white on red] NO UPDATES — enip-client may have crashed/disconnected [/bold white on red]")

    footer = f"last poll: {last_update.strftime('%H:%M:%S') if last_update else '-'}  |  Ctrl+C to exit"
    border = "red" if stale else "white"
    return Panel(table, title="enip-client — HMI simulator", subtitle=footer, border_style=border)


def main() -> None:
    parser = argparse.ArgumentParser(description="Live TUI for enip-client")
    parser.add_argument("--log-file", default="/var/log/enip-client.log")
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
                        history.append(1.0 if parsed.sensor_active else 0.0)
                        last_update = datetime.now()
                live.update(render(reading, history, last_update))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
