"""Live htop-style status view for s7comm-client, run directly on the VM.

Tails /var/log/s7comm-client.log — the same file the systemd service already
writes — and renders the engineering workstation's view of the conveyor state
as a live-updating terminal dashboard. Read-only: parses the existing log
stream, opens no S7comm connection of its own beyond what s7comm-client is
already doing.

Run:
    /opt/s7comm/venv/bin/python3 /opt/s7comm/s7_client_tui.py
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

from s7_tui_common import Reading, deltas, parse_log_line, sparkline

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


def render(reading: Optional[Reading], counts: Deque[int], last_update: Optional[datetime]) -> Panel:
    table = Table.grid(padding=(0, 2))
    stale = last_update is not None and (datetime.now() - last_update).total_seconds() > STALE_AFTER_SECONDS

    if reading is None:
        table.add_row("[dim]waiting for s7comm-client log activity...[/dim]")
    else:
        table.add_row("ITEM COUNT (as seen by engineering workstation)", f"[bold cyan]{reading.item_count}[/bold cyan]")
        motor_text = "[bold green]ON[/bold green]" if reading.motor_running else "[dim]OFF[/dim]"
        table.add_row("MOTOR", motor_text)
        producing_text = "[bold green]PRODUCING[/bold green]" if reading.producing else "[yellow]NOT ADVANCING[/yellow]"
        table.add_row("STATUS", producing_text)
        rate = deltas(counts)
        table.add_row("PRODUCTION RATE", sparkline(rate, lo=0, hi=max(1, max(rate) if rate else 1)) or "[dim](collecting...)[/dim]")

    if stale:
        table.add_row("", "[bold white on red] NO UPDATES — s7comm-client may have crashed/disconnected [/bold white on red]")

    footer = f"last poll: {last_update.strftime('%H:%M:%S') if last_update else '-'}  |  Ctrl+C to exit"
    border = "red" if stale else "white"
    return Panel(table, title="s7comm-client — engineering workstation simulator", subtitle=footer, border_style=border)


def main() -> None:
    parser = argparse.ArgumentParser(description="Live TUI for s7comm-client")
    parser.add_argument("--log-file", default="/var/log/s7comm-client.log")
    args = parser.parse_args()

    console = Console()
    counts: Deque[int] = deque(maxlen=HISTORY_LEN)
    reading: Optional[Reading] = None
    last_update: Optional[datetime] = None

    try:
        with Live(render(reading, counts, last_update), console=console, refresh_per_second=4, screen=True) as live:
            for line in follow(args.log_file):
                if line is not None:
                    parsed = parse_log_line(line)
                    if parsed is not None:
                        reading = parsed
                        counts.append(parsed.item_count)
                        last_update = datetime.now()
                live.update(render(reading, counts, last_update))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
