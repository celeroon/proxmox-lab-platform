"""Live htop-style status view for profinet-client, run directly on the VM.

Tails /var/log/profinet-client.log — the same file the systemd service
already writes — and renders the engineering station's AR-Connect attempt
history as a live-updating terminal dashboard. Read-only: parses the
existing log stream, opens no PROFINET connection of its own beyond what
profinet_client.py is already doing.

Run:
    /opt/profinet-py-venv/bin/python3 /opt/profinet/profinet_client_tui.py
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

from profinet_tui_common import ConnectAttempt, parse_client_log_line, sparkline, success_ratio

HISTORY_LEN = 60
STALE_AFTER_SECONDS = 90.0  # poller defaults to a 30s cycle; ~3 missed polls = stale


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


def render(attempt: Optional[ConnectAttempt], outcomes: Deque[bool], last_update: Optional[datetime]) -> Panel:
    table = Table.grid(padding=(0, 2))
    stale = last_update is not None and (datetime.now() - last_update).total_seconds() > STALE_AFTER_SECONDS

    if attempt is None:
        table.add_row("[dim]waiting for profinet-client log activity...[/dim]")
    else:
        table.add_row("ATTEMPT #", f"[bold cyan]{attempt.attempt}[/bold cyan]")
        if attempt.success:
            table.add_row("RESULT", "[bold green]AR-CONNECT OK[/bold green]")
            table.add_row("has_cyclic", str(attempt.has_cyclic))
            table.add_row("input/output frame IDs", f"{attempt.input_frame_id} / {attempt.output_frame_id}")
        else:
            table.add_row("RESULT", "[bold red]FAILED[/bold red]")
            table.add_row("reason", attempt.reason or "(unknown)")
        rate = success_ratio(outcomes) * 100
        table.add_row(
            "SUCCESS RATE (last 60)",
            sparkline([1.0 if o else 0.0 for o in outcomes], lo=0, hi=1) or "[dim](collecting...)[/dim]",
        )
        table.add_row("", f"{rate:.0f}%")

    if stale:
        table.add_row("", "[bold white on red] NO UPDATES — profinet-client may have crashed/disconnected [/bold white on red]")

    footer = f"last attempt: {last_update.strftime('%H:%M:%S') if last_update else '-'}  |  Ctrl+C to exit"
    border = "red" if stale else "white"
    return Panel(table, title="profinet-client — engineering station simulator", subtitle=footer, border_style=border)


def main() -> None:
    parser = argparse.ArgumentParser(description="Live TUI for profinet-client")
    parser.add_argument("--log-file", default="/var/log/profinet-client.log")
    args = parser.parse_args()

    console = Console()
    outcomes: Deque[bool] = deque(maxlen=HISTORY_LEN)
    attempt: Optional[ConnectAttempt] = None
    last_update: Optional[datetime] = None

    try:
        with Live(render(attempt, outcomes, last_update), console=console, refresh_per_second=4, screen=True) as live:
            for line in follow(args.log_file):
                if line is not None:
                    parsed = parse_client_log_line(line)
                    if parsed is not None:
                        attempt = parsed
                        outcomes.append(parsed.success)
                        last_update = datetime.now()
                live.update(render(attempt, outcomes, last_update))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
