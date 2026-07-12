"""Live htop-style status view for profinet-server, run directly on the VM.

Tails pn_dev's own log (redirected to /var/log/profinet-server.log by the
systemd service) — read-only, opens no PROFINET connection of its own.

pn_dev is a real, third-party C binary (hefloryd/p-net's sample IO-Device
app) — its own log output is much sparser than this lab's hand-rolled Python
servers (no per-connection detail at the default FATAL log level; see
profinet_logic.py's module docstring for why -DLOG_LEVEL=DEBUG builds are
avoided). This TUI shows what IS available: the parsed station identity from
the startup banner, LED-signal state changes (DCP `signal` commands), and a
raw tail of the last few log lines for anything else.

Run:
    /opt/p-net/build/pn_dev's stdout is captured by the systemd service into
    /var/log/profinet-server.log; run this TUI separately:
    python3 /opt/profinet/profinet_server_tui.py
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

from profinet_tui_common import ServerIdentity, parse_server_led_line, parse_server_startup_line

RAW_TAIL_LEN = 8
STALE_AFTER_SECONDS = 300.0  # pn_dev only logs on startup + rare signal/reset events


def follow(path: str) -> Iterator[Optional[str]]:
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


def render(
    identity: Optional[ServerIdentity],
    led_state: Optional[int],
    led_changes: int,
    raw_tail: Deque[str],
    last_update: Optional[datetime],
) -> Panel:
    table = Table.grid(padding=(0, 2))

    if identity is None:
        table.add_row("[dim]waiting for pn_dev startup banner...[/dim]")
    else:
        table.add_row("STATION", f"[bold cyan]{identity.hostname}[/bold cyan]")
        table.add_row("IP", identity.ip)

    led_text = "[bold green]ON[/bold green]" if led_state == 1 else ("[dim]OFF[/dim]" if led_state == 0 else "[dim]unknown[/dim]")
    table.add_row("SIGNAL LED", led_text)
    table.add_row("LED changes seen", str(led_changes))

    if raw_tail:
        table.add_row("", "")
        table.add_row("[dim]recent pn_dev log lines:[/dim]", "")
        for raw_line in raw_tail:
            table.add_row("", f"[dim]{raw_line.rstrip()[:100]}[/dim]")

    footer = f"last log line: {last_update.strftime('%H:%M:%S') if last_update else '-'}  |  Ctrl+C to exit"
    return Panel(table, title="profinet-server — p-net (hefloryd/p-net) IO-Device", subtitle=footer, border_style="white")


def main() -> None:
    parser = argparse.ArgumentParser(description="Live TUI for profinet-server")
    parser.add_argument("--log-file", default="/var/log/profinet-server.log")
    args = parser.parse_args()

    console = Console()
    identity: Optional[ServerIdentity] = None
    led_state: Optional[int] = None
    led_changes = 0
    raw_tail: Deque[str] = deque(maxlen=RAW_TAIL_LEN)
    last_update: Optional[datetime] = None

    try:
        with Live(render(identity, led_state, led_changes, raw_tail, last_update), console=console, refresh_per_second=4, screen=True) as live:
            for line in follow(args.log_file):
                if line is not None and line.strip():
                    raw_tail.append(line)
                    last_update = datetime.now()
                    startup = parse_server_startup_line(line)
                    if startup is not None:
                        identity = startup
                    led = parse_server_led_line(line)
                    if led is not None:
                        led_state = led
                        led_changes += 1
                live.update(render(identity, led_state, led_changes, raw_tail, last_update))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
