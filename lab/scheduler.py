from __future__ import annotations

from lab.proxmox import NodeInfo


class InsufficientCapacityError(RuntimeError):
    """No node meets the RAM/disk constraints for scheduling.

    Distinct from a generic RuntimeError so callers (e.g. the background task
    runner) can treat it as an expected, handled resource constraint — not an
    unexpected failure worth investigating as a bug.
    """


def schedule(nodes: list[NodeInfo], memory_mb: int, disk_bytes: int = 0, headroom: float = 0.1, force: bool = False) -> str:
    """Return the name of the best available node for a VM requiring memory_mb RAM.

    Phase 1 filters out offline nodes, nodes with insufficient free RAM
    (required + headroom%), and nodes with insufficient free disk (disk_bytes, no headroom).
    Phase 2 scores the remaining nodes and picks the best.

    Score = free_ram_pct * 0.5 + free_disk_pct * 0.3 + free_cpu_pct * 0.2

    When force=True the RAM check is skipped entirely — any online node is eligible.
    Raises RuntimeError if no node meets the constraints.
    """
    required_bytes = int(memory_mb * 1024 * 1024 * (1 + headroom))

    eligible = [
        n for n in nodes
        if n.status == "online"
        and (force or n.free_ram >= required_bytes)
        and (disk_bytes == 0 or n.free_disk >= disk_bytes)
    ]

    if not eligible:
        raise InsufficientCapacityError(
            f"No eligible node for {memory_mb} MB RAM "
            f"(+{headroom*100:.0f}% headroom) — checked {len(nodes)} node(s)"
        )

    def _score(node: NodeInfo) -> float:
        ram_pct  = node.free_ram  / node.total_ram  if node.total_ram  > 0 else 0.0
        disk_pct = node.free_disk / node.total_disk if node.total_disk > 0 else 0.0
        cpu_pct  = 1.0 - node.cpu_usage
        return ram_pct * 0.5 + disk_pct * 0.3 + cpu_pct * 0.2

    return max(eligible, key=_score).name
