from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class InterfaceSpec:
    name: str
    type: str
    network: str = ""


@dataclass
class VMSpec:
    name: str
    template: str
    cpus: int
    memory: int
    console: str
    clone_mode: str
    tags: list[str]
    interfaces: list[InterfaceSpec]
    depends_on: list[str]
    group: str
    ansible: dict
    type: str = "vm"          # "vm" or "container"
    qemu_agent: bool = True   # enable QEMU guest agent (false for network appliances)
    disk_gb: int = 4          # rootfs size in GB (containers only; VMs use template disk)
    cpu_type: str | None = None  # QEMU CPU model e.g. "host"; None = use template default (VMs only)
    replica_index: int = 0   # 0 = not a replica; 1..N = sequence number within group
    replica_base: str = ""   # "" = not a replica; "agent" = part of the agent replica group


@dataclass
class NetworkSpec:
    name: str
    type: str


@dataclass
class ScenarioSpec:
    version: int
    name: str
    description: str
    vm_prefix: str
    groups: list[str]
    networks: list[NetworkSpec]
    defaults: dict
    vms: list[VMSpec]


def parse_scenario(path: Path) -> ScenarioSpec:
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError("scenario file must be a YAML mapping")

    # required top-level fields
    for key in ("name", "vms"):
        if not raw.get(key):
            raise ValueError(f"scenario missing required field: '{key}'")

    # version
    version = raw.get("version", 1)
    if version != 1:
        raise ValueError(
            f"unsupported scenario version: {version} (only version 1 is supported)"
        )

    # groups
    groups: list[str] = []
    for g in raw.get("groups") or []:
        if g in groups:
            raise ValueError(f"duplicate group name: '{g}'")
        groups.append(g)

    # networks
    networks: list[NetworkSpec] = []
    network_names: set[str] = set()
    for n in raw.get("networks") or []:
        if n["name"] in network_names:
            raise ValueError(f"duplicate network name: '{n['name']}'")
        network_names.add(n["name"])
        networks.append(NetworkSpec(name=n["name"], type=n.get("type", "vnet")))

    # defaults
    defaults = raw.get("defaults") or {}
    vm_prefix = raw.get("vm_prefix", "")

    # Pass 1: validate count fields and build replica_bases map.
    # replica_bases maps prefixed base name → list of expanded replica names.
    replica_bases: dict[str, list[str]] = {}
    for v in raw["vms"]:
        count = v.get("count", 1)
        if not isinstance(count, int) or count < 1:
            raise ValueError(
                f"VM '{v.get('name', '<unnamed>')}': count must be a positive integer, got {count!r}"
            )
        if count >= 2 and v.get("name"):
            base_name = f"{vm_prefix}{v['name']}" if vm_prefix else v["name"]
            replica_bases[base_name] = [f"{base_name}-{i:02d}" for i in range(1, count + 1)]

    # Pass 2: parse and expand all VM entries into flat VMSpec list.
    vms: list[VMSpec] = []
    vm_names: set[str] = set()

    for v in raw["vms"]:
        if not v.get("name"):
            raise ValueError("VM missing required field: 'name'")
        if not v.get("template"):
            raise ValueError(f"VM '{v['name']}' missing required field: 'template'")

        count = v.get("count", 1)  # already validated in Pass 1
        base_name = f"{vm_prefix}{v['name']}" if vm_prefix else v["name"]

        memory = v.get("memory", defaults.get("memory", 2048))
        if not isinstance(memory, int) or memory <= 0:
            raise ValueError(f"VM '{base_name}': memory must be a positive integer, got {memory!r}")

        cpus = v.get("cpus", defaults.get("cpus", 2))
        if not isinstance(cpus, int) or cpus <= 0:
            raise ValueError(f"VM '{base_name}': cpus must be a positive integer, got {cpus!r}")

        console = v.get("console", defaults.get("console", "novnc"))
        if console not in ("novnc", "serial"):
            raise ValueError(
                f"VM '{base_name}' console must be 'novnc' or 'serial', got '{console}'"
            )

        vm_type = v.get("type", "vm")
        if vm_type not in ("vm", "container"):
            raise ValueError(
                f"VM '{base_name}' type must be 'vm' or 'container', got '{vm_type}'"
            )

        clone_mode = v.get("clone_mode", defaults.get("clone_mode", "full"))
        if vm_type == "vm" and clone_mode not in ("full", "linked"):
            raise ValueError(
                f"VM '{base_name}' clone_mode must be 'full' or 'linked', got '{clone_mode}'"
            )

        qemu_agent = v.get("qemu_agent", defaults.get("qemu_agent", True))
        if not isinstance(qemu_agent, bool):
            raise ValueError(
                f"VM '{base_name}': qemu_agent must be a boolean, got {qemu_agent!r}"
            )

        disk_gb = v.get("disk_gb", defaults.get("disk_gb", 4))
        if not isinstance(disk_gb, int) or disk_gb < 1:
            raise ValueError(
                f"VM '{base_name}': disk_gb must be a positive integer, got {disk_gb!r}"
            )

        cpu_type = v.get("cpu_type", defaults.get("cpu_type", None))
        if cpu_type is not None and not isinstance(cpu_type, str):
            raise ValueError(
                f"VM '{base_name}': cpu_type must be a string, got {cpu_type!r}"
            )

        group = v.get("group", "")
        if group and group not in groups:
            raise ValueError(
                f"VM '{base_name}' references undeclared group: '{group}' (not in groups:)"
            )

        # interfaces
        interfaces: list[InterfaceSpec] = []
        for iface in v.get("interfaces") or []:
            if iface.get("type") == "vnet" and not iface.get("network"):
                raise ValueError(
                    f"VM '{base_name}' interface '{iface['name']}' type is 'vnet' but 'network' field is missing"
                )
            interfaces.append(InterfaceSpec(
                name=iface["name"],
                type=iface.get("type", "vnet"),
                network=iface.get("network", ""),
            ))

        # depends_on: apply prefix, then expand replica base references.
        # If the referenced name is a replica group base, expand to all replica names.
        depends_on: list[str] = []
        for d in (v.get("depends_on") or []):
            prefixed_d = f"{vm_prefix}{d}" if vm_prefix else d
            if prefixed_d in replica_bases:
                depends_on.extend(replica_bases[prefixed_d])
            else:
                depends_on.append(prefixed_d)

        common_kwargs = dict(
            template=v["template"],
            cpus=cpus,
            memory=memory,
            console=console,
            clone_mode=clone_mode,
            qemu_agent=qemu_agent,
            disk_gb=disk_gb,
            cpu_type=cpu_type,
            tags=v.get("tags") or [],
            interfaces=interfaces,
            depends_on=depends_on,
            group=group,
            ansible=v.get("ansible") or {},
            type=vm_type,
        )

        if count == 1:
            name = base_name
            if name in vm_names:
                raise ValueError(
                    f"duplicate VM name: '{name}' (after applying vm_prefix '{vm_prefix}')"
                )
            vm_names.add(name)
            vms.append(VMSpec(name=name, replica_index=0, replica_base="", **common_kwargs))
        else:
            for i in range(1, count + 1):
                name = f"{base_name}-{i:02d}"
                if name in vm_names:
                    raise ValueError(
                        f"duplicate VM name: '{name}' (after applying vm_prefix '{vm_prefix}')"
                    )
                vm_names.add(name)
                vms.append(VMSpec(
                    name=name, replica_index=i, replica_base=base_name, **common_kwargs
                ))

    # cross-reference: vnet interfaces must reference declared networks
    for vm in vms:
        for iface in vm.interfaces:
            if iface.type == "vnet" and iface.network not in network_names:
                raise ValueError(
                    f"VM '{vm.name}' interface '{iface.name}' references unknown network: "
                    f"'{iface.network}' (not declared in networks:)"
                )

    # cross-reference: depends_on must name existing VMs
    for vm in vms:
        for dep in vm.depends_on:
            if dep not in vm_names:
                raise ValueError(
                    f"VM '{vm.name}' depends_on unknown VM: '{dep}' (not in this scenario)"
                )

    # cycle detection (DFS)
    dep_map = {vm.name: vm.depends_on for vm in vms}
    for start in vm_names:
        visited: set[str] = set()
        path_set: list[str] = []

        def dfs(node: str) -> None:
            if node in path_set:
                cycle = " → ".join(path_set[path_set.index(node):] + [node])
                raise ValueError(f"circular dependency detected: {cycle}")
            if node in visited:
                return
            visited.add(node)
            path_set.append(node)
            for dep in dep_map.get(node, []):
                dfs(dep)
            path_set.pop()

        dfs(start)

    # group consistency: all VMs in same group must share identical depends_on
    group_deps: dict[str, list[str]] = {}
    group_vm_names: dict[str, str] = {}
    for vm in vms:
        if not vm.group:
            continue
        sorted_deps = sorted(vm.depends_on)
        if vm.group in group_deps:
            if group_deps[vm.group] != sorted_deps:
                raise ValueError(
                    f"group '{vm.group}' has VMs with different depends_on:\n"
                    f"  {group_vm_names[vm.group]} depends on {list(group_deps[vm.group])}\n"
                    f"  {vm.name} depends on {vm.depends_on}\n"
                    f"  all VMs in a group must share the same dependencies"
                )
        else:
            group_deps[vm.group] = sorted_deps
            group_vm_names[vm.group] = vm.name

    # mixed scenario warning
    if groups:
        ungrouped = [vm.name for vm in vms if not vm.group]
        if ungrouped:
            warnings.warn(
                f"groups are defined but the following VMs have no group assigned: {ungrouped}\n"
                f"  these VMs cannot be targeted by group-based selection"
            )

    return ScenarioSpec(
        version=version,
        name=raw["name"],
        description=raw.get("description", ""),
        vm_prefix=vm_prefix,
        groups=groups,
        networks=networks,
        defaults=defaults,
        vms=vms,
    )


def execution_plan(spec: ScenarioSpec) -> list[list[str]]:
    dep_map = {vm.name: set(vm.depends_on) for vm in spec.vms}
    completed: set[str] = set()
    plan: list[list[str]] = []

    remaining = set(dep_map.keys())
    while remaining:
        ready = [
            name for name in remaining
            if dep_map[name].issubset(completed)
        ]
        if not ready:
            raise ValueError("could not resolve execution plan — circular dependency")
        ready.sort()
        plan.append(ready)
        completed.update(ready)
        remaining -= set(ready)

    return plan
