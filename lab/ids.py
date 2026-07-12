HOT_TEMPLATE_VMID_BASE = 20_000  # hot_templates.id + this = Proxmox VMID (range 20001–99999)


def vmid(user_id: int, vm_index: int) -> int:
    return user_id * 100_000 + vm_index


def mac(user_id: int, vm_index: int, iface_index: int) -> str:
    return f"52:54:{user_id:02x}:{vm_index >> 8:02x}:{vm_index & 0xff:02x}:{iface_index:02x}"


def mgmt_ip(user_id: int, vm_index: int) -> str:
    third = vm_index // 253
    last = (vm_index % 253) + 2
    return f"10.{user_id}.{third}.{last}"


def gateway_ip(user_id: int) -> str:
    return f"10.{user_id}.0.1"


def mgmt_mac(user_id: int) -> str:
    """MAC for the management VM's hot-plugged NIC to user N's VNet.

    Uses 0xff in byte 3 to distinguish from lab VM MACs (byte 3 = user_id, range 0x02–0xfe).
    """
    return f"52:54:ff:{user_id:02x}:00:00"
