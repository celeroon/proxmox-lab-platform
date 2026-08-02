#!/usr/bin/env bash
# Build a Windows Proxmox template with rgl/windows-vagrant using Packer's
# proxmox-iso builder — the template is created DIRECTLY on a Proxmox node (no
# nesting on the management VM, no qcow2, no import). Driven by
# `lab template build windows <variant>`.
#
# Usage: build-windows.sh <variant> [--dry-run]     (11 | 2025)
#
# Env (set by the lab CLI, or when running standalone):
#   SKIP_UPDATE=0         skip Windows Update during the build   (default 0 = updates run)
#   SKIP_OPTIMIZE=0       skip the SDelete free-space zero-fill  (default 0 = optimize runs)
#   BUILD_CPUS=4          cores for the temporary build VM
#   BUILD_MEMORY_MB=8192  RAM for the temporary build VM
#   WIN_TEMPLATE_NAME=    Proxmox template name to produce       (default windows-<variant>)
#   WIN_VMID=             template VMID in 9000-9999             (default: next free)
#   PROXMOX_NODE / DISK_STORAGE / ISO_STORAGE / BUILD_BRIDGE / BUILD_VLAN_TAG
#                         auto-detected from the platform; override any as needed.
#   DRY_RUN=1             print the detected values + patched config and exit (build nothing).
#
# The build runs on the node's real hardware, so nested virtualization is NOT
# required — but the bridge the build VM joins (the management VM's bridge/VLAN)
# must provide DHCP: Packer waits for the guest's IP over that network.
set -euo pipefail

DRY_RUN="${DRY_RUN:-0}"
VARIANT=""
for _a in "$@"; do
    case "$_a" in
        --dry-run) DRY_RUN=1 ;;
        11|2025)   VARIANT="$_a" ;;
        *) echo "usage: $0 <variant> [--dry-run]   (11 | 2025)" >&2; exit 1 ;;
    esac
done
[[ -n "$VARIANT" ]] || { echo "usage: $0 <variant> [--dry-run]   (11 | 2025)" >&2; exit 1; }
case "$VARIANT" in
    11)   IMAGE="windows-11-24h2-uefi"; ISO_ENV="WINDOWS_11";   ISO_KEY="windows-11" ;;
    2025) IMAGE="windows-2025-uefi";    ISO_ENV="WINDOWS_2025"; ISO_KEY="windows-2025" ;;
esac

SKIP_UPDATE="${SKIP_UPDATE:-0}"
SKIP_OPTIMIZE="${SKIP_OPTIMIZE:-0}"
BUILD_CPUS="${BUILD_CPUS:-4}"
BUILD_MEMORY_MB="${BUILD_MEMORY_MB:-8192}"
WIN_TEMPLATE_NAME="${WIN_TEMPLATE_NAME:-windows-${VARIANT}}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="$PROJECT_ROOT/.venv/bin/python"
REPO_URL="https://github.com/rgl/windows-vagrant.git"
REPO_DIR="/tmp/windows-vagrant-repo"
[[ -x "$VENV_PY" ]] || { echo "error: venv not found at $VENV_PY — run ./setup.sh" >&2; exit 1; }

# ── creds: our .env -> rgl's proxmox env vars (API-token auth) ────────────────
set -a; . "$PROJECT_ROOT/.env"; set +a
export PROXMOX_URL="https://${PROXMOX_HOST}:${PROXMOX_PORT:-8006}/api2/json"
export PROXMOX_USERNAME="${PROXMOX_TOKEN_ID}"     # e.g. root@pam!lab-token
export PROXMOX_TOKEN="${PROXMOX_TOKEN_SECRET}"

# ── detect node/storage/bridge/vlan + allocate a template VMID (9000-9999) ────
read -r DET_NODE DET_DISK DET_ISO DET_BRIDGE DET_TAG DET_VMID < <("$VENV_PY" - <<'PY'
import re, sys
from lab.config import get_settings
from lab.proxmox import ProxmoxClient
from lab.deploy import _auto_select_storage
from lab.templates import TemplateManager, next_template_vmid

s = get_settings()
px = ProxmoxClient(s)
node = next(n.name for n in px.get_nodes() if n.status == "online")
disk = _auto_select_storage(px, s)

iso = ""
try:
    names = [x["storage"] for x in px._px.nodes(node).storage.get(content="iso")]
    iso = "local" if "local" in names else (names[0] if names else "")
except Exception:
    pass
if not iso:
    print("WARNING: no ISO-capable storage on node — set ISO_STORAGE", file=sys.stderr)
    iso = "local"

bridge, tag = "vmbr0", ""
try:
    mnode = px.find_vm_node(s.mgmt_vmid)
    net0 = px.get_vm_config(mnode, s.mgmt_vmid).get("net0", "")
    m = re.search(r"bridge=([^,]+)", net0); bridge = m.group(1) if m else bridge
    t = re.search(r"tag=(\d+)", net0);      tag    = t.group(1) if t else ""
except Exception:
    pass

vmid = next_template_vmid(TemplateManager(px, s)._all_vmids_in_range())
print(node, disk, iso, bridge, tag or "-", vmid)
PY
)
PROXMOX_NODE="${PROXMOX_NODE:-$DET_NODE}"; export PROXMOX_NODE
DISK_STORAGE="${DISK_STORAGE:-$DET_DISK}"
ISO_STORAGE="${ISO_STORAGE:-$DET_ISO}"
BUILD_BRIDGE="${BUILD_BRIDGE:-$DET_BRIDGE}"
BUILD_VLAN_TAG="${BUILD_VLAN_TAG-$DET_TAG}"; [[ "$BUILD_VLAN_TAG" == "-" ]] && BUILD_VLAN_TAG=""
WIN_VMID="${WIN_VMID:-$DET_VMID}"

echo "template: $WIN_TEMPLATE_NAME (VMID $WIN_VMID)  node=$PROXMOX_NODE  disk=$DISK_STORAGE  iso=$ISO_STORAGE  bridge=$BUILD_BRIDGE${BUILD_VLAN_TAG:+ vlan=$BUILD_VLAN_TAG}"
echo "build-vm=${BUILD_CPUS}vCPU/${BUILD_MEMORY_MB}MB  skip_update=$SKIP_UPDATE  skip_optimize=$SKIP_OPTIMIZE"

# ── clone rgl fresh ───────────────────────────────────────────────────────────
if [[ -d "$REPO_DIR/.git" ]]; then
    git -C "$REPO_DIR" fetch --all --prune -q && git -C "$REPO_DIR" reset --hard -q origin/HEAD
else
    rm -rf "$REPO_DIR"; git clone -q "$REPO_URL" "$REPO_DIR"
fi
cd "$REPO_DIR"
PKR_FILE="${IMAGE}.pkr.hcl"

# ── ISO url/checksum + volid ──────────────────────────────────────────────────
ISO_URL_VAL="$(jq -r --arg k "$ISO_KEY" '.[$k].url' windows-evaluation-isos.json)"
ISO_SHA="$(jq -r --arg k "$ISO_KEY" '.[$k].checksum' windows-evaluation-isos.json)"
export ${ISO_ENV}_ISO_URL="$ISO_URL_VAL"
export ${ISO_ENV}_ISO_CHECKSUM="sha256:${ISO_SHA}"
ISO_FILENAME="${ISO_URL_VAL##*/}"
ISO_VOLID="${ISO_STORAGE}:iso/${ISO_FILENAME}"

# ── patch the proxmox-iso source: storages / bridge / cores+memory / name+vmid ─
# `cores` is unique to the proxmox source; `memory` is anchored to 4096 so the
# small `memory = 32` vga field is never touched.
sed -E -i \
    -e "s/^([[:space:]]*)efi_storage_pool([[:space:]]*=[[:space:]]*)\"local-lvm\"/\1efi_storage_pool\2\"${DISK_STORAGE}\"/" \
    -e "s/^([[:space:]]*)storage_pool([[:space:]]*=[[:space:]]*)\"local-lvm\"/\1storage_pool\2\"${DISK_STORAGE}\"/" \
    -e "s/^([[:space:]]*iso_storage_pool[[:space:]]*=[[:space:]]*)\"local\"/\1\"${ISO_STORAGE}\"/" \
    -e "s/^([[:space:]]*bridge[[:space:]]*=[[:space:]]*)\"vmbr0\"/\1\"${BUILD_BRIDGE}\"/" \
    -e "s/^([[:space:]]*cores[[:space:]]*=[[:space:]]*)[0-9]+/\1${BUILD_CPUS}/" \
    -e "s/^([[:space:]]*memory[[:space:]]*=[[:space:]]*)4096/\1${BUILD_MEMORY_MB}/" \
    -e "s/^([[:space:]]*template_name[[:space:]]*=[[:space:]]*)\"[^\"]*\"/\1\"${WIN_TEMPLATE_NAME}\"/" \
    "$PKR_FILE"

# Pin the template VMID into our 9000-9999 range (add vm_id after template_name).
sed -E -i "/^[[:space:]]*template_name[[:space:]]*=/a\\  vm_id = ${WIN_VMID}" "$PKR_FILE"

# Collapse rgl's multi-line template_description heredoc into a single line so it
# reads cleanly in `lab template list`.
awk -v name="$WIN_TEMPLATE_NAME" '
    /template_description[[:space:]]*=[[:space:]]*<<-EOS/ { print "  template_description     = \"" name "\""; s=1; next }
    s && /^[[:space:]]*EOS[[:space:]]*$/ { s=0; next }
    s { next }
    { print }
' "$PKR_FILE" > "$PKR_FILE.t" && mv "$PKR_FILE.t" "$PKR_FILE"

# VLAN: match the mgmt VM's tag on the build VM's NIC.
if [[ -n "$BUILD_VLAN_TAG" ]]; then
    sed -E -i "/^[[:space:]]*bridge[[:space:]]*=[[:space:]]*\"[^\"]*\"/a\\    vlan_tag = \"${BUILD_VLAN_TAG}\"" "$PKR_FILE"
fi

# boot_iso -> iso_file: reference the pre-staged ISO (below) instead of the
# plugin's own download, which gives up after ~60s on a slow link.
awk -v vol="$ISO_VOLID" '
    /boot_iso \{/ { inbi=1; print; next }
    inbi && /iso_storage_pool|iso_url|iso_checksum|iso_download_pve|iso_file/ { next }
    inbi && /^  \}/ { print "    iso_file         = \"" vol "\""; print; inbi=0; next }
    { print }
' "$PKR_FILE" > "$PKR_FILE.t" && mv "$PKR_FILE.t" "$PKR_FILE"

# Optional provisioner skips.
if [[ "$SKIP_UPDATE" == "1" ]]; then
    awk '/^[[:space:]]*provisioner "windows-update" \{/{s=1;next} s&&/^[[:space:]]*\}[[:space:]]*$/{s=0;next} !s{print}' \
        "$PKR_FILE" > "$PKR_FILE.t" && mv "$PKR_FILE.t" "$PKR_FILE"
    echo "  (Windows Update skipped)"
fi
if [[ "$SKIP_OPTIMIZE" == "1" ]]; then
    awk '/^[[:space:]]*provisioner "powershell" \{/{b=1;buf=$0;h=0;next} b{buf=buf ORS $0; if($0~/script[[:space:]]*=[[:space:]]*"optimize\.ps1"/)h=1; if($0~/^[[:space:]]*\}[[:space:]]*$/){if(!h)print buf;b=0} next} {print}' \
        "$PKR_FILE" > "$PKR_FILE.t" && mv "$PKR_FILE.t" "$PKR_FILE"
    echo "  (SDelete/optimize skipped)"
fi

# ── dry run: show the detected values + patched config, build nothing ─────────
if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "== DRY RUN — patched proxmox-iso config (nothing will be built) =="
    awk '/^source "proxmox-iso"/{p=1} /^}/{if(p){p=0}} p' "$PKR_FILE" \
      | grep -E 'template_name|vm_id|node|efi_storage_pool|cpu_type|cores|memory|network_adapters|model|bridge|vlan_tag|scsi_controller|disks|storage_pool|disk_size|format|boot_iso|iso_storage_pool|iso_file' \
      | sed 's/^[[:space:]]*/  /'
    echo "provisioners that will run:"
    grep -E 'script += "|provisioner "windows-update"' "$PKR_FILE" | sed 's/^[[:space:]]*/  /'
    echo "dry run only — re-run without --dry-run to build."
    exit 0
fi

# ── pre-stage the ISO on Proxmox (PVE download-url + wait) ────────────────────
echo "ensuring ISO present: $ISO_VOLID"
"$VENV_PY" - "$PROXMOX_NODE" "$ISO_STORAGE" "$ISO_FILENAME" "$ISO_URL_VAL" "$ISO_SHA" <<'PY'
import sys
from lab.config import get_settings
from lab.proxmox import ProxmoxClient
node, storage, filename, url, sha = sys.argv[1:6]
px = ProxmoxClient(get_settings())
volid = f"{storage}:iso/{filename}"
content = px._px.nodes(node).storage(storage).content.get(content="iso")
if any(i.get("volid") == volid for i in content):
    print(f"  already present: {volid}")
else:
    print("  downloading via PVE download-url (a few minutes)...")
    upid = px._px.nodes(node).storage(storage)("download-url").post(
        url=url, filename=filename, content="iso",
        checksum=sha, **{"checksum-algorithm": "sha256"},
    )
    px.wait_for_task(node, upid, timeout=3600)
    print(f"  ready: {volid}")
PY

# ── build ─────────────────────────────────────────────────────────────────────
echo "== building virtio drivers =="
make drivers
echo "== building $WIN_TEMPLATE_NAME (VMID $WIN_VMID) on node $PROXMOX_NODE =="
# proxmox-iso builder — no local qemu/KVM on the mgmt VM.
make "build-${IMAGE}-proxmox"

echo "done — template '$WIN_TEMPLATE_NAME' (VMID $WIN_VMID) created on $PROXMOX_NODE"
