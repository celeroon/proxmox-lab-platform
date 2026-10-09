#!/usr/bin/env bash
# Build a Cisco Nexus 9000v (NX-OS) Proxmox template from Cisco's shipped image via Packer.
#
# Cisco ships the 9000v as a bootable qcow2 (nexus9300v64-lite.<ver>.qcow2 and friends).
# Pass that .qcow2 here. This clones the Packer repo, boots the disk under Packer/QEMU,
# configures it over the serial console (an expect script that drives BOTH boots — POAP
# abort + boot-image pin, reload, then the lab config), stops qemu, and writes a
# ready-to-import qcow2. Then:
#   lab template import images/base/cisco-nxos9kv.qcow2 cisco-nxos9kv
#
# NX-OS needs UEFI + a SATA/AHCI disk + e1000 NICs; all three are set in the HCL. The
# template must therefore be imported on sata0 (lab/build.py does this via disk_bus).
#
# Usage:   build-cisco-nxos9kv.sh <image.qcow2>
# Example: build-cisco-nxos9kv.sh ~/Downloads/nexus9300v64-lite.10.6.2.F.qcow2
#
# Env: OUT_DIR (where the finished qcow2 lands), BUILD_VERSION (NX-OS version, e.g.
#      10.6.2.F — normally derived from the source filename), NXOS_LITE (1|0, likewise),
#      TELNET_PORT, CISCO_REPO_URL.
#
# Needs: git, packer, expect, qemu-img, OVMF, /dev/kvm access.
set -euo pipefail

SRC="${1:?usage: $0 <image.qcow2>}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_URL="${CISCO_REPO_URL:-https://github.com/celeroon/cisco-nxos9kv-vagrant-libvirt.git}"
REPO_DIR="/tmp/cisco-nxos9kv-packer-repo"
HCL_FILE="cisco-nxos9kv-no-vagrant.pkr.hcl"
EXP_FILE="cisco_nxos9kv_config.exp"

WORK_DIR="${WORK_DIR:-/var/lib/lab-platform/build-work/cisco-nxos9kv}"
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/images/base}"
IMAGE_NAME="cisco-nxosv.qcow2"          # internal name the qcow2 is staged as (HCL default)
TELNET_PORT="${TELNET_PORT:-52099}"     # must match the expect script's default
OVMF_BIOS="${OVMF_BIOS:-/usr/share/ovmf/OVMF.fd}"

[[ -f "$SRC" ]] || { echo "error: source not found: $SRC" >&2; exit 1; }

# Derive the NX-OS version and the lite/full flavour from Cisco's filename. Both decide
# which bootflash .bin the switch is told to boot, and a mismatch leaves it at the loader
# prompt after the reload — so they are checked, not guessed silently.
#   nexus9300v64-lite.10.6.2.F.qcow2 -> version 10.6.2.F, lite
#   nexus9500v64.10.6.2.F.qcow2      -> version 10.6.2.F, full
SRC_BASE="$(basename "$SRC")"
SRC_STEM="${SRC_BASE%.qcow2}"

if [[ -n "${NXOS_LITE:-}" ]]; then
  LITE="$NXOS_LITE"
elif [[ "$SRC_STEM" == *-lite.* ]]; then
  LITE=1
else
  LITE=0
fi

if [[ -n "${BUILD_VERSION:-}" ]]; then
  NXOS_VERSION="$BUILD_VERSION"
else
  # Everything after the first dot is the version (10.6.2.F).
  NXOS_VERSION="${SRC_STEM#*.}"
  [[ "$NXOS_VERSION" != "$SRC_STEM" ]] || NXOS_VERSION=""
fi

if [[ -z "$NXOS_VERSION" ]]; then
  echo "error: cannot determine the NX-OS version from '$SRC_BASE'" >&2
  echo "       pass it explicitly, e.g.: lab template build cisco-nxos9kv 10.6.2.F --source $SRC" >&2
  exit 1
fi

# Lite boots fine on 8 GB; the full image needs 10 GB minimum / 12 GB recommended.
if [[ "$LITE" == "1" ]]; then
  BUILD_MEMORY="${BUILD_MEMORY:-8192}"
  BOOT_BIN="nxos64-cs-lite.$NXOS_VERSION.bin"
  LITE_VAR="true"
else
  BUILD_MEMORY="${BUILD_MEMORY:-12288}"
  BOOT_BIN="nxos64-cs.$NXOS_VERSION.bin"
  LITE_VAR="false"
fi

echo "=== Cisco Nexus 9000v image builder ==="
echo "  source  : $SRC"
echo "  repo    : $REPO_URL"
echo "  version : $NXOS_VERSION"
echo "  flavour : $([[ "$LITE" == 1 ]] && echo 'lite' || echo 'full') -> boot nxos bootflash:$BOOT_BIN"
echo "  memory  : ${BUILD_MEMORY} MB"
echo "  output  : $OUT_DIR/cisco-nxos9kv.qcow2"
echo

# Step 1: clone or update the Packer repo.
echo "[1/4] fetching packer repo..."
# Validate the clone, do not just look for a .git directory: systemd-tmpfiles ages
# files out of /tmp but leaves the directory skeleton, so a stale repo still has an
# (empty) .git and the fetch below dies with "not a git repository". rev-parse is the
# real check, and a failed one falls through to a fresh clone.
if git -C "$REPO_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  git -C "$REPO_DIR" fetch --all --prune
  git -C "$REPO_DIR" reset --hard origin/HEAD
  echo "  updated: $REPO_DIR"
else
  rm -rf "$REPO_DIR"
  git clone "$REPO_URL" "$REPO_DIR"
  echo "  cloned: $REPO_DIR"
fi
[[ -f "$REPO_DIR/$HCL_FILE" ]] || { echo "error: $HCL_FILE not found in repo" >&2; exit 1; }
[[ -f "$REPO_DIR/$EXP_FILE" ]] || { echo "error: $EXP_FILE not found in repo" >&2; exit 1; }
[[ -r "$OVMF_BIOS" ]] || { echo "error: OVMF firmware not readable: $OVMF_BIOS (install the 'ovmf' package or set OVMF_BIOS)" >&2; exit 1; }

# Step 2: verify it is genuinely a qcow2, then stage it (plus the HCL + expect) into a
# clean work dir. (qemu-img reports any unrecognised file as format "raw" and exits 0, so
# check the format explicitly.) Packer copies the disk again for the boot, so the file you
# pass is never modified.
echo "[2/4] verifying + staging disk image..."
SRC_FMT="$(qemu-img info "$SRC" 2>/dev/null | sed -n 's/^file format: //p')"
if [[ "$SRC_FMT" != "qcow2" ]]; then
  echo "error: not a qcow2 image (detected format: '${SRC_FMT:-unreadable}'): $SRC" >&2
  exit 1
fi
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"   # NOT tmp_out — packer's qemu builder must create out_dir itself
cp "$REPO_DIR/$HCL_FILE" "$REPO_DIR/$EXP_FILE" "$WORK_DIR/"
cp "$SRC" "$WORK_DIR/$IMAGE_NAME"
qemu-img info "$WORK_DIR/$IMAGE_NAME" | sed 's/^/    /'

# Step 3: Packer boots the disk, runs the expect config over serial (two boots), stops qemu.
echo "[3/4] running packer build (boot -> pin image -> reload -> configure -> stop)..."
echo "      watch the console with: tail -f $WORK_DIR/cisco-nxos9kv-console.explog"
pushd "$WORK_DIR" >/dev/null
packer init "$HCL_FILE"
PACKER_LOG=1 PACKER_NO_COLOR=1 packer build \
  -var "image_name=$IMAGE_NAME" \
  -var "image_path=$WORK_DIR" \
  -var "out_dir=tmp_out" \
  -var "telnet_port=$TELNET_PORT" \
  -var "version=$NXOS_VERSION" \
  -var "lite=$LITE_VAR" \
  -var "memory=$BUILD_MEMORY" \
  -var "ovmf_bios=$OVMF_BIOS" \
  "$HCL_FILE"
popd >/dev/null

# Packer writes the configured disk to out_dir/vm_name (vm_name defaults to cisco-nxos9kv).
BUILT="$WORK_DIR/tmp_out/cisco-nxos9kv"
[[ -f "$BUILT" ]] || { echo "error: built qcow2 not found at $BUILT:" >&2; ls -la "$WORK_DIR/tmp_out" >&2; exit 1; }

# Step 4: publish.
echo "[4/4] publishing image..."
mkdir -p "$OUT_DIR"
mv -f "$BUILT" "$OUT_DIR/cisco-nxos9kv.qcow2"
rm -rf "$WORK_DIR/tmp_out"

echo
echo "Done: $OUT_DIR/cisco-nxos9kv.qcow2"
echo "Import it as a Proxmox template with (NX-OS needs the disk on SATA):"
echo "  lab template import \"$OUT_DIR/cisco-nxos9kv.qcow2\" cisco-nxos9kv   # see note: sata0"
