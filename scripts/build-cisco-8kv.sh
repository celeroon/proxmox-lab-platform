#!/usr/bin/env bash
# Build a Cisco Catalyst 8000v (IOS-XE) Proxmox template from Cisco's shipped image via Packer.
#
# Cisco ships the 8000v as a bootable qcow2. Pass that .qcow2 here. This clones the Packer
# repo, boots the disk under Packer/QEMU, configures it over the serial console (an expect
# script), stops qemu, and writes a ready-to-import qcow2. Then:
#   lab template import images/base/cisco-8kv.qcow2 cisco-8kv
#
# Usage:   build-cisco-8kv.sh <image.qcow2>
# Example: build-cisco-8kv.sh ~/Downloads/cisco-cat8kv.qcow2
#
# Needs: git, packer, expect, qemu-img, /dev/kvm access.
set -euo pipefail

SRC="${1:?usage: $0 <image.qcow2>}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_URL="${CISCO_REPO_URL:-https://github.com/celeroon/cisco-catalyst-8kv-vagrant-libvirt.git}"
REPO_DIR="/tmp/cisco-8kv-packer-repo"
HCL_FILE="cisco-cat-8kv-lab.pkr.hcl"       # non-vagrant lab build: boots the disk directly
EXP_FILE="cisco_cat8kv_config_lab.exp"     # settles after the license reload, paces each command

WORK_DIR="${WORK_DIR:-/var/lib/lab-platform/build-work/cisco-8kv}"
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/images/base}"
IMAGE_NAME="cisco-catalyst-8kv.qcow2"   # internal name the qcow2 is staged as (HCL image_name)
TELNET_PORT="${TELNET_PORT:-52099}"     # must match cisco_cat8kv_config_lab.exp

[[ -f "$SRC" ]] || { echo "error: source not found: $SRC" >&2; exit 1; }

echo "=== Cisco Catalyst 8000v image builder ==="
echo "  source : $SRC"
echo "  repo   : $REPO_URL"
echo "  output : $OUT_DIR/cisco-8kv.qcow2"
echo

# Step 1: clone or update the Packer repo.
echo "[1/4] fetching packer repo..."
if [[ -d "$REPO_DIR/.git" ]]; then
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

# Step 2: verify it is genuinely a qcow2, then stage it (plus the single HCL + expect)
# into a clean work dir. (qemu-img reports any unrecognised file as format "raw" and
# exits 0, so check the format explicitly.) Only ONE .pkr.hcl is copied so packer does
# not choke on duplicate variable blocks. Packer copies the disk again for the boot, so
# the file you pass is never modified.
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

# Step 3: Packer boots the disk, runs the expect config over serial, stops qemu.
echo "[3/4] running packer build (boot -> configure over serial -> stop)..."
pushd "$WORK_DIR" >/dev/null
packer init "$HCL_FILE"
PACKER_LOG=1 PACKER_NO_COLOR=1 packer build \
  -var "image_name=$IMAGE_NAME" \
  -var "image_path=$WORK_DIR" \
  -var "out_dir=tmp_out" \
  -var "telnet_port=$TELNET_PORT" \
  "$HCL_FILE"
popd >/dev/null

# Packer writes the configured disk to out_dir/vm_name (vm_name defaults to cisco-catalyst-8kv).
BUILT="$WORK_DIR/tmp_out/cisco-catalyst-8kv"
[[ -f "$BUILT" ]] || { echo "error: built qcow2 not found at $BUILT:" >&2; ls -la "$WORK_DIR/tmp_out" >&2; exit 1; }

# Step 4: publish.
echo "[4/4] publishing image..."
mkdir -p "$OUT_DIR"
mv -f "$BUILT" "$OUT_DIR/cisco-8kv.qcow2"
rm -rf "$WORK_DIR/tmp_out"

echo
echo "Done: $OUT_DIR/cisco-8kv.qcow2"
echo "Import it as a Proxmox template with:"
echo "  lab template import \"$OUT_DIR/cisco-8kv.qcow2\" cisco-8kv"
