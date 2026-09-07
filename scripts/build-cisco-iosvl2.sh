#!/usr/bin/env bash
# Build a Cisco IOSvL2 (vios_l2) Proxmox template from Cisco's shipped image via Packer.
#
# Cisco ships IOSvL2 as a .tgz containing a single virtioa.qcow2 disk. Extract that
# qcow2 first (tar xf viosl2-...tgz) and pass the .qcow2 here. This clones the Packer
# repo, boots the disk under Packer/QEMU, configures it over the serial console (an
# expect script), stops qemu, and writes a ready-to-import qcow2. Then:
#   lab template import images/base/cisco-iosvl2.qcow2 cisco-iosvl2
#
# Usage:   build-cisco-iosvl2.sh <image.qcow2>
# Example: build-cisco-iosvl2.sh ~/Downloads/viosl2-adventerprisek9-m-v152_6_0_81_e-20190423/virtioa.qcow2
#
# Needs: git, packer, expect, qemu-img, /dev/kvm access.
set -euo pipefail

SRC="${1:?usage: $0 <image.qcow2>}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_URL="${CISCO_REPO_URL:-https://github.com/celeroon/cisco-iosvl2-vagrant-libvirt.git}"
REPO_DIR="/tmp/cisco-iosvl2-packer-repo"
HCL_FILE="cisco-iosvl2-no-vagrant.pkr.hcl"
EXP_FILE="cisco_iosvl2_config.exp"

WORK_DIR="${WORK_DIR:-/var/lib/lab-platform/build-work/cisco-iosvl2}"
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/images/base}"
IMAGE_NAME="virtioa.qcow2"          # internal name the qcow2 is staged as (HCL default)
TELNET_PORT="${TELNET_PORT:-52099}" # must match cisco_iosvl2_config.exp

[[ -f "$SRC" ]] || { echo "error: source not found: $SRC" >&2; exit 1; }

echo "=== Cisco IOSvL2 image builder ==="
echo "  source : $SRC"
echo "  repo   : $REPO_URL"
echo "  output : $OUT_DIR/cisco-iosvl2.qcow2"
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
  echo "       extract it from the Cisco tgz first: tar xf viosl2-...tgz" >&2
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

# Packer writes the configured disk to out_dir/vm_name (vm_name defaults to cisco-iosvl2).
BUILT="$WORK_DIR/tmp_out/cisco-iosvl2"
[[ -f "$BUILT" ]] || { echo "error: built qcow2 not found at $BUILT:" >&2; ls -la "$WORK_DIR/tmp_out" >&2; exit 1; }

# Step 4: publish.
echo "[4/4] publishing image..."
mkdir -p "$OUT_DIR"
mv -f "$BUILT" "$OUT_DIR/cisco-iosvl2.qcow2"
rm -rf "$WORK_DIR/tmp_out"

echo
echo "Done: $OUT_DIR/cisco-iosvl2.qcow2"
echo "Import it as a Proxmox template with:"
echo "  lab template import \"$OUT_DIR/cisco-iosvl2.qcow2\" cisco-iosvl2"
