#!/usr/bin/env bash
# Build a Fortinet FortiGate (FortiOS) Proxmox template from Fortinet's shipped image via Packer.
#
# Fortinet ships FortiOS as a bootable qcow2. Pass that .qcow2 here. This clones the Packer
# repo, boots the disk under Packer/QEMU, configures it over the serial console (admin +
# vagrant/vagrant, SSH key, port1 in VRF 1, self-signed cert), stops qemu, and writes a
# ready-to-import qcow2. build.py then imports it as template fortigate-<version>.
#
# Usage:   build-fortigate.sh <fortios.qcow2>
# Example: build-fortigate.sh ~/Downloads/fortios.qcow2
#
# Env (set by lab template build): OUT_DIR (where the qcow2 lands), BUILD_VERSION (FortiOS
# version, names the template), GUI=1 (open the QEMU window instead of headless).
# Needs: git, packer, qemu-img, /dev/kvm access.
set -euo pipefail

SRC="${1:?usage: $0 <fortios.qcow2>}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_URL="${FORTIGATE_REPO_URL:-https://github.com/celeroon/fortigate-vagrant-libvirt.git}"
REPO_DIR="/tmp/fortigate-packer-repo"
HCL_FILE="fortigate-no-vagrant.pkr.hcl"   # non-vagrant lab build: boots the disk, configures over serial

WORK_DIR="${WORK_DIR:-/var/lib/lab-platform/build-work/fortigate}"
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/images/base}"
VERSION="${BUILD_VERSION:-lab}"           # only names the intermediate qcow2; template name is set by build.py
IMAGE_NAME="fortios.qcow2"                # internal name the qcow2 is staged as (HCL image_name)
GUI_DISABLED="true"; [[ "${GUI:-0}" == "1" ]] && GUI_DISABLED="false"

[[ -f "$SRC" ]] || { echo "error: source not found: $SRC" >&2; exit 1; }

echo "=== FortiGate (FortiOS) image builder ==="
echo "  source  : $SRC"
echo "  version : $VERSION"
echo "  repo    : $REPO_URL"
echo "  output  : $OUT_DIR/fortigate.qcow2"
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

# Step 2: verify it is genuinely a qcow2, then stage it (plus the single HCL) into a clean
# work dir. (qemu-img reports any unrecognised file as format "raw" and exits 0, so check the
# format explicitly.) Packer copies the disk again for the boot, so the file you pass is
# never modified.
echo "[2/4] verifying + staging disk image..."
SRC_FMT="$(qemu-img info "$SRC" 2>/dev/null | sed -n 's/^file format: //p')"
if [[ "$SRC_FMT" != "qcow2" ]]; then
  echo "error: not a qcow2 image (detected format: '${SRC_FMT:-unreadable}'): $SRC" >&2
  exit 1
fi
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"   # NOT tmp_out — packer's qemu builder must create out_dir itself
cp "$REPO_DIR/$HCL_FILE" "$WORK_DIR/"
cp "$SRC" "$WORK_DIR/$IMAGE_NAME"
qemu-img info "$WORK_DIR/$IMAGE_NAME" | sed 's/^/    /'

# Step 3: Packer boots the disk, runs the config over serial (boot_command), stops qemu.
echo "[3/4] running packer build (boot -> configure over serial -> stop)..."
pushd "$WORK_DIR" >/dev/null
packer init "$HCL_FILE"
PACKER_LOG=1 PACKER_NO_COLOR=1 packer build \
  -var "version=$VERSION" \
  -var "image_name=$IMAGE_NAME" \
  -var "image_path=$WORK_DIR" \
  -var "out_dir=tmp_out" \
  -var "gui_disabled=$GUI_DISABLED" \
  "$HCL_FILE"
popd >/dev/null

# Packer writes the configured disk to out_dir/vm_name (vm_name = fortigate-<version>.qcow2).
BUILT="$WORK_DIR/tmp_out/fortigate-${VERSION}.qcow2"
if [[ ! -f "$BUILT" ]]; then
  # Fall back to whatever fortigate-*.qcow2 packer produced (defensive against a version mismatch).
  BUILT="$(ls -1 "$WORK_DIR"/tmp_out/fortigate-*.qcow2 2>/dev/null | head -1 || true)"
fi
[[ -n "$BUILT" && -f "$BUILT" ]] || { echo "error: built qcow2 not found in $WORK_DIR/tmp_out:" >&2; ls -la "$WORK_DIR/tmp_out" >&2; exit 1; }

# Step 4: publish under the fixed name build.py imports.
echo "[4/4] publishing image..."
mkdir -p "$OUT_DIR"
mv -f "$BUILT" "$OUT_DIR/fortigate.qcow2"
rm -rf "$WORK_DIR/tmp_out"

echo
echo "Done: $OUT_DIR/fortigate.qcow2"
echo "Import it as a Proxmox template with:"
echo "  lab template import \"$OUT_DIR/fortigate.qcow2\" fortigate-${VERSION}"
