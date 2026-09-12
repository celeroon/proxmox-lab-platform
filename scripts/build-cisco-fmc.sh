#!/usr/bin/env bash
# Build a Cisco Secure Firewall Management Center Virtual (FMCv) Proxmox template from Cisco's
# shipped qcow2 via Packer. Clones the Packer repo, boots the disk under Packer/QEMU, runs the
# setup wizard over the console (boot_command lives in the HCL), shuts the guest down, and writes
# a ready-to-import qcow2. The result is UNREGISTERED — registering it to Cisco SSM is a
# post-deploy step. lab template build imports the result as a single-use template.
#
# Usage:   build-cisco-fmc.sh <image.qcow2>
# Example: build-cisco-fmc.sh ~/Downloads/Cisco_Secure_FW_Mgmt_Center_Virtual_KVM-10.0.1-1.qcow2
#
# Needs: git, packer >= 1.7, qemu-img, /dev/kvm access, 4 vCPU + 32 GB free. FMCv first boot is
# slow (~40 min to the console prompt), so this build is much longer than the FTDv one.
set -euo pipefail

SRC="${1:?usage: $0 <image.qcow2>}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_URL="${CISCO_FW_REPO_URL:-https://github.com/celeroon/cisco-ftd-fmc-vagrant-libvirt.git}"
REPO_DIR="/tmp/cisco-ftd-fmc-packer-repo"
HCL_FILE="cisco-fmc-no-vagrant.pkr.hcl"

WORK_DIR="${WORK_DIR:-/var/lib/lab-platform/build-work/cisco-fmc}"
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/images/base}"
IMAGE_NAME="fmcv"                       # HCL image_name default (the staged source)
VERSION_LABEL="${VERSION_LABEL:-lab}"   # only names the packer output file; template name is set on import

[[ -f "$SRC" ]] || { echo "error: source not found: $SRC" >&2; exit 1; }

echo "=== Cisco FMCv image builder ==="
echo "  source : $SRC"
echo "  repo   : $REPO_URL"
echo "  output : $OUT_DIR/cisco-fmc.qcow2"
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

# Step 2: verify the source is really a qcow2, then stage it (plus ONLY the FMC hcl — the repo
# also ships the FTD hcl, and packer would choke on duplicate variable blocks) in a clean work
# dir. Packer copies the disk again for the boot, so the file you pass is never modified.
echo "[2/4] verifying + staging disk image..."
SRC_FMT="$(qemu-img info "$SRC" 2>/dev/null | sed -n 's/^file format: //p')"
if [[ "$SRC_FMT" != "qcow2" ]]; then
  echo "error: not a qcow2 image (detected format: '${SRC_FMT:-unreadable}'): $SRC" >&2
  exit 1
fi
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"   # NOT tmp_out_fmc — packer's qemu builder must create out_dir itself
cp "$REPO_DIR/$HCL_FILE" "$WORK_DIR/"
cp "$SRC" "$WORK_DIR/$IMAGE_NAME"
qemu-img info "$WORK_DIR/$IMAGE_NAME" | sed 's/^/    /'

# Step 3: Packer boots the disk, runs the setup wizard over the console, stops qemu.
# GUI=1 turns off headless so the QEMU window opens (watch/interact during a test build);
# on the headless mgmt VM that window is a display you reach over remote desktop.
GUI_ARGS=()
if [[ "${GUI:-0}" == "1" ]]; then
  GUI_ARGS+=(-var "gui_disabled=false")
  echo "  GUI enabled — QEMU window will open (headless off)"
fi
echo "[3/4] running packer build (boot -> wizard -> shutdown; FMCv boot alone is ~40 min)..."
pushd "$WORK_DIR" >/dev/null
packer init "$HCL_FILE"
PACKER_LOG=1 PACKER_NO_COLOR=1 packer build \
  -var "image_name=$IMAGE_NAME" \
  -var "image_path=$WORK_DIR" \
  -var "out_dir=tmp_out_fmc" \
  -var "version=$VERSION_LABEL" \
  "${GUI_ARGS[@]}" \
  "$HCL_FILE"
popd >/dev/null

# Packer writes the configured disk to out_dir/vm_name (vm_name = cisco-fmc-<version>.qcow2).
BUILT="$WORK_DIR/tmp_out_fmc/cisco-fmc-${VERSION_LABEL}.qcow2"
[[ -f "$BUILT" ]] || { echo "error: built qcow2 not found at $BUILT:" >&2; ls -la "$WORK_DIR/tmp_out_fmc" >&2; exit 1; }

# Step 4: publish under the fixed name the lab importer expects.
echo "[4/4] publishing image..."
mkdir -p "$OUT_DIR"
mv -f "$BUILT" "$OUT_DIR/cisco-fmc.qcow2"
rm -rf "$WORK_DIR/tmp_out_fmc"

echo
echo "Done: $OUT_DIR/cisco-fmc.qcow2"
