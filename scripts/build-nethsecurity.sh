#!/usr/bin/env bash
# Build a NethSecurity Proxmox template via Packer.
# Usage: build-nethsecurity.sh <version> [url]
# Example: build-nethsecurity.sh 8.7.2
# Example: build-nethsecurity.sh 8.7.2 https://example.com/nethsecurity.img.gz
set -euo pipefail

VERSION="${1:?usage: $0 <version> [url]}"
DEFAULT_URL="https://updates.nethsecurity.nethserver.org/stable/${VERSION}/targets/x86/64/nethsecurity-${VERSION}-x86-64-generic-squashfs-combined-efi.img.gz"
DOWNLOAD_URL="${2:-$DEFAULT_URL}"
IMAGE_NAME="nethsecurity-${VERSION}"
REPO_DIR="/tmp/nethsecurity-packer-repo"
WORK_DIR="/var/lib/lab-platform/build-work/nethsecurity"
REPO_URL="https://github.com/celeroon/nethsecurity-vagrant-libvirt.git"
HCL_FILE="nethsecurity-no-vagrant.pkr.hcl"

# clone or update packer repo
if [[ -d "$REPO_DIR/.git" ]]; then
    echo "updating packer repo"
    git -C "$REPO_DIR" pull --ff-only
else
    echo "cloning packer repo"
    git clone "$REPO_URL" "$REPO_DIR"
fi

# download, decompress, and convert image
echo "downloading: $DOWNLOAD_URL"
TMPDIR_DL="$(mktemp -d /tmp/nethsecurity-dl-XXXXXX)"
trap 'rm -rf "$TMPDIR_DL"' EXIT

GZ_FILE="$TMPDIR_DL/nethsecurity.img.gz"
RAW_FILE="$TMPDIR_DL/nethsecurity.img"

curl -fL --progress-bar -o "$GZ_FILE" "$DOWNLOAD_URL"
echo "decompressing..."
gunzip -c "$GZ_FILE" > "$RAW_FILE" || true
[[ -s "$RAW_FILE" ]] || { echo "error: decompression produced empty output" >&2; exit 1; }

# isolate the target HCL in a clean work dir — avoids duplicate variable errors
# caused by multiple .pkr.hcl files in the repo; copy all non-HCL supporting
# files (e.g. expect scripts) so the HCL can reference them
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cp "$REPO_DIR/$HCL_FILE" "$WORK_DIR/"
find "$REPO_DIR" -maxdepth 1 -type f ! -name "*.pkr.hcl" -exec cp {} "$WORK_DIR/" \;

echo "converting raw → qcow2..."
qemu-img convert -f raw -O qcow2 "$RAW_FILE" "$WORK_DIR/${IMAGE_NAME}"

_run_packer() {
    cd "$WORK_DIR"
    export PACKER_LOG=1
    packer init .
    timeout 15m packer build \
        -var "version=$VERSION" \
        -var "image_name=$IMAGE_NAME" \
        -var "image_path=$WORK_DIR" \
        -var "out_dir=tmp_out" \
        "$HCL_FILE"
}

if groups | grep -qw kvm; then
    _run_packer
else
    # kvm group added by setup.sh but requires re-login to take effect in existing sessions
    export -f _run_packer
    export VERSION IMAGE_NAME WORK_DIR HCL_FILE
    sg kvm -c "_run_packer"
fi
