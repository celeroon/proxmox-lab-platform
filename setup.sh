#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
ENV_FILE="$SCRIPT_DIR/.env"
LOG_FILE="$SCRIPT_DIR/setup.log"

# ── output helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
section() { echo -e "\n${BOLD}${CYAN}── $* ${NC}"; }
ok()      { echo -e "  ${GREEN}✓${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}!${NC}  $*"; }
die()  {
    echo -e "\n${RED}✗ $*${NC}" >&2
    echo -e "${RED}  see setup.log for details${NC}" >&2
    tail -n 20 "$LOG_FILE" >&2
    exit 1
}

log() { "$@" >> "$LOG_FILE" 2>&1 || die "command failed: $*"; }

# ── args ──────────────────────────────────────────────────────────────────────
ORIGINAL_ARGS=("$@")
SKIP_TAGS=""
TAGS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-tags) SKIP_TAGS="$2"; shift 2 ;;
        --tags)      TAGS="$2";      shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ── env validation ────────────────────────────────────────────────────────────
validate_env() {
    section "Validate .env"

    # shellcheck source=/dev/null
    source "$ENV_FILE"

    local missing=()
    [[ -z "${PROXMOX_HOST:-}"         ]] && missing+=("PROXMOX_HOST")
    [[ -z "${PROXMOX_TOKEN_ID:-}"     ]] && missing+=("PROXMOX_TOKEN_ID")
    [[ -z "${PROXMOX_TOKEN_SECRET:-}" ]] && missing+=("PROXMOX_TOKEN_SECRET")
    [[ -z "${MGMT_VMID:-}"            ]] && missing+=("MGMT_VMID")

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "required .env values not set: ${missing[*]}"$'\n'"  edit $ENV_FILE and fill in the missing values"
    fi

    if ! [[ "${MGMT_VMID}" =~ ^[0-9]+$ ]]; then
        die "MGMT_VMID must be a positive integer (got: '${MGMT_VMID}')"
    fi

    ok ".env: all required fields set"
}

# ── preflight ─────────────────────────────────────────────────────────────────
preflight() {
    if [[ "$(id -u)" -ne 0 ]]; then
        exec sudo "$0" "${ORIGINAL_ARGS[@]}"
    fi

    section "Preflight"

    : > "$LOG_FILE"   # truncate log on each run

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "debian" ]]; then
            die "OS: $ID — only Debian 12/13 supported"
        fi
        if [[ "${VERSION_ID:-}" != "12" && "${VERSION_ID:-}" != "13" ]]; then
            die "OS: Debian $VERSION_ID — expected 12 or 13"
        fi
        if [[ "${VERSION_ID:-}" == "13" ]]; then
            ok "OS: Debian $VERSION_ID"
        else
            warn "OS: Debian $VERSION_ID — Debian 13 is the primary target"
        fi
    else
        die "OS: /etc/os-release not found"
    fi

    grep -qE 'vmx|svm' /proc/cpuinfo \
        && ok "nested KVM: detected" \
        || die "nested KVM: not detected — set CPU type to 'host' in Proxmox"

    # The primary interface IP is written into Proxmox storage config as the NFS server address.
    # If the interface has multiple IPs (e.g. lingering DHCP + new static), Ansible may pick the
    # wrong one, causing NFS mounts to fail after the DHCP lease expires or the IP changes.
    local primary_iface
    primary_iface=$(ip route show default 2>/dev/null | awk '/^default/ {print $5; exit}')
    if [[ -z "$primary_iface" ]]; then
        die "no default route found — check network configuration before running setup"
    fi
    local ip_count
    ip_count=$(ip -4 addr show dev "$primary_iface" | grep -c 'inet ' || true)
    if [[ "$ip_count" -gt 1 ]]; then
        local ips
        ips=$(ip -4 addr show dev "$primary_iface" | awk '/inet / {print $2}' | tr '\n' ' ')
        die "primary interface $primary_iface has $ip_count IPv4 addresses: ${ips}
  setup.sh registers this IP as the NFS server in Proxmox storage config
  ensure the interface has exactly one IP before running setup
  (remove the DHCP address if a static IP is already configured)"
    fi
    local mgmt_ip
    mgmt_ip=$(ip -4 addr show dev "$primary_iface" | awk '/inet / {print $2}' | cut -d/ -f1)
    ok "network: $primary_iface → $mgmt_ip (single IP confirmed)"

    if [[ -f "$ENV_FILE" ]]; then
        ok ".env: found"
    else
        die ".env: not found"$'\n'"  cp .env.example .env"$'\n'"  fill in the required values and re-run setup"
    fi

    # curl is needed for the Proxmox API check — install early if missing
    if ! command -v curl &>/dev/null; then
        log apt-get update
        log apt-get install -y curl
        ok "curl: installed"
    else
        ok "curl: present"
    fi
}

# ── proxmox api check ─────────────────────────────────────────────────────────
check_proxmox_api() {
    section "Proxmox API"

    # shellcheck source=/dev/null
    source "$ENV_FILE"

    local url="https://${PROXMOX_HOST}:${PROXMOX_PORT:-8006}/api2/json/version"
    local token="PVEAPIToken=${PROXMOX_TOKEN_ID}=${PROXMOX_TOKEN_SECRET}"
    local verify=""
    [[ "${PROXMOX_VERIFY_SSL:-false}" != "true" ]] && verify="-k"

    local response
    response=$(curl -sf $verify -H "Authorization: $token" "$url" 2>/dev/null) \
        || die "cannot connect to ${PROXMOX_HOST} — check PROXMOX_HOST and token in .env"

    local version
    version=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['version'])" 2>/dev/null) \
        || die "unexpected response from ${PROXMOX_HOST}"

    ok "connected to ${PROXMOX_HOST} (Proxmox $version)"
}

# ── proxmox storage check ─────────────────────────────────────────────────────
_die_permissions() {
    local token_user="${PROXMOX_TOKEN_ID%%!*}"
    echo -e "\n${RED}✗ API token has insufficient permissions — storage list is empty${NC}" >&2
    if [[ "$token_user" != "root@pam" ]]; then
        echo -e "  check token permissions in Proxmox UI → Datacenter → Permissions" >&2
    else
        echo -e "  token is root@pam — check that privilege separation is disabled" >&2
    fi
    echo "" >&2
    exit 1
}

check_proxmox_storage() {
    section "Proxmox Storage"

    # shellcheck source=/dev/null
    source "$ENV_FILE"

    local base="https://${PROXMOX_HOST}:${PROXMOX_PORT:-8006}/api2/json"
    local token="PVEAPIToken=${PROXMOX_TOKEN_ID}=${PROXMOX_TOKEN_SECRET}"
    local verify=""
    [[ "${PROXMOX_VERIFY_SSL:-false}" != "true" ]] && verify="-k"

    # Try global storage endpoint; fall back to node-level if empty (token scope issue).
    local response data_count
    response=$(curl -sf $verify -H "Authorization: $token" "$base/storage" 2>/dev/null) \
        || die "cannot fetch storage list from ${PROXMOX_HOST}"
    data_count=$(echo "$response" | python3 -c \
        "import sys,json; print(len(json.load(sys.stdin).get('data',[])))" 2>/dev/null || echo "0")

    if [[ "$data_count" == "0" ]]; then
        local node
        node=$(curl -sf $verify -H "Authorization: $token" "$base/nodes" 2>/dev/null \
            | python3 -c \
              "import sys,json; d=json.load(sys.stdin).get('data',[]); print(d[0]['node'] if d else '')" \
              2>/dev/null || echo "")
        if [[ -n "$node" ]]; then
            response=$(curl -sf $verify -H "Authorization: $token" \
                "$base/nodes/$node/storage" 2>/dev/null) || true
            data_count=$(echo "$response" | python3 -c \
                "import sys,json; print(len(json.load(sys.stdin).get('data',[])))" 2>/dev/null || echo "0")
        fi
    fi

    [[ "$data_count" != "0" ]] || _die_permissions

    if [[ -n "${PROXMOX_STORAGE:-}" ]]; then
        local stype
        stype=$(echo "$response" | python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
for s in data:
    if s['storage'] == '${PROXMOX_STORAGE}':
        print(s.get('type', 'unknown'))
        break
" 2>/dev/null)
        [[ -n "$stype" ]] || die "PROXMOX_STORAGE='${PROXMOX_STORAGE}' not found in Proxmox"
        ok "storage: ${PROXMOX_STORAGE} ($stype, configured)"
    else
        local selected
        selected=$(echo "$response" | python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
candidates = [s for s in data if s.get('type') != 'nfs']
for ptype in ('rbd', 'zfspool', 'lvmthin'):
    for s in candidates:
        if s.get('type') == ptype:
            print(s['storage'], s['type'])
            sys.exit(0)
if candidates:
    s = candidates[0]
    print(s['storage'], s['type'])
" 2>/dev/null)
        [[ -n "$selected" ]] || die "no suitable storage pool found — set PROXMOX_STORAGE in .env"
        local pool stype
        pool=$(echo "$selected" | awk '{print $1}')
        stype=$(echo "$selected" | awk '{print $2}')
        warn "PROXMOX_STORAGE not set → auto-selected: ${pool} (${stype})"
    fi
}

# ── packages ──────────────────────────────────────────────────────────────────
install_packages() {
    section "System packages"

    local pkgs=(
        curl gpg lsb-release ca-certificates
        python3 python3-venv python3-dev python3-psycopg2 build-essential git
        postgresql postgresql-client
        qemu-system-x86 qemu-utils
        nfs-kernel-server
        dnsmasq
        expect jq p7zip-full ethtool xorriso
        sshpass
    )
    local to_install=()
    for pkg in "${pkgs[@]}"; do
        dpkg -s "$pkg" &>/dev/null || to_install+=("$pkg")
    done

    if [[ ${#to_install[@]} -gt 0 ]]; then
        log apt-get update
        ok "installing: ${to_install[*]}"
        log apt-get install -y "${to_install[@]}"
    fi

    if ! dpkg -s packer &>/dev/null; then
        ok "adding HashiCorp apt repo"
        curl -fsSL https://apt.releases.hashicorp.com/gpg \
            | gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg
        echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
            > /etc/apt/sources.list.d/hashicorp.list
        log apt-get update
        ok "installing: packer"
        log apt-get install -y packer
    fi

    ok "all packages installed"

    if [[ -n "${SUDO_USER:-}" ]]; then
        usermod -aG kvm "$SUDO_USER"
        ok "kvm group: $SUDO_USER added"
    fi
}

# ── venv ──────────────────────────────────────────────────────────────────────
setup_venv() {
    section "Python venv"

    if [[ ! -d "$VENV_DIR" ]]; then
        ok "creating .venv"
        log python3 -m venv "$VENV_DIR"
    fi

    log "$VENV_DIR/bin/pip" install --upgrade pip
    log "$VENV_DIR/bin/pip" install -e "$SCRIPT_DIR[dev]"

    # allow non-root users to run pip install and tests
    chown -R "$SUDO_USER:$SUDO_USER" "$VENV_DIR" 2>/dev/null || true

    ln -sf "$VENV_DIR/bin/lab" /usr/local/bin/lab
    ok "venv ready — lab command available system-wide"
}

# ── ansible collections ───────────────────────────────────────────────────────
install_ansible_collections() {
    section "Ansible collections"

    log "$VENV_DIR/bin/ansible-galaxy" collection install -r "$SCRIPT_DIR/ansible/requirements.yml"
    ok "collections installed"
}

# ── secrets ───────────────────────────────────────────────────────────────────
generate_secrets() {
    section "Secrets"

    if ! grep -qE '^SECRET_KEY=.+' "$ENV_FILE"; then
        local key
        key=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
        sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$key|" "$ENV_FILE"
        ok "SECRET_KEY: generated"
    else
        ok "SECRET_KEY: already set"
    fi

    if ! grep -qE '^DB_PASSWORD=.+' "$ENV_FILE"; then
        local pw
        pw=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
        sed -i "s|^DB_PASSWORD=.*|DB_PASSWORD=$pw|" "$ENV_FILE"
        sed -i "s|DB_URL=postgresql://lab:@|DB_URL=postgresql://lab:${pw}@|" "$ENV_FILE"
        ok "DB_PASSWORD: generated"
    else
        ok "DB_PASSWORD: already set"
    fi
}

# ── ansible playbook ──────────────────────────────────────────────────────────
run_playbook() {
    section "Ansible playbook"

    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a
    export ANSIBLE_CONFIG="$SCRIPT_DIR/ansible/ansible.cfg"
    local skip_args=()
    [[ -n "$SKIP_TAGS" ]] && skip_args+=(--skip-tags "$SKIP_TAGS")
    [[ -n "$TAGS"      ]] && skip_args+=(--tags      "$TAGS"     )

    local tmp
    tmp=$(mktemp)

    "$VENV_DIR/bin/ansible-playbook" \
        -i "$SCRIPT_DIR/ansible/inventory/mgmt.ini" \
        "$SCRIPT_DIR/ansible/playbooks/setup-mgmt.yml" \
        --extra-vars "project_dir=$SCRIPT_DIR admin_user=${SUDO_USER:-root}" \
        "${skip_args[@]}" >"$tmp" 2>&1 &
    local apid=$!

    # stream task names to terminal while playbook runs
    tail -f "$tmp" 2>/dev/null | grep --line-buffered '^TASK \[' | \
        sed -u 's/TASK \[platform : //;s/\] \*\+//' | \
        while IFS= read -r task; do
            echo -e "  ${CYAN}·${NC}  $task"
        done &
    local tpid=$!

    local rc=0
    wait "$apid" || rc=$?
    sleep 0.1
    kill "$tpid" 2>/dev/null || true

    cat "$tmp" >> "$LOG_FILE"
    rm -f "$tmp"

    [[ $rc -eq 0 ]] || die "Ansible playbook failed"
    ok "setup-mgmt.yml complete"
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
    preflight "$@"
    validate_env
    check_proxmox_api
    check_proxmox_storage
    install_packages
    setup_venv
    install_ansible_collections
    generate_secrets
    run_playbook

    echo -e "\n${BOLD}${GREEN}✓ Setup complete${NC}\n"
}

main "$@"
