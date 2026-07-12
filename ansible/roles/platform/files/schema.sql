CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    user_id       INT  NOT NULL UNIQUE CHECK (user_id BETWEEN 2 AND 254),
    username      TEXT NOT NULL UNIQUE,
    role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    password_hash TEXT NOT NULL,
    ssh_key       TEXT,
    mgmt_nic      TEXT,
    created_at    TIMESTAMP DEFAULT NOW()
);

-- Upgrade columns for existing installs (no-op on fresh installs)
ALTER TABLE users ADD COLUMN IF NOT EXISTS user_id       INT  UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS role          TEXT NOT NULL DEFAULT 'user';
ALTER TABLE users ADD COLUMN IF NOT EXISTS ssh_key       TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mgmt_nic      TEXT;

CREATE TABLE IF NOT EXISTS nodes (
    name          TEXT PRIMARY KEY,
    status        TEXT NOT NULL DEFAULT 'offline',
    cpu_total     INT,
    cpu_used_pct  FLOAT,
    ram_total_mb  INT,
    ram_used_mb   INT,
    disk_total_gb INT,
    disk_used_gb  INT,
    last_seen     TIMESTAMP
);

CREATE TABLE IF NOT EXISTS deployments (
    id             SERIAL PRIMARY KEY,
    user_id        INT NOT NULL REFERENCES users(id),
    name           TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    scenario       JSONB,
    base_vm_index  INT NOT NULL DEFAULT 0,
    created_at     TIMESTAMP DEFAULT NOW(),
    updated_at     TIMESTAMP DEFAULT NOW()
);

-- Upgrade columns for existing installs
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS base_vm_index INT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS vms (
    id             SERIAL PRIMARY KEY,
    deployment_id  INT  NOT NULL REFERENCES deployments(id),
    name           TEXT NOT NULL,
    vmid           INT  NOT NULL UNIQUE,
    node           TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'stopped',
    image          TEXT NOT NULL,
    cpus           INT  NOT NULL,
    memory_mb      INT  NOT NULL,
    mac_address    TEXT,
    management_ip  TEXT,
    ansible_status TEXT NOT NULL DEFAULT 'pending',
    created_at     TIMESTAMP DEFAULT NOW()
);

-- Upgrade columns for existing installs
ALTER TABLE vms ADD COLUMN IF NOT EXISTS mac_address    TEXT;
ALTER TABLE vms ADD COLUMN IF NOT EXISTS management_ip  TEXT;
ALTER TABLE vms ADD COLUMN IF NOT EXISTS type           TEXT NOT NULL DEFAULT 'vm';
ALTER TABLE vms ADD COLUMN IF NOT EXISTS ansible_status TEXT NOT NULL DEFAULT 'pending';

-- Per-VM NIC inventory: one row per interface per VM.
-- iface_name is the scenario-declared name (eth1, eth2…) or 'eth0' for the implicit mgmt NIC.
CREATE TABLE IF NOT EXISTS vm_nics (
    id          SERIAL PRIMARY KEY,
    vmid        INTEGER NOT NULL REFERENCES vms(vmid) ON DELETE CASCADE,
    slot        TEXT NOT NULL,   -- net0, net1, net2…
    iface_name  TEXT NOT NULL,   -- eth0 (mgmt), eth1… from scenario interfaces[].name
    network     TEXT NOT NULL,   -- mgmt | scenario network name (internal, dmz…)
    vnet        TEXT NOT NULL,   -- mgmt2, v0200005…
    mac         TEXT NOT NULL,
    ip          TEXT,            -- set only for the mgmt NIC
    UNIQUE(vmid, slot)
);

-- Tracks SDN VNets created per deployment so destroy can clean them up.
-- `name` is the user-declared name from scenario YAML (display only).
-- `vnet` is the auto-generated Proxmox VNet name: v{user_id:02x}{net_id:05x}.
-- `vnet` is nullable to support a two-phase insert: INSERT returns the row id,
-- which is then used to compute the vnet name, followed by an UPDATE.
-- Multiple NULL values satisfy UNIQUE in PostgreSQL (NULLs are distinct).
CREATE TABLE IF NOT EXISTS networks (
    id            SERIAL PRIMARY KEY,
    deployment_id INT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    vnet          TEXT UNIQUE
);

-- Upgrade columns for existing installs
ALTER TABLE networks ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE networks ALTER COLUMN vnet DROP NOT NULL;

CREATE TABLE IF NOT EXISTS operations (
    id           SERIAL PRIMARY KEY,
    type         TEXT        NOT NULL,
    command      TEXT        NOT NULL,
    username     TEXT        NOT NULL,
    target       TEXT        NOT NULL,
    status       TEXT        NOT NULL DEFAULT 'started',
    pid          INT,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Upgrade columns for existing installs
ALTER TABLE operations ADD COLUMN IF NOT EXISTS pid INT;

CREATE TABLE IF NOT EXISTS operation_logs (
    id           SERIAL PRIMARY KEY,
    operation_id INT         NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    ts           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    level        TEXT        NOT NULL DEFAULT 'info',
    message      TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS operation_logs_op_idx ON operation_logs(operation_id);

-- Hot templates: CoW-capable copies of NFS templates placed on fast storage (Ceph/LVM-thin)
-- for use as linked clone sources. ref_count tracks how many active deployments reference each.
-- VMID = ids.HOT_TEMPLATE_VMID_BASE + id  (range 20001–99999).
CREATE TABLE IF NOT EXISTS hot_templates (
    id          SERIAL PRIMARY KEY,
    user_id     INT  NOT NULL REFERENCES users(id),
    template    TEXT NOT NULL,
    vmid        INT,                        -- NULL during two-phase insert, set after Proxmox clone
    storage     TEXT NOT NULL,
    ref_count   INT  NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, template, storage)
);

-- Links each deployment to the hot templates it uses, so destroy can decrement ref_counts.
CREATE TABLE IF NOT EXISTS deployment_hot_templates (
    deployment_id   INT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    hot_template_id INT NOT NULL REFERENCES hot_templates(id),
    PRIMARY KEY (deployment_id, hot_template_id)
);

-- Console access tokens: scoped per-user, generated by `lab console`, expire after 24h.
-- The legacy ?node=X&vmid=Y path bypasses this table.
CREATE TABLE IF NOT EXISTS console_tokens (
    token       TEXT PRIMARY KEY,
    vmid        INTEGER NOT NULL,
    node        TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

GRANT ALL ON ALL TABLES IN SCHEMA public TO lab;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO lab;
