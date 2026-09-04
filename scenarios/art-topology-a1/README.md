# ART Topology A1 (Windows endpoint)

Atomic Red Team endpoint lab: VyOS → NethSecurity → OVS core → single-node Elastic
(ELK/Kibana/Fleet) + a Windows 11 workstation, plus a Linux attacker (`art-1`) that
runs atomic tests over SSH. First in the a/b/c/d series. No domain join.

After the atomics run, a test report (PDF + ATT&CK Navigator layer + JSON + the run
CSV/log) is written to **`data/artifacts/art/reports/`** — see the `art_report*` vars on
the `art-1` node. That directory holds **only** report/run artifacts, so it is safe to
clear manually (`rm data/artifacts/art/reports/*`); the lab SSH keys live one level up in
`data/artifacts/art/` and are never touched.

## Detonation range (snapshot reset)

Deploy and detonation are **separate**. `lab deploy` builds the topology and provisions
everything **except** the atomics (the `run_atomic_test` / `generate_art_report` tasks are
marked `phase: detonate`, so deploy skips them). You then take a clean baseline and fire
tests repeatably against a pristine Windows box — no redeploy.

**Per-VM snapshot controls** (scenario `defaults:` + per-VM overrides):
- `snapshot: disk | live` — this VM gets a `clean-baseline` snapshot so it *can* be rolled
  back. `disk` = fresh boot on rollback (the default here, via `defaults: {snapshot: disk}`);
  `live` = RAM/vmstate (instant resume, but wakes with a stale guest clock).
- `rollback: true` — this VM is **auto-reverted** at the start of every `lab detonate`.
  Only `win-user-1` has it.

```bash
# 1. build the range (no atomics fire)
lab deploy start scenarios/art-topology-a1/scenario.yml

# 2. baseline snapshots (take once the Windows agent has checked in to Fleet)
lab snapshot create   art-topology-a1
lab snapshot list     art-topology-a1
lab snapshot delete   art-topology-a1                      # remove baselines
lab snapshot rollback art-topology-a1 --vm win-user-1      # manual revert, one VM
lab snapshot rollback art-topology-a1 --all                # whole-lab reset (baselined VMs)

# 3. detonate — rolls the rollback VMs back to baseline, runs, reports
lab detonate art-topology-a1 --tactic discovery            # one report for the tactic
lab detonate art-topology-a1                               # omit --tactic = all tests
lab detonate art-topology-a1 --tactic initial-access --per-technique   # a report per technique
```

**`lab detonate` flags:**

| Flag | Effect |
|------|--------|
| `--tactic a[,b]` | run only tests tagged with these ATT&CK tactic(s); default = all |
| `--per-technique` | one report per **base** technique (T1078.001/.003 → one `T1078`), run back-to-back after a single rollback |
| `--revert vm[,vm]` | roll back only these victim VMs (default: all `rollback: true` VMs) |
| `--settle N` | seconds to wait after rollback for agent check-in / clock resync (default 90) |

Each atomic test carries a `tactic:` field and runs in file (kill-chain) order. A live
rollback wakes with a stale clock, so `--settle` lets the agent re-check-in and NTP resync
before firing (the report correlates on timestamps).

**Where reports land.** The flat working copies stay in `data/artifacts/art/reports/` as
`report-<runid>[-<TECHNIQUE>].{pdf,html}` + `navigator/summary/run-*` and are mirrored to
`/opt/lab/reports/<user>/` and `/home/vagrant/art-reports/` on `art-1`. In addition, every
detonation is filed into an **organised batch tree** (in all three homes), so repeated runs
don't pile up in one flat directory:

```
<yy-mm-dd-hh-mm>/                       # one dir per `lab detonate` invocation
├── reports/                           # pdf-only quick index (mirrors the tree below)
│   └── <tactic>/<technique>/report-<runid>.pdf
└── <tactic>/<technique>/              # full artifacts for that technique
    ├── report-<runid>.html
    ├── navigator-<runid>.json
    ├── summary-<runid>.json
    └── run-<runid>.csv / .log
```

`--per-technique` gives the clean `<tactic>/<technique>/` nesting (one report each). An
aggregate run (bare `lab detonate`, or `--tactic X` alone) writes its single multi-technique
report to the **batch root** (`<yy-mm-dd-hh-mm>/…`, and `…/reports/report-*.pdf`).

## Detection rules

Rules are imported into Elastic during the build (on `elk-1`, via localhost Kibana).
Control it with these vars in the `x-elastic-config` block of `scenario.yml`:

| Var | Effect |
|-----|--------|
| `upload_sigma_rules`  | download SigmaHQ (Windows) rules, convert to Elastic ndjson, import |
| `enable_sigma_rules`  | import them **enabled** (else imported disabled) |
| `upload_custom_rules` | import every `.ndjson` under `data/rules/custom/` |
| `enable_custom_rules` | import them **enabled** (else imported disabled) |

`upload_*` gates `enable_*` — if `upload_*_rules` is `false`, the matching `enable_*`
flag is ignored. `enable_*` works by rewriting `"enabled": true` → `false` in the
ndjson before import.

### Custom rules

Drop one or more Kibana **Detection Engine** rule files here (git-ignored, never pushed):

```
data/rules/custom/*.ndjson      # export format: one JSON rule per line
data/rules/custom/*.json        # a single rule object, or an array [ {...}, {...} ]
```

`.ndjson` is the Security → Rules **export** format (one rule per line) — use
[`art-custom-rules.ndjson`](../../art-custom-rules.ndjson) (repo root) as a template.
`.json` is a convenience: a lone rule object or a (possibly pretty-printed) array of them
is **auto-converted to NDJSON** on the controller before import, so you can paste a rule
straight out of Kibana without flattening it yourself. Minimum viable rule fields:
`rule_id`, `name`, `description`, `severity`, `risk_score`, `type` (`query`), `language`
(`kuery`/`lucene`), `index` (`["logs-*"]`), `query`.

> Note: `created_at` / `updated_at`, if present, must be `…Z` with milliseconds
> (e.g. `2026-08-05T16:48:24.196Z`) or the import is rejected.

Sigma is currently SigmaHQ **Windows** rules; Linux coverage may be added later.
