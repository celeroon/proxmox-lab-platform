# ART Topology A1 (Windows endpoint)

Atomic Red Team endpoint lab: VyOS → NethSecurity → OVS core → single-node Elastic
(ELK/Kibana/Fleet) + a Windows 11 workstation, plus a Linux attacker (`art-1`) that
runs atomic tests over SSH. First in the a/b/c/d series. No domain join.

After the atomics run, a test report (PDF + ATT&CK Navigator layer + JSON + the run
CSV/log) is written to **`data/artifacts/art/reports/`** — see the `art_report*` vars on
the `art-1` node. That directory holds **only** report/run artifacts, so it is safe to
clear manually (`rm data/artifacts/art/reports/*`); the lab SSH keys live one level up in
`data/artifacts/art/` and are never touched.

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
data/rules/custom/*.ndjson      # one rule per line; a single file or several
```

Format = the Security → Rules **export** format (one JSON rule per line). Use
[`art-custom-rules.ndjson`](../../art-custom-rules.ndjson) (repo root) as a template.
Minimum viable rule fields: `rule_id`, `name`, `description`, `severity`, `risk_score`,
`type` (`query`), `language` (`kuery`/`lucene`), `index` (`["logs-*"]`), `query`.

> Note: `created_at` / `updated_at`, if present, must be `…Z` with milliseconds
> (e.g. `2026-08-05T16:48:24.196Z`) or the import is rejected.

Sigma is currently SigmaHQ **Windows** rules; Linux coverage may be added later.
