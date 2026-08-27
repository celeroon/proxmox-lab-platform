#!/usr/bin/env python3
"""Generate an Atomic Red Team test report from a single run.

Runs on the controller. Correlates two sources:
  * execution proof  — an invoke-atomicredteam ExecutionLog CSV (-ExecutionLogPath)
  * detection proof  — Elastic Security alerts (.alerts-security.alerts-*),
                       linked to the triggering event via kibana.alert.ancestors

For tests with no alert it also queries the process telemetry (Sysmon EID 1) in
that test's window to show WHAT executed (detection gap vs no telemetry).

Outputs (into --out, default data/artifacts/art/reports/):
  report-<runid>.html / .pdf   styled report (PDF via Gotenberg)
  navigator-<runid>.json       ATT&CK Navigator layer (green=detected, red=gap)
  summary-<runid>.json         machine-readable run summary

With --wait, polls the alerts index until detections settle (or timeout) before
rendering — use this right after a run so the 5-minute rule interval has elapsed.
Read-only against Elasticsearch.
"""
import argparse, csv, glob, json, os, ssl, base64, urllib.request, datetime, html, sys, time
from zoneinfo import ZoneInfo

# Defaults, all overridable via flags/env. ES has NO baked-in IP on purpose: every
# lab user has their own mgmt subnet (10.<user_id>.0.0/16), so a static default would
# be wrong for everyone but one user. The deploy finalizer passes an explicit
# --es https://{{ elk_1_ip }}:9200 (resolved per-user from the platform DB). Ad-hoc
# runs set ES_URL or pass --es (get the elk mgmt IP from `lab deploy show`).
DEF_ES        = os.environ.get("ES_URL")            # e.g. https://10.<user_id>.0.5:9200
DEF_OUT       = os.environ.get("ART_OUT", "data/artifacts/art/reports")
DEF_GOTENBERG = os.environ.get("GOTENBERG_URL", "http://localhost:3000")
GREEN, RED, AMBER = "#2ca02c", "#d62728", "#d9822b"
EXECUTORS = ["cmd.exe", "pwsh.exe", "powershell.exe"]


def parse_ts(ts):
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))


class ES:
    def __init__(self, url, user, pw):
        self.url = url.rstrip("/")
        self.auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def req(self, path, body=None, method="POST"):
        r = urllib.request.Request(
            self.url + path,
            data=(json.dumps(body).encode() if body is not None else None),
            headers={"Content-Type": "application/json", "Authorization": "Basic " + self.auth},
            method=method)
        return json.load(urllib.request.urlopen(r, context=self.ctx, timeout=30))


# ---------- timezone display ----------
class TZ:
    def __init__(self, name):
        self.name = name
        if name.lower() == "utc":
            self.zone = datetime.timezone.utc
        elif name.lower() == "local":
            self.zone = datetime.datetime.now().astimezone().tzinfo
        else:
            self.zone = ZoneInfo(name)

    def t(self, dt):    # HH:MM:SS in display tz
        return dt.astimezone(self.zone).strftime("%H:%M:%S")

    def full(self, dt):
        return dt.astimezone(self.zone).strftime("%Y-%m-%d %H:%M:%S")

    @property
    def label(self):
        return datetime.datetime.now(self.zone).strftime("%Z") or self.name


def load_run(csv_path):
    rows = list(csv.DictReader(open(csv_path)))
    tests = sorted(
        [dict(tech=r["Technique"], num=r["Test Number"], name=r["Test Name"],
              guid=r["GUID"], host=r["Hostname"], exitc=r["ExitCode"],
              start=parse_ts(r["Execution Time (UTC)"])) for r in rows],
        key=lambda x: x["start"])
    if not tests:
        sys.exit(f"[!] no rows in {csv_path}")
    return tests


def alert_count(es, host, run_start, run_end):
    q = {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": [
        {"term": {"host.name": host}},
        {"range": {"kibana.alert.original_time":
                   {"gte": run_start.isoformat(), "lte": run_end.isoformat()}}}]}}}
    return es.req("/.alerts-security.alerts-*/_search", q)["hits"]["total"]["value"]


def wait_for_alerts(es, host, run_start, run_end, timeout, interval):
    """Poll until the alert count is >0 and stable for two polls, or timeout."""
    deadline = time.time() + timeout
    last, stable = -1, 0
    while time.time() < deadline:
        n = alert_count(es, host, run_start, run_end)
        stable = stable + 1 if (n > 0 and n == last) else 0
        print(f"[wait] alerts in window: {n} (stable {stable})", flush=True)
        if n > 0 and stable >= 2:
            return n
        last = n
        if time.time() + interval < deadline:
            time.sleep(interval)
        else:
            break
    return last if last > 0 else 0


def executed_command(es, host, start):
    """The atomic's top-level executor command — the cmd.exe/powershell launched by
    the SSH pwsh session nearest this test's start, i.e. exactly what the test ran.
    Anchored on the executor (not a window) so adjacent tests don't bleed together."""
    q = {"size": 3, "sort": [{"@timestamp": "asc"}], "_source": ["process.command_line"],
         "query": {"bool": {"filter": [
             {"term": {"host.name": host}}, {"term": {"event.code": "1"}},
             {"term": {"process.parent.name": "pwsh.exe"}},
             {"terms": {"process.name": EXECUTORS}},
             {"range": {"@timestamp": {
                 "gte": (start - datetime.timedelta(seconds=3)).isoformat(),
                 "lte": (start + datetime.timedelta(seconds=60)).isoformat()}}}]}}}
    try:
        hits = es.req("/logs-windows.sysmon_operational-*/_search", q)["hits"]["hits"]
        cmds = [h["_source"]["process"]["command_line"] for h in hits
                if (h.get("_source", {}).get("process") or {}).get("command_line")]
        return cmds[:1]
    except Exception:
        return []


def parse_errors(log_path, tests):
    """From the run's captured output log, pull the failing command / error lines per
    test, so the report shows WHAT failed (not just the exit code). invoke-atomicredteam
    prints 'Executing test: T####-N <name>' before each test, so we split on that."""
    import re
    for t in tests:
        t["errors"] = []
    if not log_path or not os.path.exists(log_path):
        return
    text = open(log_path, errors="replace").read()
    parts = re.split(r"Executing test:\s*(T\d+(?:\.\d+)?)-(\d+)", text)
    errpat = re.compile(r"not recognized|is not recognized|denied|cannot find|not found|"
                        r"unavailable|Exception|The system cannot|\bError\b|\bfailed\b", re.I)
    by_key = {}
    for i in range(1, len(parts) - 2, 3):
        key, body = f"{parts[i]}-{parts[i+1]}", parts[i + 2]
        seen = []
        for ln in body.splitlines():
            ln = ln.strip()
            if ln and errpat.search(ln) and ln not in seen:
                seen.append(ln)
        if seen:
            by_key[key] = seen[:6]
    for t in tests:
        t["errors"] = by_key.get(f"{t['tech']}-{t['num']}", [])


def correlate(es, tests):
    host = tests[0]["host"]
    run_start = tests[0]["start"] - datetime.timedelta(seconds=30)
    run_end = tests[-1]["start"] + datetime.timedelta(seconds=180)

    def by_time(otime, pool):
        cand = [t for t in pool if t["start"] <= otime + datetime.timedelta(seconds=5)]
        return cand[-1] if cand else pool[0]

    def assign(techs, otime):
        # Prefer an ATT&CK-technique match (rules that carry threat mapping) so a
        # T1033 rule can't be credited to T1016 just because their windows are close;
        # disambiguate same-technique tests by time. Fall back to pure time when the
        # rule has no technique mapping (e.g. some generic/prebuilt rules).
        pool = [t for t in tests if t["tech"] in techs] if techs else []
        return by_time(otime, pool or tests)

    q = {"size": 200, "sort": [{"kibana.alert.original_time": "asc"}],
         "query": {"bool": {"filter": [
             {"term": {"host.name": host}},
             {"range": {"kibana.alert.original_time":
                        {"gte": run_start.isoformat(), "lte": run_end.isoformat()}}}]}}}
    hits = es.req("/.alerts-security.alerts-*/_search", q)["hits"]["hits"]

    alerts = []
    for h in hits:
        s = h["_source"]
        proc = s.get("process", {}) or {}
        techs = []
        for th in (s.get("kibana.alert.rule.threat") or []):
            tech = th.get("technique")
            if isinstance(tech, list):
                techs += [x.get("id") for x in tech if x.get("id")]
            elif isinstance(tech, dict) and tech.get("id"):
                techs.append(tech["id"])
        otime, dtime = parse_ts(s["kibana.alert.original_time"]), parse_ts(s["@timestamp"])
        alerts.append(dict(
            rule=s.get("kibana.alert.rule.name"), sev=s.get("kibana.alert.severity"),
            risk=s.get("kibana.alert.risk_score"), techs=techs,
            proc_name=proc.get("name"), cmd=proc.get("command_line") or "",
            otime=otime, dtime=dtime, mttd=int((dtime - otime).total_seconds()),
            url=s.get("kibana.alert.url"), mapped=assign(techs, otime),
            ancestors=[{"id": a.get("id"), "index": a.get("index")}
                       for a in s.get("kibana.alert.ancestors", []) if a.get("depth") == 0]))

    for i, t in enumerate(tests):
        t["alerts"] = [a for a in alerts if a["mapped"] is t]
        t["detected"] = bool(t["alerts"])
        t["telemetry"] = [] if t["detected"] else executed_command(es, host, t["start"])
    return dict(host=host, run_start=run_start, run_end=run_end, tests=tests, alerts=alerts)


# ---------- outputs ----------
def build_summary(run, runid):
    return {
        "run_id": runid, "run_host": run["host"],
        "run_window_utc": [run["run_start"].isoformat(), run["run_end"].isoformat()],
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "coverage": {"executed": len(run["tests"]),
                     "detected": sum(1 for t in run["tests"] if t["detected"])},
        "tests": [{"technique": t["tech"], "test": t["num"], "name": t["name"], "guid": t["guid"],
                   "executed_utc": t["start"].isoformat(), "exit": t["exitc"],
                   "detected": t["detected"], "rules": [a["rule"] for a in t["alerts"]],
                   "mttd_seconds": min([a["mttd"] for a in t["alerts"]], default=None),
                   "executed_commands": t["telemetry"],
                   "evidence_doc_ids": [x["id"] for a in t["alerts"] for x in a["ancestors"]]}
                  for t in run["tests"]]}


def build_navigator(run, runid, attack_version="19"):
    # Manual per-technique color (no score/gradient) so cells colour reliably.
    # attack_version must match the Navigator instance's loaded ATT&CK to avoid the
    # "outdated layer / upgrade?" prompt (which leaves cells uncoloured until run).
    techs = {}
    for t in run["tests"]:
        d = t["detected"]
        if techs.get(t["tech"], {}).get("_det"):   # a detected entry already wins
            continue
        techs[t["tech"]] = {
            "techniqueID": t["tech"], "color": GREEN if d else RED, "enabled": True,
            "comment": (f"Detected by {', '.join(sorted({a['rule'] for a in t['alerts']}))}"
                        if d else "Executed, no detection"), "_det": d}
    out = [{k: v for k, v in tv.items() if k != "_det"} for tv in techs.values()]
    return {"name": f"ART run {runid}",
            "versions": {"attack": str(attack_version), "navigator": "5.1.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Atomic Red Team run {runid} on {run['host']} — green=detected, red=no detection.",
            "techniques": out,
            "legendItems": [{"label": "Detected", "color": GREEN},
                            {"label": "Executed, no detection", "color": RED}],
            "sorting": 0, "hideDisabled": False}


def build_html(run, runid, tz):
    e = html.escape
    def cmd(s, n=2000): s = s or ""; return e(s if len(s) <= n else s[:n] + " …")
    executed = len(run["tests"])
    detected = sum(1 for t in run["tests"] if t["detected"])
    pct = round(detected / executed * 100) if executed else 0
    gen = tz.full(datetime.datetime.now(datetime.timezone.utc))
    win = f'{tz.t(run["run_start"])}–{tz.t(run["run_end"])}'

    rows = []
    for t in run["tests"]:
        det = t["detected"]
        badge = ('<span class="b ok">Detected</span>' if det else
                 ('<span class="b gap">Detection gap</span>' if t["telemetry"]
                  else '<span class="b none">No telemetry</span>'))
        exitc = e(str(t["exitc"]))
        exit_html = exitc if exitc == "0" else f'<span class="warn">{exitc}</span>'
        rules = ", ".join(sorted({e(a["rule"] or "-") for a in t["alerts"]})) if det else "—"
        rows.append(f"""<tr class="{'ok' if det else 'gap'}">
          <td><b>{e(t['tech'])}</b> #{e(t['num'])}<div class="sub">{e(t['name'])}</div></td>
          <td class="c">{tz.t(t['start'])}</td><td class="c">{exit_html}</td>
          <td class="c">{badge}</td><td>{rules}</td></tr>""")

    # per-test evidence
    cards = []
    for t in run["tests"]:
        head = f'<b>{e(t["tech"])} #{e(t["num"])}</b> <span class="sub">{e(t["name"])}</span>'
        if t["detected"]:
            body = []
            for a in t["alerts"]:
                link = (f'<a href="{e(a["url"])}">open alert in Kibana ↗</a>' if a["url"] else "")
                anc = "".join(
                    f'<div class="kv"><b>ancestor _id</b> <span class="mono">{e(x["id"])}</span></div>'
                    f'<div class="kv"><b>source index</b> <span class="mono">{e(x["index"])}</span></div>'
                    for x in a["ancestors"])
                body.append(f"""<div class="al">
                  <div class="ct"><span class="b ok">{e(a['rule'] or '-')}</span>{link}</div>
                  <div class="kv"><b>What triggered the rule</b></div>
                  <div class="cmdblock">{cmd(a['cmd'])}</div>
                  <div class="kv"><b>process</b> <span class="mono">{e(a['proc_name'] or '')}</span></div>
                  {anc}</div>""")
            cards.append(f'<div class="card ok">{head}{"".join(body)}</div>')
        else:
            if t["telemetry"]:
                blocks = "".join(f'<div class="cmdblock">{cmd(c)}</div>' for c in t["telemetry"])
                note = (f'<div class="kv"><b>outcome</b> executed &amp; produced telemetry, '
                        f'but no rule matched — <b>detection gap</b></div>'
                        f'<div class="kv"><b>What the test ran (from telemetry)</b></div>{blocks}')
            else:
                note = ('<div class="kv"><b>outcome</b> no matching telemetry found in window — '
                        'check logging/visibility</div>')
            cards.append(f'<div class="card gap">{head}{note}</div>')

    # Execution notes: atomics that returned a non-zero exit (a guest sub-command
    # failed — e.g. a missing tool). This is the atomic's own status, not detection.
    nonzero = [t for t in run["tests"] if str(t["exitc"]) not in ("0", "")]
    notes = ""
    if nonzero:
        lis = []
        for t in nonzero:
            errs = t.get("errors") or []
            if errs:
                detail = '<ul class="errs">' + "".join(f'<li>{cmd(x, 300)}</li>' for x in errs) + '</ul>'
            else:
                detail = '<div class="sub">(no error output captured for this run)</div>'
            lis.append(
                f'<li><b>{e(t["tech"])} #{e(t["num"])}</b> — exit '
                f'<span class="warn">{e(str(t["exitc"]))}</span> '
                f'<span class="sub">({e(t["name"])})</span>{detail}</li>')
        notes = (
            '<h2>Execution notes</h2><div class="card">'
            '<div class="kv">These tests returned a <b>non-zero exit</b> — the failing '
            'sub-command(s) / error output are shown below. This is the atomic\'s own exit '
            'status and does <b>not</b> affect detection.</div>'
            f'<ul class="cmds">{"".join(lis)}</ul></div>')

    return f"""<!doctype html><html><head><meta charset="utf-8"><title>ART Test Report {e(runid)}</title>
<style>
 @page {{ size: A4; margin: 7mm; }}
 * {{ box-sizing: border-box; }}
 body {{ font: 12px/1.4 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#1b2330; margin:0; }}
 .hdr {{ background:#2d1b4e; color:#fff; padding:11px 14px; }}
 .hdr h1 {{ margin:0 0 3px; font-size:18px; }}
 .hdr .meta {{ color:#c9b8e8; font-size:11px; }}
 .wrap {{ padding:12px 14px; }}
 .cards {{ display:flex; gap:10px; margin:0 0 16px; }}
 .stat {{ flex:1; border:1px solid #e3e6ee; border-radius:8px; padding:10px 12px; }}
 .stat .n {{ font-size:22px; font-weight:700; }}
 .stat .l {{ color:#6b7280; font-size:10px; text-transform:uppercase; letter-spacing:.04em; }}
 .bar {{ height:8px; border-radius:5px; background:#eee; overflow:hidden; margin-top:6px; }}
 .bar > i {{ display:block; height:100%; background:{GREEN}; width:{pct}%; }}
 table {{ width:100%; border-collapse:collapse; font-size:11.5px; table-layout:fixed; }}
 th,td {{ text-align:left; padding:6px 8px; border-bottom:1px solid #eceff4; vertical-align:top;
          overflow-wrap:anywhere; word-break:break-word; }}
 th {{ background:#f7f8fb; font-size:10px; text-transform:uppercase; letter-spacing:.03em; color:#55607a; }}
 td.c {{ text-align:center; white-space:nowrap; }}
 tr.gap td {{ background:#fff8f7; }}
 .sub {{ color:#6b7280; font-size:10.5px; }}
 .b {{ padding:2px 7px; border-radius:20px; font-size:10px; font-weight:600; white-space:nowrap; }}
 .b.ok {{ background:#e5f4ea; color:{GREEN}; }}
 .b.gap {{ background:#fdeee1; color:{AMBER}; }}
 .b.none {{ background:#fdeaea; color:{RED}; }}
 .warn {{ color:{RED}; font-weight:600; }}
 .mono {{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:10.5px; overflow-wrap:anywhere; word-break:break-all; }}
 h2 {{ font-size:13px; margin:16px 0 8px; }}
 .card {{ border:1px solid #e3e6ee; border-left-width:3px; border-radius:8px; padding:10px 12px; margin-bottom:14px; }}
 .card.ok {{ border-left-color:{GREEN}; }} .card.gap {{ border-left-color:{AMBER}; }}
 .al {{ margin-top:6px; padding-top:6px; border-top:1px dashed #e7eaf1; }}
 .ct {{ display:flex; gap:7px; align-items:center; margin-bottom:5px; flex-wrap:wrap; }}
 .ct a {{ font-size:11px; color:#5b3fa6; }}
 .pill {{ background:#eef1f7; color:#3b4a66; padding:2px 7px; border-radius:20px; font-size:10px; }}
 .kv {{ font-size:11.5px; margin:4px 0 2px; }} .kv b {{ color:#55607a; }}
 .cmdblock {{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:10px; line-height:1.35;
   background:#f6f7fa; border:1px solid #e7eaf1; border-radius:5px; padding:6px 8px; margin:2px 0 6px;
   white-space:pre-wrap; overflow-wrap:anywhere; word-break:break-word; }}
 .errs {{ margin:3px 0 4px 14px; padding:0; }}
 .errs li {{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:10px; color:#a12a2a;
   list-style:square; overflow-wrap:anywhere; word-break:break-word; margin:1px 0; }}
</style></head><body>
<div class="hdr">
  <h1>Atomic Red Team - Test Report</h1>
  <div class="meta">run <b>{e(runid)}</b> &nbsp;·&nbsp; host <b>{e(run['host'])}</b> &nbsp;·&nbsp;
    window {e(win)} {e(tz.label)} &nbsp;·&nbsp; generated {e(gen)} {e(tz.label)}</div>
</div>
<div class="wrap">
  <div class="cards">
    <div class="stat"><div class="n">{executed}</div><div class="l">Tests executed</div></div>
    <div class="stat"><div class="n">{detected}</div><div class="l">Detected</div></div>
    <div class="stat"><div class="n">{executed - detected}</div><div class="l">Not detected</div></div>
    <div class="stat"><div class="n">{pct}%</div><div class="l">Coverage</div><div class="bar"><i></i></div></div>
  </div>
  <table>
    <colgroup><col style="width:40%"><col style="width:12%"><col style="width:9%">
      <col style="width:16%"><col style="width:23%"></colgroup>
    <thead><tr><th>Test</th><th>Executed</th><th>Exit</th><th>Outcome</th><th>Rule(s)</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <h2>Per-test evidence</h2>
  {''.join(cards)}
  {notes}
</div></body></html>"""


def gotenberg_pdf(html_str, gotenberg_url):
    boundary = "----artreport" + base64.urlsafe_b64encode(os.urandom(9)).decode()
    body = (f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="files"; filename="index.html"\r\n'
            f'Content-Type: text/html\r\n\r\n{html_str}\r\n--{boundary}--\r\n').encode()
    req = urllib.request.Request(
        gotenberg_url.rstrip("/") + "/forms/chromium/convert/html", data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, method="POST")
    return urllib.request.urlopen(req, timeout=60).read()


def main():
    ap = argparse.ArgumentParser(description="ART test-report generator")
    ap.add_argument("--csv", help="ExecutionLog CSV (default: latest run-*.csv under --out)")
    ap.add_argument("--es", default=DEF_ES)
    ap.add_argument("--es-user", default=os.environ.get("ES_USER", "elastic"))
    ap.add_argument("--es-pass", default=os.environ.get("ES_PASSWORD", "labpassword"))
    ap.add_argument("--out", default=DEF_OUT)
    ap.add_argument("--gotenberg", default=DEF_GOTENBERG)
    ap.add_argument("--tz", default=os.environ.get("ART_TZ", "UTC"),
                    help="display timezone: UTC (default), local, or IANA name e.g. Europe/Warsaw")
    ap.add_argument("--attack-version", default=os.environ.get("ART_ATTACK_VERSION", "19"),
                    help="ATT&CK version for the Navigator layer (match your Navigator, default 19)")
    ap.add_argument("--wait", action="store_true", help="poll for detections before rendering")
    ap.add_argument("--wait-timeout", type=int, default=420, help="max seconds to wait (default 420)")
    ap.add_argument("--poll", type=int, default=30, help="poll interval seconds (default 30)")
    ap.add_argument("--no-pdf", action="store_true")
    args = ap.parse_args()

    if not args.es:
        sys.exit("[!] no Elasticsearch URL. Pass --es https://<elk-mgmt-ip>:9200 or set "
                 "ES_URL. Find the elk mgmt IP with:  lab deploy show <deployment>")

    os.makedirs(args.out, exist_ok=True)
    csv_path = args.csv or max(glob.glob(os.path.join(args.out, "run-*.csv")),
                               key=os.path.getmtime, default=None)
    if not csv_path or not os.path.exists(csv_path):
        sys.exit(f"[!] no ExecutionLog CSV found (looked in {args.out}); pass --csv")
    runid = os.path.basename(csv_path)[4:-4] if os.path.basename(csv_path).startswith("run-") \
        else datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    tz = TZ(args.tz)

    tests = load_run(csv_path)
    es = ES(args.es, args.es_user, args.es_pass)
    if args.wait:
        rs = tests[0]["start"] - datetime.timedelta(seconds=30)
        re_ = tests[-1]["start"] + datetime.timedelta(seconds=180)
        print(f"[wait] polling up to {args.wait_timeout}s for detections on {tests[0]['host']}…", flush=True)
        wait_for_alerts(es, tests[0]["host"], rs, re_, args.wait_timeout, args.poll)
    run = correlate(es, tests)
    parse_errors(os.path.join(args.out, f"run-{runid}.log"), run["tests"])

    summary = build_summary(run, runid)
    nav = build_navigator(run, runid, args.attack_version)
    doc = build_html(run, runid, tz)
    open(f"{args.out}/summary-{runid}.json", "w").write(json.dumps(summary, indent=2))
    open(f"{args.out}/navigator-{runid}.json", "w").write(json.dumps(nav, indent=2))
    open(f"{args.out}/report-{runid}.html", "w").write(doc)
    outs = [f"summary-{runid}.json", f"navigator-{runid}.json", f"report-{runid}.html"]
    if not args.no_pdf:
        try:
            open(f"{args.out}/report-{runid}.pdf", "wb").write(gotenberg_pdf(doc, args.gotenberg))
            outs.append(f"report-{runid}.pdf")
        except Exception as ex:
            print(f"[!] PDF skipped (Gotenberg at {args.gotenberg}): {ex}")

    cov = summary["coverage"]
    print(f"[+] run {runid} on {run['host']}: {cov['detected']}/{cov['executed']} detected")
    for o in outs:
        print(f"    {args.out}/{o}")


if __name__ == "__main__":
    main()
