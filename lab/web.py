from __future__ import annotations

import json
from urllib.parse import quote, urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from lab.config import get_settings
from lab.db import get_conn
from lab.proxmox import ProxmoxClient

app = FastAPI()


def _build_console_html(node: str, vmid: int) -> str:
    s = get_settings()
    px = ProxmoxClient(s)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT type FROM vms WHERE vmid = %s", (vmid,))
            row = cur.fetchone()
    vm_type = row["type"] if row else "vm"

    ticket_data = px.get_vnc_ticket(node, vmid, vm_type=vm_type)
    vnc_port = ticket_data["port"]

    parsed = urlparse(s.web_url)
    mgmt_host = parsed.hostname
    mgmt_port = parsed.port or 443

    ticket = ticket_data["ticket"]
    api_type = "lxc" if vm_type == "container" else "qemu"
    ws_url = (
        f"wss://{mgmt_host}:{mgmt_port}"
        f"/ws/api2/json/nodes/{node}/{api_type}/{vmid}/vncwebsocket"
        f"?port={vnc_port}&vncticket={quote(ticket, safe='')}"
    )
    # JSON-encode so any chars in the ticket/URL are safe inside a JS string literal
    ws_url_js  = json.dumps(ws_url)
    ticket_js  = json.dumps(ticket)
    title_js   = json.dumps(f"Console — {node}/{vmid}")

    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>Console — {node}/{vmid}</title>"
        "<style>"
        "*{margin:0;padding:0;box-sizing:border-box}"
        "html,body,#screen{width:100%;height:100%;background:#000;overflow:hidden}"
        "#screen canvas{display:block}"
        "</style>"
        "</head><body>"
        '<div id="screen"></div>'
        "<script type='module'>"
        "import RFB from '/novnc/core/rfb.js';\n"
        f"const WS_URL  = {ws_url_js};\n"
        f"const TICKET  = {ticket_js};\n"
        f"const TITLE   = {title_js};\n"
        "let _retried = false;\n"
        "function connect() {\n"
        "  const rfb = new RFB(document.getElementById('screen'), WS_URL,"
        "    { credentials: { password: TICKET } });\n"
        "  rfb.scaleViewport = true;\n"
        "  rfb.resizeSession = true;\n"
        "  rfb.addEventListener('connect', () => { document.title = TITLE; });\n"
        "  rfb.addEventListener('disconnect', (e) => {\n"
        "    if (!e.detail.clean && !_retried) {\n"
        "      _retried = true;\n"
        "      setTimeout(() => location.reload(), 400);\n"
        "    }\n"
        "  });\n"
        "}\n"
        "connect();\n"
        "</script>"
        "</body></html>"
    )


@app.get("/console/redirect")
def console_redirect(
    token: str | None = None,
    node: str | None = None,
    vmid: int | None = None,
) -> HTMLResponse:
    if token is not None:
        # Token path: scoped to user, 24h lifetime.
        from lab.tokens import resolve_token
        row = resolve_token(token)
        if not row:
            raise HTTPException(status_code=404, detail="Token not found or expired")
        node = row["node"]
        vmid = row["vmid"]
    else:
        # Legacy path (?node=X&vmid=Y): no user scoping — rollback target.
        if node is None or vmid is None:
            raise HTTPException(status_code=400, detail="Provide token or node+vmid")
        from lab.db import get_conn
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT v.vmid FROM vms v
                    JOIN deployments d ON d.id = v.deployment_id
                    WHERE v.vmid = %s AND d.status != 'destroyed'
                    """,
                    (vmid,),
                )
                if not cur.fetchone():
                    raise HTTPException(status_code=404, detail="VM not found")

    return HTMLResponse(_build_console_html(node, vmid))
