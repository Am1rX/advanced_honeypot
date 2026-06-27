#!/usr/bin/env python3
"""
🍯 Honeypot Analysis Dashboard
══════════════════════════════
A dependency-free (stdlib-only) web UI for analysing the data the honeypot
records in its SQLite store (honeypot.db):

  • Overview of every attacker session ever recorded
  • Drill into a single source IP: credentials tried, commands run, HTTP
    requests, tools, malware up/downloads, and a full event timeline
  • Delete a session (and all its events)
  • Export a per-session incident report (Markdown / HTML / JSON)

SECURITY — this is an admin tool that displays attacker-controlled data.
  • It binds to 127.0.0.1 by default. Do NOT expose it on 0.0.0.0 / the
    internet. Reach it over SSH port-forwarding if it runs on the honeypot VM:
        ssh -L 8080:127.0.0.1:8080 user@honeypot-vm
  • Optionally require a token:  --token <secret>  (then open /?token=<secret>)
  • All attacker data is HTML-escaped before rendering.

Run:
    python3 dashboard.py                 # http://127.0.0.1:8080
    python3 dashboard.py --port 9000 --db honeypot.db --token s3cret
"""
import argparse
import html
import json
import os
import sys
import sqlite3
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote

# ──────────────────────────────────────────────────────────────────────────────
# DATA ACCESS  (pure, testable — no HTTP here)
# ──────────────────────────────────────────────────────────────────────────────
CRED_EVENTS = ("SSH_CRED_ATTEMPT", "FTP_CRED_ATTEMPT", "TELNET_CRED_ATTEMPT")
CMD_EVENTS  = ("SSH_EXEC_CMD", "SSH_INTERACTIVE_CMD", "TELNET_CMD")
DL_EVENTS   = ("MALWARE_DOWNLOAD_ATTEMPT", "MALWARE_CAPTURED",
               "SFTP_UPLOAD", "SFTP_DOWNLOAD")


class DashboardDB:
    """Thin read/delete layer over the honeypot's SQLite store."""

    def __init__(self, path):
        self.path = path

    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def available(self):
        return os.path.exists(self.path)

    # ── aggregate stats for the overview header ──
    def stats(self):
        with self._conn() as c:
            ev = c.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
            ips = c.execute("SELECT COUNT(DISTINCT ip) n FROM events").fetchone()["n"]
            creds = c.execute(
                "SELECT COUNT(*) n FROM events WHERE event LIKE '%CRED_ATTEMPT'"
            ).fetchone()["n"]
            cmds = c.execute(
                "SELECT COUNT(*) n FROM events WHERE event IN (%s)"
                % ",".join("?" * len(CMD_EVENTS)), CMD_EVENTS
            ).fetchone()["n"]
            crit = c.execute(
                "SELECT COUNT(*) n FROM events WHERE alert_level='CRITICAL'"
            ).fetchone()["n"]
            by_event = c.execute(
                "SELECT event, COUNT(*) n FROM events GROUP BY event ORDER BY n DESC"
            ).fetchall()
        return {"events": ev, "ips": ips, "creds": creds, "commands": cmds,
                "critical": crit, "by_event": [(r["event"], r["n"]) for r in by_event]}

    # ── distinct event types present (for filter dropdowns) ──
    def event_types(self):
        with self._conn() as c:
            rows = c.execute(
                "SELECT event, COUNT(*) n FROM events GROUP BY event ORDER BY n DESC"
            ).fetchall()
        return [(r["event"], r["n"]) for r in rows]

    # ── session list — aggregated straight from `events` so it is ALWAYS
    #    populated (the `sessions` table is only snapshotted every 60s). ──
    def list_sessions(self, search="", sort="last_seen", event_type=""):
        cmd_in = ",".join("?" * len(CMD_EVENTS))
        rank = ("MAX(CASE alert_level WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
                "WHEN 'MEDIUM' THEN 2 ELSE 1 END)")
        q = f"""
            SELECT e.ip AS ip,
                   MIN(e.ts) AS first_seen,
                   MAX(e.ts) AS last_seen,
                   COUNT(*)  AS events,
                   SUM(CASE WHEN e.event LIKE '%CRED_ATTEMPT' THEN 1 ELSE 0 END) AS creds,
                   SUM(CASE WHEN e.event IN ({cmd_in}) THEN 1 ELSE 0 END)        AS commands,
                   COUNT(DISTINCT e.port) AS ports,
                   {rank} AS lvl_rank,
                   (SELECT country FROM events x WHERE x.ip=e.ip AND x.country IS NOT NULL
                    AND x.country!='' LIMIT 1) AS country
            FROM events e
        """
        params = list(CMD_EVENTS)
        where = []
        if event_type:
            where.append("e.ip IN (SELECT ip FROM events WHERE event=?)")
            params.append(event_type)
        if search:
            where.append("(e.ip LIKE ? OR EXISTS(SELECT 1 FROM events s "
                         "WHERE s.ip=e.ip AND (s.country LIKE ? OR s.extra LIKE ?)))")
            params += [f"%{search}%"] * 3
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " GROUP BY e.ip"
        order = {
            "last_seen": "last_seen DESC", "first_seen": "first_seen DESC",
            "events": "events DESC", "commands": "commands DESC",
            "creds": "creds DESC", "ports": "ports DESC",
            "alert": "lvl_rank DESC, events DESC", "ip": "ip ASC",
        }.get(sort, "last_seen DESC")
        q += f" ORDER BY {order}"
        rank2lvl = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}
        with self._conn() as c:
            rows = c.execute(q, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["alert_level"] = rank2lvl.get(d.pop("lvl_rank", 1), "LOW")
            out.append(d)
        return out

    # ── raw event explorer with strong filtering + sorting + paging ──
    def events_query(self, ip="", event="", level="", q="", sort="ts",
                     desc=True, limit=200, offset=0):
        cols = {"ts": "ts", "ip": "ip", "event": "event",
                "level": "CASE alert_level WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
                         "WHEN 'MEDIUM' THEN 2 ELSE 1 END", "port": "port"}
        order_col = cols.get(sort, "ts")
        direction = "DESC" if desc else "ASC"
        where, params = [], []
        if ip:
            where.append("ip LIKE ?"); params.append(f"%{ip}%")
        if event:
            where.append("event = ?"); params.append(event)
        if level:
            where.append("alert_level = ?"); params.append(level)
        if q:
            where.append("(ip LIKE ? OR event LIKE ? OR extra LIKE ? OR country LIKE ?)")
            params += [f"%{q}%"] * 4
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) n FROM events" + clause, params
                              ).fetchone()["n"]
            rows = c.execute(
                "SELECT ts, ip, event, port, alert_level, country, mitre, extra "
                f"FROM events{clause} ORDER BY {order_col} {direction}, id {direction} "
                "LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["extra"] = json.loads(d["extra"]) if d["extra"] else {}
            except Exception:
                d["extra"] = {}
            out.append(d)
        return {"total": total, "rows": out, "limit": limit, "offset": offset}

    @staticmethod
    def _has_table(conn, name):
        return conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone() is not None

    # ── all events for one IP ──
    def events_for(self, ip, limit=2000):
        with self._conn() as c:
            rows = c.execute(
                "SELECT ts, event, port, alert_level, mitre, country, extra "
                "FROM events WHERE ip=? ORDER BY id ASC LIMIT ?", (ip, limit)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["extra"] = json.loads(d["extra"]) if d["extra"] else {}
            except Exception:
                d["extra"] = {}
            out.append(d)
        return out

    def delete_session(self, ip):
        with self._conn() as c:
            c.execute("DELETE FROM events WHERE ip=?", (ip,))
            try:
                c.execute("DELETE FROM sessions WHERE ip=?", (ip,))
            except Exception:
                pass
            c.commit()
        return True

    # ── build a structured incident report for one IP ──
    def build_report(self, ip):
        events = self.events_for(ip)
        creds, commands, https, downloads = [], [], [], []
        tools, mitre = set(), set()
        first = last = None
        geo = {}
        alert = "LOW"
        rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

        for e in events:
            first = first or e["ts"]
            last = e["ts"]
            ex = e["extra"]
            if e.get("mitre") and e["mitre"] != "-":
                mitre.add(e["mitre"])
            if e.get("country"):
                geo.setdefault("country", e["country"])
            if rank.get(e["alert_level"], 0) >= rank.get(alert, 0):
                alert = e["alert_level"] or alert
            if e["event"] in CRED_EVENTS:
                creds.append({"ts": e["ts"], "service": e["event"].split("_")[0],
                              "username": ex.get("username", ""),
                              "password": ex.get("password", "")})
            elif e["event"] in CMD_EVENTS:
                commands.append({"ts": e["ts"], "via": e["event"],
                                 "command": ex.get("command", "")})
            elif e["event"] == "HTTP_REQUEST":
                https.append({"ts": e["ts"], "method": ex.get("method", ""),
                              "path": ex.get("path", ""),
                              "ua": ex.get("user_agent", "")})
                for t in (ex.get("scanners") or []):
                    tools.add(t)
            elif e["event"] in DL_EVENTS:
                downloads.append({"ts": e["ts"], "kind": e["event"],
                                  "detail": ex.get("url") or ex.get("filename")
                                  or ex.get("sha256", "")})
            for t in (ex.get("tools_detected") or ex.get("scanners") or []):
                tools.add(t)

        return {
            "ip": ip, "first_seen": first, "last_seen": last,
            "alert_level": alert, "geo": geo, "total_events": len(events),
            "credentials": creds, "commands": commands, "http_requests": https,
            "downloads": downloads, "tools": sorted(tools),
            "mitre": sorted(mitre), "events": events,
        }


# ──────────────────────────────────────────────────────────────────────────────
# REPORT RENDERERS
# ──────────────────────────────────────────────────────────────────────────────
def report_markdown(rep):
    L = []
    L.append(f"# 🍯 Honeypot Incident Report — `{rep['ip']}`\n")
    L.append(f"- **Generated:** {datetime.now().isoformat(timespec='seconds')}")
    L.append(f"- **Alert level:** {rep['alert_level']}")
    L.append(f"- **First seen:** {rep['first_seen']}")
    L.append(f"- **Last seen:** {rep['last_seen']}")
    if rep["geo"]:
        L.append(f"- **Country:** {rep['geo'].get('country', '?')}")
    L.append(f"- **Total events:** {rep['total_events']}")
    if rep["tools"]:
        L.append(f"- **Tools detected:** {', '.join(rep['tools'])}")
    if rep["mitre"]:
        L.append("\n## MITRE ATT&CK observed\n")
        for m in rep["mitre"]:
            L.append(f"- {m}")
    if rep["credentials"]:
        L.append("\n## Credentials tried\n")
        L.append("| Time | Service | Username | Password |")
        L.append("|---|---|---|---|")
        for c in rep["credentials"]:
            L.append(f"| {c['ts']} | {c['service']} | `{c['username']}` | `{c['password']}` |")
    if rep["commands"]:
        L.append("\n## Commands run by attacker\n```")
        for c in rep["commands"]:
            L.append(f"{c['ts']}  $ {c['command']}")
        L.append("```")
    if rep["http_requests"]:
        L.append("\n## HTTP requests\n")
        L.append("| Time | Method | Path | User-Agent |")
        L.append("|---|---|---|---|")
        for h in rep["http_requests"]:
            L.append(f"| {h['ts']} | {h['method']} | {h['path']} | {h['ua']} |")
    if rep["downloads"]:
        L.append("\n## Malware / file transfers\n")
        for d in rep["downloads"]:
            L.append(f"- **{d['kind']}** — {d['detail']}")
    return "\n".join(L) + "\n"


def report_html(rep):
    md = report_markdown(rep)
    return ("<!doctype html><meta charset='utf-8'><title>Report %s</title>"
            "<style>body{font:14px/1.5 ui-monospace,monospace;max-width:900px;"
            "margin:2rem auto;padding:0 1rem;background:#0d1117;color:#c9d1d9}"
            "pre{white-space:pre-wrap}</style><pre>%s</pre>"
            % (html.escape(rep["ip"]), html.escape(md)))


# ──────────────────────────────────────────────────────────────────────────────
# HTML UI
# ──────────────────────────────────────────────────────────────────────────────
def _e(v):
    return html.escape("" if v is None else str(v))


def _safe_int(v, default=0):
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return default


LEVEL_CLASS = {"LOW": "low", "MEDIUM": "med", "HIGH": "high", "CRITICAL": "crit"}

PAGE_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--txt:#c9d1d9;--mut:#8b949e;
--acc:#58a6ff;--low:#3fb950;--med:#d29922;--high:#f85149;--crit:#ff7b72}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);
font:14px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
header{padding:18px 26px;border-bottom:1px solid var(--line);display:flex;
align-items:center;gap:14px}header h1{font-size:18px;margin:0}
.wrap{padding:22px 26px;max-width:1200px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .n{font-size:26px;font-weight:700}.card .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}
th{color:var(--mut);font-weight:600;background:#1b2230;position:sticky;top:0}
tr:last-child td{border-bottom:0}tr:hover td{background:#1b2230}
.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:11px;font-weight:700}
.pill.low{background:#16341f;color:var(--low)}.pill.med{background:#3a2d10;color:var(--med)}
.pill.high{background:#3a1614;color:var(--high)}.pill.crit{background:#491a16;color:var(--crit)}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:#010409;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;white-space:pre-wrap}
input,select,button{font:inherit;background:var(--panel);color:var(--txt);border:1px solid var(--line);border-radius:7px;padding:7px 10px}
button{cursor:pointer}button.danger{border-color:var(--high);color:var(--high)}
button.danger:hover{background:#3a1614}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;align-items:center}
.sec{margin:26px 0 10px;font-size:15px;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
.muted{color:var(--mut)}.tag{display:inline-block;background:#1b2230;border:1px solid var(--line);
border-radius:6px;padding:1px 8px;margin:2px;font-size:12px}
"""


def layout(title, body, token):
    t = f"?token={quote(token)}" if token else ""
    tok_js = json.dumps(token)   # safely embed token for the fetch URL
    home = "/" + t
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title><style>{PAGE_CSS}</style></head><body>
<header>🍯<h1><a href="{home}">Honeypot Dashboard</a></h1>
<span class="muted">{_e(title)}</span></header>
<div class="wrap">{body}</div>
<script>
var TOKEN = {tok_js};
function delSession(ip){{
  if(!confirm('Delete session '+ip+' and all its events? This cannot be undone.'))return;
  var url='/delete?ip='+encodeURIComponent(ip)+(TOKEN?('&token='+encodeURIComponent(TOKEN)):'');
  fetch(url,{{method:'POST'}}).then(function(){{location.href={json.dumps(home)};}});
}}
</script></body></html>"""


def _tok_field(token):
    return f"<input type='hidden' name='token' value='{_e(token)}'>" if token else ""


def render_overview(db, token, search="", sort="last_seen", event_type=""):
    if not db.available():
        return layout("No data", "<p class='muted'>No <code>honeypot.db</code> found. "
                      "Make sure <code>persist_enabled</code> is on and the honeypot has "
                      "recorded at least one event.</p>", token)
    s = db.stats()
    tok = f"&token={quote(token)}" if token else ""
    cards = "".join(
        f"<div class='card'><div class='n'>{v}</div><div class='l'>{l}</div></div>"
        for l, v in [("Events", s["events"]), ("Unique IPs", s["ips"]),
                     ("Cred attempts", s["creds"]), ("Commands", s["commands"]),
                     ("Critical", s["critical"])])

    rows = []
    for x in db.list_sessions(search, sort, event_type):
        lvl = x["alert_level"] or "LOW"
        cls = LEVEL_CLASS.get(lvl, "low")
        link = f"/session?ip={quote(x['ip'])}{tok}"
        ev_link = f"/events?ip={quote(x['ip'])}{tok}"
        rows.append(
            f"<tr><td><a href='{link}'>{_e(x['ip'])}</a></td>"
            f"<td><span class='pill {cls}'>{_e(lvl)}</span></td>"
            f"<td>{_e(x['country'] or '?')}</td>"
            f"<td>{x['events']}</td><td>{x['ports'] or 0}</td>"
            f"<td>{x['creds'] or 0}</td><td>{x['commands'] or 0}</td>"
            f"<td class='muted'>{_e((x['last_seen'] or '')[:19])}</td>"
            f"<td><a href='{ev_link}'>events</a> · "
            f"<button class='danger' onclick=\"delSession('{_e(x['ip'])}')\">del</button></td></tr>")
    table = ("<table><tr><th>Source IP</th><th>Alert</th><th>Country</th>"
             "<th>Events</th><th>Ports</th><th>Creds</th><th>Cmds</th>"
             "<th>Last seen</th><th></th></tr>" + ("".join(rows) or
             "<tr><td colspan='9' class='muted'>No sessions match.</td></tr>") + "</table>")

    ev_opts = "".join(
        f"<option value='{_e(ev)}'{' selected' if ev==event_type else ''}>{_e(ev)} ({n})</option>"
        for ev, n in db.event_types())
    sort_opts = "".join(
        f"<option value='{v}'{' selected' if v==sort else ''}>{l}</option>"
        for v, l in [("last_seen", "Last seen"), ("first_seen", "First seen"),
                     ("alert", "Alert level"), ("events", "Events"),
                     ("commands", "Commands"), ("creds", "Credentials"),
                     ("ports", "Ports"), ("ip", "IP")])
    toolbar = (f"<form class='toolbar' method='get'>{_tok_field(token)}"
               f"<input name='q' placeholder='search ip / country / username / tool…' "
               f"value='{_e(search)}' style='min-width:240px'>"
               f"<label class='muted'>event "
               f"<select name='event'><option value=''>any</option>{ev_opts}</select></label>"
               f"<label class='muted'>sort "
               f"<select name='sort' onchange='this.form.submit()'>{sort_opts}</select></label>"
               f"<button>Apply</button>"
               f"<a class='tag' href='/events{('?'+tok[1:]) if tok else ''}'>↦ Events explorer</a>"
               "</form>")

    top_events = "".join(
        f"<a class='tag' href='/?event={quote(ev)}{tok}'>{_e(ev)} · {n}</a>"
        for ev, n in s["by_event"][:14])
    body = (f"<div class='cards'>{cards}</div>"
            f"<div class='sec'>Event mix (click to filter)</div><div>{top_events}</div>"
            f"<div class='sec'>Sessions ({len(rows)})</div>{toolbar}{table}")
    return layout("Overview", body, token)


def render_events(db, token, ip="", event="", level="", q="", sort="ts",
                  desc=True, page=0):
    if not db.available():
        return layout("No data", "<p class='muted'>No <code>honeypot.db</code> found.</p>", token)
    per = 200
    res = db.events_query(ip=ip, event=event, level=level, q=q, sort=sort,
                          desc=desc, limit=per, offset=page * per)
    tok = f"&token={quote(token)}" if token else ""

    rows = []
    for e in res["rows"]:
        lvl = e["alert_level"] or "LOW"
        ipl = f"/session?ip={quote(e['ip'])}{tok}"
        extra = _e(json.dumps(e["extra"], ensure_ascii=False))
        rows.append(
            f"<tr><td class='muted'>{_e((e['ts'] or '')[:19])}</td>"
            f"<td><a href='{ipl}'>{_e(e['ip'])}</a></td>"
            f"<td><span class='pill {LEVEL_CLASS.get(lvl,'low')}'>{_e(e['event'])}</span></td>"
            f"<td>{_e(e['port'])}</td><td>{_e(e['country'] or '')}</td>"
            f"<td><code>{extra[:160]}</code></td></tr>")
    table = ("<table><tr><th>Time</th><th>Source IP</th><th>Event</th><th>Port</th>"
             "<th>Country</th><th>Details</th></tr>" + ("".join(rows) or
             "<tr><td colspan='6' class='muted'>No events match.</td></tr>") + "</table>")

    ev_opts = "".join(
        f"<option value='{_e(ev)}'{' selected' if ev==event else ''}>{_e(ev)} ({n})</option>"
        for ev, n in db.event_types())
    lvl_opts = "".join(
        f"<option value='{v}'{' selected' if v==level else ''}>{v or 'any'}</option>"
        for v in ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    sort_opts = "".join(
        f"<option value='{v}'{' selected' if v==sort else ''}>{l}</option>"
        for v, l in [("ts", "Time"), ("ip", "IP"), ("event", "Event"),
                     ("level", "Alert level"), ("port", "Port")])
    dir_opts = "".join(
        f"<option value='{v}'{' selected' if (v=='desc')==desc else ''}>{l}</option>"
        for v, l in [("desc", "↓ desc"), ("asc", "↑ asc")])
    toolbar = (f"<form class='toolbar' method='get'>{_tok_field(token)}"
               f"<input name='ip' placeholder='IP' value='{_e(ip)}' style='width:140px'>"
               f"<input name='q' placeholder='text in details…' value='{_e(q)}' style='min-width:200px'>"
               f"<label class='muted'>event <select name='event'>"
               f"<option value=''>any</option>{ev_opts}</select></label>"
               f"<label class='muted'>level <select name='level'>{lvl_opts}</select></label>"
               f"<label class='muted'>sort <select name='sort'>{sort_opts}</select></label>"
               f"<select name='dir'>{dir_opts}</select>"
               f"<button>Apply</button></form>")

    total = res["total"]
    base = (f"/events?ip={quote(ip)}&event={quote(event)}&level={quote(level)}"
            f"&q={quote(q)}&sort={quote(sort)}&dir={'desc' if desc else 'asc'}{tok}")
    nav = ""
    if page > 0:
        nav += f"<a class='tag' href='{base}&page={page-1}'>← prev</a> "
    if (page + 1) * per < total:
        nav += f"<a class='tag' href='{base}&page={page+1}'>next →</a>"
    shown = f"{res['offset']+1}–{min(res['offset']+per, total)} of {total}" if total else "0"

    body = (f"<div class='sec'>Events explorer</div>{toolbar}"
            f"<div class='muted' style='margin-bottom:10px'>Showing {shown} &nbsp; {nav}</div>"
            f"{table}"
            f"<div style='margin-top:12px'>{nav}</div>")
    return layout("Events", body, token)


def render_session(db, ip, token):
    rep = db.build_report(ip)
    if rep["total_events"] == 0:
        return layout("Not found", f"<p class='muted'>No events for {_e(ip)}.</p>", token)
    tok = f"&token={quote(token)}" if token else ""
    lvl = rep["alert_level"]
    head = (f"<div class='toolbar'><h2 style='margin:0'>{_e(ip)}</h2>"
            f"<span class='pill {LEVEL_CLASS.get(lvl,'low')}'>{_e(lvl)}</span>"
            f"<span class='muted'>{_e(rep['geo'].get('country','?'))} · "
            f"{rep['total_events']} events · {_e((rep['first_seen'] or '')[:19])} → "
            f"{_e((rep['last_seen'] or '')[:19])}</span>"
            f"<a href='/report?ip={quote(ip)}&format=md{tok}'>⬇ Markdown</a>"
            f"<a href='/report?ip={quote(ip)}&format=html{tok}'>⬇ HTML</a>"
            f"<a href='/report?ip={quote(ip)}&format=json{tok}'>⬇ JSON</a>"
            f"<button class='danger' onclick=\"delSession('{_e(ip)}')\">Delete session</button></div>")

    def tbl(title, header, rows):
        if not rows:
            return ""
        h = "".join(f"<th>{c}</th>" for c in header)
        return f"<div class='sec'>{title}</div><table><tr>{h}</tr>{''.join(rows)}</table>"

    creds = [f"<tr><td class='muted'>{_e(c['ts'][:19])}</td><td>{_e(c['service'])}</td>"
             f"<td><code>{_e(c['username'])}</code></td><td><code>{_e(c['password'])}</code></td></tr>"
             for c in rep["credentials"]]
    https = [f"<tr><td class='muted'>{_e(h['ts'][:19])}</td><td>{_e(h['method'])}</td>"
             f"<td>{_e(h['path'])}</td><td>{_e(h['ua'][:80])}</td></tr>"
             for h in rep["http_requests"]]
    dls = [f"<tr><td class='muted'>{_e(d['ts'][:19])}</td><td>{_e(d['kind'])}</td>"
           f"<td><code>{_e(d['detail'])}</code></td></tr>" for d in rep["downloads"]]

    cmds = ""
    if rep["commands"]:
        lines = "\n".join(f"{_e(c['ts'][:19])}  $ {_e(c['command'])}" for c in rep["commands"])
        cmds = f"<div class='sec'>Commands run by attacker</div><pre>{lines}</pre>"

    tools = ("".join(f"<span class='tag'>{_e(t)}</span>" for t in rep["tools"])
             or "<span class='muted'>none</span>")
    mitre = ("".join(f"<span class='tag'>{_e(m)}</span>" for m in rep["mitre"])
             or "<span class='muted'>none</span>")

    timeline = "".join(
        f"<tr><td class='muted'>{_e(e['ts'][:19])}</td>"
        f"<td><span class='pill {LEVEL_CLASS.get(e['alert_level'],'low')}'>{_e(e['event'])}</span></td>"
        f"<td>{_e(e['port'])}</td><td><code>{_e(json.dumps(e['extra'])[:140])}</code></td></tr>"
        for e in rep["events"])

    body = (head
            + f"<div class='sec'>Tools</div><div>{tools}</div>"
            + f"<div class='sec'>MITRE ATT&CK</div><div>{mitre}</div>"
            + tbl("Credentials tried", ["Time", "Service", "Username", "Password"], creds)
            + cmds
            + tbl("HTTP requests", ["Time", "Method", "Path", "User-Agent"], https)
            + tbl("Malware / file transfers", ["Time", "Kind", "Detail"], dls)
            + tbl("Full event timeline", ["Time", "Event", "Port", "Extra"], [timeline]))
    return layout(f"Session {ip}", body, token)


# ──────────────────────────────────────────────────────────────────────────────
# HTTP SERVER
# ──────────────────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    db = None
    token = ""

    def _auth_ok(self, qs):
        if not self.token:
            return True
        supplied = (qs.get("token", [""])[0]
                    or self.headers.get("X-Auth-Token", ""))
        return supplied == self.token

    def _send(self, body, code=200, ctype="text/html; charset=utf-8", extra_headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if not self._auth_ok(qs):
            return self._send("<h1>401</h1><p>token required: add ?token=…</p>", 401)
        if u.path == "/health":
            return self._send("ok", ctype="text/plain")
        if u.path == "/":
            return self._send(render_overview(
                self.db, self.token, qs.get("q", [""])[0],
                qs.get("sort", ["last_seen"])[0], qs.get("event", [""])[0]))
        if u.path == "/events":
            return self._send(render_events(
                self.db, self.token,
                ip=qs.get("ip", [""])[0], event=qs.get("event", [""])[0],
                level=qs.get("level", [""])[0], q=qs.get("q", [""])[0],
                sort=qs.get("sort", ["ts"])[0],
                desc=qs.get("dir", ["desc"])[0] != "asc",
                page=_safe_int(qs.get("page", ["0"])[0])))
        if u.path == "/session":
            ip = qs.get("ip", [""])[0]
            return self._send(render_session(self.db, ip, self.token))
        if u.path == "/report":
            ip = qs.get("ip", [""])[0]
            fmt = qs.get("format", ["md"])[0]
            rep = self.db.build_report(ip)
            if fmt == "json":
                return self._send(json.dumps(rep, indent=2, default=str),
                                  ctype="application/json",
                                  extra_headers={"Content-Disposition":
                                                 f'attachment; filename="report_{ip}.json"'})
            if fmt == "html":
                return self._send(report_html(rep))
            return self._send(report_markdown(rep), ctype="text/markdown; charset=utf-8",
                              extra_headers={"Content-Disposition":
                                             f'attachment; filename="report_{ip}.md"'})
        return self._send("<h1>404</h1>", 404)

    def do_POST(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if not self._auth_ok(qs):
            return self._send("unauthorized", 401, ctype="text/plain")
        if u.path == "/delete":
            ip = qs.get("ip", [""])[0]
            if ip:
                self.db.delete_session(ip)
            return self._send(json.dumps({"deleted": ip}), ctype="application/json")
        return self._send("not found", 404, ctype="text/plain")

    def log_message(self, fmt, *args):   # quieter console
        return


def main():
    # Never let a limited console code page (e.g. Windows cp1256) crash startup
    # on the emoji/box-drawing characters we print.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="Honeypot analysis dashboard")
    ap.add_argument("--db", default="honeypot.db", help="path to honeypot.db")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (keep 127.0.0.1 unless you know what you're doing)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--token", default=os.environ.get("HONEYPOT_DASH_TOKEN", ""),
                    help="optional access token (or set HONEYPOT_DASH_TOKEN)")
    args = ap.parse_args()

    Handler.db = DashboardDB(args.db)
    Handler.token = args.token
    srv = ThreadingHTTPServer((args.host, args.port), Handler)

    warn = "" if args.host == "127.0.0.1" else "  ⚠ EXPOSED beyond localhost!"
    print(f"🍯 Honeypot dashboard → http://{args.host}:{args.port}/{warn}")
    print(f"   DB: {args.db}  |  auth: {'token' if args.token else 'none (localhost only)'}")
    if args.host != "127.0.0.1" and not args.token:
        print("   ⚠ Binding off-localhost without a token is dangerous. Use --token.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
