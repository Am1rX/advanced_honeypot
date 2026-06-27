"""Tests for the dashboard data layer + report rendering (no HTTP server)."""
import json
import sqlite3
import sys
import os

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import dashboard as dash


@pytest.fixture
def db(tmp_path):
    """A honeypot.db seeded with a small attacker session."""
    path = str(tmp_path / "honeypot.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, event TEXT,
            ip TEXT, port INTEGER, alert_level TEXT, mitre TEXT, country TEXT, extra TEXT);
        CREATE TABLE sessions (ip TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
            alert_level TEXT, country TEXT, org TEXT, ports INTEGER, creds INTEGER,
            commands INTEGER, tools TEXT);
    """)
    ip = "203.0.113.7"
    rows = [
        ("2026-06-27T10:00:00", "SSH_CRED_ATTEMPT", ip, 22, "MEDIUM", "T1110", "NL",
         json.dumps({"username": "root", "password": "toor"})),
        ("2026-06-27T10:00:05", "SSH_INTERACTIVE_CMD", ip, 22, "HIGH", "T1059", "NL",
         json.dumps({"command": "cat /etc/passwd"})),
        ("2026-06-27T10:00:09", "MALWARE_DOWNLOAD_ATTEMPT", ip, 22, "HIGH", "T1105", "NL",
         json.dumps({"tool": "wget", "url": "http://evil/x.sh"})),
    ]
    conn.executemany("INSERT INTO events (ts,event,ip,port,alert_level,mitre,country,extra)"
                     " VALUES (?,?,?,?,?,?,?,?)", rows)
    conn.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (ip, "2026-06-27T10:00:00", "2026-06-27T10:00:09", "HIGH", "NL",
                  "EvilCorp", 1, 1, 1, "wget"))
    conn.commit()
    conn.close()
    return dash.DashboardDB(path), ip


def test_available(db):
    d, _ = db
    assert d.available()


def test_stats(db):
    d, _ = db
    s = d.stats()
    assert s["events"] == 3 and s["ips"] == 1 and s["creds"] == 1


def test_list_sessions_aggregates_from_events(db):
    d, ip = db
    rows = d.list_sessions()
    assert len(rows) == 1
    r = rows[0]
    assert r["ip"] == ip
    assert r["events"] == 3        # all three seeded events
    assert r["creds"] == 1
    assert r["commands"] == 1
    assert r["alert_level"] == "HIGH"


def test_list_sessions_populates_without_sessions_table(tmp_path):
    """Regression: the overview must list IPs even when the `sessions` table
    is empty (it is only snapshotted every 60s by the honeypot)."""
    path = str(tmp_path / "ev_only.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, "
                 "event TEXT, ip TEXT, port INTEGER, alert_level TEXT, mitre TEXT, "
                 "country TEXT, extra TEXT)")
    conn.execute("INSERT INTO events (ts,event,ip,port,alert_level,mitre,country,extra) "
                 "VALUES ('2026-06-27T10:00:00','TCP_CONNECT','198.51.100.9',445,'LOW','-','US','{}')")
    conn.commit(); conn.close()
    d = dash.DashboardDB(path)
    rows = d.list_sessions()
    assert [r["ip"] for r in rows] == ["198.51.100.9"]


def test_list_sessions_search_matches_extra(db):
    d, _ = db
    # 'toor' lives inside an event's extra JSON, not in any sessions table.
    assert len(d.list_sessions(search="toor")) == 1
    assert d.list_sessions(search="no-such-thing") == []


def test_list_sessions_event_type_filter(db):
    d, ip = db
    assert len(d.list_sessions(event_type="MALWARE_DOWNLOAD_ATTEMPT")) == 1
    assert d.list_sessions(event_type="SSH_PUBKEY_ATTEMPT") == []


def test_list_sessions_sort_by_ip(db):
    d, _ = db
    rows = d.list_sessions(sort="ip")
    assert rows == sorted(rows, key=lambda r: r["ip"])


def test_event_types(db):
    d, _ = db
    types = dict(d.event_types())
    assert types["SSH_CRED_ATTEMPT"] == 1
    assert "SSH_INTERACTIVE_CMD" in types


def test_events_query_filter_and_sort(db):
    d, ip = db
    res = d.events_query(event="SSH_INTERACTIVE_CMD")
    assert res["total"] == 1
    assert res["rows"][0]["extra"]["command"] == "cat /etc/passwd"

    # free-text search hits the extra JSON
    assert d.events_query(q="toor")["total"] == 1
    # level filter
    assert d.events_query(level="HIGH")["total"] == 2
    # ip filter + ascending sort by time
    asc = d.events_query(ip=ip, sort="ts", desc=False)["rows"]
    assert asc[0]["ts"] <= asc[-1]["ts"]


def test_events_query_paging(db):
    d, _ = db
    res = d.events_query(limit=2, offset=0)
    assert res["total"] == 3 and len(res["rows"]) == 2


def test_build_report_extracts_activity(db):
    d, ip = db
    rep = d.build_report(ip)
    assert rep["alert_level"] == "HIGH"
    assert rep["credentials"][0]["username"] == "root"
    assert rep["commands"][0]["command"] == "cat /etc/passwd"
    assert rep["downloads"][0]["detail"] == "http://evil/x.sh"
    assert "T1059 Command and Scripting Interpreter" not in rep["mitre"]  # short form stored
    assert "T1110" in rep["mitre"]


def test_report_markdown_contains_key_facts(db):
    d, ip = db
    md = dash.report_markdown(d.build_report(ip))
    assert ip in md and "root" in md and "cat /etc/passwd" in md


def test_report_html_escapes(db):
    d, ip = db
    # Inject an XSS-ish command and confirm it is escaped in HTML output.
    import sqlite3 as s
    conn = s.connect(d.path)
    conn.execute("INSERT INTO events (ts,event,ip,port,alert_level,mitre,country,extra)"
                 " VALUES (?,?,?,?,?,?,?,?)",
                 ("2026-06-27T10:01:00", "SSH_INTERACTIVE_CMD", ip, 22, "HIGH", "T1059",
                  "NL", json.dumps({"command": "<script>alert(1)</script>"})))
    conn.commit(); conn.close()
    out = dash.report_html(d.build_report(ip))
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_delete_session(db):
    d, ip = db
    d.delete_session(ip)
    assert d.build_report(ip)["total_events"] == 0
    assert d.list_sessions() == []
