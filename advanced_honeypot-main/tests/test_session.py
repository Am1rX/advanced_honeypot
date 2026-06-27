"""Tests for session tracking: bounded lists, alert escalation, and that the
randomised SSH auth threshold stays in range."""
import threading


def test_session_created_with_defaults(hp):
    s = hp.get_session("198.51.100.1")
    assert s["alert_level"] == "LOW"
    assert 1 <= s["auth_grant_at"] <= 3


def test_session_append_is_bounded(hp):
    ip = "198.51.100.2"
    hp.get_session(ip)
    hp.CONFIG["max_list_per_session"] = 10
    for i in range(50):
        hp.session_append(ip, "commands_run", {"cmd": i})
    assert len(hp.sessions[ip]["commands_run"]) == 10
    # Keeps the most recent entries.
    assert hp.sessions[ip]["commands_run"][-1]["cmd"] == 49


def test_alert_escalates_with_commands(hp):
    ip = "198.51.100.3"
    hp.get_session(ip)
    hp.session_append(ip, "commands_run", {"cmd": "id"})
    hp._recalc_alert(ip)
    assert hp.sessions[ip]["alert_level"] in ("HIGH", "CRITICAL")


def test_prune_removes_stale_sessions(hp):
    ip = "198.51.100.4"
    hp.get_session(ip)
    hp.sessions[ip]["last_seen"] = 0           # ancient
    hp.prune_sessions()
    assert ip not in hp.sessions


def test_concurrent_appends_do_not_lose_lock(hp):
    ip = "198.51.100.5"
    hp.get_session(ip)
    hp.CONFIG["max_list_per_session"] = 100000

    def worker():
        for _ in range(200):
            hp.session_append(ip, "credentials_tried", {"u": "x"})

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(hp.sessions[ip]["credentials_tried"]) == 8 * 200


def test_add_tools_thread_safe(hp):
    ip = "198.51.100.6"
    hp.get_session(ip)
    hp.session_add_tools(ip, ["nmap", "sqlmap"])
    assert {"nmap", "sqlmap"} <= hp.sessions[ip]["identified_tools"]
