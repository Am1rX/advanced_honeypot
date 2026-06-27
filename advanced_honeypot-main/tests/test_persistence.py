"""Tests for SQLite persistence and the quarantine store."""
import os
import threading


def test_init_db_creates_tables(hp):
    hp.init_db()
    tables = {r[0] for r in hp._db_conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"events", "sessions"} <= tables


def test_event_is_persisted(hp):
    hp.init_db()
    worker = threading.Thread(target=hp._persist_worker, daemon=True)
    worker.start()
    hp.log_event("FTP_CRED_ATTEMPT", "192.0.2.50", port=21,
                 extra={"username": "admin", "password": "admin"})
    hp.persist_queue.join()
    row = hp._db_conn.execute(
        "SELECT event, ip, port FROM events WHERE ip='192.0.2.50'").fetchone()
    assert row == ("FTP_CRED_ATTEMPT", "192.0.2.50", 21)


def test_session_snapshot_upsert(hp):
    hp.init_db()
    ip = "192.0.2.51"
    hp.get_session(ip)
    hp.session_append(ip, "credentials_tried", {"u": "root"})
    hp.persist_sessions_snapshot()
    row = hp._db_conn.execute(
        "SELECT ip, creds FROM sessions WHERE ip=?", (ip,)).fetchone()
    assert row[0] == ip and row[1] >= 1


def test_quarantine_store_writes_file(hp):
    payload = b"#!/bin/sh\n# fake malware\n"
    info = hp.quarantine_store(payload, "192.0.2.52", source="sftp", original="x.sh")
    assert info["size"] == len(payload)
    assert os.path.exists(info["path"])
    with open(info["path"], "rb") as f:
        assert f.read() == payload


def test_quarantine_dedup_by_hash(hp):
    payload = b"identical-content"
    a = hp.quarantine_store(payload, "192.0.2.53", source="sftp")
    b = hp.quarantine_store(payload, "192.0.2.54", source="sftp")
    assert a["sha256"] == b["sha256"]   # same content → same quarantine path
