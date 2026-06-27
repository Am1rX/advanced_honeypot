"""Tests for fingerprinting, CEF sanitisation, and GeoIP behaviour that must
never touch the network."""


def test_fingerprint_detects_nmap(hp):
    found = hp.fingerprint_data(b"GET / HTTP/1.0\r\n\r\n", "192.0.2.1", 80)
    assert "nmap" in found


def test_fingerprint_http_user_agent(hp):
    raw = b"GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.5\r\n\r\n"
    found = hp.fingerprint_data(raw, "192.0.2.2", 80)
    assert any("sqlmap" in f for f in found)


def test_fingerprint_empty(hp):
    assert hp.fingerprint_data(b"", "192.0.2.3", 80) == []


def test_cef_sanitize_escapes_specials(hp):
    out = hp._cef_sanitize("a=b|c\nd")
    assert "\n" not in out and "|" not in out
    assert "\\=" in out


def test_geo_private_ip_no_network(hp):
    # Must resolve instantly without any HTTP call.
    result = hp._geo_fetch("10.0.0.5")
    assert result["country"] == "Local Network"


def test_request_geo_is_nonblocking(hp):
    hp.geo_cache.clear()
    hp.geo_pending.clear()
    # First call enqueues and returns None immediately (no worker running here).
    assert hp.request_geo("192.0.2.200") is None
    assert "192.0.2.200" in hp.geo_pending


def test_mitre_mapping_present(hp):
    assert "T1110" in hp.MITRE_MAP["SSH_CRED_ATTEMPT"]
    assert "T1105" in hp.MITRE_MAP["MALWARE_DOWNLOAD_ATTEMPT"]
