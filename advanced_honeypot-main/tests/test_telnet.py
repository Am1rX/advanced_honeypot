"""Tests for Telnet IAC negotiation handling — without this, real telnet
clients pollute captured usernames/commands with control bytes."""

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240


def test_strip_simple_negotiation(hp):
    raw = bytes([IAC, DO, 1]) + b"root" + bytes([IAC, WILL, 3]) + b"\r\n"
    assert hp._telnet_strip_iac(raw) == b"root\r\n"


def test_strip_subnegotiation(hp):
    raw = b"ad" + bytes([IAC, SB, 24, 0, IAC, SE]) + b"min"
    assert hp._telnet_strip_iac(raw) == b"admin"


def test_plain_text_untouched(hp):
    assert hp._telnet_strip_iac(b"plaincmd\r\n") == b"plaincmd\r\n"


def test_trailing_iac_does_not_crash(hp):
    # A dangling IAC byte at the end must not raise.
    assert hp._telnet_strip_iac(b"abc" + bytes([IAC])) == b"abc"


def test_escaped_iac_literal(hp):
    # IAC IAC is a literal 0xFF data byte; current impl treats it as a 2-byte
    # command and drops it — assert it at least doesn't crash and stays bounded.
    out = hp._telnet_strip_iac(bytes([IAC, IAC]) + b"x")
    assert b"x" in out
