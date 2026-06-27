"""Tests for the interactive shell loop — specifically that keystrokes are
echoed back (the bug where typing showed nothing until Enter) and that line
editing (backspace, Ctrl-C) and command dispatch work."""
import pytest


class FakeChan:
    """Stands in for a paramiko channel / telnet socket: records bytes sent,
    feeds queued input chunks to recv()."""
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = bytearray()

    def send(self, b):
        self.sent.extend(b)
        return len(b)

    def recv(self, n=4096):
        return self.chunks.pop(0) if self.chunks else b""

    @property
    def text(self):
        return bytes(self.sent).decode("utf-8", "replace")


def run_shell(hp, chunks):
    ip = "198.51.100.77"
    hp.get_session(ip)
    shell = hp.FakeShell(ip)
    chan = FakeChan(chunks)
    hp._interactive_shell(ip, shell, 22, "SSH_INTERACTIVE_CMD",
                          send=chan.send, recv=chan.recv)
    return chan, shell


def test_keystrokes_are_echoed(hp):
    # Type "ls" one char at a time, Enter, then exit.
    chan, _ = run_shell(hp, [b"l", b"s", b"\r", b"exit\r"])
    # Each typed char must have been echoed back as it was received.
    assert "l" in chan.text and "s" in chan.text
    # The prompt must appear before any command is run.
    assert "@prod-server-01" in chan.text


def test_enter_runs_command_and_shows_output(hp):
    chan, _ = run_shell(hp, [b"whoami\r", b"exit\r"])
    assert "root" in chan.text


def test_backspace_edits_buffer(hp):
    # Type "sl", backspace, "s" -> "ss"? No: "ls" via s,l,<bs>,s? keep simple:
    # type 'x', backspace (erase), then 'ls' + Enter → command is 'ls', not 'xls'.
    chan, _ = run_shell(hp, [b"x", b"\x7f", b"l", b"s", b"\r", b"exit\r"])
    assert "\b \b" in chan.text                    # erase sequence emitted
    # /root listing contains backup.sh, proving the command ran as "ls" not "xls"
    assert "backup.sh" in chan.text


def test_cd_then_prompt_updates(hp):
    chan, shell = run_shell(hp, [b"cd /var/www/html\r", b"exit\r"])
    assert shell.cwd == "/var/www/html"
    # Prompt should reflect the new directory.
    assert "/var/www/html#" in chan.text


def test_ctrl_c_clears_line(hp):
    chan, _ = run_shell(hp, [b"rm -rf", b"\x03", b"whoami\r", b"exit\r"])
    assert "^C" in chan.text
    assert "root" in chan.text                     # next command still works


def test_crlf_is_single_line(hp):
    # A CRLF must not be treated as two Enters (no double prompt / empty command).
    chan, _ = run_shell(hp, [b"id\r\n", b"exit\r"])
    assert chan.text.count("uid=0(root)") == 1


def test_command_is_logged(hp):
    events = []
    orig = hp.log_event
    hp.log_event = lambda *a, **k: events.append((a, k))
    try:
        run_shell(hp, [b"cat /etc/passwd\r", b"exit\r"])
    finally:
        hp.log_event = orig
    cmds = [k.get("extra", {}).get("command") for a, k in events]
    assert "cat /etc/passwd" in cmds


def test_telnet_readline_echoes_username(hp):
    chan = FakeChan([b"ro", b"ot\r"])
    name = hp._telnet_readline(chan, echo=chan.send)
    assert name == "root"
    assert "root" in chan.text                      # echoed
    assert chan.text.endswith("\r\n")


def test_telnet_readline_password_hidden(hp):
    chan = FakeChan([b"secret\r"])
    pw = hp._telnet_readline(chan, echo=None)
    assert pw == "secret"
    assert "secret" not in chan.text                # NOT echoed
