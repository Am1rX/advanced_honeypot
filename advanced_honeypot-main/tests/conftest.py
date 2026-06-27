"""Shared pytest fixtures. Keeps all honeypot side effects (host key, DB,
quarantine, log files) inside a throwaway temp dir so the repo stays clean."""
import os
import sys
import importlib
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture(scope="session")
def hp(tmp_path_factory):
    """Import the honeypot module with its file outputs redirected to a tmp dir."""
    workdir = tmp_path_factory.mktemp("honeypot_run")
    cwd = os.getcwd()
    os.chdir(workdir)
    try:
        import advanced_honeypot as module
        importlib.reload(module)
    finally:
        os.chdir(cwd)
    # Point every file-producing feature at the temp dir.
    module.CONFIG["db_file"]          = str(workdir / "honeypot.db")
    module.CONFIG["log_file"]         = str(workdir / "honeypot.log")
    module.CONFIG["json_log_file"]    = str(workdir / "events.jsonl")
    module.CONFIG["quarantine_dir"]   = str(workdir / "quarantine")
    module.CONFIG["geoip_enabled"]    = False   # never hit the network in tests
    return module


@pytest.fixture
def shell(hp):
    return hp.FakeShell("203.0.113.10")
