#!/usr/bin/env python3
"""
Push this repository to GitHub using a Personal Access Token (PAT).

It will:
  1. Sanity-check the local git repo (commits exist, no secrets tracked).
  2. Create the GitHub repo via the API if it doesn't exist yet.
  3. Point `origin` at the clean HTTPS URL (no token stored in .git/config).
  4. Push the current branch + tags, authenticating with the token via a
     one-shot HTTP header (the token is never written to disk or the remote URL).

The token is read from --token or the GITHUB_TOKEN environment variable. It is
never printed, never committed, and never stored in git config.

Examples
--------
    # PowerShell — set the token for this session only, then push:
    $env:GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"
    python push_to_github.py --owner Am1rX --repo advanced_honeypot

    # Preview everything without creating or pushing anything:
    python push_to_github.py --owner Am1rX --repo advanced_honeypot --dry-run

Create a token at: GitHub → Settings → Developer settings →
Personal access tokens → Tokens (classic) → scope: **repo**.
"""
import argparse
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"

# Files that must never be pushed (defence in depth on top of .gitignore).
SECRET_PATTERNS = ("honeypot.db", "honeypot_ssh_host.key", ".jsonl",
                   "honeypot.log", "quarantine/")


def run(cmd, check=True, capture=True):
    """Run a git/shell command. Returns (rc, stdout)."""
    res = subprocess.run(cmd, capture_output=capture, text=True)
    if check and res.returncode != 0:
        sys.stderr.write((res.stderr or res.stdout or "").strip() + "\n")
        raise SystemExit(f"✗ command failed: {' '.join(cmd)}")
    return res.returncode, (res.stdout or "").strip()


def info(msg):  print(f"  {msg}")
def step(msg):  print(f"▶ {msg}")
def ok(msg):    print(f"✓ {msg}")


def preflight():
    """Verify we're in a clean, pushable git repo with no secrets tracked."""
    step("Pre-flight checks")
    rc, _ = run(["git", "rev-parse", "--is-inside-work-tree"], check=False)
    if rc != 0:
        raise SystemExit("✗ not a git repository — run `git init` first.")

    rc, out = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], check=False)
    branch = out or "main"
    info(f"branch: {branch}")

    rc, out = run(["git", "log", "--oneline", "-1"], check=False)
    if rc != 0 or not out:
        raise SystemExit("✗ no commits yet — make at least one commit first.")
    info(f"head: {out}")

    # Refuse to push if any sensitive runtime file is tracked.
    _, tracked = run(["git", "ls-files"], check=False)
    leaked = [f for f in tracked.splitlines()
              if any(p in f for p in SECRET_PATTERNS)]
    if leaked:
        print("✗ refusing to push — these sensitive files are tracked:")
        for f in leaked:
            print(f"    {f}")
        print("  Remove them with:  git rm --cached <file>   (and check .gitignore)")
        raise SystemExit(1)
    ok("no secrets tracked")

    # Warn (don't block) on uncommitted changes.
    _, dirty = run(["git", "status", "--porcelain"], check=False)
    if dirty:
        info("note: you have uncommitted changes (they won't be pushed):")
        for line in dirty.splitlines()[:10]:
            info("   " + line)
    return branch


def api_request(method, path, token, data=None):
    url = path if path.startswith("http") else API + path
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"token {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "honeypot-push-script")
    if body:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode() or "{}")
        except Exception:
            payload = {}
        return e.code, payload


def ensure_repo(owner, repo, token, private, description, create):
    """Make sure the GitHub repo exists; create it if allowed."""
    step(f"Checking github.com/{owner}/{repo}")
    status, _ = api_request("GET", f"/repos/{owner}/{repo}", token)
    if status == 200:
        ok("repo already exists")
        return
    if status == 404:
        if not create:
            raise SystemExit("✗ repo not found and --no-create was set. "
                             "Create it manually, then re-run.")
        step("Creating repository")
        # Detect whether owner is the token's user or an org.
        s2, me = api_request("GET", "/user", token)
        if s2 != 200:
            raise SystemExit(f"✗ token rejected by GitHub (HTTP {s2}). "
                             "Check the token and its `repo` scope.")
        body = {"name": repo, "private": private, "description": description,
                "has_issues": True}
        if me.get("login", "").lower() == owner.lower():
            status, data = api_request("POST", "/user/repos", token, body)
        else:
            status, data = api_request("POST", f"/orgs/{owner}/repos", token, body)
        if status not in (200, 201):
            raise SystemExit(f"✗ could not create repo (HTTP {status}): "
                             f"{data.get('message', data)}")
        ok(f"created {data.get('full_name', owner + '/' + repo)}")
        return
    if status == 401:
        raise SystemExit("✗ 401 Unauthorized — the token is invalid or expired.")
    raise SystemExit(f"✗ unexpected GitHub API response: HTTP {status}")


def set_clean_remote(owner, repo):
    """Point origin at the token-free HTTPS URL."""
    clean = f"https://github.com/{owner}/{repo}.git"
    rc, _ = run(["git", "remote", "get-url", "origin"], check=False)
    if rc == 0:
        run(["git", "remote", "set-url", "origin", clean])
    else:
        run(["git", "remote", "add", "origin", clean])
    info(f"origin → {clean}")


def push(owner, repo, token, branch, force=False):
    """Push using a one-shot Authorization header so the token never persists."""
    step(f"Pushing {branch} + tags" + ("  (FORCE)" if force else ""))
    auth = base64.b64encode(f"{owner}:{token}".encode()).decode()
    header = f"http.extraHeader=Authorization: Basic {auth}"
    extra = ["--force"] if force else []
    # The header is passed via -c (process argv), never stored in config.
    run(["git", "-c", header, "push"] + extra + ["-u", "origin", branch],
        capture=False)
    run(["git", "-c", header, "push"] + extra + ["origin", "--tags"], capture=False)
    ok(f"pushed → https://github.com/{owner}/{repo}")


def main():
    ap = argparse.ArgumentParser(description="Push this repo to GitHub with a PAT")
    ap.add_argument("--owner", default="Am1rX", help="GitHub user or org")
    ap.add_argument("--repo", default="advanced_honeypot", help="repository name")
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""),
                    help="PAT (or set GITHUB_TOKEN env var)")
    ap.add_argument("--private", action="store_true", help="create as private")
    ap.add_argument("--no-create", action="store_true",
                    help="don't create the repo via API (must already exist)")
    ap.add_argument("--force", action="store_true",
                    help="force-push, overwriting remote history (use when the "
                         "remote has an old/unrelated history you want to replace)")
    ap.add_argument("--description",
                    default="Multi-protocol defensive honeypot with a stateful "
                            "fake shell, SQLite persistence, SFTP capture, and a "
                            "web analysis dashboard.")
    ap.add_argument("--dry-run", action="store_true",
                    help="run all checks but don't touch GitHub or push")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    branch = preflight()

    if args.dry_run:
        clean = f"https://github.com/{args.owner}/{args.repo}.git"
        print("\n— DRY RUN — would now:")
        print(f"    1. ensure github.com/{args.owner}/{args.repo} exists "
              f"({'create if missing' if not args.no_create else 'no create'})")
        print(f"    2. set origin → {clean}")
        print(f"    3. git push {'--force ' if args.force else ''}-u origin {branch} --tags")
        print("\nProvide a token and drop --dry-run to actually push.")
        return

    if not args.token:
        raise SystemExit("✗ no token. Pass --token or set GITHUB_TOKEN "
                         "(GitHub → Settings → Developer settings → "
                         "Personal access tokens, scope: repo).")

    ensure_repo(args.owner, args.repo, args.token, args.private,
                args.description, create=not args.no_create)
    set_clean_remote(args.owner, args.repo)
    push(args.owner, args.repo, args.token, branch, force=args.force)
    print("\n🎉 Done. Open: "
          f"https://github.com/{args.owner}/{args.repo}")


if __name__ == "__main__":
    main()
