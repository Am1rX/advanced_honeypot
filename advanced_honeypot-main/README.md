<div align="center">

# 🍯 Advanced Red Team Detection Honeypot

**A multi-protocol Python honeypot that detects, fingerprints, and logs attackers in real time** — credential capture, a *stateful* fake shell, malware capture, passive OS/tool fingerprinting, SQLite persistence, and native SIEM integration via Syslog/CEF.

[![tests](https://github.com/Am1rX/advanced_honeypot/actions/workflows/tests.yml/badge.svg)](https://github.com/Am1rX/advanced_honeypot/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Defensive Security](https://img.shields.io/badge/purpose-defensive%20security-orange.svg)](#-disclaimer)

</div>

---

## ⚠️ Disclaimer

This tool is intended **strictly for defensive security purposes** — deception, early-warning detection, and threat-intelligence gathering on infrastructure you own or are authorized to monitor. It does not attack, exploit, or compromise anything; it only listens, presents decoy services, and logs interactions. Deploy only on isolated systems you control, and in compliance with your local laws and organizational policy.

---

## ✨ Features

### Detection & deception
- **Multi-service emulation** — SSH, HTTP, FTP, Telnet, plus banner-only listeners for SMTP, POP3, IMAP, SMB, MSSQL, MySQL, RDP, VNC, Redis, MongoDB, and HTTP-alt ports.
- **Real credential capture** — SSH, FTP, Telnet, and HTTP login forms all capture username/password attempts, not just connection banners.
- **🆕 Stateful fake shell** — SSH/Telnet sessions drop into a believable shell backed by a **virtual filesystem**: `cd` actually changes directory, `ls`/`ls -la` reflect the current path, `cat` reads decoy files (`.env`, `/etc/passwd`, `~/.bash_history`, …), and the prompt tracks the working dir — so it doesn't out itself as a honeypot on the first `cd`.
- **🆕 Malware capture** — files attackers **SFTP-upload** are saved to a SHA-256-named quarantine; `wget`/`curl` inside the shell are logged as `MALWARE_DOWNLOAD_ATTEMPT` (and can optionally be fetched into quarantine).
- **Red Team / scanner fingerprinting** — signatures for `nmap`, `masscan`, `Metasploit`, `Cobalt Strike`, `Hydra`, `sqlmap`, `nikto`, `nuclei`, `gobuster`, and more, via payload signatures and HTTP User-Agent matching.
- **Passive OS fingerprinting** — guesses OS and scanning tool from TTL and TCP window size, no active probing.
- **SYN stealth-scan detection** — Scapy sniffer flags port scans even when no full TCP connection completes.

### Anti-fingerprinting hardening 🆕
- **Persisted SSH host key** — a key that changes every restart is itself a honeypot tell; this one is generated once and reused.
- **OpenSSH-like cipher/MAC set** advertised by the SSH transport.
- **Randomised login-grant threshold** (1–3 attempts per source IP) instead of a fixed, fingerprintable "always in after N tries".
- **Proper Telnet IAC negotiation handling** so control bytes don't pollute captured credentials.

### Reliability & scale 🆕
- **Thread-safe, bounded state** — all attacker-session access is lock-guarded (no races under concurrent scans), per-session lists are capped, and stale sessions are purged so memory stays flat under sustained attack.
- **Non-blocking GeoIP** — a rate-limited background worker pool with a per-IP cache; enrichment never stalls a connection-handling thread.
- **SQLite persistence** — every event and a rolling session summary are written to a queryable `honeypot.db` (WAL mode, single-writer thread).

### Output & alerting
- **Attacker session tracking** with an automatic alert level (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`).
- **MITRE ATT&CK tagging** — every event mapped to a technique ID (`T1110`, `T1059`, `T1105`, …) for SOC context.
- **Syslog / CEF forwarding** to Splunk, QRadar, ArcSight, Graylog, or any CEF collector over UDP/TCP.
- **Telegram alerts** for `HIGH`/`CRITICAL` events, rate-limited per IP.
- **Dual logging** — human-readable text log + structured JSON Lines (`.jsonl`) for ELK/Filebeat.
- **Automatic log rotation**, **IP whitelisting**, and a **live console dashboard**.

---

## 📦 Requirements

- Python 3.8+
- [`paramiko`](https://pypi.org/project/paramiko/) — SSH honeypot + SFTP capture
- [`scapy`](https://pypi.org/project/scapy/) — passive SYN-scan / OS fingerprinting

```bash
pip install -r requirements.txt
```

Both are optional — the script degrades gracefully and disables only the related module if a package is missing.

---

## 🚀 Quick Start

```bash
git clone https://github.com/Am1rX/advanced_honeypot.git
cd advanced_honeypot
pip install -r requirements.txt
sudo python3 advanced_honeypot.py
```

`sudo` is required because the script binds privileged ports (< 1024) and the Scapy sniffer needs raw-socket access.

On startup you'll see a status banner confirming which modules are active:

```
╔════════════════════════════════════════════════════════╗
║       ADVANCED RED TEAM DETECTION HONEYPOT  v3.0      ║
╚════════════════════════════════════════════════════════╝
SSH Honeypot   : ✓ Enabled
HTTP Honeypot  : ✓ Enabled
FTP Honeypot   : ✓ Enabled
Telnet Honeypot: ✓ Enabled
SYN Sniffer    : ✓ Enabled
GeoIP Lookup   : ✓ Enabled
SQLite Store   : ✓ honeypot.db
SFTP Capture   : ✓ → quarantine/
Fetch Downloads: ✗ Disabled (safe)
```

> On first run the honeypot generates and **persists** an SSH host key to `honeypot_ssh_host.key`. Keep this file next to the script so the host key stays stable across restarts.

---

## ⚙️ Configuration

All settings live in the `CONFIG` dictionary at the top of `advanced_honeypot.py` — no external config file. Highlights:

| Key | Description | Default |
|---|---|---|
| `ssh_port` / `http_port` / `ftp_port` / `telnet_port` | Interactive honeypot ports | `22` / `80` / `21` / `23` |
| `monitored_ports` | Banner-only listener ports | see source |
| `ssh_host_key_file` | Persisted SSH host key path | `honeypot_ssh_host.key` |
| `persist_enabled` / `db_file` | SQLite event/session store | `True` / `honeypot.db` |
| `capture_uploads` / `quarantine_dir` | Save SFTP-uploaded files | `True` / `quarantine` |
| `fetch_downloads` / `max_download_bytes` | Actually fetch `wget`/`curl` URLs into quarantine | `False` (⚠️ outbound) |
| `session_retention` / `max_sessions` / `max_list_per_session` | Memory bounds | `86400s` / `50000` / `500` |
| `telegram_*` | Push alerts to Telegram | disabled |
| `syslog_*` | Forward events to your SIEM | disabled |
| `whitelisted_ips` | IPs excluded from alerting | empty |

See [`SERVICES_AND_CREDENTIALS_EN.md`](./SERVICES_AND_CREDENTIALS_EN.md) for every fake banner, route, and decoy credential the honeypot presents.

---

## 🔔 Alerting & SIEM

### Telegram

```python
"telegram_enabled":   True,
"telegram_bot_token": "123456:ABC-your-bot-token",
"telegram_chat_id":   "your-chat-id",
```

### Syslog → SIEM (Splunk / QRadar / ArcSight / Graylog / ELK)

```python
"syslog_enabled":   True,
"syslog_host":      "10.0.0.50",
"syslog_port":       514,
"syslog_protocol":  "udp",   # or "tcp"
"syslog_format":    "cef",   # or "plain"
"syslog_min_level": "MEDIUM",
```

Events are sent in [CEF](https://www.microfocus.com/documentation/arcsight/) by default:

```
<132>Jun 16 14:22:01 honeypot-vm honeypot: CEF:0|AM1RX|AdvancedHoneypot|2.0|SSH_CRED_ATTEMPT|SSH_CRED_ATTEMPT|5|src=1.2.3.4 dpt=22 cs1Label=AlertLevel cs1=HIGH cs2Label=Country cs2=NL ...
```

---

## 📊 Data Outputs

**Text log** (`honeypot.log`)
```
[2026-06-16 14:22:01] [HIGH] SSH_CRED_ATTEMPT | 1.2.3.4 | port=22 | {"username": "root", "password": "toor"}
```

**JSON Lines** (`honeypot_events.jsonl`) — ideal for Filebeat/Logstash:
```json
{"ts":"2026-06-16T14:22:01","event":"SSH_CRED_ATTEMPT","ip":"1.2.3.4","port":22,"alert_level":"HIGH","mitre_attack":"T1110.001 Brute Force: Password Guessing","session":{...},"geo":{...}}
```

**SQLite** (`honeypot.db`) — query attacker activity directly:
```sql
-- Top 10 noisiest source IPs
SELECT ip, COUNT(*) hits FROM events GROUP BY ip ORDER BY hits DESC LIMIT 10;

-- Every credential attempt seen
SELECT ts, ip, extra FROM events WHERE event LIKE '%CRED_ATTEMPT';

-- Captured malware payloads
SELECT ts, ip, extra FROM events WHERE event = 'MALWARE_CAPTURED';
```

---

## 🧠 How Detection Works

1. **SYN-scan layer** — Scapy passively sniffs SYN packets to catch stealth scans, even ones that never complete a handshake.
2. **Service layer** — each emulated service accepts connections, presents a realistic banner, and captures whatever the client sends.
3. **Fingerprinting layer** — payloads and headers are matched against tool signatures; TTL/window size give a passive OS/tool guess.
4. **Session & scoring layer** — every IP accumulates a profile; the alert level escalates automatically.
5. **Output layer** — every event is written to text + JSON + SQLite, optionally forwarded to your SIEM and pushed to Telegram.

---

## 📈 Analysis Dashboard

A dependency-free (stdlib-only) web UI for analysing everything the honeypot has
recorded in `honeypot.db`:

```bash
python3 dashboard.py                       # http://127.0.0.1:8080
python3 dashboard.py --port 9000 --token s3cret --db honeypot.db
```

- **Overview** — totals, event mix, and a session table aggregated **directly
  from the event log** (so it's populated the moment any event is recorded).
  Free-text search (IP / country / username / tool), filter by event type, and
  sort by last-seen / alert level / events / commands / creds / ports / IP.
- **Events explorer** (`/events`) — every raw event with strong filtering by
  **IP, event type, alert level, and free-text** (matches inside the event
  details), sortable by time / IP / event / level, paginated. Each row links
  back to its source IP's session.
- **Session drill-down** — per source IP: credentials tried, every command the
  attacker ran, HTTP requests, tools, malware up/downloads, and a full event
  timeline.
- **Delete a session** — removes the session and all its events.
- **Export an incident report** — per session, as **Markdown / HTML / JSON**.

> 🔒 The dashboard displays attacker-controlled data, so all values are
> HTML-escaped and it **binds to `127.0.0.1` by default**. Don't expose it on the
> internet — reach it over an SSH tunnel and/or set `--token`:
> ```bash
> ssh -L 8080:127.0.0.1:8080 user@honeypot-vm
> ```

## 🧪 Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The suite covers the stateful shell, Telnet IAC handling, session locking/bounds, SQLite persistence, the quarantine store, fingerprinting, and CEF formatting — all offline (no network). CI runs them on Python 3.8 / 3.10 / 3.12 via GitHub Actions.

---

## 🛡️ Deployment Recommendations

- Run on an **isolated VM or container** — never on a production host with real services on the same ports.
- Put it in its own VLAN/segment with **restricted outbound** access (only Syslog/Telegram out). Keep `fetch_downloads` **off** unless you have a sandboxed, contained environment.
- Add your own IP and internal scanners to `whitelisted_ips` to avoid noisy alerts.
- Periodically rotate the decoy banners/credentials if you suspect attackers are fingerprinting this honeypot specifically.
- Forward `honeypot_events.jsonl` / `honeypot.db` into your existing pipeline for long-term retention and correlation.

---

## 📁 Project Structure

```
.
├── advanced_honeypot.py            # Main honeypot
├── dashboard.py                    # Stdlib web UI for analysing honeypot.db
├── SERVICES_AND_CREDENTIALS_EN.md  # Full list of decoy services/credentials
├── tests/                          # pytest suite
├── requirements.txt                # Runtime deps
├── requirements-dev.txt            # + pytest
├── .github/workflows/tests.yml     # CI
└── README.md
```

---

## 🤝 Contributing

Issues and PRs welcome — additional service emulators, fingerprint signatures, shell commands, and SIEM integrations are especially appreciated. Please run `pytest` before submitting.

## 📄 License

Released under the [MIT License](LICENSE). Use responsibly and only on systems you own or are authorized to monitor.
