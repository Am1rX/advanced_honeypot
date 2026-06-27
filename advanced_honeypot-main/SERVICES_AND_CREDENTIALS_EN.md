# Services & Decoy Credentials Guide (Honeytokens)

This file is for the Blue Team / honeypot operator, so you know exactly which
services on this system are fake, what banners they present, and which
username/password combinations are accepted as **decoys**. None of these
credentials are real and none grant access to any real system — they exist
solely to lure and track Red Team activity / attackers.

---

## ⚠️ Important Security Note Before Running

This script must be run on an **isolated machine/VM/container**, not on a
production server. Since it binds the standard system ports (22, 80, ...),
if you have a real SSH or HTTP service on the same host, you'll need to
change the ports in `CONFIG` or deploy this on a separate honeypot VM.

Recommendation: run it on a dedicated VPS/VM with no real data or services,
in its own VLAN/segment isolated from your main network, with restricted
outbound firewall rules (allow only Syslog/Telegram traffic out).

---

## 🖥️ SSH Service (Port 22)

- **Banner:** `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1`
- **Host key:** persisted to `honeypot_ssh_host.key` and reused across
  restarts (a key that rotates on every restart is itself a honeypot tell).
  The transport also advertises an OpenSSH-like cipher/MAC set.
- **Behavior:** After a **randomised number of attempts (1–3, decided per
  source IP)**, the attacker is granted access (regardless of the
  username/password) and dropped into a **fake shell**. Randomising the
  threshold avoids the "always in after exactly N tries" pattern, which would
  otherwise fingerprint the honeypot. This keeps the attacker engaged so we can
  observe and log the commands they run (`whoami`, `ls`, `cat /etc/passwd`, …).
- **Stateful fake shell — there is no real shell.** A small in-memory virtual
  filesystem backs it: `cd` actually changes directory, `pwd` and the prompt
  track it, `ls`/`ls -la` list the current directory, and `cat` reads decoy
  files (fake `/etc/passwd`, `/etc/shadow`, `.env`, `~/.bash_history`, etc.).
  `wget`/`curl` are logged as `MALWARE_DOWNLOAD_ATTEMPT` (MITRE T1105) with the
  URL, then fail realistically. Unknown commands return `command not found`.
- **What gets logged:** every username/password attempt, plus every command
  typed inside the fake shell.

## 🌐 HTTP Service (Port 80)

The following pages and routes are designed as bait (the attacker believes
they're real):

| Path | What it shows | Purpose |
|---|---|---|
| `/` | "Corporate Intranet" login form | Capture credentials from POST form |
| `/admin`, `/admin/login` | Fake admin panel | Capture credentials |
| `/.env` | Fake environment variables including `DB_PASS=Sup3rS3cr3t!` | Honeytoken — if this password ever appears elsewhere, it indicates a leak |
| `/config.php` | Fake PHP config file | Same honeytoken purpose as above |
| `/.git/config` | Fake Git config file | Detects tools like `git-dumper` |
| `/wp-login.php` | Fake WordPress login page | Detects WordPress scanners (WPScan, etc.) |
| `/api/v1/config` | JSON with a fake `secret_key` | API honeytoken |
| `robots.txt` | Indirectly hints at the paths above | Increases the chance the attacker stumbles into the traps |

Any credentials POSTed to the `/` or `/admin/login` forms are saved to the
log. In addition, every request's **User-Agent** is checked — if it contains
`sqlmap`, `nikto`, `nmap`, `nuclei`, `gobuster`, etc., it's flagged as an
"identified tool."

## 📁 FTP Service (Port 21)

- **Banner:** `220 ProFTPD 1.3.5 Server (Debian)`
- Partially implements the real FTP protocol: `USER` → `331 Password
  required`, then `PASS` → always `530 Login incorrect` (the attacker never
  actually logs in — only the credentials are recorded).

## 💻 Telnet Service (Port 23)

- **Banner:** `Debian GNU/Linux 10` + `login:` / `Password:` prompts
- **Telnet IAC negotiation** (`IAC DO/WILL/SB…`) is parsed and stripped, so the
  control bytes a real telnet client sends don't get logged as garbage
  usernames/commands.
- Just like SSH, once a username/password is captured it grants the **same
  stateful fake shell** (shared virtual filesystem, so `cd`/`ls`/`cat` behave
  identically). This mirrors the classic behavior of IoT/botnet honeypots (like
  Cowrie), since botnets (Mirai and similar) typically brute-force Telnet.

## 🗄️ Other Services (Banner + Data Capture Only, No Interaction)

These services simply send a realistic-looking banner and record any data
the attacker sends — there's no full protocol interaction (it's enough for
the attacker to believe the service is real and attempt a connect/auth for
it to be logged):

| Port | Service | Banner Sent |
|---|---|---|
| 25 | SMTP | `220 mail.internal.corp ESMTP Postfix` |
| 110 | POP3 | `+OK POP3 server ready` |
| 143 | IMAP | `* OK [CAPABILITY IMAP4rev1] Dovecot ready.` |
| 445 | SMB | Minimal SMB bytes |
| 1433 | MSSQL | Fake pre-login packet |
| 3306 | MySQL | Handshake reporting version `8.0.25` |
| 3389 | RDP | No response (connection only is logged) |
| 5900 | VNC | `RFB 003.008` |
| 6379 | Redis | `+PONG` |
| 8080/8443 | HTTP Alt | Fake Apache response |
| 27017 | MongoDB | Fake handshake packet |

**None of these ports actually perform authentication** — a mere connection
or data transmission is enough to be logged, and fingerprinting is applied
to the received data (detecting nmap/masscan/etc.).

---

## 🔑 Username/Password List Flagged as "Suspected Red Team/Scanner"

If an attacker uses anything from these lists, the log entry is marked with
`is_common_redteam_cred: true` (you can edit/extend these lists via the
`REDTEAM_USERNAMES` and `REDTEAM_PASSWORDS` variables in the code):

**Usernames:** admin, root, user, test, guest, administrator, ubuntu, debian, centos,
oracle, postgres, mysql, hadoop, pi, deploy, www-data, nginx, apache, jenkins, git, backup

**Passwords:** password, 123456, admin, root, toor, pass, test, 12345, qwerty, abc123,
letmein, monkey, master, shadow, sunshine, dragon, passw0rd, iloveyou, admin123,
1234567890, welcome, login, hello, P@ssw0rd, Password1, admin@123

---

## 📡 Forwarding Logs to the Blue Team (Syslog / SIEM)

In `CONFIG`:

```python
"syslog_enabled":   True,
"syslog_host":      "YOUR_SIEM_SERVER_IP",
"syslog_port":       514,
"syslog_protocol":  "udp",   # or "tcp"
"syslog_format":    "cef",   # CEF format for Splunk/QRadar/ArcSight/Graylog
"syslog_min_level": "MEDIUM" # only forward events at MEDIUM and above
```

Messages are sent in CEF format, for example:
```
<134>Jun 16 14:22:01 honeypot-vm honeypot: CEF:0|AM1RX|AdvancedHoneypot|2.0|SSH_CRED_ATTEMPT|SSH_CRED_ATTEMPT|5|src=1.2.3.4 dpt=22 cs1Label=AlertLevel cs1=HIGH cs2Label=Country cs2=NL ...
```
This format is parsed natively by most open-source and commercial SIEMs
(Splunk, QRadar, Graylog, ArcSight, ELK with a CEF plugin), and fields like
`src`, `dpt`, and `cs1` get indexed automatically.

If your SIEM doesn't support CEF, set `syslog_format` to `"plain"` to send a
simple `key=value` format instead.

---

## ✅ Checklist Before Real Deployment

1. Run the script on an **isolated** VM/container with no real data.
2. Add your own IP and any internal vulnerability scanner (Nessus/OpenVAS)
   to `whitelisted_ips` so they don't trigger unnecessary alerts.
3. Set `syslog_host` to your team's actual SIEM IP and send a test event
   (e.g. `nc -u SIEM_IP 514` or similar).
4. If you want instant alerts on your phone, set `telegram_enabled = True`.
5. Regularly check `honeypot_events.jsonl`, or pipe it directly into
   ELK/Splunk (via Filebeat or rsyslog).
6. Periodically rotate the fake credentials and banners so that if an
   attacker fingerprints this honeypot (e.g. by comparing it against known
   honeypot signatures), it isn't trivially identifiable.
