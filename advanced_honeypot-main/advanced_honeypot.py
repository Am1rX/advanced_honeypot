"""
Requirements:
  pip install scapy paramiko

Run as root (needed for SYN sniffer + privileged ports):
  sudo python3 advanced_honeypot.py
"""

import os
import socket
import threading
import json
import time
import re
import random
import ipaddress
import queue
import sqlite3
import hashlib
from datetime import datetime
from collections import defaultdict, deque
import urllib.request
import urllib.parse

# ── Optional dependencies ─────────────────────────────────────────────────────
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION  ← Edit this block to suit your deployment
# ══════════════════════════════════════════════════════════════════════════════
CONFIG = {
    "host": "0.0.0.0",
    "log_file":        "honeypot.log",
    "json_log_file":   "honeypot_events.jsonl",

    # Port-scan detection
    "time_window":          10,   # seconds
    "port_scan_threshold":  10,   # SYN packets in window → alert

    # Session
    "session_timeout": 300,       # seconds of inactivity before hiding session
    "session_retention": 86400,   # seconds before a stale session is purged from memory
    "max_sessions": 50000,        # hard cap on tracked sessions (oldest evicted first)
    "max_list_per_session": 500,  # cap on creds/cmds/http lists per session (prevents memory blow-up)

    # Persisted SSH host key (a key that changes every restart is itself a honeypot tell)
    "ssh_host_key_file": "honeypot_ssh_host.key",

    # GeoIP rate limiting (ip-api.com free tier ≈ 45 req/min)
    "geoip_min_interval": 1.4,    # min seconds between external GeoIP calls

    # Telegram  (set telegram_enabled = True and fill in your details)
    "telegram_enabled":   False,
    "telegram_bot_token": "YOUR_BOT_TOKEN_HERE",
    "telegram_chat_id":   "YOUR_CHAT_ID_HERE",

    # ── Syslog → Blue Team SIEM (Splunk / QRadar / ArcSight / Graylog / ELK) ──
    "syslog_enabled":  False,
    "syslog_host":     "192.168.1.100",   # SIEM collector IP
    "syslog_port":     514,
    "syslog_protocol": "udp",             # "udp" or "tcp"
    "syslog_format":   "cef",             # "cef" (recommended) or "plain"
    "syslog_min_level": "MEDIUM",         # only forward LOW/MEDIUM/HIGH/CRITICAL ≥ this

    # ── Trusted IPs (admin / internal vuln-scanner) — logged quietly, no alerts ──
    "whitelisted_ips": set([
        # "10.0.0.5",
    ]),

    # ── Log rotation ──
    "log_max_mb": 20,   # rotate honeypot.log / .jsonl when they exceed this size

    # ── Persistence (SQLite) — long-term, queryable storage of every event ──
    "persist_enabled": True,
    "db_file":         "honeypot.db",

    # ── Malware / upload capture ──
    "quarantine_dir":   "quarantine",   # captured SFTP uploads land here
    "capture_uploads":  True,           # save files attackers SFTP-upload
    "fetch_downloads":  False,          # if True, actually fetch wget/curl URLs into
                                        # quarantine (DANGEROUS — only on a sandboxed,
                                        # outbound-restricted host). Off by default.
    "max_download_bytes": 5 * 1024 * 1024,

    # Services
    "ssh_port":    22,
    "http_port":   80,
    "ftp_port":    21,
    "telnet_port": 23,
    "ssh_enabled":    True,
    "http_enabled":   True,
    "ftp_enabled":    True,
    "telnet_enabled": True,
    "geoip_enabled": True,

    # Generic TCP ports (SSH/HTTP/FTP/Telnet are handled separately above)
    "monitored_ports": [
        25, 110, 143, 445,
        1433, 3306, 3389, 5900,
        6379, 8080, 8443, 27017,
    ],
}

# ══════════════════════════════════════════════════════════════════════════════
# TERMINAL COLOURS
# ══════════════════════════════════════════════════════════════════════════════
class C:
    RESET  = '\033[0m'
    BOLD   = '\033[1m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    RED    = '\033[91m'
    CYAN   = '\033[96m'
    BLUE   = '\033[94m'
    MAGENTA= '\033[95m'
    WHITE  = '\033[97m'
    RED_BG = '\033[41m'

# ══════════════════════════════════════════════════════════════════════════════
# RED TEAM TOOL SIGNATURES
# ══════════════════════════════════════════════════════════════════════════════
BINARY_SIGNATURES = {
    "nmap":         [b"Nmap", b"nmap", b"GET / HTTP/1.0\r\n\r\n",
                     b"OPTIONS / HTTP/1.0\r\n\r\n", b"HELP\r\n"],
    "masscan":      [b"masscan", b"MASSCAN"],
    "metasploit":   [b"Metasploit", b"meterpreter", b"MSFCONSOLE"],
    "cobalt_strike":[b"Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\n"],
    "hydra":        [b"HYDRA"],
    "zgrab":        [b"zgrab"],
}

HTTP_SCANNER_UAS = [
    "sqlmap", "nikto", "acunetix", "nessus", "openvas",
    "masscan", "nmap", "zgrab", "gobuster", "dirbuster",
    "wfuzz", "nuclei", "burpsuite", "zaproxy", "metasploit",
    "python-requests", "go-http-client", "curl/", "wget/",
    "shodan", "censys", "binaryedge", "zmap", "hydra",
]

# Common credentials used by Red Team / scanners
REDTEAM_USERNAMES = {
    "admin","root","user","test","guest","administrator","ubuntu",
    "debian","centos","oracle","postgres","mysql","hadoop","pi",
    "deploy","www-data","nginx","apache","jenkins","git","backup",
}
REDTEAM_PASSWORDS = {
    "password","123456","admin","root","toor","pass","test","12345",
    "qwerty","abc123","letmein","monkey","master","shadow","sunshine",
    "dragon","passw0rd","iloveyou","admin123","1234567890","welcome",
    "login","hello","P@ssw0rd","Password1","admin@123","",
}

# ══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK MAPPING  (context for the Blue Team / SOC analyst)
# ══════════════════════════════════════════════════════════════════════════════
MITRE_MAP = {
    "SYN_SCAN_DETECTED":     "T1046 Network Service Discovery",
    "TCP_CONNECT":           "T1046 Network Service Discovery / T1595 Active Scanning",
    "HTTP_REQUEST":          "T1595.002 Active Scanning: Vulnerability Scanning",
    "SSH_CONNECTION":        "T1595 Active Scanning",
    "SSH_CRED_ATTEMPT":      "T1110.001 Brute Force: Password Guessing",
    "SSH_PUBKEY_ATTEMPT":    "T1110 Brute Force",
    "SSH_LOGIN_GRANTED":     "T1078 Valid Accounts (honeypot decoy)",
    "SSH_EXEC_CMD":          "T1059 Command and Scripting Interpreter",
    "SSH_INTERACTIVE_CMD":   "T1059 Command and Scripting Interpreter",
    "FTP_CRED_ATTEMPT":      "T1110.001 Brute Force: Password Guessing",
    "TELNET_CRED_ATTEMPT":   "T1110.001 Brute Force: Password Guessing",
    "TELNET_CMD":            "T1059 Command and Scripting Interpreter",
    "MALWARE_DOWNLOAD_ATTEMPT": "T1105 Ingress Tool Transfer",
    "MALWARE_CAPTURED":      "T1105 Ingress Tool Transfer",
    "SFTP_SESSION":          "T1071 Application Layer Protocol",
    "SFTP_UPLOAD":           "T1105 Ingress Tool Transfer",
    "SFTP_DOWNLOAD":         "T1083 File and Directory Discovery",
}

# ══════════════════════════════════════════════════════════════════════════════
# FAKE SERVICE BANNERS
# ══════════════════════════════════════════════════════════════════════════════
BANNERS = {
    21:    b'220 ProFTPD 1.3.5 Server (Debian) [::ffff:127.0.0.1]\r\n',
    22:    b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n',
    23:    b'Debian GNU/Linux 10\r\nKernel 4.19.0-13-amd64 on an x86_64\r\nlogin: ',
    25:    b'220 mail.internal.corp ESMTP Postfix (Ubuntu)\r\n',
    110:   b'+OK POP3 server ready\r\n',
    143:   b'* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n',
    445:   b'\x00\x00\x00\x00',
    1433:  b'\x04\x01\x00\x25\x00\x00\x01\x00',          # MSSQL pre-login
    3306:  b'\x5a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x32\x35\x00',  # MySQL 8.0.25
    5900:  b'RFB 003.008\n',                               # VNC
    6379:  b'+PONG\r\n',                                   # Redis
    8080:  b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Length: 0\r\n\r\n',
    27017: b'\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00',  # MongoDB
}

# ══════════════════════════════════════════════════════════════════════════════
# HTTP FAKE PAGES  (honeytokens embedded)
# ══════════════════════════════════════════════════════════════════════════════
HTTP_ROUTES = {
    "/": ("200 OK", "text/html", """<!DOCTYPE html>
<html><head><title>Corporate Intranet</title></head>
<body>
<h2>Internal Admin Portal</h2>
<form method="POST" action="/login">
  Username: <input name="username" type="text"><br>
  Password: <input name="password" type="password"><br>
  <input type="submit" value="Login">
</form>
</body></html>"""),

    "/login": ("200 OK", "text/html", "<html><body><b>Invalid credentials.</b> <a href='/'>Try again</a></body></html>"),

    "/admin": ("302 Found", "text/html", ""),

    "/admin/login": ("200 OK", "text/html", """<!DOCTYPE html>
<html><head><title>Admin Login</title></head>
<body><h2>Admin Login</h2>
<form method="POST">
  User: <input name="user"><br>
  Pass: <input name="pass" type="password"><br>
  <input type="submit" value="Sign In">
</form></body></html>"""),

    "/.env": ("200 OK", "text/plain",
        "APP_ENV=production\nDB_HOST=10.0.1.5\nDB_USER=root\n"
        "DB_PASS=Sup3rS3cr3t!\nAPP_KEY=base64:FakeKeyABCDEF1234567890==\n"
        "REDIS_PASS=RedisP@ss123\n"),

    "/config.php": ("200 OK", "text/plain",
        "<?php\n$db_host='10.0.1.5';\n$db_pass='Sup3rS3cr3t!';\n?>"),

    "/wp-login.php": ("200 OK", "text/html",
        "<html><body>WordPress Login</body></html>"),

    "/phpinfo.php": ("200 OK", "text/html",
        "<html><body>PHP Version 7.4.3</body></html>"),

    "/api/v1/users": ("200 OK", "application/json",
        '{"users":[{"id":1,"role":"admin","email":"admin@corp.internal"}]}'),

    "/api/v1/config": ("200 OK", "application/json",
        '{"debug":true,"db_host":"10.0.1.5","secret_key":"fakekey_honeytoken_001"}'),

    "/.git/config": ("200 OK", "text/plain",
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"),

    "/robots.txt": ("200 OK", "text/plain",
        "User-agent: *\nDisallow: /admin/\nDisallow: /.env\nDisallow: /api/\n"),

    "/backup.zip": ("200 OK", "application/zip", ""),
}

# ══════════════════════════════════════════════════════════════════════════════
# SSH FAKE SHELL RESPONSES
# ══════════════════════════════════════════════════════════════════════════════
HOSTNAME = "prod-server-01"

# ── Virtual filesystem: directory tree + file contents ────────────────────────
# Directories map to their child entries; FILES map absolute paths to contents.
VFS_DIRS = {
    "/":              ["bin","boot","dev","etc","home","lib","lib64","mnt","opt",
                       "proc","root","run","srv","sys","tmp","usr","var"],
    "/root":          [".bashrc",".bash_history",".profile",".ssh","backup.sh","notes.txt"],
    "/root/.ssh":     ["authorized_keys","id_rsa","known_hosts"],
    "/home":          ["admin"],
    "/home/admin":    [".bashrc",".bash_history",".profile"],
    "/etc":           ["passwd","shadow","hostname","hosts","os-release","crontab","ssh"],
    "/etc/ssh":       ["sshd_config","ssh_host_rsa_key.pub"],
    "/var":           ["www","log","backups"],
    "/var/www":       ["html"],
    "/var/www/html":  ["index.php","config.php",".env","wp-config.php"],
    "/var/log":       ["auth.log","syslog","nginx"],
    "/var/backups":   ["db_backup.sql.gz","etc.tar.gz"],
    "/tmp":           [],
    "/opt":           [],
}

VFS_FILES = {
    "/etc/passwd": ("root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                    "admin:x:1000:1000:admin:/home/admin:/bin/bash\n"
                    "mysql:x:106:110:MySQL Server,,,:/nonexistent:/bin/false\n"),
    "/etc/shadow": "root:$6$rounds=5000$fakehashhoneypot$abc123def456:18000:0:99999:7:::\n"
                   "admin:$6$rounds=5000$anotherfakehash$xyz789:18000:0:99999:7:::\n",
    "/etc/hostname": HOSTNAME + "\n",
    "/etc/hosts": "127.0.0.1\tlocalhost\n127.0.1.1\t" + HOSTNAME + "\n10.0.1.4\t" + HOSTNAME + "\n",
    "/etc/os-release": ('PRETTY_NAME="Ubuntu 20.04.4 LTS"\nNAME="Ubuntu"\n'
                        'VERSION_ID="20.04"\nVERSION="20.04.4 LTS (Focal Fossa)"\nID=ubuntu\n'),
    "/etc/crontab": ("# m h dom mon dow user  command\n"
                     "*/5 * * * * root /usr/local/bin/backup.sh\n"
                     "0 2 * * * root /usr/bin/find /tmp -mtime +7 -delete\n"),
    "/etc/ssh/sshd_config": ("Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n"
                             "PubkeyAuthentication yes\nX11Forwarding yes\n"),
    "/root/.bash_history": ("ls -la\ncd /var/www/html\ncat .env\n"
                            "mysql -u root -pSup3rS3cr3t! corp_db\nsystemctl status nginx\n"
                            "wget http://10.0.1.5/backup.tar.gz\ncrontab -l\n"),
    "/root/notes.txt": "TODO: rotate the DB password (Sup3rS3cr3t!) before the audit.\n",
    "/root/backup.sh": "#!/bin/bash\nmysqldump -u root -pSup3rS3cr3t! corp_db > /var/backups/db_backup.sql\n",
    "/root/.ssh/id_rsa": ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                          "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFAKEHONEYTOKEN\n"
                          "-----END OPENSSH PRIVATE KEY-----\n"),
    "/root/.ssh/authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABfakehoneytokenkey admin@corp\n",
    "/var/www/html/.env": ("APP_ENV=production\nDB_HOST=10.0.1.5\nDB_USER=root\n"
                           "DB_PASS=Sup3rS3cr3t!\nAPP_KEY=base64:FakeKeyABCDEF1234567890==\n"
                           "REDIS_PASS=RedisP@ss123\n"),
    "/var/www/html/config.php": "<?php\n$db_host='10.0.1.5';\n$db_pass='Sup3rS3cr3t!';\n?>\n",
    "/var/www/html/wp-config.php": ("<?php\ndefine('DB_NAME','wordpress');\n"
                                    "define('DB_USER','wpuser');\ndefine('DB_PASSWORD','WpP@ss2023');\n"),
    "/var/log/auth.log": ("Jan 12 10:21:03 " + HOSTNAME + " sshd[842]: Accepted password for root from 10.0.0.5\n"
                          "Jan 12 10:30:11 " + HOSTNAME + " sudo: root : COMMAND=/usr/bin/apt update\n"),
}

# Static, cwd-independent command outputs (uname, ps, hardware, etc.)
STATIC_CMDS = {
    "id":            "uid=0(root) gid=0(root) groups=0(root)",
    "uname":         "Linux",
    "uname -a":      "Linux %h 5.4.0-120-generic #136-Ubuntu SMP Fri Jun 10 09:42:11 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux",
    "uname -r":      "5.4.0-120-generic",
    "uname -s":      "Linux",
    "uname -m":      "x86_64",
    "ifconfig":      ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                      "        inet 10.0.1.4  netmask 255.255.255.0  broadcast 10.0.1.255\n"
                      "        ether 02:42:0a:00:01:04  txqueuelen 1000  (Ethernet)\n"
                      "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
                      "        inet 127.0.0.1  netmask 255.0.0.0"),
    "ip a":          ("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
                      "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.1.4/24 brd 10.0.1.255 scope global eth0"),
    "ip addr":       "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.1.4/24 scope global eth0",
    "ps aux":        ("USER   PID %CPU %MEM    VSZ   RSS TTY  STAT START   TIME COMMAND\n"
                      "root     1  0.0  0.1 169292 11000 ?   Ss   Jan12   0:04 /sbin/init\n"
                      "root   842  0.0  0.2  72300  6500 ?   Ss   Jan12   0:00 /usr/sbin/sshd -D\n"
                      "mysql 1190  0.1  4.2 1782680 84000 ? Sl  Jan12   2:11 /usr/sbin/mysqld\n"
                      "www-d 1455  0.0  0.5 145600 11200 ?   S    Jan12   0:03 nginx: worker process"),
    "netstat -tulpn":("Proto Recv-Q Send-Q Local Address    Foreign Address  State   PID/Program name\n"
                      "tcp        0      0 0.0.0.0:22       0.0.0.0:*        LISTEN  842/sshd\n"
                      "tcp        0      0 0.0.0.0:80       0.0.0.0:*        LISTEN  1455/nginx\n"
                      "tcp        0      0 127.0.0.1:3306   0.0.0.0:*        LISTEN  1190/mysqld"),
    "env":           ("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                      "HOME=/root\nUSER=root\nLOGNAME=root\nSHELL=/bin/bash\nTERM=xterm\nPWD=/root"),
    "crontab -l":    "# m h dom mon dow   command\n*/5 * * * * /usr/local/bin/backup.sh",
    "find / -perm -4000 2>/dev/null": "/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/pkexec\n/usr/bin/chsh\n/bin/mount",
    "uptime":        " %t up 14 days,  3:42,  1 user,  load average: 0.08, 0.03, 0.01",
    "free -m":       ("              total        used        free      shared  buff/cache   available\n"
                      "Mem:           1987         412         901          12         673        1402\n"
                      "Swap:           976           0         976"),
    "df -h":         ("Filesystem      Size  Used Avail Use% Mounted on\n"
                      "/dev/vda1        40G   12G   26G  32% /\n"
                      "tmpfs           995M     0  995M   0% /dev/shm"),
    "lscpu":         ("Architecture:        x86_64\nCPU(s):              2\n"
                      "Model name:          Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz"),
    "w":             (" %t up 14 days,  3:42,  1 user,  load average: 0.08, 0.03, 0.01\n"
                      "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                      "root     pts/0    10.0.0.5         10:21    0.00s  0.04s  0.00s -bash"),
    "sudo -l":       "User root may run the following commands on " + HOSTNAME + ":\n    (ALL : ALL) ALL",
}


class FakeShell:
    """A small stateful shell emulator: tracks cwd, supports cd/ls/cat/echo/…

    Static "always the same" outputs would let an attacker fingerprint the
    honeypot instantly; this resolves real-ish paths against VFS_DIRS so that
    `cd /var/www && ls` behaves the way a real box would.
    """

    def __init__(self, ip: str):
        self.ip      = ip
        self.cwd     = "/root"
        self.user    = "root"
        self.history = []

    # ── path helpers ──────────────────────────────────────────────────────────
    def _resolve(self, path: str) -> str:
        if not path or path == "~":
            return "/root"
        if path.startswith("~"):
            path = "/root" + path[1:]
        if not path.startswith("/"):
            path = (self.cwd.rstrip("/") + "/" + path) if self.cwd != "/" else "/" + path
        parts = []
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(part)
        return "/" + "/".join(parts)

    def _is_dir(self, path):  return path in VFS_DIRS
    def _is_file(self, path): return path in VFS_FILES

    def _exists(self, path):
        if self._is_dir(path) or self._is_file(path):
            return True
        parent = path.rsplit("/", 1)[0] or "/"
        name   = path.rsplit("/", 1)[1]
        return parent in VFS_DIRS and name in VFS_DIRS[parent]

    # ── command dispatch ──────────────────────────────────────────────────────
    def run(self, line: str) -> str:
        """Return the shell output (no trailing prompt) for one command line."""
        line = line.strip()
        if not line:
            return ""
        self.history.append(line)

        # Handle simple `cmd1 ; cmd2` / `cmd1 && cmd2` chains.
        if any(sep in line for sep in (";", "&&", "|")) and not line.startswith("echo"):
            for sep in (" && ", ";", " | "):
                if sep in line:
                    outs = [self.run(p) for p in line.split(sep) if p.strip()]
                    return "".join(outs)

        parts = line.split()
        cmd   = parts[0]
        args  = parts[1:]

        handler = getattr(self, f"_cmd_{cmd}", None)
        if handler:
            return handler(args, line)

        # cwd-independent static commands (try longest match first)
        if line in STATIC_CMDS:
            return self._expand(STATIC_CMDS[line]) + "\r\n"
        if cmd in STATIC_CMDS:
            return self._expand(STATIC_CMDS[cmd]) + "\r\n"

        # Known binaries that just produce no output / a benign line
        if cmd in ("export", "unset", "set", "alias", "umask", "clear", ":", "true"):
            return ""
        if cmd in ("sudo",):
            return self.run(" ".join(args)) if args else "usage: sudo command\r\n"

        return f"{cmd}: command not found\r\n"

    def _expand(self, s: str) -> str:
        return (s.replace("%h", HOSTNAME)
                 .replace("%t", datetime.now().strftime("%H:%M:%S")))

    # ── individual commands ───────────────────────────────────────────────────
    def _cmd_pwd(self, args, line):  return self.cwd + "\r\n"
    def _cmd_whoami(self, args, line): return self.user + "\r\n"
    def _cmd_hostname(self, args, line): return HOSTNAME + "\r\n"
    def _cmd_date(self, args, line):
        return datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y") + "\r\n"

    def _cmd_echo(self, args, line):
        body = line[len("echo"):].strip()
        body = body.replace("$USER", self.user).replace("$HOSTNAME", HOSTNAME)
        body = body.replace("$HOME", "/root").replace("$PWD", self.cwd).replace("$?", "0")
        if (body.startswith('"') and body.endswith('"')) or \
           (body.startswith("'") and body.endswith("'")):
            body = body[1:-1]
        return body + "\r\n"

    def _cmd_cd(self, args, line):
        target = self._resolve(args[0] if args else "~")
        if self._is_dir(target):
            self.cwd = target
            return ""
        if self._is_file(target):
            return f"-bash: cd: {args[0]}: Not a directory\r\n"
        return f"-bash: cd: {args[0] if args else ''}: No such file or directory\r\n"

    def _cmd_ls(self, args, line):
        flags  = [a for a in args if a.startswith("-")]
        paths  = [a for a in args if not a.startswith("-")]
        target = self._resolve(paths[0]) if paths else self.cwd
        long_  = any("l" in f for f in flags)
        all_   = any("a" in f for f in flags)

        if self._is_file(target):
            return (paths[0] if paths else target) + "\r\n"
        if not self._is_dir(target):
            tgt = paths[0] if paths else target
            return f"ls: cannot access '{tgt}': No such file or directory\r\n"

        entries = list(VFS_DIRS[target])
        if all_:
            entries = [".", ".."] + entries
        else:
            entries = [e for e in entries if not e.startswith(".")]
        if not entries:
            return ""
        if long_:
            lines = ["total %d" % (len(entries) * 4)]
            for e in sorted(entries):
                full = self._resolve(target + "/" + e) if e not in (".", "..") else target
                if e == "." or self._is_dir(full):
                    perm, size = "drwxr-xr-x", 4096
                elif e == "..":
                    perm, size = "drwxr-xr-x", 4096
                else:
                    perm = "-rw-r--r--"
                    size = len(VFS_FILES.get(full, "x" * 220))
                owner = "root root"
                lines.append(f"{perm} 1 {owner} {size:>6} Jan 12 10:30 {e}")
            return "\r\n".join(lines) + "\r\n"
        return "  ".join(sorted(entries)) + "\r\n"

    def _cmd_cat(self, args, line):
        if not args:
            return ""
        out = []
        for a in args:
            if a.startswith("-"):
                continue
            p = self._resolve(a)
            if self._is_file(p):
                out.append(VFS_FILES[p])
            elif self._is_dir(p):
                out.append(f"cat: {a}: Is a directory\r\n")
            else:
                out.append(f"cat: {a}: No such file or directory\r\n")
        return "".join(o if o.endswith("\n") else o + "\n" for o in out).replace("\n", "\r\n")

    def _cmd_head(self, args, line): return self._cmd_cat([a for a in args if not a.startswith("-")], line)
    def _cmd_tail(self, args, line): return self._cmd_cat([a for a in args if not a.startswith("-")], line)
    def _cmd_less(self, args, line): return self._cmd_cat(args, line)
    def _cmd_more(self, args, line): return self._cmd_cat(args, line)

    def _cmd_history(self, args, line):
        seed = ["ls -la", "cd /var/www/html", "cat .env", "mysql -u root -p", "crontab -l"]
        full = seed + self.history
        return "".join(f"{i:>5}  {c}\r\n" for i, c in enumerate(full, 1))

    def _cmd_wget(self, args, line):
        url = next((a for a in args if a.startswith("http")), args[-1] if args else "")
        log_event("MALWARE_DOWNLOAD_ATTEMPT", self.ip, port=22,
                  extra={"tool": "wget", "url": url})
        maybe_fetch_payload(url, self.ip)   # captures into quarantine if enabled
        host = re.sub(r"^https?://", "", url).split("/")[0]
        return (f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\r\n"
                f"Resolving {host}... failed: Name or service not known.\r\n"
                f"wget: unable to resolve host address '{host}'\r\n")

    def _cmd_curl(self, args, line):
        url = next((a for a in args if a.startswith("http")), args[-1] if args else "")
        log_event("MALWARE_DOWNLOAD_ATTEMPT", self.ip, port=22,
                  extra={"tool": "curl", "url": url})
        maybe_fetch_payload(url, self.ip)   # captures into quarantine if enabled
        host = re.sub(r"^https?://", "", url).split("/")[0]
        return f"curl: (6) Could not resolve host: {host}\r\n"

    def _cmd_mkdir(self, args, line):
        for a in args:
            if a.startswith("-"):
                continue
            p = self._resolve(a)
            parent = p.rsplit("/", 1)[0] or "/"
            name   = p.rsplit("/", 1)[1]
            if parent in VFS_DIRS:
                VFS_DIRS.setdefault(p, [])
                if name not in VFS_DIRS[parent]:
                    VFS_DIRS[parent].append(name)
        return ""

    def _cmd_touch(self, args, line):
        for a in args:
            if a.startswith("-"):
                continue
            p = self._resolve(a)
            parent = p.rsplit("/", 1)[0] or "/"
            name   = p.rsplit("/", 1)[1]
            if parent in VFS_DIRS and name not in VFS_DIRS[parent]:
                VFS_DIRS[parent].append(name)
                VFS_FILES[p] = ""
        return ""

# ══════════════════════════════════════════════════════════════════════════════
# SHARED STATE
# ══════════════════════════════════════════════════════════════════════════════
console_lock   = threading.Lock()
file_lock      = threading.Lock()
session_lock   = threading.RLock()          # guards all access to `sessions`
sessions: dict = {}
syn_lock       = threading.Lock()           # guards syn_tracker
syn_tracker    = defaultdict(lambda: {'ts': time.time(), 'ports': set(), 'fp': {}})
alert_cooldown: dict = {}

# ── GeoIP: cache + background worker so lookups never block a session thread ──
geo_cache: dict       = {}
geo_lock              = threading.Lock()
geo_pending: set      = set()
geo_queue: queue.Queue = queue.Queue()
_geo_last_call        = [0.0]                # last external-call timestamp (rate limit)

# ══════════════════════════════════════════════════════════════════════════════
# SESSION MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
def get_session(ip: str) -> dict:
    now = time.time()
    with session_lock:
        if ip not in sessions:
            # Evict oldest sessions if we are at the hard cap (bounded memory).
            if len(sessions) >= CONFIG['max_sessions']:
                oldest = sorted(sessions.items(), key=lambda kv: kv[1]['last_seen'])
                for old_ip, _ in oldest[:max(1, len(sessions) // 10)]:
                    sessions.pop(old_ip, None)
            sessions[ip] = {
                'ip':               ip,
                'first_seen':       now,
                'last_seen':        now,
                'ports_touched':    set(),
                'credentials_tried':[],
                'commands_run':     [],
                'http_requests':    [],
                'identified_tools': set(),
                'connection_count': 0,
                'alert_level':      'LOW',
                'geo':              None,
                # Grant a fake shell after a *randomised* number of attempts so the
                # "always in after N tries" pattern isn't a fingerprint of its own.
                'auth_grant_at':    random.randint(1, 3),
                'shell':            None,
            }
        else:
            sessions[ip]['last_seen'] = now
            sessions[ip]['connection_count'] += 1
        return sessions[ip]

def session_append(ip: str, key: str, item) -> None:
    """Thread-safe, bounded append to a per-session list."""
    cap = CONFIG['max_list_per_session']
    with session_lock:
        s = sessions.get(ip)
        if s is None:
            return
        lst = s[key]
        lst.append(item)
        if len(lst) > cap:
            del lst[:len(lst) - cap]

def session_add_tools(ip: str, tools) -> None:
    with session_lock:
        s = sessions.get(ip)
        if s is not None:
            s['identified_tools'].update(tools)

def get_shell(ip: str):
    """Return the per-session stateful fake shell, creating it on first use."""
    with session_lock:
        s = sessions.get(ip)
        if s is None:
            return FakeShell(ip)
        if s.get('shell') is None:
            s['shell'] = FakeShell(ip)
        return s['shell']

def prune_sessions() -> None:
    """Drop sessions we haven't seen in a long time so memory stays bounded."""
    cutoff = time.time() - CONFIG['session_retention']
    with session_lock:
        for ip in [ip for ip, s in sessions.items() if s['last_seen'] < cutoff]:
            sessions.pop(ip, None)
        alert_cooldown_purge = [ip for ip in alert_cooldown if ip not in sessions]
    for ip in alert_cooldown_purge:
        alert_cooldown.pop(ip, None)

def _recalc_alert(ip: str):
    """Recalculate the alert level for a session."""
    with session_lock:
        s = sessions.get(ip)
        if s is None:
            return
        pts   = len(s['ports_touched'])
        creds = len(s['credentials_tried'])
        tools = len(s['identified_tools'])
        cmds  = len(s['commands_run'])
        reqs  = len(s['http_requests'])

        if pts > 100 or creds > 50 or cmds > 5 or reqs > 20:
            s['alert_level'] = 'CRITICAL'
        elif pts > 50 or creds > 30 or cmds > 0:
            s['alert_level'] = 'HIGH'
        elif pts > 20 or creds > 10 or tools > 0:
            s['alert_level'] = 'MEDIUM'
        else:
            s['alert_level'] = 'LOW'

# ══════════════════════════════════════════════════════════════════════════════
# GEOLOCATION
# ══════════════════════════════════════════════════════════════════════════════
def _geo_fetch(ip: str) -> dict:
    """Blocking GeoIP lookup — only ever called from the background worker."""
    try:
        if ipaddress.ip_address(ip).is_private:
            return {"country": "Local Network", "city": "-", "org": "-"}
        # Rate limit external calls (ip-api free tier ≈ 45/min).
        with geo_lock:
            wait = CONFIG['geoip_min_interval'] - (time.time() - _geo_last_call[0])
            if wait > 0:
                time.sleep(wait)
            _geo_last_call[0] = time.time()
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,org,isp,as"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as r:
            d = json.loads(r.read().decode())
        if d.get('status') == 'success':
            return {k: d.get(k, '?') for k in ('country','city','regionName','org','isp','as')}
    except Exception:
        pass
    return {"country": "?", "city": "?", "org": "?"}

def request_geo(ip: str) -> dict:
    """
    Non-blocking GeoIP. Returns a cached result immediately if we have one,
    otherwise enqueues a background lookup and returns None (the session gets
    enriched on a later event). Never blocks the calling session thread.
    """
    with geo_lock:
        if ip in geo_cache:
            return geo_cache[ip]
        if ip not in geo_pending:
            geo_pending.add(ip)
            geo_queue.put(ip)
    return None

def _geo_worker():
    while True:
        ip = geo_queue.get()
        try:
            result = _geo_fetch(ip)
            with geo_lock:
                geo_cache[ip] = result
                geo_pending.discard(ip)
            # Back-fill the session so future reports/alerts show the location.
            with session_lock:
                s = sessions.get(ip)
                if s is not None:
                    s['geo'] = result
        except Exception:
            with geo_lock:
                geo_pending.discard(ip)
        finally:
            geo_queue.task_done()

# ══════════════════════════════════════════════════════════════════════════════
# TELEGRAM
# ══════════════════════════════════════════════════════════════════════════════
def _telegram(msg: str):
    if not CONFIG['telegram_enabled']:
        return
    try:
        token   = CONFIG['telegram_bot_token']
        chat_id = CONFIG['telegram_chat_id']
        url  = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({'chat_id': chat_id, 'text': msg, 'parse_mode': 'HTML'}).encode()
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=5)
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
# SYSLOG → BLUE TEAM SIEM  (CEF or plain RFC-3164 format, UDP or TCP)
# ══════════════════════════════════════════════════════════════════════════════
_LEVEL_RANK     = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SYSLOG_SEVERITY = {"LOW": 6, "MEDIUM": 5, "HIGH": 4, "CRITICAL": 3}   # RFC-5424 severity
CEF_SEVERITY    = {"LOW": 2, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}  # CEF 0-10 scale

def _cef_sanitize(value) -> str:
    """CEF extension values must not contain pipe/newline; keep them on one line."""
    s = str(value)
    return s.replace('\n', ' ').replace('\r', ' ').replace('|', '_').replace('=', '\\=')[:400]

def send_syslog(event_type: str, ip: str, port, lvl: str,
                extra: dict = None, geo: dict = None):
    """Forward the event to the Blue Team's syslog/SIEM collector."""
    if not CONFIG['syslog_enabled']:
        return
    if _LEVEL_RANK.get(lvl, 0) < _LEVEL_RANK.get(CONFIG['syslog_min_level'], 0):
        return
    try:
        facility = 4  # security/authorization messages
        severity = SYSLOG_SEVERITY.get(lvl, 6)
        pri      = facility * 8 + severity
        hostname = socket.gethostname()
        ts       = datetime.now().strftime('%b %d %H:%M:%S')
        geo      = geo or {}

        if CONFIG['syslog_format'] == 'cef':
            ext = (
                f"src={ip} dpt={port or 0} "
                f"cs1Label=AlertLevel cs1={lvl} "
                f"cs2Label=Country cs2={_cef_sanitize(geo.get('country','?'))} "
                f"cs3Label=ISP cs3={_cef_sanitize(geo.get('org','?'))} "
            )
            if extra:
                for k, v in extra.items():
                    if v is not None:
                        ext += f"cs4Label={k} cs4={_cef_sanitize(v)} "
            payload = (
                f"CEF:0|AM1RX|AdvancedHoneypot|2.0|{event_type}|{event_type}|"
                f"{CEF_SEVERITY.get(lvl,2)}|{ext.strip()}"
            )
        else:
            details = " ".join(f"{k}={_cef_sanitize(v)}" for k, v in (extra or {}).items() if v is not None)
            payload = f"event={event_type} src={ip} dpt={port or 0} level={lvl} {details}"

        line = f"<{pri}>{ts} {hostname} honeypot: {payload}"

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM if CONFIG['syslog_protocol'] == 'udp' else socket.SOCK_STREAM
        )
        sock.settimeout(3)
        if CONFIG['syslog_protocol'] == 'udp':
            sock.sendto(line.encode('utf-8', errors='replace'),
                        (CONFIG['syslog_host'], CONFIG['syslog_port']))
        else:
            sock.connect((CONFIG['syslog_host'], CONFIG['syslog_port']))
            sock.sendall((line + "\n").encode('utf-8', errors='replace'))
            sock.close()
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
# PERSISTENCE  (SQLite — long-term, queryable storage of every event)
# ══════════════════════════════════════════════════════════════════════════════
_db_conn          = None
_db_lock          = threading.Lock()
persist_queue: "queue.Queue" = queue.Queue(maxsize=10000)

def init_db():
    """Open the SQLite DB and create tables. Returns the connection or None."""
    global _db_conn
    if not CONFIG['persist_enabled']:
        return None
    try:
        _db_conn = sqlite3.connect(CONFIG['db_file'], check_same_thread=False)
        _db_conn.execute("PRAGMA journal_mode=WAL")
        _db_conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT,
                event       TEXT,
                ip          TEXT,
                port        INTEGER,
                alert_level TEXT,
                mitre       TEXT,
                country     TEXT,
                extra       TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_ip    ON events(ip);
            CREATE INDEX IF NOT EXISTS idx_events_event ON events(event);
            CREATE INDEX IF NOT EXISTS idx_events_level ON events(alert_level);

            CREATE TABLE IF NOT EXISTS sessions (
                ip           TEXT PRIMARY KEY,
                first_seen   TEXT,
                last_seen    TEXT,
                alert_level  TEXT,
                country      TEXT,
                org          TEXT,
                ports        INTEGER,
                creds        INTEGER,
                commands     INTEGER,
                tools        TEXT
            );
        """)
        _db_conn.commit()
        return _db_conn
    except Exception as e:
        with console_lock:
            print(f"{C.RED}[!] SQLite disabled: {e}{C.RESET}")
        _db_conn = None
        return None

def persist_event(entry: dict):
    """Queue an event for the DB writer (non-blocking; drops on overflow)."""
    if not CONFIG['persist_enabled'] or _db_conn is None:
        return
    try:
        persist_queue.put_nowait(entry)
    except queue.Full:
        pass

def _persist_worker():
    """Single writer thread — SQLite likes one writer; batches commits."""
    while True:
        entry = persist_queue.get()
        try:
            geo = entry.get('geo') or {}
            extra = {k: v for k, v in entry.items()
                     if k not in ('ts', 'event', 'ip', 'port', 'alert_level',
                                  'mitre_attack', 'geo', 'session')}
            with _db_lock:
                if _db_conn is None:
                    continue
                _db_conn.execute(
                    "INSERT INTO events (ts,event,ip,port,alert_level,mitre,country,extra) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (entry.get('ts'), entry.get('event'), entry.get('ip'),
                     entry.get('port'), entry.get('alert_level'),
                     entry.get('mitre_attack'), geo.get('country'),
                     json.dumps(extra, default=str)),
                )
                _db_conn.commit()
        except Exception:
            pass
        finally:
            persist_queue.task_done()

def persist_sessions_snapshot():
    """Upsert the current session table (called periodically by the reporter)."""
    if not CONFIG['persist_enabled'] or _db_conn is None:
        return
    with session_lock:
        rows = [(
            ip,
            datetime.fromtimestamp(s['first_seen']).isoformat(),
            datetime.fromtimestamp(s['last_seen']).isoformat(),
            s['alert_level'], (s.get('geo') or {}).get('country'),
            (s.get('geo') or {}).get('org'),
            len(s['ports_touched']), len(s['credentials_tried']),
            len(s['commands_run']), ",".join(sorted(s['identified_tools'])),
        ) for ip, s in sessions.items()]
    try:
        with _db_lock:
            if _db_conn is None:
                return
            _db_conn.executemany(
                "INSERT INTO sessions (ip,first_seen,last_seen,alert_level,country,org,"
                "ports,creds,commands,tools) VALUES (?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, "
                "alert_level=excluded.alert_level, country=excluded.country, "
                "org=excluded.org, ports=excluded.ports, creds=excluded.creds, "
                "commands=excluded.commands, tools=excluded.tools",
                rows,
            )
            _db_conn.commit()
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
# QUARANTINE  (store captured uploads / fetched payloads with a SHA-256 name)
# ══════════════════════════════════════════════════════════════════════════════
def quarantine_store(data: bytes, ip: str, source: str, original: str = "") -> dict:
    """Save captured bytes to the quarantine dir under their SHA-256 and log it."""
    info = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
            "source": source, "original_name": original}
    try:
        qdir = CONFIG['quarantine_dir']
        os.makedirs(qdir, exist_ok=True)
        path = os.path.join(qdir, info['sha256'])
        if not os.path.exists(path):
            with open(path, 'wb') as f:
                f.write(data)
        info['path'] = path
    except Exception:
        pass
    log_event("MALWARE_CAPTURED", ip, port=None, extra=info)
    return info

def maybe_fetch_payload(url: str, ip: str):
    """If fetch_downloads is enabled, download the URL into quarantine (capped).
    DANGEROUS on a networked host — disabled by default. Runs in a daemon thread
    so the fake shell never blocks on it."""
    if not CONFIG['fetch_downloads'] or not url.lower().startswith(("http://", "https://")):
        return

    def _do():
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Wget/1.20.3 (linux-gnu)'})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = r.read(CONFIG['max_download_bytes'] + 1)
            if len(data) > CONFIG['max_download_bytes']:
                data = data[:CONFIG['max_download_bytes']]
            quarantine_store(data, ip, source=f"fetch:{url}",
                             original=url.rsplit('/', 1)[-1])
        except Exception:
            pass
    threading.Thread(target=_do, daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
# LOG ROTATION  (keep honeypot.log / .jsonl from growing forever)
# ══════════════════════════════════════════════════════════════════════════════
def _rotate_if_needed(path: str):
    try:
        max_bytes = CONFIG['log_max_mb'] * 1024 * 1024
        if os.path.exists(path) and os.path.getsize(path) > max_bytes:
            stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            os.rename(path, f"{path}.{stamp}.bak")
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
# CENTRAL LOGGING
# ══════════════════════════════════════════════════════════════════════════════
LEVEL_COLORS = {
    'LOW':      C.CYAN,
    'MEDIUM':   C.YELLOW,
    'HIGH':     C.RED,
    'CRITICAL': C.RED_BG + C.BOLD,
}

def log_event(event_type: str, ip: str, port: int = None,
              data: bytes = None, extra: dict = None):
    """
    Central event logger.
    Updates the attacker session, prints to console, writes to files,
    and triggers Telegram/Syslog alerts when warranted.
    """
    # ── Whitelisted (trusted) IPs: log quietly, skip alerting entirely ──
    if ip in CONFIG['whitelisted_ips']:
        with console_lock:
            print(f"{C.GREEN}[whitelisted]{C.RESET} {ip} → {event_type} (no alert){C.RESET}")
        return

    ts  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    iso = datetime.now().isoformat()

    sess = get_session(ip)
    with session_lock:
        if port:
            sess['ports_touched'].add(port)
    _recalc_alert(ip)

    # GeoIP — non-blocking; cached/back-filled by the worker, never stalls us here
    if CONFIG['geoip_enabled'] and not sess['geo']:
        geo_now = request_geo(ip)
        if geo_now:
            with session_lock:
                sess['geo'] = geo_now

    lvl   = sess['alert_level']
    color = LEVEL_COLORS.get(lvl, C.CYAN)
    geo   = sess.get('geo') or {}
    mitre = MITRE_MAP.get(event_type, '-')

    # ── Console ──
    with console_lock:
        geo_str = (f" | {C.BLUE}{geo.get('country','?')}/{geo.get('city','?')}{C.RESET}"
                   if geo else "")
        print(
            f"[{C.GREEN}{ts}{C.RESET}] {color}[{lvl}]{C.RESET} "
            f"{C.BOLD}{event_type}{C.RESET} | "
            f"IP: {C.YELLOW}{ip}{C.RESET}"
            f"{f'  Port:{C.RED}{port}{C.RESET}' if port else ''}"
            f"{geo_str}"
        )
        if data:
            print(f"    {C.MAGENTA}Data:{C.RESET} {repr(data[:200])}")
        if extra:
            for k, v in extra.items():
                if v is not None and k != 'geo':
                    print(f"    {C.CYAN}{k}:{C.RESET} {v}")
        if lvl in ('HIGH', 'CRITICAL'):
            print(f"    {C.WHITE}MITRE ATT&CK:{C.RESET} {mitre}")

    # ── JSON log ──  (take a consistent snapshot under the lock)
    with session_lock:
        sess_snapshot = {
            "connection_count":  sess['connection_count'],
            "ports_touched":     len(sess['ports_touched']),
            "creds_tried":       len(sess['credentials_tried']),
            "commands_run":      len(sess['commands_run']),
            "tools_identified":  list(sess['identified_tools']),
        }
    entry = {
        "ts": iso, "event": event_type, "ip": ip,
        "port": port, "alert_level": lvl, "mitre_attack": mitre,
        "session": sess_snapshot,
        "geo": geo,
    }
    if data:
        entry["data_repr"] = repr(data[:512])
    if extra:
        entry.update(extra)

    with file_lock:
        _rotate_if_needed(CONFIG['json_log_file'])
        _rotate_if_needed(CONFIG['log_file'])
        with open(CONFIG['json_log_file'], 'a') as f:
            f.write(json.dumps(entry, default=str) + '\n')
        with open(CONFIG['log_file'], 'a') as f:
            f.write(f"[{ts}] [{lvl}] {event_type} | {ip}"
                    f"{f' | port={port}' if port else ''}"
                    f"{f' | {json.dumps(extra, default=str)}' if extra else ''}\n")

    # ── Persistence (SQLite, async) ──
    persist_event(entry)

    # ── Syslog → Blue Team SIEM ──
    send_syslog(event_type, ip, port, lvl, extra=extra, geo=geo)

    # ── Telegram (HIGH / CRITICAL, max 1/min/IP) ──
    if lvl in ('HIGH', 'CRITICAL'):
        now = time.time()
        if now - alert_cooldown.get(ip, 0) > 60:
            alert_cooldown[ip] = now
            with session_lock:
                tools_str = ', '.join(sorted(sess['identified_tools'])) or '-'
                n_ports   = len(sess['ports_touched'])
                n_creds   = len(sess['credentials_tried'])
                n_cmds    = len(sess['commands_run'])
            msg = (
                f"🚨 <b>Honeypot [{lvl}]</b>\n"
                f"Event: {event_type}\n"
                f"IP: <code>{ip}</code>\n"
                f"Port: {port}\n"
                f"Location: {geo.get('country','?')}, {geo.get('city','?')}\n"
                f"ISP: {geo.get('org','?')}\n"
                f"MITRE: {mitre}\n"
                f"Tools detected: {tools_str}\n"
                f"Ports probed: {n_ports}\n"
                f"Creds tried: {n_creds}\n"
                f"Commands run: {n_cmds}\n"
            )
            threading.Thread(target=_telegram, args=(msg,), daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
# FINGERPRINTING ENGINE
# ══════════════════════════════════════════════════════════════════════════════
def fingerprint_data(data: bytes, ip: str, port: int) -> list:
    """Identify Red Team tools from raw bytes."""
    if not data:
        return []
    found = []
    dl = data.lower()
    for tool, sigs in BINARY_SIGNATURES.items():
        if any(s.lower() in dl for s in sigs):
            found.append(tool)
    # HTTP UA check
    if port in (80, 8080, 443, 8443):
        m = re.search(rb'user-agent:\s*(.+?)\r\n', data, re.IGNORECASE)
        if m:
            ua = m.group(1).decode('utf-8', errors='replace').lower()
            for s in HTTP_SCANNER_UAS:
                if s.lower() in ua:
                    found.append(f"scanner:{s}")
    return list(set(found))

def tcp_os_fingerprint(pkt) -> dict:
    """Passive OS / tool guess from TTL + window size."""
    if not SCAPY_AVAILABLE:
        return {}
    try:
        ttl    = pkt[scapy.IP].ttl
        window = pkt[scapy.TCP].window
        os_g   = "Linux/Unix" if ttl <= 64 else "Windows" if ttl <= 128 else "Network Device"
        tool_g = None
        if window == 1024:  tool_g = "nmap (likely)"
        if window == 2048:  tool_g = "masscan (likely)"
        if window == 65535: os_g   = "macOS/BSD"
        return {"ttl": ttl, "window": window, "os_guess": os_g, "tool_guess": tool_g,
                "tcp_opts": str(pkt[scapy.TCP].options)}
    except Exception:
        return {}

# ══════════════════════════════════════════════════════════════════════════════
# SECTION A: SSH HONEYPOT
# ══════════════════════════════════════════════════════════════════════════════
_SSH_HOST_KEY = None
def _load_or_create_host_key():
    """Load a persistent RSA host key, generating + saving one on first run.
    A host key that changes on every restart is itself a honeypot fingerprint."""
    if not PARAMIKO_AVAILABLE:
        return None
    path = CONFIG['ssh_host_key_file']
    try:
        if os.path.exists(path):
            return paramiko.RSAKey(filename=path)
    except Exception:
        pass
    try:
        key = paramiko.RSAKey.generate(2048)
        try:
            key.write_private_key_file(path)
        except Exception:
            pass
        return key
    except Exception:
        return None

if PARAMIKO_AVAILABLE:
    _SSH_HOST_KEY = _load_or_create_host_key()

# ── SFTP capture: attackers often SFTP-upload their toolkit; grab it. ──────────
if PARAMIKO_AVAILABLE:
    class _HoneySFTPHandle(paramiko.SFTPHandle):
        """A write handle that buffers everything an attacker uploads, then
        stores it to quarantine on close."""
        def __init__(self, ip, filename, flags=0):
            super().__init__(flags)
            self.ip       = ip
            self.filename = filename
            self.buffer   = bytearray()

        def write(self, offset, data):
            try:
                self.buffer.extend(data)
                if len(self.buffer) > CONFIG['max_download_bytes']:
                    del self.buffer[CONFIG['max_download_bytes']:]
            except Exception:
                pass
            return paramiko.SFTP_OK

        def read(self, offset, length):
            return b""   # downloads of our decoy files just return nothing useful

        def close(self):
            try:
                if self.buffer:
                    quarantine_store(bytes(self.buffer), self.ip,
                                     source="sftp", original=self.filename)
                    log_event("SFTP_UPLOAD", self.ip, port=22,
                              extra={"filename": self.filename, "bytes": len(self.buffer)})
            except Exception:
                pass
            return paramiko.SFTP_OK

    class _HoneySFTP(paramiko.SFTPServerInterface):
        def __init__(self, server, *args, **kwargs):
            super().__init__(server, *args, **kwargs)
            self.ip = getattr(server, 'ip', '?')

        def open(self, path, flags, attr):
            log_event("SFTP_SESSION", self.ip, port=22,
                      extra={"action": "open", "path": path})
            # Writing (upload) → capture; reading → benign empty handle.
            return _HoneySFTPHandle(self.ip, path, flags)

        def list_folder(self, path):
            out = []
            for name in ("backup.sh", "notes.txt", ".bash_history"):
                a = paramiko.SFTPAttributes()
                a.filename = name
                a.st_mode  = 0o100644
                a.st_size  = 220
                out.append(a)
            return out

        def stat(self, path):
            a = paramiko.SFTPAttributes()
            a.st_mode = 0o040755 if path.endswith("/") else 0o100644
            a.st_size = 4096
            return a

        lstat = stat

        def remove(self, path):
            log_event("SFTP_SESSION", self.ip, port=22,
                      extra={"action": "remove", "path": path})
            return paramiko.SFTP_OK

        def rename(self, oldpath, newpath):
            return paramiko.SFTP_OK

        def mkdir(self, path, attr):
            return paramiko.SFTP_OK

class _FakeSSHServer(paramiko.ServerInterface if PARAMIKO_AVAILABLE else object):
    def __init__(self, ip):
        self.ip       = ip
        self.username = None
        self._ready   = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        sess = get_session(self.ip)
        cred = {'username': username, 'password': password, 'ts': datetime.now().isoformat()}
        session_append(self.ip, 'credentials_tried', cred)

        is_rt = username in REDTEAM_USERNAMES or password in REDTEAM_PASSWORDS
        log_event("SSH_CRED_ATTEMPT", self.ip, port=22,
                  extra={"username": username, "password": password,
                         "is_common_redteam_cred": is_rt})

        # Grant a fake shell after a *randomised* threshold (set per session) so
        # the "always in after exactly N tries" pattern isn't itself a tell.
        with session_lock:
            attempts  = len(sess['credentials_tried'])
            threshold = sess.get('auth_grant_at', 2)
        if attempts >= threshold:
            log_event("SSH_LOGIN_GRANTED", self.ip, port=22,
                      extra={"username": username, "password": password})
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        log_event("SSH_PUBKEY_ATTEMPT", self.ip, port=22,
                  extra={"username": username, "key_type": key.get_name()})
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'

    def check_channel_shell_request(self, channel):
        self._ready.set()
        return True

    def check_channel_pty_request(self, channel, term, w, h, pw, ph, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode('utf-8', errors='replace').strip()
        get_session(self.ip)
        session_append(self.ip, 'commands_run', {'cmd': cmd, 'ts': datetime.now().isoformat()})
        log_event("SSH_EXEC_CMD", self.ip, port=22, extra={"command": cmd})
        resp = get_shell(self.ip).run(cmd)
        channel.send(resp.encode())
        channel.send_exit_status(0)
        return True

def _shell_prompt_path(shell) -> str:
    """Display form of the cwd in a bash prompt (~ for the home dir)."""
    if shell.cwd == "/root":
        return "~"
    if shell.cwd.startswith("/root/"):
        return "~" + shell.cwd[len("/root"):]
    return shell.cwd

def _ssh_prompt(shell) -> str:
    return f"{shell.user}@{HOSTNAME}:{_shell_prompt_path(shell)}# "

def _interactive_shell(ip, shell, port, event_name, send, recv, clean=None):
    """Drive a fake interactive shell with proper terminal echo + line editing.

    In a PTY session the server is responsible for echoing keystrokes; without
    this the attacker sees nothing as they type (chars only appeared after Enter).
    Echoes printable chars, handles Backspace, Ctrl-C, Ctrl-D, and swallows
    arrow-key / escape sequences so they don't corrupt the captured command.
    """
    try:
        send(_ssh_prompt(shell).encode())
    except Exception:
        return
    buf = bytearray()
    last_cr = False
    while True:
        try:
            chunk = recv()
        except Exception:
            break
        if not chunk:
            break
        if clean:
            chunk = clean(chunk)
        i, n = 0, len(chunk)
        while i < n:
            byte = chunk[i]
            i += 1
            # Treat CR, LF, or CRLF as a single line terminator.
            if byte == 0x0a and last_cr:
                last_cr = False
                continue
            last_cr = (byte == 0x0d)
            if byte in (0x0d, 0x0a):
                try:
                    send(b"\r\n")
                except Exception:
                    return
                cmd = buf.decode('utf-8', errors='replace').strip()
                buf.clear()
                if cmd.lower() in ('exit', 'quit', 'logout'):
                    try:
                        send(b"logout\r\n")
                    except Exception:
                        pass
                    return
                if cmd:
                    session_append(ip, 'commands_run',
                                   {'cmd': cmd, 'ts': datetime.now().isoformat()})
                    log_event(event_name, ip, port=port, extra={"command": cmd})
                    out = shell.run(cmd) + _ssh_prompt(shell)
                else:
                    out = _ssh_prompt(shell)
                try:
                    send(out.encode())
                except Exception:
                    return
            elif byte in (0x7f, 0x08):              # Backspace / Delete
                if buf:
                    buf.pop()
                    try:
                        send(b"\b \b")
                    except Exception:
                        return
            elif byte == 0x03:                      # Ctrl-C
                buf.clear()
                try:
                    send(("^C\r\n" + _ssh_prompt(shell)).encode())
                except Exception:
                    return
            elif byte == 0x04:                      # Ctrl-D (EOF)
                if not buf:
                    try:
                        send(b"logout\r\n")
                    except Exception:
                        pass
                    return
            elif byte == 0x1b:                      # ESC — swallow CSI/escape seq
                if i < n and chunk[i] == 0x5b:      # '['
                    i += 1
                    while i < n and not (0x40 <= chunk[i] <= 0x7e):
                        i += 1
                    if i < n:
                        i += 1
            elif 0x20 <= byte < 0x7f:               # printable → buffer + echo
                buf.append(byte)
                try:
                    send(bytes([byte]))
                except Exception:
                    return
            # any other control byte is ignored

def _ssh_session(sock, ip):
    if not PARAMIKO_AVAILABLE or not _SSH_HOST_KEY:
        return
    try:
        transport = paramiko.Transport(sock)
        transport.local_version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
        # Advertise a modern, OpenSSH-like algorithm set (reduces paramiko-default
        # fingerprinting). Best-effort: older paramiko may not expose all of these.
        try:
            opts = transport.get_security_options()
            opts.ciphers = ('aes128-ctr', 'aes192-ctr', 'aes256-ctr',
                            'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com')
            opts.macs    = ('hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1')
        except Exception:
            pass
        transport.add_server_key(_SSH_HOST_KEY)
        # Register SFTP so we can capture toolkits attackers upload.
        if CONFIG['capture_uploads']:
            try:
                transport.set_subsystem_handler('sftp', paramiko.SFTPServer, _HoneySFTP)
            except Exception:
                pass
        srv = _FakeSSHServer(ip)
        transport.start_server(server=srv)

        chan = transport.accept(30)
        if not chan:
            return

        srv._ready.wait(10)
        shell = get_shell(ip)
        chan.send(b"\r\nWelcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-120-generic x86_64)\r\n")
        chan.send(("\r\n Last login: %s from 10.0.0.5\r\n\r\n"
                   % datetime.now().strftime('%a %b %d %H:%M:%S %Y')).encode())

        def _recv():
            try:
                chan.settimeout(300.0)
                return chan.recv(1024)
            except socket.timeout:
                return b""

        _interactive_shell(ip, shell, 22, "SSH_INTERACTIVE_CMD",
                           send=chan.send, recv=_recv)
        chan.close()
        transport.close()
    except Exception:
        pass
    finally:
        sock.close()

def run_ssh_honeypot():
    if not PARAMIKO_AVAILABLE:
        with console_lock:
            print(f"{C.YELLOW}[!] SSH honeypot disabled — install paramiko.{C.RESET}")
        return
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((CONFIG['host'], CONFIG['ssh_port']))
        srv.listen(10)
        with console_lock:
            print(f"{C.GREEN}[+] SSH honeypot listening on :{CONFIG['ssh_port']}{C.RESET}")
        while True:
            client, addr = srv.accept()
            ip = addr[0]
            log_event("SSH_CONNECTION", ip, port=22)
            threading.Thread(target=_ssh_session, args=(client, ip), daemon=True).start()
    except Exception as e:
        with console_lock:
            print(f"{C.RED}[!] SSH error: {e}{C.RESET}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION B: HTTP HONEYPOT
# ══════════════════════════════════════════════════════════════════════════════
def _http_session(sock, ip):
    try:
        sock.settimeout(10.0)
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
            if b'\r\n\r\n' in raw:
                break

        if not raw:
            return

        text  = raw.decode('utf-8', errors='replace')
        lines = text.split('\r\n')
        rl    = lines[0].split(' ')
        method = rl[0] if len(rl) > 0 else ""
        path   = rl[1] if len(rl) > 1 else "/"

        # Parse headers
        hdrs = {}
        for line in lines[1:]:
            if ': ' in line:
                k, v = line.split(': ', 1)
                hdrs[k.lower()] = v

        ua   = hdrs.get('user-agent', '')
        host = hdrs.get('host', '')

        # POST body
        body = ""
        if b'\r\n\r\n' in raw:
            body = raw.split(b'\r\n\r\n', 1)[1].decode('utf-8', errors='replace')

        # Credentials in POST
        creds = {}
        if method == 'POST' and body:
            params = urllib.parse.parse_qs(body)
            for fld in ('username','password','user','pass','passwd','pwd','login'):
                if fld in params:
                    creds[fld] = params[fld][0]

        # Detect scanning tools
        tools = [s for s in HTTP_SCANNER_UAS if s.lower() in ua.lower()]

        get_session(ip)
        session_append(ip, 'http_requests', {'method': method, 'path': path, 'ua': ua,
                                             'ts': datetime.now().isoformat()})
        if tools:
            session_add_tools(ip, tools)
        if creds:
            session_append(ip, 'credentials_tried', creds)

        log_event("HTTP_REQUEST", ip, port=CONFIG['http_port'],
                  extra={"method": method, "path": path,
                         "user_agent": ua[:120], "scanners": tools or None,
                         "credentials": creds or None, "host": host})

        # Build response
        if path == "/admin":
            resp = (b"HTTP/1.1 302 Found\r\n"
                    b"Location: /admin/login\r\n"
                    b"Server: Apache/2.4.41 (Ubuntu)\r\n"
                    b"Connection: close\r\n\r\n")
        elif path in HTTP_ROUTES:
            status, ctype, body_html = HTTP_ROUTES[path]
            body_b = body_html.encode()
            resp = (
                f"HTTP/1.1 {status}\r\n"
                f"Content-Type: {ctype}\r\n"
                f"Content-Length: {len(body_b)}\r\n"
                f"Server: Apache/2.4.41 (Ubuntu)\r\n"
                f"X-Powered-By: PHP/7.4.3\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + body_b
        else:
            body_b = b"<html><body><h1>404 Not Found</h1></body></html>"
            resp = (
                b"HTTP/1.1 404 Not Found\r\n"
                b"Content-Type: text/html\r\n"
                b"Server: Apache/2.4.41 (Ubuntu)\r\n"
                b"Connection: close\r\n\r\n"
            ) + body_b

        sock.send(resp)
    except Exception:
        pass
    finally:
        sock.close()

def run_http_honeypot():
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((CONFIG['host'], CONFIG['http_port']))
        srv.listen(10)
        with console_lock:
            print(f"{C.GREEN}[+] HTTP honeypot listening on :{CONFIG['http_port']}{C.RESET}")
        while True:
            client, addr = srv.accept()
            threading.Thread(target=_http_session, args=(client, addr[0]), daemon=True).start()
    except Exception as e:
        with console_lock:
            print(f"{C.RED}[!] HTTP error: {e}{C.RESET}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION B2: FTP HONEYPOT  (captures USER/PASS, not just a banner)
# ══════════════════════════════════════════════════════════════════════════════
def _ftp_session(sock, ip):
    try:
        sock.settimeout(20.0)
        sock.send(BANNERS[21])
        username = None
        sess = get_session(ip)

        while True:
            data = sock.recv(512)
            if not data:
                break
            line  = data.decode('utf-8', errors='replace').strip()
            parts = line.split(' ', 1)
            cmd   = parts[0].upper() if parts else ''
            arg   = parts[1] if len(parts) > 1 else ''

            if cmd == 'USER':
                username = arg
                sock.send(f'331 Password required for {arg}\r\n'.encode())
            elif cmd == 'PASS':
                cred = {'username': username, 'password': arg, 'ts': datetime.now().isoformat()}
                session_append(ip, 'credentials_tried', cred)
                log_event("FTP_CRED_ATTEMPT", ip, port=21,
                          extra={"username": username, "password": arg})
                sock.send(b'530 Login incorrect.\r\n')
            elif cmd == 'SYST':
                sock.send(b'215 UNIX Type: L8\r\n')
            elif cmd in ('QUIT', ''):
                sock.send(b'221 Goodbye.\r\n')
                break
            else:
                sock.send(b'530 Please login with USER and PASS.\r\n')
    except Exception:
        pass
    finally:
        sock.close()

def run_ftp_honeypot():
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((CONFIG['host'], CONFIG['ftp_port']))
        srv.listen(10)
        with console_lock:
            print(f"{C.GREEN}[+] FTP honeypot listening on :{CONFIG['ftp_port']}{C.RESET}")
        while True:
            client, addr = srv.accept()
            ip = addr[0]
            log_event("FTP_CONNECTION", ip, port=CONFIG['ftp_port'])
            threading.Thread(target=_ftp_session, args=(client, ip), daemon=True).start()
    except Exception as e:
        with console_lock:
            print(f"{C.RED}[!] FTP error: {e}{C.RESET}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION B3: TELNET HONEYPOT  (captures login/password + fake interactive shell)
# ══════════════════════════════════════════════════════════════════════════════
# Telnet protocol constants (RFC 854)
_IAC, _DONT, _DO, _WONT, _WILL, _SB, _SE = 255, 254, 253, 252, 251, 250, 240

def _telnet_strip_iac(data: bytes) -> bytes:
    """Remove Telnet IAC negotiation sequences so they don't pollute captured
    usernames/commands. Real telnet clients send these; a naive honeypot logs
    them as garbage credentials."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b == _IAC:
            if i + 1 >= n:
                break
            cmd = data[i + 1]
            if cmd in (_DO, _DONT, _WILL, _WONT):
                i += 3            # IAC + command + option
                continue
            if cmd == _SB:        # subnegotiation: skip until IAC SE
                j = i + 2
                while j + 1 < n and not (data[j] == _IAC and data[j + 1] == _SE):
                    j += 1
                i = j + 2
                continue
            i += 2                # other 2-byte IAC command
            continue
        out.append(b)
        i += 1
    return bytes(out)

def _telnet_readline(sock, echo=None) -> str:
    """Read one line from a telnet client with optional echo + backspace editing.

    We advertise IAC WILL ECHO, so the client suppresses local echo and expects
    the server to echo — pass `echo=sock.send` for the username (visible) and
    `echo=None` for the password (hidden), like a real login. Ends on CR and
    swallows the trailing LF/NUL telnet sends with it."""
    out = bytearray()
    while len(out) < 4096:
        try:
            chunk = sock.recv(256)
        except Exception:
            break
        if not chunk:
            break
        for byte in _telnet_strip_iac(chunk):
            if byte == 0x0d:                       # CR → end of line
                if echo:
                    try:
                        echo(b"\r\n")
                    except Exception:
                        pass
                return out.decode('utf-8', errors='replace').strip()
            if byte in (0x0a, 0x00):               # ignore LF / NUL
                continue
            if byte in (0x7f, 0x08):               # backspace
                if out:
                    out.pop()
                    if echo:
                        try:
                            echo(b"\b \b")
                        except Exception:
                            pass
                continue
            if 0x20 <= byte < 0x7f:
                out.append(byte)
                if echo:
                    try:
                        echo(bytes([byte]))
                    except Exception:
                        pass
    return out.decode('utf-8', errors='replace').strip()

def _telnet_session(sock, ip):
    try:
        sock.settimeout(30.0)
        # Tell the client we'll echo + suppress-go-ahead (typical server behaviour).
        sock.send(bytes([_IAC, _WILL, 1, _IAC, _WILL, 3]))
        sock.send(b'Debian GNU/Linux 10\r\nKernel 4.19.0-13-amd64 on an x86_64\r\n\r\nlogin: ')
        username = _telnet_readline(sock, echo=sock.send)   # echo the username
        sock.send(b'Password: ')
        password = _telnet_readline(sock, echo=None)        # hide the password

        get_session(ip)
        session_append(ip, 'credentials_tried',
                       {'username': username, 'password': password, 'ts': datetime.now().isoformat()})
        log_event("TELNET_CRED_ATTEMPT", ip, port=23,
                  extra={"username": username, "password": password})

        # Grant a fake shell (classic Cowrie/IoT-honeypot behaviour: keeps the
        # attacker engaged so we capture the commands/tools they run)
        shell = get_shell(ip)
        sock.send(f"\r\nLast login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from 10.0.0.5\r\n"
                  .encode())

        def _recv():
            try:
                sock.settimeout(300.0)
                return sock.recv(512)
            except socket.timeout:
                return b""

        _interactive_shell(ip, shell, 23, "TELNET_CMD",
                           send=sock.send, recv=_recv, clean=_telnet_strip_iac)
    except socket.timeout:
        pass
    except Exception:
        pass
    finally:
        sock.close()

def run_telnet_honeypot():
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((CONFIG['host'], CONFIG['telnet_port']))
        srv.listen(10)
        with console_lock:
            print(f"{C.GREEN}[+] Telnet honeypot listening on :{CONFIG['telnet_port']}{C.RESET}")
        while True:
            client, addr = srv.accept()
            ip = addr[0]
            log_event("TELNET_CONNECTION", ip, port=CONFIG['telnet_port'])
            threading.Thread(target=_telnet_session, args=(client, ip), daemon=True).start()
    except Exception as e:
        with console_lock:
            print(f"{C.RED}[!] Telnet error: {e}{C.RESET}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION C: GENERIC TCP HONEYPOTS
# ══════════════════════════════════════════════════════════════════════════════
def _generic_listener(port):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((CONFIG['host'], port))
        srv.listen(5)
        while True:
            client, addr = srv.accept()
            ip = addr[0]
            data = None
            try:
                banner = BANNERS.get(port)
                if banner:
                    client.send(banner)
                client.settimeout(5.0)
                data = client.recv(2048)
            except socket.timeout:
                pass
            except Exception:
                pass
            finally:
                tools = fingerprint_data(data, ip, port) if data else []
                get_session(ip)
                if tools:
                    session_add_tools(ip, tools)
                log_event("TCP_CONNECT", ip, port=port,
                          data=data,
                          extra={"data_bytes": len(data) if data else 0,
                                 "tools_detected": tools or None})
                client.close()
    except Exception:
        pass

def run_generic_honeypots():
    skip = {CONFIG['ssh_port'], CONFIG['http_port'], CONFIG['ftp_port'], CONFIG['telnet_port']}
    ports = [p for p in CONFIG['monitored_ports'] if p not in skip]
    with console_lock:
        print(f"{C.GREEN}[+] Generic TCP honeypots on {len(ports)} ports: {ports}{C.RESET}")
    for port in ports:
        threading.Thread(target=_generic_listener, args=(port,), daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
# SECTION D: SYN SCAN DETECTOR (Scapy)
# ══════════════════════════════════════════════════════════════════════════════
def _pkt_handler(pkt):
    if not (pkt.haslayer(scapy.TCP) and pkt[scapy.TCP].flags == 'S'):
        return

    ip   = pkt[scapy.IP].src
    port = pkt[scapy.TCP].dport
    now  = time.time()

    with syn_lock:
        t = syn_tracker[ip]
        if now - t['ts'] > CONFIG['time_window']:
            syn_tracker[ip] = {'ts': now, 'ports': {port}, 'fp': tcp_os_fingerprint(pkt)}
        else:
            t['ports'].add(port)
            if not t['fp']:
                t['fp'] = tcp_os_fingerprint(pkt)

        count = len(syn_tracker[ip]['ports'])
        fired = count >= CONFIG['port_scan_threshold']
        if fired:
            fp           = syn_tracker[ip]['fp']
            sample_ports = sorted(list(syn_tracker[ip]['ports']))[:20]
            # Reset to avoid log spam from same scan
            syn_tracker[ip]['ts'] = now - CONFIG['time_window'] - 1
            syn_tracker[ip]['ports'].clear()

    if fired:
        log_event("SYN_SCAN_DETECTED", ip,
                  extra={"ports_scanned": count,
                         "sample_ports":  sample_ports,
                         "os_guess":  fp.get('os_guess'),
                         "tool_guess":fp.get('tool_guess'),
                         "ttl":       fp.get('ttl'),
                         "tcp_window":fp.get('window')})

def run_sniffer():
    if not SCAPY_AVAILABLE:
        with console_lock:
            print(f"{C.YELLOW}[!] SYN sniffer disabled — install scapy.{C.RESET}")
        return
    try:
        with console_lock:
            print(f"{C.GREEN}[+] SYN scan detector active.{C.RESET}")
        scapy.sniff(filter="tcp[tcpflags] == 0x02", prn=_pkt_handler, store=0)
    except PermissionError:
        with console_lock:
            print(f"{C.RED}[!] Sniffer needs root/sudo!{C.RESET}")
    except Exception as e:
        with console_lock:
            print(f"{C.RED}[!] Sniffer error: {e}{C.RESET}")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION E: SESSION REPORTER (background, every 60s)
# ══════════════════════════════════════════════════════════════════════════════
def _reporter():
    while True:
        time.sleep(60)
        prune_sessions()                       # keep memory bounded
        persist_sessions_snapshot()            # upsert session table in SQLite
        now = time.time()
        # Snapshot under the lock so we never iterate sets/dicts being mutated.
        with session_lock:
            rows = []
            for ip, s in sessions.items():
                if now - s['last_seen'] >= CONFIG['session_timeout']:
                    continue
                rows.append((
                    ip, s['alert_level'], dict(s.get('geo') or {}),
                    len(s['ports_touched']), len(s['credentials_tried']),
                    len(s['commands_run']), len(s['http_requests']),
                    sorted(s['identified_tools']),
                ))
        if not rows:
            continue
        with console_lock:
            print(f"\n{C.BOLD}{C.WHITE}{'━'*64}{C.RESET}")
            print(f"{C.BOLD}{C.WHITE}  ACTIVE ATTACKER SESSIONS ({len(rows)}){C.RESET}")
            print(f"{C.BOLD}{C.WHITE}{'━'*64}{C.RESET}")
            for ip, level, geo, n_ports, n_creds, n_cmds, n_http, tools in rows:
                loc   = f"{geo.get('country','?')}/{geo.get('city','?')}"
                color = LEVEL_COLORS.get(level, C.CYAN)
                print(
                    f"  {color}[{level}]{C.RESET} "
                    f"{C.YELLOW}{ip}{C.RESET}  {C.BLUE}{loc}{C.RESET}\n"
                    f"    ISP: {geo.get('isp','?')} | AS: {geo.get('as','?')}\n"
                    f"    Ports:{n_ports}  Creds:{n_creds}  Cmds:{n_cmds}  HTTP:{n_http}\n"
                    f"    Tools: {', '.join(tools) or '-'}"
                )
            print(f"{C.BOLD}{C.WHITE}{'━'*64}{C.RESET}\n")

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    banner = f"""
{C.RED_BG}{C.BOLD}
  ╔════════════════════════════════════════════════════════╗
  ║       ADVANCED RED TEAM DETECTION HONEYPOT  v3.0      ║
  ║              Blue Team Edition — AM1RX                ║
  ╚════════════════════════════════════════════════════════╝
{C.RESET}
  {C.CYAN}SSH Honeypot   : {'✓ Enabled' if PARAMIKO_AVAILABLE and CONFIG['ssh_enabled'] else '✗ Disabled  (pip install paramiko)'}{C.RESET}
  {C.CYAN}HTTP Honeypot  : {'✓ Enabled' if CONFIG['http_enabled'] else '✗ Disabled'}{C.RESET}
  {C.CYAN}FTP Honeypot   : {'✓ Enabled' if CONFIG['ftp_enabled'] else '✗ Disabled'}{C.RESET}
  {C.CYAN}Telnet Honeypot: {'✓ Enabled' if CONFIG['telnet_enabled'] else '✗ Disabled'}{C.RESET}
  {C.CYAN}SYN Sniffer    : {'✓ Enabled' if SCAPY_AVAILABLE else '✗ Disabled  (pip install scapy)'}{C.RESET}
  {C.CYAN}GeoIP Lookup   : {'✓ Enabled' if CONFIG['geoip_enabled'] else '✗ Disabled'}{C.RESET}
  {C.CYAN}Telegram Alerts: {'✓ Enabled' if CONFIG['telegram_enabled'] else '✗ Disabled'}{C.RESET}
  {C.CYAN}Syslog → SIEM  : {'✓ Enabled → ' + CONFIG['syslog_host'] + ':' + str(CONFIG['syslog_port']) + ' (' + CONFIG['syslog_format'].upper() + '/' + CONFIG['syslog_protocol'].upper() + ')' if CONFIG['syslog_enabled'] else '✗ Disabled'}{C.RESET}
  {C.CYAN}Whitelisted IPs: {len(CONFIG['whitelisted_ips']) or 'none'}{C.RESET}
  {C.CYAN}SQLite Store   : {'✓ ' + CONFIG['db_file'] if CONFIG['persist_enabled'] else '✗ Disabled'}{C.RESET}
  {C.CYAN}SFTP Capture   : {'✓ → ' + CONFIG['quarantine_dir'] + '/' if (PARAMIKO_AVAILABLE and CONFIG['capture_uploads']) else '✗ Disabled'}{C.RESET}
  {C.CYAN}Fetch Downloads: {'✓ Enabled (ACTIVE OUTBOUND!)' if CONFIG['fetch_downloads'] else '✗ Disabled (safe)'}{C.RESET}
  {C.CYAN}JSON Log       : {CONFIG['json_log_file']}{C.RESET}
  {C.CYAN}Text Log       : {CONFIG['log_file']}{C.RESET}

  {C.YELLOW}See SERVICES_AND_CREDENTIALS.md for the full list of decoy{C.RESET}
  {C.YELLOW}services, fake banners, and credentials configured on this honeypot.{C.RESET}
"""
    print(banner)

    # Open the SQLite store before any events start flowing.
    if CONFIG['persist_enabled']:
        init_db()

    threads = [
        threading.Thread(target=run_generic_honeypots, daemon=True),
        threading.Thread(target=run_sniffer,           daemon=True),
        threading.Thread(target=_reporter,             daemon=True),
    ]
    # GeoIP worker pool — keeps lookups off the session threads entirely.
    if CONFIG['geoip_enabled']:
        for _ in range(2):
            threads.append(threading.Thread(target=_geo_worker, daemon=True))
    # SQLite writer thread (single writer).
    if CONFIG['persist_enabled']:
        threads.append(threading.Thread(target=_persist_worker, daemon=True))
    if CONFIG['http_enabled']:
        threads.append(threading.Thread(target=run_http_honeypot, daemon=True))
    if CONFIG['ssh_enabled'] and PARAMIKO_AVAILABLE:
        threads.append(threading.Thread(target=run_ssh_honeypot,  daemon=True))
    if CONFIG['ftp_enabled']:
        threads.append(threading.Thread(target=run_ftp_honeypot, daemon=True))
    if CONFIG['telnet_enabled']:
        threads.append(threading.Thread(target=run_telnet_honeypot, daemon=True))

    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{C.GREEN}[+] Shutting down. Final session report:{C.RESET}")
        with session_lock:
            snapshot = [
                (ip, dict(s.get('geo') or {}), len(s['ports_touched']),
                 len(s['credentials_tried']), len(s['commands_run']),
                 sorted(s['identified_tools']))
                for ip, s in sessions.items()
            ]
        for ip, geo, n_ports, n_creds, n_cmds, tools in snapshot:
            print(f"  {ip} | {geo.get('country','?')} | "
                  f"ports={n_ports} creds={n_creds} "
                  f"cmds={n_cmds} tools={','.join(tools) or '-'}")
