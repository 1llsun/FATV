"""
Multi-source forensic data ingestion.
Handles: CSV (comma/semicolon/tab), auth.log, syslog, Apache/Nginx, PCAP.

Fixed bugs:
  - CSV: semicolon/tab delimiters now auto-detected
  - CSV: NaN values cleaned from IP/string fields
  - Apache: authenticated username lines now parse correctly
  - Apache: IPv6 addresses now handled
  - Syslog: ISO-format timestamps (2026-04-28T10:00:00) now parsed
  - Auth events: sudo events correctly classified as Privileged Command
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import List

import importlib.util

import pandas as pd

from app.core.models import ForensicEvent

# Avoid importing scapy at application startup. Some systems print noisy route/IPv6
# errors during scapy import. We only import it lazily when a PCAP is actually parsed.
SCAPY_AVAILABLE = importlib.util.find_spec("scapy") is not None

# ── Regex patterns ────────────────────────────────────────────────────────────
_RE_SYSLOG = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s+(?P<msg>.*)$'
)
# ISO-format syslog: 2026-04-28T10:00:00 host process[pid]: msg
_RE_SYSLOG_ISO = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s+(?P<msg>.*)$'
)
# Apache/Nginx Combined Log Format — supports IPv4 AND IPv6
_RE_APACHE = re.compile(
    r'^(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<dt>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<url>\S+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
)
_RE_IP  = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_RE_USER = re.compile(r'(?:user|for)\s+(\w[\w.\-@]+)', re.I)

_SYSLOG_MONTHS = {
    'Jan':'01','Feb':'02','Mar':'03','Apr':'04','May':'05','Jun':'06',
    'Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12',
    # Full month names too
    'January':'01','February':'02','March':'03','April':'04','May':'05','June':'06',
    'July':'07','August':'08','September':'09','October':'10','November':'11','December':'12',
}

CURRENT_YEAR = datetime.now().year


def _syslog_ts(month: str, day: str, time_str: str) -> datetime:
    mo = _SYSLOG_MONTHS.get(month, '01')
    try:
        return datetime.strptime(f"{CURRENT_YEAR}-{mo}-{int(day):02d} {time_str}",
                                 "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.now()


def _iso_ts(ts_str: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return datetime.now()


def _apache_ts(raw: str) -> datetime:
    try:
        return datetime.strptime(raw.split()[0], "%d/%b/%Y:%H:%M:%S")
    except Exception:
        return datetime.now()


def _clean_str(val) -> str:
    """Clean pandas value — convert NaN/None/nan to empty string."""
    if val is None:
        return ''
    s = str(val).strip()
    if s.lower() in ('nan', 'none', 'null', 'n/a', '-', ''):
        return ''
    return s


def _classify_web_event(method: str, url: str, status: int) -> tuple:
    url_low = url.lower()
    sqli_patterns = ["' or ", "' or'", "union select", " or 1=1", "--", "xp_cmd",
                     "exec(", "sleep(", "' and ", "1=1", "or'1'='1"]
    xss_patterns  = ["<script", "javascript:", "onerror=", "alert(", "<img", "svg/onload"]
    lfi_patterns  = ["../", "%2e%2e", "..%2f", "etc/passwd", "etc/shadow",
                     "proc/self", "win.ini", "boot.ini"]
    path_scan     = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/.git",
                     "/etc/", "/backup", "/shell", "/cmd", "/phpinfo", "/.htaccess",
                     "/.htpasswd", "/web.config", "/config.php"]

    if any(p in url_low for p in sqli_patterns):
        return "SQL Injection Attempt", f"{method} {url[:100]} → {status}", "HIGH"
    if any(p in url_low for p in xss_patterns):
        return "XSS Attempt", f"{method} {url[:100]} → {status}", "MEDIUM"
    if any(p in url_low for p in lfi_patterns):
        return "LFI / Path Traversal", f"{method} {url[:100]} → {status}", "HIGH"
    if any(p in url_low for p in path_scan):
        return "Path Enumeration", f"{method} {url[:80]} → {status}", "MEDIUM"
    if status in (401, 403):
        return "Access Denied", f"{method} {url[:80]} → {status}", "LOW"
    if status >= 500:
        return "Server Error", f"{method} {url[:80]} → {status}", "LOW"
    return "Web Request", f"{method} {url[:80]} → {status}", "INFO"


def _classify_auth_event(msg: str) -> tuple:
    m = msg.lower()
    # Check sudo FIRST (before generic auth checks) — fixes Bug 9
    if 'sudo' in m:
        if 'command' in m or 'cmd' in m or 'tty=' in m or ';' in m:
            return "Privileged Command", msg[:200], "HIGH"
    if 'su for root' in m or ('su[' in m and 'root' in m):
        return "Root Escalation", msg[:200], "CRITICAL"
    if 'failed password' in m or 'authentication failure' in m or 'invalid user' in m:
        return "Login Failure", msg[:200], "MEDIUM"
    if 'accepted password' in m or 'accepted publickey' in m:
        return "Login Success", msg[:200], "LOW"
    if 'session opened' in m:
        return "Session Opened", msg[:200], "INFO"
    if 'session closed' in m:
        return "Session Closed", msg[:200], "INFO"
    if any(x in m for x in ['auth.log', 'syslog', 'kern.log', '.log']):
        if any(x in m for x in ['rotat', 'clear', 'delet', 'remov']):
            return "Log Tampering", msg[:200], "CRITICAL"
    return "Auth Event", msg[:200], "INFO"


def _classify_syslog_event(process: str, msg: str) -> tuple:
    m   = msg.lower()
    pro = process.lower()
    if 'iptables' in m or 'netfilter' in m:
        return "Firewall Event", msg[:200], "LOW"
    if 'apparmor' in m and 'denied' in m:
        return "AppArmor Denied", msg[:200], "MEDIUM"
    if pro in ('cron', 'crond') and 'cmd' in m:
        return "Cron Execution", msg[:200], "LOW"
    if any(x in m for x in ['auth.log', 'syslog', 'kern.log', 'audit.log', 'btmp']):
        if any(x in m for x in ['rm ', 'remov', 'delet', 'clear', 'truncat']):
            return "Log Tampering", msg[:200], "CRITICAL"
    if any(x in m for x in ['rm ', '/var/log']):
        return "File Deletion", msg[:200], "HIGH"
    if any(x in m for x in ['/etc/shadow', '/etc/passwd']):
        return "Credential File Access", msg[:200], "CRITICAL"
    if any(x in m for x in ['.exfil', '.hidden', 'tar ', 'nc ', 'curl ', 'wget ', 'chmod']):
        return "Suspicious Process", msg[:200], "HIGH"
    if 'kernel' in pro or 'audit' in pro:
        return "Kernel / Audit", msg[:200], "INFO"
    return "System Event", msg[:200], "INFO"


# ── Format-specific parsers ───────────────────────────────────────────────────

def _parse_syslog(path: Path, source_name: str) -> List[ForensicEvent]:
    events: List[ForensicEvent] = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            ts   = None
            host = ''
            process = ''
            msg  = ''

            m = _RE_SYSLOG.match(line)
            if m:
                ts      = _syslog_ts(m['month'], m['day'], m['time'])
                host    = m['host']
                process = m['process']
                msg     = m['msg']
            else:
                m2 = _RE_SYSLOG_ISO.match(line)
                if m2:
                    ts      = _iso_ts(m2['ts'])
                    host    = m2['host']
                    process = m2['process']
                    msg     = m2['msg']
                else:
                    continue  # unrecognized format

            pro_low = process.lower()
            if any(x in pro_low for x in ['sshd', 'login', 'sudo', 'su', 'pam', 'auth']):
                stype = 'auth'
                # Handle sudo and su directly by process name — message won't contain 'sudo'
                if 'sudo' in pro_low:
                    m_low = msg.lower()
                    # Escalation to root: USER=root in sudo log
                    if 'user=root' in m_low or '; user=root' in m_low:
                        ev_type, desc, severity = "Root Escalation", msg[:200], "CRITICAL"
                    else:
                        ev_type, desc, severity = "Privileged Command", msg[:200], "HIGH"
                elif pro_low in ('su', 'su-l'):
                    if 'root' in msg.lower():
                        ev_type, desc, severity = "Root Escalation", msg[:200], "CRITICAL"
                    else:
                        ev_type, desc, severity = _classify_auth_event(msg)
                else:
                    ev_type, desc, severity = _classify_auth_event(msg)
            else:
                stype = 'syslog'
                ev_type, desc, severity = _classify_syslog_event(process, msg)

            ips   = _RE_IP.findall(msg)
            # Sudo log format: "username : TTY=... COMMAND=..."
            # Extract username before the colon
            if 'sudo' in pro_low and ' : ' in msg:
                sudo_user = msg.split(' : ')[0].strip()
                users = [sudo_user] if sudo_user else []
            else:
                users = _RE_USER.findall(msg)

            events.append(ForensicEvent(
                timestamp   = ts,
                source      = source_name,
                source_type = stype,
                event_type  = ev_type,
                description = desc,
                severity    = severity,
                src_ip      = ips[0] if ips else '',
                dst_ip      = ips[1] if len(ips) > 1 else '',
                hostname    = host,
                user        = users[0] if users else '',
                raw         = line,
            ))
    return events


def _parse_apache(path: Path, source_name: str) -> List[ForensicEvent]:
    events: List[ForensicEvent] = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            m = _RE_APACHE.match(line)
            if not m:
                continue
            ts     = _apache_ts(m['dt'])
            status = int(m['status'])
            ev_type, desc, severity = _classify_web_event(m['method'], m['url'], status)
            user_val = m['user'] if m['user'] not in ('-', '') else ''
            # Validate IP (skip garbage matches)
            raw_ip = m['ip']
            if raw_ip in ('', '-'):
                raw_ip = ''
            events.append(ForensicEvent(
                timestamp   = ts,
                source      = source_name,
                source_type = 'web',
                event_type  = ev_type,
                description = desc,
                severity    = severity,
                src_ip      = raw_ip,
                dst_port    = 80,
                protocol    = 'HTTP',
                user        = user_val,
                raw         = line,
            ))
    return events


def _parse_csv(path: Path, source_name: str) -> List[ForensicEvent]:
    rename = {
        'time': 'timestamp', 'date': 'timestamp', 'datetime': 'timestamp',
        'ts': 'timestamp',
        'source_ip': 'src_ip', 'sourceip': 'src_ip', 'source': 'src_ip',
        'src': 'src_ip', 'ip_src': 'src_ip',
        'destination_ip': 'dst_ip', 'dest_ip': 'dst_ip', 'destip': 'dst_ip',
        'destination': 'dst_ip', 'dst': 'dst_ip', 'ip_dst': 'dst_ip',
        'target': 'dst_ip', 'target_ip': 'dst_ip',
        'source_port': 'src_port', 'sourceport': 'src_port', 'sport': 'src_port',
        'destination_port': 'dst_port', 'destport': 'dst_port', 'dport': 'dst_port',
        'port': 'dst_port',
        'proto': 'protocol', 'proto_name': 'protocol', 'transport': 'protocol',
        'size': 'length', 'bytes': 'length', 'len': 'length', 'pkt_size': 'length',
        'packet_size': 'length', 'network_packet_size': 'length',
        'message': 'description', 'msg': 'description', 'info': 'description',
        'details': 'description', 'summary': 'description',
        'event': 'event_type', 'action': 'event_type', 'type': 'event_type',
        'label': 'event_type', 'category': 'event_type', 'attack_type': 'event_type',
        'flags': 'flags', 'tcp_flags': 'flags', 'flag': 'flags',
    }

    # Auto-detect delimiter (comma, semicolon, tab, pipe)
    df = None
    last_err = None
    for sep in [',', ';', '\t', '|']:
        try:
            candidate = pd.read_csv(path, sep=sep, engine='python',
                                    on_bad_lines='skip', nrows=5)
            if len(candidate.columns) >= 2:
                # Re-read full file with this separator
                df = pd.read_csv(path, sep=sep, engine='python', on_bad_lines='skip')
                break
        except Exception as e:
            last_err = e
            continue

    if df is None or df.empty:
        return []

    # Normalize column names
    df.columns = [rename.get(c.lower().strip().replace(' ', '_'), c.lower().strip()) for c in df.columns]

    events: List[ForensicEvent] = []
    for _, row in df.iterrows():
        # Timestamp
        ts = None
        for tc in ['timestamp', 'ts', 'time', 'datetime', 'date']:
            if tc in row and pd.notna(row[tc]):
                try:
                    ts = pd.to_datetime(row[tc]).to_pydatetime()
                    break
                except Exception:
                    pass
        if ts is None:
            ts = datetime.now()

        # Clean all string fields — convert NaN to ''
        src_ip  = _clean_str(row.get('src_ip', ''))
        dst_ip  = _clean_str(row.get('dst_ip', ''))
        proto   = _clean_str(row.get('protocol', '')).upper()
        user    = _clean_str(row.get('user', ''))
        hostname = _clean_str(row.get('hostname', ''))
        flags   = _clean_str(row.get('flags', '')).upper()

        # Description: prefer description, fallback to event_type, fallback to generic
        desc_raw = _clean_str(row.get('description', ''))
        ev_type_raw = _clean_str(row.get('event_type', ''))
        desc     = desc_raw or ev_type_raw or f"{proto or 'TCP'} connection"
        ev_type  = ev_type_raw or 'Network Event'

        try:
            src_port = int(float(row.get('src_port', 0) or 0))
        except Exception:
            src_port = 0
        try:
            dst_port = int(float(row.get('dst_port', 0) or 0))
        except Exception:
            dst_port = 0

        # Auto-classify based on port and event type
        severity = 'INFO'
        if dst_port in {4444, 5555, 6666, 9001, 9999, 31337, 12345, 8888, 1337, 6667}:
            if ev_type not in ('Login Failure', 'Login Success'):
                ev_type = 'C2 Traffic'
            severity = 'CRITICAL'
        elif ev_type == 'Login Failure':
            severity = 'MEDIUM'
        elif ev_type == 'Login Success':
            severity = 'LOW'
        elif ev_type in ('C2 Traffic', 'Credential File Access'):
            severity = 'CRITICAL'
        elif ev_type in ('Large Transfer', 'Data Transfer') and dst_port in {9001, 9999, 4444, 5555}:
            severity = 'HIGH'

        events.append(ForensicEvent(
            timestamp   = ts,
            source      = source_name,
            source_type = 'network',
            event_type  = ev_type,
            description = desc[:300],
            severity    = severity,
            src_ip      = src_ip,
            dst_ip      = dst_ip,
            src_port    = src_port,
            dst_port    = dst_port,
            protocol    = proto,
            user        = user,
            hostname    = hostname,
            raw         = ','.join(_clean_str(v) for v in row.values),
        ))
    return events


def _parse_pcap(path: Path, source_name: str) -> List[ForensicEvent]:
    if not SCAPY_AVAILABLE:
        raise RuntimeError(
            'Scapy is not installed — PCAP files cannot be parsed. '
            'Please upload CSV or LOG files instead. '
            'To enable PCAP support: pip install scapy'
        )
    try:
        from scapy.utils import rdpcap
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.packet import Raw
    except Exception as exc:
        raise RuntimeError(
            'Scapy is installed but could not be imported correctly, so PCAP parsing is unavailable. '
            'Use CSV/LOG evidence or reinstall Scapy.'
        ) from exc

    packets = rdpcap(str(path))
    events: List[ForensicEvent] = []
    for pkt in packets:
        if IP not in pkt:
            continue
        src_port = dst_port = 0
        proto = 'IP'
        if TCP in pkt:
            src_port, dst_port, proto = pkt[TCP].sport, pkt[TCP].dport, 'TCP'
        elif UDP in pkt:
            src_port, dst_port, proto = pkt[UDP].sport, pkt[UDP].dport, 'UDP'
        elif ICMP in pkt:
            proto = 'ICMP'

        # Protocol identification by port
        ports = {src_port, dst_port}
        if 53  in ports: proto = 'DNS'
        elif 80  in ports or 8080 in ports: proto = 'HTTP'
        elif 443 in ports: proto = 'HTTPS'
        elif 22  in ports: proto = 'SSH'
        elif 21  in ports: proto = 'FTP'

        raw_payload = ''
        if Raw in pkt:
            try:
                raw_payload = bytes(pkt[Raw].load).decode('utf-8', errors='ignore')[:200]
            except Exception:
                pass

        ts = datetime.fromtimestamp(float(pkt.time))
        events.append(ForensicEvent(
            timestamp   = ts,
            source      = source_name,
            source_type = 'pcap',
            event_type  = 'Captured Packet',
            description = f'{proto} {pkt[IP].src}:{src_port} → {pkt[IP].dst}:{dst_port}',
            severity    = 'INFO',
            src_ip      = pkt[IP].src,
            dst_ip      = pkt[IP].dst,
            src_port    = src_port,
            dst_port    = dst_port,
            protocol    = proto,
            raw         = raw_payload,
        ))
    return events


def _detect_format(path: Path, first_lines: List[str]) -> str:
    ext = path.suffix.lower()
    if ext in ('.pcap', '.pcapng', '.cap'):
        return 'pcap'
    if ext == '.csv':
        return 'csv'
    joined = ' '.join(first_lines[:5])
    # Apache: IP - - [DD/Mon/YYYY: (IPv4 or IPv6)
    if re.search(r'[\da-fA-F:.]+\s+-\s+\S+\s+\[', joined):
        return 'apache'
    # Standard syslog: Mon DD HH:MM:SS
    if re.search(r'^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d',
                 joined, re.M | re.I):
        return 'syslog'
    # ISO syslog: 2026-04-28T
    if re.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', joined):
        return 'syslog'  # handled by ISO branch in _parse_syslog
    return 'syslog'


def ingest_file(file_path: str) -> List[ForensicEvent]:
    path = Path(file_path)
    source_name = path.name
    first_lines: List[str] = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            for _, line in zip(range(10), fh):
                first_lines.append(line)
    except Exception:
        first_lines = []

    fmt = _detect_format(path, first_lines)
    if fmt == 'pcap':   return _parse_pcap(path, source_name)
    if fmt == 'csv':    return _parse_csv(path, source_name)
    if fmt == 'apache': return _parse_apache(path, source_name)
    return _parse_syslog(path, source_name)


def ingest_files(file_paths: List[str]) -> List[ForensicEvent]:
    all_events: List[ForensicEvent] = []
    for fp in file_paths:
        try:
            events = ingest_file(fp)
            all_events.extend(events)
        except Exception as exc:
            print(f'[ingestion] Skipped {fp}: {exc}')
    all_events.sort(key=lambda e: e.timestamp or datetime.min)
    return all_events
