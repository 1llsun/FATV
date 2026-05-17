# 🔬 FATV — Forensic Artifact Timeline Visualizer

**Multi-Source Forensic Investigation Platform**

| Field | Detail |
|---|---|
| **Authors** | Farhan Saifullah (55596) & Tayyab Ayub (51599) |
| **Course** | Digital Forensics |
| **Instructor** | Sir Humayun |
| **Program** | BSCY-6-1, Riphah International University |
| **Date** | 2026 |

---

## Overview

FATV is a web-based forensic investigation platform that ingests raw evidence files from multiple sources, automatically detects attack patterns, and presents a unified interactive timeline — allowing investigators to reconstruct the complete sequence of an intrusion.

## Features

| Category | Capabilities |
|---|---|
| **Ingestion** | auth.log, syslog, Apache/Nginx access logs, network CSV, PCAP |
| **Detection** | Port scan, SSH brute force, privilege escalation, lateral movement, data exfiltration, C2 beaconing, log tampering, web attacks, credential access |
| **Correlation** | Cross-source event linking by IP, user, and hostname |
| **Visualization** | Interactive Plotly timeline, attack chain cards, entity graph |
| **Investigation** | Per-event investigator notes, evidence tagging, correlated events |
| **Gaps** | Missing evidence detection (suspicious timeline holes) |
| **Reporting** | HTML report download, CSV export |

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

> **Note:** `scapy` is only required for PCAP analysis. All other formats work without it.

### 2. Run the server

```bash
python app.py
```

### 3. Open in browser

```
http://127.0.0.1:5001
```

### 4. Load sample data

Click **"Load Sample Attack Scenario"** on the home page to immediately explore a realistic multi-stage intrusion demo with:

- Web enumeration & SQL injection
- SSH brute force → successful compromise
- Privilege escalation to root
- Lateral movement across 5 internal hosts
- Credential access (/etc/shadow)
- Data exfiltration via C2 channel (port 9001)
- C2 beaconing to external IP (port 4444)
- Log tampering / evidence destruction

## Supported Evidence Formats

| Format | Extension | Description |
|---|---|---|
| Linux auth/syslog | `.log`, `.txt` | SSH, sudo, PAM events |
| Apache/Nginx | `.log` | Web access logs |
| Network flow | `.csv` | Columnar network records |
| PCAP capture | `.pcap`, `.pcapng` | Raw packet capture (requires scapy) |

## Project Structure

```
fatv/
├── app.py                    # Flask entry point & routes
├── requirements.txt
├── app/
│   ├── core/
│   │   ├── models.py         # ForensicEvent, AttackChain, Entity dataclasses
│   │   └── config.py
│   └── services/
│       ├── ingestion.py      # Multi-format parser (auto-detects format)
│       ├── detection.py      # Attack detection algorithms
│       ├── entities.py       # IP/user/hostname tracking
│       ├── timeline.py       # Gap detection & event correlation
│       └── report.py         # HTML report generation
├── templates/
│   ├── index.html            # Upload / landing page
│   └── timeline.html         # Main investigation dashboard
├── static/js/
│   └── fatv.js               # Plotly, table, detail panel, filters
└── samples/                  # Built-in attack scenario
    ├── sample_auth.log
    ├── sample_network.csv
    ├── sample_syslog.txt
    └── sample_web.log
```

## Detection Algorithms

### Port Scan
Triggers when a source IP contacts ≥15 unique destination ports within a 120-second window. Tags events as **Reconnaissance** phase.

### SSH Brute Force
Detects ≥8 failed login attempts from the same IP within 600 seconds. Escalates to **CRITICAL** if a subsequent login success is observed from the same source.

### Privilege Escalation
Flags `sudo`, `su`, and root escalation events. Always **CRITICAL**.

### Lateral Movement
Identifies internal-to-internal connections on SSH (22), RDP (3389), SMB (445), or WinRM (5985/5986) to ≥2 distinct targets from the same source.

### Data Exfiltration
Detects outbound connections from internal IPs to external destinations on known C2/exfil ports (4444, 5555, 9001, 31337, etc.).

### C2 Beaconing
Flags ≥4 repeated connections to the same external IP on suspicious ports — a hallmark of command-and-control beaconing.

### Log Tampering
Detects deletion of system log files (auth.log, syslog, kern.log, audit) — evidence of an attacker covering their tracks. Always **CRITICAL**, tagged as **Defense Evasion**.

### Web Attacks
Identifies SQL injection (UNION SELECT, OR 1=1), XSS payloads, and path enumeration from Apache/Nginx access logs.

## Kill Chain Mapping

FATV automatically maps each detected event to a Lockheed Martin Cyber Kill Chain phase:

`Reconnaissance → Initial Access → Execution → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Command & Control → Exfiltration`

## License

Academic project — Riphah International University, 2026.

## Fixed Version Notes

This package includes fixes for the main dashboard and backend issues found during review:

- Fixed anomaly click action by using `openDetailById()` consistently.
- Fixed entity filtering so clicking an IP, user, or hostname opens the evidence table with matching events only.
- Fixed source filtering from the sidebar and from the timeline dropdown.
- Fixed kill-chain phase filtering.
- Fixed timeline search so it filters the timeline and the evidence table.
- Fixed attack-chain filtering so multi-stage chains also match events through `event_ids`, not only `attack_chain_id`.
- Added graceful handling when Plotly CDN is unavailable.
- Moved the Flask secret key to `FATV_SECRET_KEY` environment-variable support with a development fallback.
- Prevented uploaded evidence files with the same name from overwriting each other.
- Improved API robustness for notes and tags by safely handling invalid or missing JSON.
- Escaped evidence values in the generated HTML report to reduce HTML/script injection risk.
- Added pytest smoke tests for sample loading, APIs, export, report generation, notes/tags, and report escaping.

Run tests with:

```bash
python -m pytest
```

...
