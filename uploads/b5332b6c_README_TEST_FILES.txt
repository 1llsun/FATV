FATV Natural Test Evidence Pack
================================

Purpose
-------
These files are realistic sample evidence files for testing the FATV Forensic Artifact Timeline Visualizer.
They cover every file extension accepted by the project:

1. .log    -> 01_linux_auth_bruteforce.log
2. .txt    -> 02_linux_system_activity.txt
3. .log    -> 03_web_access_mixed.log
4. .csv    -> 04_network_flows_full.csv
5. .csv    -> 05_network_flows_semicolon.csv, tests semicolon delimiter auto-detection
6. .csv    -> 09_network_flows_tab_delimited.csv, tests tab delimiter auto-detection
7. .csv    -> 10_network_flows_pipe_delimited.csv, tests pipe delimiter auto-detection
8. .pcap   -> 06_packet_capture_http_scan_c2.pcap
9. .cap    -> 07_packet_capture_legacy.cap
10. .pcapng -> 08_packet_capture_modern.pcapng

Natural scenario
----------------
The evidence describes a small company web server called web01 at 10.10.5.15.
A public source IP, 198.51.100.23, performs web enumeration and SSH brute force.
The server is later used for privilege escalation, credential access, lateral movement,
C2 traffic, exfiltration, and log tampering.

Recommended upload test
-----------------------
Upload all files together in the FATV home page. The project should parse the files,
create a combined timeline, detect attack chains, extract entities, and allow CSV/report export.

Expected detections
-------------------
- Web attack pattern from 198.51.100.23
- Port scan from 198.51.100.23
- SSH brute force from 198.51.100.23, with successful login after failures
- Privilege escalation on web01
- Credential access to /etc/passwd and /etc/shadow
- Lateral movement from 10.10.5.15 to internal hosts
- C2 beaconing from 10.10.5.15 to 203.0.113.77:4444
- Data exfiltration from 10.10.5.15 to 203.0.113.88:9001
- Log tampering involving auth.log, syslog, and audit.log

Important note
--------------
These files are designed to use common formats and common column names, so they are a strong compatibility test.
No test pack can guarantee every possible real-world log will parse, because real logs vary by product, timestamp,
field names, and export style. If these work, then files with similar structure should work in the project.
