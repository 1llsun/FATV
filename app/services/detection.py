"""
Attack detection engine.
Detects: Port Scan, SSH Brute Force, Privilege Escalation, Lateral Movement,
         Data Exfiltration, C2 Beaconing, Log Tampering, Web Attacks, Credential Access.

Each detector returns a list of AttackChain objects and tags the relevant ForensicEvents
in-place with kill_chain_phase, severity, is_anomaly, anomaly_reason, attack_chain_id.
"""
from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple

from app.core.models import AttackChain, ForensicEvent, SEVERITY_ORDER

# ── Thresholds ────────────────────────────────────────────────────────────────
PORT_SCAN_PORTS     = 15
PORT_SCAN_WINDOW    = 120     # seconds
BRUTE_FORCE_TRIES   = 8
BRUTE_FORCE_WINDOW  = 600     # seconds
C2_MIN_CONNECTIONS  = 4

_INTERNAL_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.", "127.",
)
_C2_PORTS      = {4444, 5555, 6666, 9001, 9999, 31337, 12345, 8888, 1337, 6667}
_LATERAL_PORTS = {22, 3389, 445, 135, 5985, 5986}


def _is_internal(ip: str) -> bool:
    return bool(ip) and any(ip.startswith(p) for p in _INTERNAL_PREFIXES)


def _is_external(ip: str) -> bool:
    return bool(ip) and not _is_internal(ip)


def _ts(e: ForensicEvent) -> datetime:
    return e.timestamp or datetime.min


def _tag(e: ForensicEvent, phase: str, severity: str,
         anomaly_reason: str, chain_id: str) -> None:
    """Tag an event in-place; only upgrade severity, never downgrade."""
    e.kill_chain_phase = e.kill_chain_phase or phase
    if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(e.severity, 0):
        e.severity = severity
    e.is_anomaly = True
    e.anomaly_reason = e.anomaly_reason or anomaly_reason
    if not e.attack_chain_id:
        e.attack_chain_id = chain_id


# ── Detectors ─────────────────────────────────────────────────────────────────

def detect_port_scans(events: List[ForensicEvent]) -> List[AttackChain]:
    chains: List[AttackChain] = []
    net = [e for e in events if e.source_type in ("network", "pcap") and e.src_ip]
    by_src: Dict[str, List[ForensicEvent]] = defaultdict(list)
    for e in net:
        by_src[e.src_ip].append(e)

    for src_ip, evts in by_src.items():
        evts.sort(key=_ts)
        w0 = 0
        for i, e in enumerate(evts):
            while w0 < i and (_ts(e) - _ts(evts[w0])).total_seconds() > PORT_SCAN_WINDOW:
                w0 += 1
            window = evts[w0:i + 1]
            unique_ports = {ev.dst_port for ev in window if ev.dst_port}
            if len(unique_ports) >= PORT_SCAN_PORTS:
                cid = uuid.uuid4().hex[:8]
                reason = f"Port scan: {len(unique_ports)} ports in {PORT_SCAN_WINDOW}s window"
                for ev in window:
                    _tag(ev, "Reconnaissance", "HIGH", reason, cid)
                chains.append(AttackChain(
                    chain_id    = cid,
                    name        = f"Port Scan from {src_ip}",
                    attacker_ip = src_ip,
                    victim_ip   = window[0].dst_ip,
                    phases      = ["Reconnaissance"],
                    event_ids   = [ev.event_id for ev in window],
                    start_time  = _ts(window[0]),
                    end_time    = _ts(window[-1]),
                    description = f"{src_ip} scanned {len(unique_ports)} unique ports in {PORT_SCAN_WINDOW}s",
                    severity    = "HIGH",
                ))
                break  # one chain per src_ip
    return chains


def detect_brute_force(events: List[ForensicEvent]) -> List[AttackChain]:
    chains: List[AttackChain] = []
    fail_evts = [e for e in events if e.event_type == "Login Failure" and e.src_ip]
    succ_map: Dict[str, ForensicEvent] = {
        e.src_ip: e for e in events if e.event_type == "Login Success" and e.src_ip
    }

    by_src: Dict[str, List[ForensicEvent]] = defaultdict(list)
    for e in fail_evts:
        by_src[e.src_ip].append(e)

    for src_ip, evts in by_src.items():
        evts.sort(key=_ts)
        w0 = 0
        for i, e in enumerate(evts):
            while w0 < i and (_ts(e) - _ts(evts[w0])).total_seconds() > BRUTE_FORCE_WINDOW:
                w0 += 1
            window = evts[w0:i + 1]
            if len(window) >= BRUTE_FORCE_TRIES:
                succeeded = src_ip in succ_map
                severity  = "CRITICAL" if succeeded else "HIGH"
                cid       = uuid.uuid4().hex[:8]
                reason    = (
                    f"SSH brute force: {len(window)} failed attempts"
                    + (" — LOGIN SUCCEEDED" if succeeded else "")
                )
                for ev in window:
                    _tag(ev, "Initial Access", "HIGH", reason, cid)
                eids = [ev.event_id for ev in window]
                end_ts = _ts(window[-1])
                if succeeded:
                    succ_ev = succ_map[src_ip]
                    _tag(succ_ev, "Initial Access", "CRITICAL",
                         "Successful login after brute force", cid)
                    eids.append(succ_ev.event_id)
                    end_ts = max(end_ts, _ts(succ_ev))

                chains.append(AttackChain(
                    chain_id    = cid,
                    name        = (f"SSH Brute Force from {src_ip}"
                                   + (" — COMPROMISED" if succeeded else "")),
                    attacker_ip = src_ip,
                    phases      = ["Initial Access"],
                    event_ids   = eids,
                    start_time  = _ts(window[0]),
                    end_time    = end_ts,
                    description = (
                        f"{src_ip} made {len(window)} failed SSH login attempts. "
                        + ("Login succeeded — system compromised." if succeeded
                           else "Attack did not succeed.")
                    ),
                    severity    = severity,
                ))
                break  # one chain per attacker
    return chains


def detect_privilege_escalation(events: List[ForensicEvent]) -> List[AttackChain]:
    chains: List[AttackChain] = []
    # Only chain actual root escalation, not routine sudo commands
    # Privileged Command (non-root sudo) is flagged individually but not chained
    priv_evts = [e for e in events if e.event_type == "Root Escalation"]
    if not priv_evts:
        return chains
    # Group by hostname so one chain per host
    by_host: Dict[str, List[ForensicEvent]] = defaultdict(list)
    for e in priv_evts:
        by_host[e.hostname or "_unknown_"].append(e)

    for host, evts in by_host.items():
        evts.sort(key=_ts)
        cid = uuid.uuid4().hex[:8]
        reason = "Privilege escalation detected"
        for e in evts:
            _tag(e, "Privilege Escalation", "CRITICAL", reason, cid)
        chains.append(AttackChain(
            chain_id    = cid,
            name        = f"Privilege Escalation on {host}",
            attacker_ip = evts[0].src_ip,
            victim_ip   = host,
            phases      = ["Privilege Escalation"],
            event_ids   = [e.event_id for e in evts],
            start_time  = _ts(evts[0]),
            end_time    = _ts(evts[-1]),
            description = f"{len(evts)} privilege escalation events on {host}: "
                          + "; ".join(e.description[:60] for e in evts[:3]),
            severity    = "CRITICAL",
        ))
    return chains


def detect_lateral_movement(events: List[ForensicEvent]) -> List[AttackChain]:
    chains: List[AttackChain] = []
    lateral = [
        e for e in events
        if e.source_type in ("network", "pcap", "auth")
        and e.dst_port in _LATERAL_PORTS
        and _is_internal(e.src_ip) and _is_internal(e.dst_ip)
        and e.src_ip != e.dst_ip
    ]
    by_src: Dict[str, List[ForensicEvent]] = defaultdict(list)
    for e in lateral:
        by_src[e.src_ip].append(e)

    for src_ip, evts in by_src.items():
        unique_targets = {e.dst_ip for e in evts}
        if len(unique_targets) < 2:
            continue
        cid    = uuid.uuid4().hex[:8]
        reason = f"Lateral movement to {len(unique_targets)} internal hosts"
        for e in evts:
            _tag(e, "Lateral Movement", "HIGH", reason, cid)
        chains.append(AttackChain(
            chain_id    = cid,
            name        = f"Lateral Movement from {src_ip}",
            attacker_ip = src_ip,
            phases      = ["Lateral Movement"],
            event_ids   = [e.event_id for e in evts],
            start_time  = _ts(evts[0]),
            end_time    = _ts(evts[-1]),
            description = (f"{src_ip} connected to {len(unique_targets)} internal hosts: "
                           + ", ".join(list(unique_targets)[:5])),
            severity    = "HIGH",
        ))
    return chains


EXFIL_MIN_CONNECTIONS = 2  # require at least 2 connections to avoid false positives

def detect_exfiltration(events: List[ForensicEvent]) -> List[AttackChain]:
    chains: List[AttackChain] = []
    # Network exfil: internal → external on C2 ports
    exfil_evts = [
        e for e in events
        if e.source_type in ("network", "pcap")
        and _is_internal(e.src_ip) and _is_external(e.dst_ip)
        and e.dst_port in _C2_PORTS
    ]
    # Group by dst_ip so one chain per external destination
    by_dst: Dict[str, List[ForensicEvent]] = defaultdict(list)
    for e in exfil_evts:
        by_dst[e.dst_ip].append(e)

    for dst_ip, evts in by_dst.items():
        if len(evts) < EXFIL_MIN_CONNECTIONS:
            continue
        evts.sort(key=_ts)
        cid    = uuid.uuid4().hex[:8]
        reason = f"Data sent to external {dst_ip} on suspicious port {evts[0].dst_port}"
        for e in evts:
            _tag(e, "Exfiltration", "CRITICAL", reason, cid)
        chains.append(AttackChain(
            chain_id    = cid,
            name        = f"Data Exfiltration → {dst_ip}:{evts[0].dst_port}",
            attacker_ip = evts[0].src_ip,
            victim_ip   = dst_ip,
            phases      = ["Exfiltration"],
            event_ids   = [e.event_id for e in evts],
            start_time  = _ts(evts[0]),
            end_time    = _ts(evts[-1]),
            description = (f"{evts[0].src_ip} sent data to external host {dst_ip} "
                           f"on port {evts[0].dst_port} ({len(evts)} connections)"),
            severity    = "CRITICAL",
        ))

    # Also tag syslog staging events (no chain, just phase/severity)
    for e in events:
        if e.source_type in ("syslog", "auth") and e.kill_chain_phase == "":
            d = e.description.lower()
            if any(x in d for x in ["archiv", "staging", "tar ", "zip ", ".exfil"]):
                e.kill_chain_phase = "Collection"
                if SEVERITY_ORDER.get(e.severity, 0) < SEVERITY_ORDER["HIGH"]:
                    e.severity = "HIGH"

    return chains


def detect_c2_beaconing(events: List[ForensicEvent]) -> List[AttackChain]:
    chains: List[AttackChain] = []
    c2_evts = [
        e for e in events
        if e.source_type in ("network", "pcap")
        and _is_external(e.dst_ip)
        and e.dst_port in _C2_PORTS
    ]
    # Group by (dst_ip, dst_port) — one chain per C2 endpoint
    by_endpoint: Dict[Tuple, List[ForensicEvent]] = defaultdict(list)
    for e in c2_evts:
        by_endpoint[(e.dst_ip, e.dst_port)].append(e)

    for (dst_ip, dst_port), evts in by_endpoint.items():
        if len(evts) < C2_MIN_CONNECTIONS:
            continue
        evts.sort(key=_ts)
        cid    = uuid.uuid4().hex[:8]
        reason = f"C2 beaconing to {dst_ip}:{dst_port} ({len(evts)} connections)"
        for e in evts:
            _tag(e, "Command & Control", "CRITICAL", reason, cid)
        chains.append(AttackChain(
            chain_id    = cid,
            name        = f"C2 Beaconing → {dst_ip}:{dst_port}",
            attacker_ip = evts[0].src_ip,
            victim_ip   = dst_ip,
            phases      = ["Command & Control"],
            event_ids   = [e.event_id for e in evts],
            start_time  = _ts(evts[0]),
            end_time    = _ts(evts[-1]),
            description = f"Repeated connections to {dst_ip}:{dst_port} ({len(evts)} packets)",
            severity    = "CRITICAL",
        ))
    return chains


def detect_log_tampering(events: List[ForensicEvent]) -> List[AttackChain]:
    """Group ALL log-tampering events into a single chain (not one per event)."""
    chains: List[AttackChain] = []
    tamper_evts = [
        e for e in events
        if e.event_type in ("Log Tampering", "File Deletion")
        and any(x in (e.raw or e.description).lower()
                for x in ["auth.log", "syslog", "kern.log", ".log", "audit", "btmp"])
    ]
    if not tamper_evts:
        return chains

    tamper_evts.sort(key=_ts)
    cid    = uuid.uuid4().hex[:8]
    reason = "Log file deletion / tampering — attacker covering tracks"
    for e in tamper_evts:
        _tag(e, "Defense Evasion", "CRITICAL", reason, cid)

    file_names = list({
        w for e in tamper_evts
        for w in (e.raw or e.description).split()
        if '.log' in w or 'btmp' in w or 'audit' in w
    })[:6]

    chains.append(AttackChain(
        chain_id    = cid,
        name        = "Log Tampering / Defense Evasion",
        attacker_ip = tamper_evts[0].src_ip,
        victim_ip   = tamper_evts[0].hostname,
        phases      = ["Defense Evasion"],
        event_ids   = [e.event_id for e in tamper_evts],
        start_time  = _ts(tamper_evts[0]),
        end_time    = _ts(tamper_evts[-1]),
        description = (f"Attacker deleted {len(tamper_evts)} forensic evidence files: "
                       + ", ".join(file_names)),
        severity    = "CRITICAL",
    ))
    return chains


def detect_web_attacks(events: List[ForensicEvent]) -> List[AttackChain]:
    chains: List[AttackChain] = []
    web_atk = [
        e for e in events
        if e.source_type == "web" and e.severity in ("HIGH", "CRITICAL", "MEDIUM")
    ]
    by_src: Dict[str, List[ForensicEvent]] = defaultdict(list)
    for e in web_atk:
        if e.src_ip:
            by_src[e.src_ip].append(e)

    for src_ip, evts in by_src.items():
        if len(evts) < 3:
            continue
        evts.sort(key=_ts)
        cid    = uuid.uuid4().hex[:8]
        reason = f"Web attack pattern from {src_ip}"
        for e in evts:
            _tag(e, "Reconnaissance", "HIGH", reason, cid)
        chains.append(AttackChain(
            chain_id    = cid,
            name        = f"Web Attack from {src_ip}",
            attacker_ip = src_ip,
            phases      = ["Reconnaissance"],
            event_ids   = [e.event_id for e in evts],
            start_time  = _ts(evts[0]),
            end_time    = _ts(evts[-1]),
            description = (f"{src_ip} made {len(evts)} suspicious web requests "
                           f"(SQLi, XSS, path enumeration)"),
            severity    = "HIGH",
        ))
    return chains


def detect_credential_access(events: List[ForensicEvent]) -> List[AttackChain]:
    """Group all credential-access events into a single chain."""
    chains: List[AttackChain] = []
    cred_evts = [e for e in events if e.event_type == "Credential File Access"]
    if not cred_evts:
        return chains

    cred_evts.sort(key=_ts)
    cid    = uuid.uuid4().hex[:8]
    reason = "Access to credential files (/etc/shadow or similar)"
    for e in cred_evts:
        _tag(e, "Credential Access", "CRITICAL", reason, cid)

    chains.append(AttackChain(
        chain_id    = cid,
        name        = "Credential Access — Password Files",
        attacker_ip = cred_evts[0].src_ip,
        phases      = ["Credential Access"],
        event_ids   = [e.event_id for e in cred_evts],
        start_time  = _ts(cred_evts[0]),
        end_time    = _ts(cred_evts[-1]),
        description = (f"Attacker accessed {len(cred_evts)} credential files: "
                       + "; ".join(e.description[:60] for e in cred_evts[:3])),
        severity    = "CRITICAL",
    ))
    return chains


# ── Merge overlapping chains by attacker ──────────────────────────────────────

_PHASE_ORDER = {p: i for i, p in enumerate([
    "Reconnaissance", "Initial Access", "Execution",
    "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection",
    "Command & Control", "Exfiltration",
])}


def _merge_chains_by_attacker(chains: List[AttackChain]) -> List[AttackChain]:
    """
    For each attacker IP that has multiple sub-chains, create a top-level
    'Multi-Stage Attack' chain. Sub-chains are preserved alongside it.
    Chains with no attacker IP are returned as-is.
    """
    by_attacker: Dict[str, List[AttackChain]] = defaultdict(list)
    no_attacker: List[AttackChain] = []

    for c in chains:
        if c.attacker_ip:
            by_attacker[c.attacker_ip].append(c)
        else:
            no_attacker.append(c)

    result: List[AttackChain] = []

    for attacker, sub_chains in by_attacker.items():
        if len(sub_chains) == 1:
            result.append(sub_chains[0])
            continue

        # Build master chain
        all_phases: List[str] = []
        all_eids:   List[str] = []
        all_times:  List[datetime] = []
        max_sev = "INFO"
        victims: set = set()

        for sc in sub_chains:
            all_phases.extend(sc.phases)
            all_eids.extend(sc.event_ids)
            if sc.start_time: all_times.append(sc.start_time)
            if sc.end_time:   all_times.append(sc.end_time)
            if SEVERITY_ORDER.get(sc.severity, 0) > SEVERITY_ORDER.get(max_sev, 0):
                max_sev = sc.severity
            if sc.victim_ip:
                for v in sc.victim_ip.split(", "):
                    if v.strip():
                        victims.add(v.strip())

        # Deduplicate + sort phases by kill chain order
        ordered_phases = sorted(
            set(all_phases),
            key=lambda p: _PHASE_ORDER.get(p, 99),
        )

        master_cid = uuid.uuid4().hex[:8]
        master = AttackChain(
            chain_id    = master_cid,
            name        = f"⚠ Multi-Stage Attack — {attacker}",
            attacker_ip = attacker,
            victim_ip   = ", ".join(list(victims)[:4]),
            phases      = ordered_phases,
            event_ids   = list(set(all_eids)),
            start_time  = min(all_times) if all_times else None,
            end_time    = max(all_times) if all_times else None,
            description = (
                f"Coordinated multi-stage attack from {attacker}. "
                f"Kill chain: {' → '.join(ordered_phases)}. "
                f"Targets: {', '.join(list(victims)[:4]) or 'N/A'}."
            ),
            severity    = max_sev,
        )
        result.append(master)
        result.extend(sub_chains)

    result.extend(no_attacker)
    # Sort: master chains first, then by severity descending
    result.sort(key=lambda c: (
        0 if c.name.startswith("⚠") else 1,
        -SEVERITY_ORDER.get(c.severity, 0),
    ))
    return result


# ── Main entry point ──────────────────────────────────────────────────────────

def run_detection(events: List[ForensicEvent]) -> List[AttackChain]:
    all_chains: List[AttackChain] = []
    all_chains.extend(detect_port_scans(events))
    all_chains.extend(detect_brute_force(events))
    all_chains.extend(detect_privilege_escalation(events))
    all_chains.extend(detect_lateral_movement(events))
    # Run C2 before exfiltration so duplicate events prefer the C2 label
    all_chains.extend(detect_c2_beaconing(events))
    all_chains.extend(detect_exfiltration(events))
    all_chains.extend(detect_log_tampering(events))
    all_chains.extend(detect_web_attacks(events))
    all_chains.extend(detect_credential_access(events))
    merged = _merge_chains_by_attacker(all_chains)
    _deduplicate_event_ids(merged)
    # Drop any chains that ended up with no events after dedup
    return [c for c in merged if c.event_ids]

# ── Post-processing: remove duplicate event_ids across sub-chains ─────────────

def _deduplicate_event_ids(chains: List[AttackChain]) -> None:
    """
    Within sub-chains (not master chains), remove event_ids that are already
    claimed by a higher-priority chain so the same event isn't counted twice.
    Master chains (Multi-Stage) are allowed to reference all events.
    Priority order: C2 > Exfiltration (same events, C2 is more specific).
    """
    # Find exfiltration and C2 chains covering the same events
    c2_eids: set = set()
    for c in chains:
        if c.name.startswith("C2 Beaconing"):
            c2_eids.update(c.event_ids)

    for c in chains:
        if c.name.startswith("Data Exfiltration") and not c.name.startswith("⚠"):
            # Remove any events already owned by a C2 chain
            c.event_ids = [eid for eid in c.event_ids if eid not in c2_eids]
            if not c.event_ids:
                c.event_ids = []  # will be filtered out below
