"""
Core data models for the Forensic Artifact Timeline Visualizer.
Farhan Saifullah & Tayyab Ayub — Digital Forensics, 2026
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

# ── Severity ──────────────────────────────────────────────────────────────────
SEVERITY_ORDER  = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#f59e0b",
    "LOW":      "#3b82f6",
    "INFO":     "#64748b",
}
SEVERITY_SIZES  = {"CRITICAL": 18, "HIGH": 14, "MEDIUM": 11, "LOW": 9, "INFO": 7}

# ── Source types ──────────────────────────────────────────────────────────────
SOURCE_COLORS = {
    "auth":       "#a78bfa",
    "network":    "#22d3ee",
    "syslog":     "#34d399",
    "filesystem": "#fb923c",
    "pcap":       "#f472b6",
    "web":        "#fbbf24",
    "windows":    "#60a5fa",
    "unknown":    "#94a3b8",
}
SOURCE_SYMBOLS = {
    "auth":       "circle",
    "network":    "diamond",
    "syslog":     "square",
    "filesystem": "triangle-up",
    "pcap":       "star",
    "web":        "cross",
    "windows":    "pentagon",
    "unknown":    "circle-open",
}

# ── Attack Kill Chain Phases ───────────────────────────────────────────────────
KILL_CHAIN_PHASES = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command & Control",
    "Exfiltration",
]

PHASE_COLORS = {
    "Reconnaissance":    "#6366f1",
    "Initial Access":    "#f97316",
    "Execution":         "#ef4444",
    "Privilege Escalation": "#dc2626",
    "Defense Evasion":   "#78716c",
    "Credential Access": "#ec4899",
    "Discovery":         "#8b5cf6",
    "Lateral Movement":  "#0ea5e9",
    "Collection":        "#f59e0b",
    "Command & Control": "#10b981",
    "Exfiltration":      "#e11d48",
}


# ── ForensicEvent ──────────────────────────────────────────────────────────────
@dataclass
class ForensicEvent:
    timestamp: datetime
    source: str           # filename
    source_type: str      # auth | network | syslog | filesystem | pcap | web | windows | unknown
    event_type: str       # human-readable type
    description: str

    severity: str = "INFO"
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    user: str = ""
    hostname: str = ""
    raw: str = ""

    tags: List[str] = field(default_factory=list)
    note: str = ""

    # Correlation / detection
    attack_chain_id: str = ""
    kill_chain_phase: str = ""
    correlation_ids: List[str] = field(default_factory=list)
    is_anomaly: bool = False
    anomaly_reason: str = ""

    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])

    def to_dict(self) -> dict:
        return {
            "event_id":         self.event_id,
            "timestamp":        self.timestamp.isoformat() if self.timestamp else None,
            "timestamp_human":  self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "",
            "source":           self.source,
            "source_type":      self.source_type,
            "event_type":       self.event_type,
            "description":      self.description[:300],
            "severity":         self.severity,
            "src_ip":           self.src_ip,
            "dst_ip":           self.dst_ip,
            "src_port":         self.src_port,
            "dst_port":         self.dst_port,
            "protocol":         self.protocol,
            "user":             self.user,
            "hostname":         self.hostname,
            "raw":              self.raw[:500] if self.raw else "",
            "tags":             self.tags,
            "note":             self.note,
            "attack_chain_id":  self.attack_chain_id,
            "kill_chain_phase": self.kill_chain_phase,
            "correlation_ids":  self.correlation_ids,
            "is_anomaly":       self.is_anomaly,
            "anomaly_reason":   self.anomaly_reason,
            "severity_num":     SEVERITY_ORDER.get(self.severity, 0),
            "severity_color":   SEVERITY_COLORS.get(self.severity, "#64748b"),
            "severity_size":    SEVERITY_SIZES.get(self.severity, 7),
            "source_color":     SOURCE_COLORS.get(self.source_type, "#94a3b8"),
            "source_symbol":    SOURCE_SYMBOLS.get(self.source_type, "circle"),
            "phase_color":      PHASE_COLORS.get(self.kill_chain_phase, "#64748b"),
        }


# ── AttackChain ────────────────────────────────────────────────────────────────
@dataclass
class AttackChain:
    chain_id: str
    name: str
    attacker_ip: str = ""
    victim_ip: str = ""
    phases: List[str] = field(default_factory=list)
    event_ids: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    description: str = ""
    severity: str = "HIGH"

    def to_dict(self) -> dict:
        dur = 0
        if self.start_time and self.end_time:
            dur = int((self.end_time - self.start_time).total_seconds())
        return {
            "chain_id":      self.chain_id,
            "name":          self.name,
            "attacker_ip":   self.attacker_ip,
            "victim_ip":     self.victim_ip,
            "phases":        self.phases,
            "event_count":   len(self.event_ids),
            "event_ids":     self.event_ids,
            "start_time":    self.start_time.isoformat() if self.start_time else None,
            "end_time":      self.end_time.isoformat() if self.end_time else None,
            "description":   self.description,
            "severity":      self.severity,
            "duration_sec":  dur,
            "severity_color": SEVERITY_COLORS.get(self.severity, "#64748b"),
        }


# ── Entity ─────────────────────────────────────────────────────────────────────
@dataclass
class Entity:
    entity_id: str
    entity_type: str   # ip | user | hostname | domain
    value: str

    event_count: int = 0
    critical_count: int = 0
    sources: List[str] = field(default_factory=list)
    connected_to: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    severity: str = "INFO"
    tags: List[str] = field(default_factory=list)
    is_internal: bool = True

    def to_dict(self) -> dict:
        return {
            "entity_id":     self.entity_id,
            "entity_type":   self.entity_type,
            "value":         self.value,
            "event_count":   self.event_count,
            "critical_count": self.critical_count,
            "sources":       list(set(self.sources)),
            "connected_to":  list(set(self.connected_to)),
            "first_seen":    self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":     self.last_seen.isoformat() if self.last_seen else None,
            "severity":      self.severity,
            "severity_color": SEVERITY_COLORS.get(self.severity, "#64748b"),
            "tags":          self.tags,
            "is_internal":   self.is_internal,
        }


# ── TimelineGap ────────────────────────────────────────────────────────────────
@dataclass
class TimelineGap:
    gap_id: str
    start: datetime
    end: datetime
    duration_minutes: float
    source: str
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "gap_id":            self.gap_id,
            "start":             self.start.isoformat(),
            "end":               self.end.isoformat(),
            "start_human":       self.start.strftime("%H:%M:%S"),
            "end_human":         self.end.strftime("%H:%M:%S"),
            "duration_minutes":  round(self.duration_minutes, 1),
            "source":            self.source,
            "description":       self.description,
        }
