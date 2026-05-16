"""
Entity extraction & tracking service.
Builds a graph of IPs, users, and hostnames from all events.
"""
from __future__ import annotations

import uuid
from collections import defaultdict
from typing import Dict, List

from app.core.models import Entity, ForensicEvent, SEVERITY_ORDER


def extract_entities(events: List[ForensicEvent]) -> List[Entity]:
    ips:   Dict[str, Entity] = {}
    users: Dict[str, Entity] = {}
    hosts: Dict[str, Entity] = {}

    def _get_or_create(store: Dict, key: str, etype: str) -> Entity:
        if key not in store:
            store[key] = Entity(
                entity_id   = uuid.uuid4().hex[:8],
                entity_type = etype,
                value       = key,
                is_internal = (etype != "ip") or any(
                    key.startswith(p) for p in ("10.", "192.168.", "172.", "127.")
                ),
            )
        return store[key]

    for e in events:
        sev_num = SEVERITY_ORDER.get(e.severity, 0)

        for ip in [e.src_ip, e.dst_ip]:
            if not ip or ip in ("0.0.0.0", "unknown", ""):
                continue
            ent = _get_or_create(ips, ip, "ip")
            ent.event_count += 1
            if sev_num >= SEVERITY_ORDER["CRITICAL"]:
                ent.critical_count += 1
            ent.sources.append(e.source)
            if not ent.first_seen or e.timestamp < ent.first_seen:
                ent.first_seen = e.timestamp
            if not ent.last_seen or e.timestamp > ent.last_seen:
                ent.last_seen = e.timestamp
            if SEVERITY_ORDER.get(e.severity, 0) > SEVERITY_ORDER.get(ent.severity, 0):
                ent.severity = e.severity

        # Link src ↔ dst
        if e.src_ip and e.dst_ip and e.src_ip in ips and e.dst_ip in ips:
            if e.dst_ip not in ips[e.src_ip].connected_to:
                ips[e.src_ip].connected_to.append(e.dst_ip)
            if e.src_ip not in ips[e.dst_ip].connected_to:
                ips[e.dst_ip].connected_to.append(e.src_ip)

        if e.user and e.user not in ("-", "", "root_ignored", "nan", "null"):
            ent = _get_or_create(users, e.user, "user")
            ent.event_count += 1
            ent.sources.append(e.source)
            if not ent.first_seen or e.timestamp < ent.first_seen:
                ent.first_seen = e.timestamp
            if not ent.last_seen or e.timestamp > ent.last_seen:
                ent.last_seen = e.timestamp
            if SEVERITY_ORDER.get(e.severity, 0) > SEVERITY_ORDER.get(ent.severity, 0):
                ent.severity = e.severity

        if e.hostname and e.hostname not in ("-", "", "localhost", "nan", "null"):
            ent = _get_or_create(hosts, e.hostname, "hostname")
            ent.event_count += 1
            ent.sources.append(e.source)

    all_entities = list(ips.values()) + list(users.values()) + list(hosts.values())
    all_entities.sort(key=lambda x: (SEVERITY_ORDER.get(x.severity, 0), x.event_count), reverse=True)
    return all_entities
