"""
Timeline gap detection — identifies suspicious gaps in evidence.
"""
from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List

from app.core.models import ForensicEvent, TimelineGap

GAP_THRESHOLD_MINUTES = 10.0   # gaps > this are flagged


def detect_gaps(events: List[ForensicEvent]) -> List[TimelineGap]:
    """Find suspicious gaps in the timeline per source."""
    if len(events) < 2:
        return []

    gaps: List[TimelineGap] = []
    by_source: Dict[str, List[ForensicEvent]] = defaultdict(list)
    for e in events:
        if e.timestamp:
            by_source[e.source].append(e)

    for source, evts in by_source.items():
        evts.sort(key=lambda x: x.timestamp)
        for i in range(1, len(evts)):
            delta = (evts[i].timestamp - evts[i-1].timestamp).total_seconds() / 60
            if delta >= GAP_THRESHOLD_MINUTES:
                g = TimelineGap(
                    gap_id           = uuid.uuid4().hex[:8],
                    start            = evts[i-1].timestamp,
                    end              = evts[i].timestamp,
                    duration_minutes = delta,
                    source           = source,
                    description      = (
                        f"{delta:.1f}-minute gap in {source}. "
                        "Possible log deletion or missing evidence."
                        if delta > 60 else
                        f"{delta:.1f}-minute gap in {source}."
                    ),
                )
                gaps.append(g)

    gaps.sort(key=lambda g: g.duration_minutes, reverse=True)
    return gaps[:20]  # top 20 most significant gaps


def correlate_events(events: List[ForensicEvent]) -> None:
    """Link events that share the same IP or user across different sources."""
    by_ip:   Dict[str, List[str]] = defaultdict(list)
    by_user: Dict[str, List[str]] = defaultdict(list)

    for e in events:
        if e.src_ip:
            by_ip[e.src_ip].append(e.event_id)
        if e.dst_ip:
            by_ip[e.dst_ip].append(e.event_id)
        if e.user:
            by_user[e.user].append(e.event_id)

    eid_to_event = {e.event_id: e for e in events}

    for ip, eids in by_ip.items():
        if len(eids) > 1:
            for eid in eids:
                if eid in eid_to_event:
                    others = [x for x in eids[:10] if x != eid]
                    eid_to_event[eid].correlation_ids = list(set(
                        eid_to_event[eid].correlation_ids + others
                    ))[:10]

    for user, eids in by_user.items():
        if len(eids) > 1:
            for eid in eids:
                if eid in eid_to_event:
                    others = [x for x in eids[:10] if x != eid]
                    eid_to_event[eid].correlation_ids = list(set(
                        eid_to_event[eid].correlation_ids + others
                    ))[:10]
