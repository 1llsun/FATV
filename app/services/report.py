"""
Report generation for FATV.

The report is HTML so it can be opened in a browser and printed/saved as PDF.
All user-controlled evidence values are HTML-escaped before insertion.
"""
from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any, Dict, List

from app.core.models import AttackChain, Entity, ForensicEvent, TimelineGap, SEVERITY_COLORS


def _h(value: Any) -> str:
    """Escape text before putting it inside HTML."""
    if value is None:
        return ""
    return escape(str(value), quote=True)


def _severity_badge(sev: str) -> str:
    colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316",
              "MEDIUM": "#f59e0b", "LOW": "#3b82f6", "INFO": "#64748b"}
    sev_safe = _h(sev)
    c = colors.get(sev, "#64748b")
    return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">{sev_safe}</span>'


def generate_html_report(ctx: Dict[str, Any]) -> str:
    events: List[ForensicEvent] = ctx.get("events", [])
    chains: List[AttackChain] = ctx.get("attack_chains", [])
    entities: List[Entity] = ctx.get("entities", [])
    gaps: List[TimelineGap] = ctx.get("gaps", [])
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    case_id = ctx.get("case_id", "N/A")

    crit = sum(1 for e in events if e.severity == "CRITICAL")
    high = sum(1 for e in events if e.severity == "HIGH")
    anom = sum(1 for e in events if e.is_anomaly)

    master_chains = [c for c in chains if "Multi-Stage" in c.name]
    sub_chains = [c for c in chains if "Multi-Stage" not in c.name]

    events_table_rows = ""
    for e in sorted(events, key=lambda x: x.timestamp or datetime.min)[:500]:
        ts = e.timestamp.strftime("%H:%M:%S") if e.timestamp else ""
        events_table_rows += f"""<tr>
            <td>{_h(ts)}</td>
            <td>{_severity_badge(e.severity)}</td>
            <td><span style="color:#94a3b8;font-size:11px">{_h(e.source_type)}</span></td>
            <td style="font-weight:600">{_h(e.event_type)}</td>
            <td>{_h(e.src_ip or '-')}</td>
            <td>{_h(e.dst_ip or '-')}</td>
            <td style="color:#94a3b8;font-size:12px">{_h((e.description or '')[:100])}</td>
        </tr>"""

    chains_html = ""
    for c in (master_chains + sub_chains)[:15]:
        phases_html = " → ".join(
            f'<span style="background:#1e293b;padding:2px 8px;border-radius:4px;font-size:11px">{_h(p)}</span>'
            for p in c.phases
        )
        dur = ""
        if c.start_time and c.end_time:
            dur_s = int((c.end_time - c.start_time).total_seconds())
            dur = f"{dur_s//60}m {dur_s%60}s"
        chain_color = SEVERITY_COLORS.get(c.severity, "#64748b")
        chains_html += f"""<div style="border:1px solid #334155;border-left:4px solid {chain_color};
                            padding:16px;margin:12px 0;border-radius:8px;background:#0f172a">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <h3 style="margin:0;color:#e2e8f0;font-size:15px">{_h(c.name)}</h3>
                {_severity_badge(c.severity)}
            </div>
            <div style="margin:8px 0;color:#94a3b8;font-size:13px">{_h(c.description)}</div>
            <div style="margin:6px 0">{phases_html}</div>
            <div style="margin-top:8px;color:#64748b;font-size:12px">
                {_h(len(c.event_ids))} events · Attacker: {_h(c.attacker_ip or 'N/A')} · Duration: {_h(dur or 'N/A')}
            </div>
        </div>"""

    entities_rows = ""
    for ent in entities[:30]:
        if ent.entity_type == "ip":
            icon = "🌐"
        elif ent.entity_type == "user":
            icon = "👤"
        else:
            icon = "💻"
        sources = ", ".join(list(set(ent.sources))[:3])
        first_seen = ent.first_seen.strftime('%H:%M:%S') if ent.first_seen else '-'
        entities_rows += f"""<tr>
            <td>{icon} {_h(ent.value)}</td>
            <td>{_h(ent.entity_type)}</td>
            <td>{_severity_badge(ent.severity)}</td>
            <td>{_h(ent.event_count)}</td>
            <td>{_h(sources)}</td>
            <td>{_h(first_seen)}</td>
        </tr>"""

    gaps_html = ""
    for g in gaps[:10]:
        gaps_html += f"""<tr>
            <td style="color:#f59e0b">⚠ Gap</td>
            <td>{_h(g.source)}</td>
            <td>{_h(g.start_human)} – {_h(g.end_human)}</td>
            <td>{_h(f'{g.duration_minutes:.1f} min')}</td>
            <td style="color:#94a3b8;font-size:12px">{_h(g.description)}</td>
        </tr>"""

    time_start = ctx.get("time_start", "N/A")
    time_end = ctx.get("time_end", "N/A")
    source_count = len(ctx.get('sources', []))

    gaps_section = (
        '<table><thead><tr><th>Type</th><th>Source</th><th>Time Range</th><th>Duration</th><th>Note</th></tr></thead><tbody>'
        + gaps_html + '</tbody></table>'
        if gaps_html else '<p style="color:#64748b;padding:16px">No significant gaps detected.</p>'
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Report — {_h(case_id)}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ font-family:'Segoe UI',sans-serif; background:#0a0e1a; color:#e2e8f0; padding:40px }}
  h1 {{ font-size:28px; color:#22d3ee; margin-bottom:4px }}
  h2 {{ font-size:18px; color:#94a3b8; border-bottom:1px solid #334155; padding-bottom:8px; margin:32px 0 16px }}
  table {{ width:100%; border-collapse:collapse; font-size:13px }}
  th {{ background:#1e293b; padding:10px 12px; text-align:left; color:#94a3b8; font-weight:600 }}
  td {{ padding:8px 12px; border-bottom:1px solid #1e293b; vertical-align:top }}
  .stat-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin:16px 0 }}
  .stat {{ background:#1e293b; padding:16px; border-radius:10px; text-align:center }}
  .stat .num {{ font-size:28px; font-weight:700; color:#22d3ee }}
  .stat .lbl {{ color:#64748b; font-size:12px; margin-top:4px }}
  .header-bar {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:24px }}
  .print-btn {{ background:#2563eb; color:#fff; border:none; padding:10px 20px; border-radius:8px;
               cursor:pointer; font-size:14px }}
  @media print {{ .print-btn {{ display:none }} .no-break {{ page-break-inside:avoid }} }}
</style>
</head>
<body>
<div class="header-bar">
  <div>
    <h1>🔬 Forensic Investigation Report</h1>
    <p style="color:#64748b;margin-top:4px">Case ID: {_h(case_id)} &nbsp;|&nbsp; Generated: {_h(now)}</p>
  </div>
  <button class="print-btn" onclick="window.print()">🖨 Print / Save PDF</button>
</div>

<div style="background:#1e293b;padding:16px 20px;border-radius:10px;margin-bottom:24px;border-left:4px solid #22d3ee">
  <strong>Investigators:</strong> Farhan Saifullah &amp; Tayyab Ayub &nbsp;|&nbsp;
  <strong>Course:</strong> Digital Forensics — Riphah International University &nbsp;|&nbsp;
  <strong>Period:</strong> {_h(time_start)} → {_h(time_end)}
</div>

<h2>Executive Summary</h2>
<div class="stat-grid">
  <div class="stat"><div class="num">{_h(len(events))}</div><div class="lbl">Total Events</div></div>
  <div class="stat"><div class="num" style="color:#ef4444">{_h(crit)}</div><div class="lbl">Critical</div></div>
  <div class="stat"><div class="num" style="color:#f97316">{_h(high)}</div><div class="lbl">High</div></div>
  <div class="stat"><div class="num" style="color:#f59e0b">{_h(anom)}</div><div class="lbl">Anomalies</div></div>
  <div class="stat"><div class="num">{_h(len(chains))}</div><div class="lbl">Attack Chains</div></div>
  <div class="stat"><div class="num">{_h(len(entities))}</div><div class="lbl">Entities</div></div>
  <div class="stat"><div class="num">{_h(len(gaps))}</div><div class="lbl">Evidence Gaps</div></div>
  <div class="stat"><div class="num">{_h(source_count)}</div><div class="lbl">Data Sources</div></div>
</div>

<h2>Detected Attack Chains</h2>
{chains_html or '<p style="color:#64748b;padding:16px">No attack chains detected.</p>'}

<h2>Evidence Timeline Gaps</h2>
{gaps_section}

<h2>Entity Analysis</h2>
<table>
  <thead><tr><th>Entity</th><th>Type</th><th>Severity</th><th>Events</th><th>Sources</th><th>First Seen</th></tr></thead>
  <tbody>{entities_rows}</tbody>
</table>

<h2>Full Event Log (first 500 events)</h2>
<table>
  <thead>
    <tr><th>Time</th><th>Severity</th><th>Source</th><th>Event Type</th>
        <th>Src IP</th><th>Dst IP</th><th>Description</th></tr>
  </thead>
  <tbody>{events_table_rows}</tbody>
</table>

<div style="margin-top:40px;padding:20px;border-top:1px solid #334155;color:#64748b;font-size:12px;text-align:center">
  Generated by FATV — Forensic Artifact Timeline Visualizer &nbsp;|&nbsp;
  Farhan Saifullah &amp; Tayyab Ayub &nbsp;|&nbsp; Digital Forensics, Riphah International University 2026
</div>
</body>
</html>"""
    return html
