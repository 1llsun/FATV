"""
FATV — Forensic Artifact Timeline Visualizer
Flask application entry point.

Authors: Farhan Saifullah & Tayyab Ayub
Course:  Digital Forensics, Riphah International University, 2026
"""
from __future__ import annotations

import io
import json
import os
import uuid
from datetime import datetime
from pathlib import Path

from flask import (Flask, flash, jsonify, redirect, render_template,
                   request, send_file, url_for)
from werkzeug.utils import secure_filename

from app.core.config import Config
from app.core.models import (SEVERITY_COLORS, SEVERITY_ORDER,
                              SOURCE_COLORS, KILL_CHAIN_PHASES, PHASE_COLORS)
from app.services.detection import run_detection
from app.services.entities import extract_entities
from app.services.ingestion import ingest_files
from app.services.report import generate_html_report
from app.services.timeline import correlate_events, detect_gaps

ALLOWED_EXTENSIONS = {".csv", ".log", ".txt", ".pcap", ".pcapng", ".cap"}


def _allowed(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def create_app() -> Flask:
    _HERE = Path(__file__).parent
    app = Flask(__name__,
                template_folder=str(_HERE / "templates"),
                static_folder=str(_HERE / "static"))
    app.config.from_object(Config)

    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["REPORT_FOLDER"]).mkdir(parents=True, exist_ok=True)

    # ── Index / Upload ─────────────────────────────────────────────────────────
    @app.route("/", methods=["GET", "POST"])
    def index():
        if request.method == "POST":
            files = request.files.getlist("evidence_files")
            if not files or all(f.filename == "" for f in files):
                flash("Please select at least one evidence file.", "warning")
                return redirect(url_for("index"))

            saved_paths = []
            for f in files:
                if not f or f.filename == "":
                    continue
                if not _allowed(f.filename):
                    flash(f"Skipped {f.filename} — unsupported type.", "warning")
                    continue
                fname = secure_filename(f.filename)
                # Prefix with a short unique id so evidence files with the same name do not overwrite each other.
                fname = f"{uuid.uuid4().hex[:8]}_{fname}"
                dest = Path(app.config["UPLOAD_FOLDER"]) / fname
                f.save(dest)
                saved_paths.append(str(dest))

            if not saved_paths:
                flash("No valid files uploaded.", "danger")
                return redirect(url_for("index"))

            try:
                _build_investigation(app, saved_paths)
                return redirect(url_for("timeline"))
            except ValueError as exc:
                msg = str(exc)
                if 'scapy' in msg.lower() or 'pcap' in msg.lower() or 'PCAP' in msg:
                    flash(
                        "PCAP analysis requires Scapy (not installed). "
                        "Please upload CSV or LOG files instead. "
                        "To enable PCAP: pip install scapy",
                        "warning"
                    )
                elif 'No events' in msg.lower() or 'no events' in msg.lower():
                    flash(
                        "No events could be parsed. "
                        "Supported formats: auth.log · syslog · Apache/Nginx logs · network CSV",
                        "warning"
                    )
                else:
                    flash(f"Analysis error: {msg}", "warning")
                return redirect(url_for("index"))
            except Exception as exc:
                flash(f"Unexpected error: {exc}", "danger")
                return redirect(url_for("index"))

        return render_template("index.html")

    # ── Timeline dashboard ─────────────────────────────────────────────────────
    @app.route("/timeline")
    def timeline():
        ctx = app.config.get("INVESTIGATION")
        if not ctx:
            flash("Upload evidence files first.", "info")
            return redirect(url_for("index"))
        return render_template("timeline.html", **ctx)

    # ── JSON API ───────────────────────────────────────────────────────────────
    @app.route("/api/events")
    def api_events():
        ctx = app.config.get("INVESTIGATION", {})
        return jsonify(ctx.get("events_list", []))

    @app.route("/api/attack_chains")
    def api_chains():
        ctx = app.config.get("INVESTIGATION", {})
        return jsonify(ctx.get("chains_list", []))

    @app.route("/api/entities")
    def api_entities():
        ctx = app.config.get("INVESTIGATION", {})
        return jsonify(ctx.get("entities_list", []))

    # ── Investigator Notes ─────────────────────────────────────────────────────
    @app.route("/api/note/<event_id>", methods=["POST"])
    def add_note(event_id: str):
        ctx = app.config.get("INVESTIGATION")
        if not ctx:
            return jsonify({"error": "No investigation loaded"}), 400
        data = request.get_json(silent=True) or {}
        note = str(data.get("note", "")).strip()
        events = ctx.get("_events_raw", [])
        for e in events:
            if e.event_id == event_id:
                e.note = note
                # Rebuild events_list entry
                for d in ctx["events_list"]:
                    if d["event_id"] == event_id:
                        d["note"] = note
                        break
                return jsonify({"ok": True, "note": note})
        return jsonify({"error": "Event not found"}), 404

    # ── Evidence Tags ──────────────────────────────────────────────────────────
    @app.route("/api/tag/<event_id>", methods=["POST"])
    def add_tag(event_id: str):
        ctx = app.config.get("INVESTIGATION")
        if not ctx:
            return jsonify({"error": "No investigation loaded"}), 400
        data = request.get_json(silent=True) or {}
        tag = str(data.get("tag", "")).strip()[:40]
        tag = " ".join(tag.split())
        if not tag:
            return jsonify({"error": "Empty tag"}), 400
        events = ctx.get("_events_raw", [])
        for e in events:
            if e.event_id == event_id:
                if tag not in e.tags:
                    e.tags.append(tag)
                for d in ctx["events_list"]:
                    if d["event_id"] == event_id:
                        d["tags"] = e.tags
                        break
                return jsonify({"ok": True, "tags": e.tags})
        return jsonify({"error": "Event not found"}), 404

    # ── Report ─────────────────────────────────────────────────────────────────
    @app.route("/report")
    def report():
        ctx = app.config.get("INVESTIGATION")
        if not ctx:
            flash("No investigation loaded.", "warning")
            return redirect(url_for("index"))
        html = generate_html_report(ctx)
        return html

    @app.route("/report/download")
    def report_download():
        ctx = app.config.get("INVESTIGATION")
        if not ctx:
            return redirect(url_for("index"))
        html = generate_html_report(ctx)
        buf = io.BytesIO(html.encode("utf-8"))
        buf.seek(0)
        return send_file(buf, mimetype="text/html", as_attachment=True,
                         download_name=f"forensic_report_{ctx['case_id']}.html")

    # ── Export events CSV ──────────────────────────────────────────────────────
    @app.route("/export/csv")
    def export_csv():
        ctx = app.config.get("INVESTIGATION")
        if not ctx:
            return redirect(url_for("index"))
        import csv as _csv
        output = io.StringIO()
        fields = ["event_id", "timestamp_human", "source", "source_type",
                  "event_type", "severity", "src_ip", "dst_ip",
                  "src_port", "dst_port", "protocol", "user",
                  "hostname", "description", "kill_chain_phase",
                  "attack_chain_id", "is_anomaly", "tags"]
        w = _csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(ctx.get("events_list", []))
        buf = io.BytesIO(output.getvalue().encode("utf-8"))
        buf.seek(0)
        return send_file(buf, mimetype="text/csv", as_attachment=True,
                         download_name=f"events_{ctx['case_id']}.csv")

    # ── Load sample data ───────────────────────────────────────────────────────
    @app.route("/load_sample", methods=["POST"])
    def load_sample():
        sample_dir = Path(__file__).parent / "samples"
        sample_files = list(sample_dir.glob("*"))
        paths = [str(p) for p in sample_files if p.suffix in
                 {".csv", ".log", ".txt"}]
        if not paths:
            flash("No sample files found.", "danger")
            return redirect(url_for("index"))
        try:
            _build_investigation(app, paths)
            return redirect(url_for("timeline"))
        except Exception as exc:
            flash(f"Sample load failed: {exc}", "danger")
            return redirect(url_for("index"))

    return app



_SCRIPT_ESC = '<' + chr(92) + '/'   # <\/ — safe to embed in <script> blocks

def _safe_json(obj) -> str:
    """Serialize to JSON and escape </ so raw </script> in log data cannot break the page."""
    return json.dumps(obj).replace('</', _SCRIPT_ESC)


# ── Investigation builder ──────────────────────────────────────────────────────
def _build_investigation(app: Flask, file_paths: list) -> None:
    events = ingest_files(file_paths)
    if not events:
        # Check if any file was a PCAP (they get skipped silently when Scapy missing)
        pcap_exts = {".pcap", ".pcapng", ".cap"}
        had_pcap = any(Path(fp).suffix.lower() in pcap_exts for fp in file_paths)
        if had_pcap:
            raise ValueError(
                "PCAP files require Scapy. No other parseable files were found. "
                "Please install Scapy (pip install scapy) or upload CSV/LOG files."
            )
        raise ValueError("No events could be parsed from the uploaded files.")

    chains = run_detection(events)
    correlate_events(events)
    entities = extract_entities(events)
    gaps = detect_gaps(events)

    ts_list  = [e.timestamp for e in events if e.timestamp]
    time_start = min(ts_list).strftime("%Y-%m-%d %H:%M:%S") if ts_list else "N/A"
    time_end   = max(ts_list).strftime("%Y-%m-%d %H:%M:%S") if ts_list else "N/A"

    case_id = f"INV-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    sources = list({e.source for e in events})

    sev_counts = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    for e in events:
        sev_counts[e.severity] = sev_counts.get(e.severity, 0) + 1

    events_list  = [e.to_dict() for e in events[:5000]]
    chains_list  = [c.to_dict() for c in chains]
    entities_list = [ent.to_dict() for ent in entities]
    gaps_list    = [g.to_dict() for g in gaps]

    # Build summary stats by source_type
    source_stats: dict = {}
    for e in events:
        st = e.source_type
        if st not in source_stats:
            source_stats[st] = {"count": 0, "color": SOURCE_COLORS.get(st, "#94a3b8")}
        source_stats[st]["count"] += 1

    # Kill chain phase summary
    phase_summary = {}
    for e in events:
        if e.kill_chain_phase:
            phase_summary[e.kill_chain_phase] = phase_summary.get(e.kill_chain_phase, 0) + 1

    app.config["INVESTIGATION"] = {
        "case_id":        case_id,
        "sources":        sources,
        "time_start":     time_start,
        "time_end":       time_end,
        "total_events":   len(events),
        "sev_counts":     sev_counts,
        "source_stats":   source_stats,
        "phase_summary":  phase_summary,
        "events_list":    events_list,
        "chains_list":    chains_list,
        "entities_list":  entities_list,
        "gaps_list":      gaps_list,
        "anomaly_count":  sum(1 for e in events if e.is_anomaly),
        # raw objects for note/tag mutations
        "_events_raw":    events,
        "_chains_raw":    chains,
        # for report
        "events":         events,
        "attack_chains":  chains,
        "entities":       entities,
        "gaps":           gaps,
        # JSON strings for template embedding — escaped so </script> in log data cannot break out
        "events_json":    _safe_json(events_list),
        "chains_json":    _safe_json(chains_list),
        "entities_json":  _safe_json(entities_list),
        "gaps_json":      _safe_json(gaps_list),
        "severity_colors_json": _safe_json(SEVERITY_COLORS),
        "phase_colors_json":    _safe_json(PHASE_COLORS),
        "source_colors_json":   _safe_json(SOURCE_COLORS),
        "kill_chain_phases":    KILL_CHAIN_PHASES,
    }


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5001)
