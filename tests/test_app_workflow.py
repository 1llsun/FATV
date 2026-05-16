"""Smoke tests for the FATV Flask workflow.

Run with: python -m pytest
"""
from __future__ import annotations

import importlib.util
from pathlib import Path


def load_main_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("fatv_main", root / "app.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def make_client():
    module = load_main_module()
    app = module.create_app()
    app.testing = True
    return app, app.test_client()


def test_sample_scenario_builds_investigation_context():
    app, client = make_client()
    response = client.post("/load_sample", follow_redirects=True)
    assert response.status_code == 200
    ctx = app.config["INVESTIGATION"]
    assert ctx["total_events"] == 109
    assert ctx["anomaly_count"] == 66
    assert len(ctx["chains_list"]) == 10
    assert len(ctx["entities_list"]) >= 10


def test_api_export_and_report_after_sample_load():
    app, client = make_client()
    client.post("/load_sample", follow_redirects=True)

    assert client.get("/api/events").status_code == 200
    assert len(client.get("/api/events").get_json()) == app.config["INVESTIGATION"]["total_events"]

    csv_response = client.get("/export/csv")
    assert csv_response.status_code == 200
    assert csv_response.mimetype == "text/csv"
    assert b"event_id" in csv_response.data

    report_response = client.get("/report")
    assert report_response.status_code == 200
    assert b"Forensic Investigation Report" in report_response.data


def test_notes_and_tags_update_current_case_context():
    app, client = make_client()
    client.post("/load_sample", follow_redirects=True)
    event_id = app.config["INVESTIGATION"]["events_list"][0]["event_id"]

    note_response = client.post(f"/api/note/{event_id}", json={"note": "Important finding"})
    assert note_response.status_code == 200
    assert note_response.get_json()["note"] == "Important finding"

    tag_response = client.post(f"/api/tag/{event_id}", json={"tag": "critical review"})
    assert tag_response.status_code == 200
    assert "critical review" in tag_response.get_json()["tags"]


def test_report_escapes_raw_evidence_text():
    module = load_main_module()
    from app.core.models import ForensicEvent

    malicious = ForensicEvent(
        timestamp=__import__("datetime").datetime(2026, 1, 1, 10, 0, 0),
        source="evil.log",
        source_type="syslog",
        event_type="<script>alert(1)</script>",
        description="</script><img src=x onerror=alert(1)>",
        severity="HIGH",
    )
    ctx = {
        "case_id": "CASE<script>",
        "events": [malicious],
        "attack_chains": [],
        "entities": [],
        "gaps": [],
        "sources": ["evil.log"],
        "time_start": "2026-01-01 10:00:00",
        "time_end": "2026-01-01 10:00:00",
    }
    html = module.generate_html_report(ctx)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;/script&gt;&lt;img" in html
