"""Alerting + anomaly detection wired into the Flask routes."""

import json
import re

import pytest

import security_logger as sl


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_LOG_PATH", str(tmp_path / "events.jsonl"))
    monkeypatch.setenv("RISK_ALERTS_PATH", str(tmp_path / "alerts.jsonl"))
    monkeypatch.setenv("RISK_DATA_DIR", str(tmp_path))
    import app as app_module
    app_module.limiter.reset()
    app_module.limiter.enabled = True
    # never call the real Gemini API from tests
    monkeypatch.setattr(app_module, "generate_response_plans",
                        lambda *a, **k: {"available": True, "reason": "", "plans": {}})
    c = app_module.app.test_client()
    c.app_module = app_module
    return c


def token(client):
    page = client.get("/").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)


def risk(rid, p, i, title=None):
    return {"id": rid, "title": title or f"Risk {rid}", "category": "Technical",
            "probability": p, "impact": i, "description": "d"}


def save(client, label, risks, project="Proj"):
    return client.post("/snapshot", data={
        "csrf_token": token(client), "project": project, "label": label,
        "pasted_json": json.dumps(risks)})


def analyze(client, risks, project="Proj"):
    return client.post("/analyze", data={
        "csrf_token": token(client),
        "pasted_json": json.dumps({"project_name": project, "risks": risks})})


# ── alerts from the /snapshot route ─────────────────────────────────────────
def test_first_snapshot_raises_no_alert(client):
    assert save(client, "W1", [risk("R1", 3, 3)]).status_code == 302
    assert client.get("/alerts").get_json() == {"project": None, "count": 0, "alerts": []}


def test_worsening_risk_alerts_and_shows_everywhere(client):
    save(client, "W1", [risk("R1", 3, 3)])                       # score 9, Medium
    save(client, "W2", [risk("R1", 4, 5)])                       # score 20, Critical
    data = client.get("/alerts?project=Proj").get_json()
    assert data["count"] == 1 and data["project"] == "Proj"
    a = data["alerts"][0]
    assert (a["alert_type"], a["severity"], a["risk_id"]) == ("SEVERITY_WORSENED", "CRITICAL", "R1")
    assert (a["previous_score"], a["new_score"]) == (9, 20)

    events = sl.get_events(event_type_filter="RISK_ALERT")        # picked up by the SIEM log
    assert len(events) == 1 and events[0]["severity"] == "CRITICAL"

    page = client.get("/security").get_data(as_text=True)
    assert "Active risk alerts" in page and "SEVERITY_WORSENED" in page and "Proj" in page


def test_alerts_endpoint_filters_by_project(client):
    for proj in ("A", "B"):
        save(client, "W1", [risk("R1", 3, 3)], project=proj)
        save(client, "W2", [risk("R1", 4, 5)], project=proj)
    assert client.get("/alerts").get_json()["count"] == 2
    only_a = client.get("/alerts?project=A").get_json()
    assert only_a["count"] == 1 and only_a["alerts"][0]["project_name"] == "A"
    assert client.get("/alerts?project=Nope").get_json()["count"] == 0


def test_security_page_shows_empty_state_without_alerts(client):
    page = client.get("/security").get_data(as_text=True)
    assert "Active risk alerts" in page and "No risk alerts in the last 48 hours" in page


def test_alerting_failure_never_blocks_the_snapshot_route(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("alerting is down")
    monkeypatch.setattr(client.app_module, "check_and_alert", boom)
    save(client, "W1", [risk("R1", 3, 3)])
    assert save(client, "W2", [risk("R1", 4, 5)]).status_code == 302
    assert [s["label"] for s in client.app_module.list_snapshots("Proj")] == ["W1", "W2"]


def test_no_alert_against_a_tampered_previous_snapshot(client, tmp_path):
    save(client, "W1", [risk("R1", 3, 3)])
    f = tmp_path / "Proj.snapshots.json"
    d = json.loads(f.read_text())
    d["snapshots"][0]["risks"][0]["probability"] = 1               # edit W1 behind the app's back
    f.write_text(json.dumps(d))
    save(client, "W2", [risk("R1", 4, 5)])
    assert client.get("/alerts").get_json()["count"] == 0


# ── anomalies in the pages ──────────────────────────────────────────────────
def build_history(client):
    for label, (p, i) in zip(("W1", "W2", "W3", "W4"), [(1, 5), (1, 5), (2, 3), (1, 5)]):
        save(client, label, [risk("R1", p, i, "Slow burner"), risk("R2", 1, 1, "Quiet one")])


def test_report_marks_an_anomalous_risk_but_not_the_quiet_one(client):
    build_history(client)                                          # R1 scores 5, 5, 6, 5
    page = analyze(client, [risk("R1", 5, 3, "Slow burner"), risk("R2", 1, 1, "Quiet one")]).get_data(as_text=True)
    assert page.count('class="anomaly"') == 1
    assert "standard deviations above" in page                     # the tooltip text


def test_analyzing_what_was_just_saved_does_not_dilute_the_spike(client):
    build_history(client)
    spike = [risk("R1", 5, 3, "Slow burner"), risk("R2", 1, 1, "Quiet one")]
    save(client, "W5", spike)                                      # the spike is now the newest snapshot
    page = analyze(client, spike).get_data(as_text=True)           # same data: must not count twice
    assert page.count('class="anomaly"') == 1


def test_report_has_no_marker_without_history_and_does_not_error(client):
    resp = analyze(client, [risk("R1", 5, 3)])
    assert resp.status_code == 200 and 'class="anomaly"' not in resp.get_data(as_text=True)


def test_anomaly_failure_never_blocks_analyze_or_history(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("detector broke")
    monkeypatch.setattr(client.app_module, "detect_anomalies", boom)
    assert analyze(client, [risk("R1", 5, 3)]).status_code == 200
    save(client, "W1", [risk("R1", 3, 3)])
    assert client.get("/history?project=Proj").status_code == 200


def test_history_lists_anomalies_with_pill_styles(client):
    build_history(client)
    save(client, "W5", [risk("R1", 5, 3, "Slow burner"), risk("R2", 1, 1, "Quiet one")])   # R1 jumps to 15
    page = client.get("/history?project=Proj").get_data(as_text=True)
    assert "Anomaly report" in page and "Slow burner" in page
    assert "pill b-Critical" in page and "Statistical outlier" in page


def test_history_hides_the_section_when_nothing_is_anomalous(client):
    save(client, "W1", [risk("R1", 3, 3)])
    page = client.get("/history?project=Proj").get_data(as_text=True)
    assert "Anomaly report" not in page
