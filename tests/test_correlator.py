import re
from datetime import datetime, timedelta, timezone

import pytest

import correlator as cor
import security_logger as sl


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_LOG_PATH", str(tmp_path / "events.jsonl"))
    return tmp_path


class Peer:
    def __init__(self, ip):
        self.remote_addr = ip


def log(event_type, severity="WARN", ip="10.0.0.1", **meta):
    return sl.log_event(event_type, severity, Peer(ip), "test", meta)


def types():
    return [i["incident_type"] for i in cor.get_incidents()]


# ── Rule 1: brute force ─────────────────────────────────────────────────────
def test_brute_force_fires_at_three_not_two(env):
    log("UPLOAD_REJECTED")
    log("INVALID_JSON")
    assert cor.get_incidents() == []          # two events: nothing
    log("UPLOAD_REJECTED")                    # third event: fires (auto, from log_event)
    [inc] = cor.get_incidents()
    assert inc["incident_type"] == "BRUTE_FORCE_SUSPECTED"
    assert inc["severity"] == "CRITICAL"
    assert inc["source_ip"] == "10.0.0.1"
    assert inc["matched_event_count"] == 3 == len(inc["matched_event_ids"])
    assert "10.0.0.1" in inc["detail"]


def test_brute_force_needs_same_ip(env):
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        log("UPLOAD_REJECTED", ip=ip)
    assert cor.get_incidents() == []


def test_brute_force_respects_five_minute_window(env):
    old = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(timespec="seconds")
    with open(sl.log_path(), "w", encoding="utf-8") as f:
        for n in range(2):  # two old events, then one new one: never 3 within 5 minutes
            f.write(f'{{"id": "old{n}", "timestamp": "{old}", "event_type": "UPLOAD_REJECTED", '
                    f'"severity": "WARN", "source_ip": "10.0.0.1", "detail": "", "metadata": {{}}}}\n')
    log("UPLOAD_REJECTED")
    assert cor.get_incidents() == []


def test_run_correlation_is_idempotent(env):
    for _ in range(3):
        log("UPLOAD_REJECTED")
    assert len(cor.get_incidents()) == 1
    assert cor.run_correlation() == []
    assert cor.run_correlation() == []
    assert len(cor.get_incidents()) == 1
    log("UPLOAD_REJECTED")                    # one extra event is not a new burst
    assert len(cor.get_incidents()) == 1
    log("UPLOAD_REJECTED")
    log("UPLOAD_REJECTED")                    # three fresh events are
    assert len(cor.get_incidents()) == 2


def test_manual_run_returns_new_incidents(env, monkeypatch):
    monkeypatch.setattr(cor, "TRIGGER_TYPES", frozenset())  # disable the automatic hook
    for _ in range(3):
        log("INVALID_JSON")
    assert cor.get_incidents() == []
    fired = cor.run_correlation()
    assert [i["incident_type"] for i in fired] == ["BRUTE_FORCE_SUSPECTED"]
    assert cor.run_correlation() == []


# ── Rule 2: rate limit abuse ────────────────────────────────────────────────
def test_rate_limit_abuse_at_five(env):
    for _ in range(4):
        log("RATE_LIMITED")
    assert cor.get_incidents() == []
    log("RATE_LIMITED")
    [inc] = cor.get_incidents()
    assert inc["incident_type"] == "RATE_LIMIT_ABUSE" and inc["severity"] == "CRITICAL"
    assert "possible DoS attempt" in inc["detail"]


# ── Rule 3: integrity breach ────────────────────────────────────────────────
def test_integrity_breach_fires_on_second_tampered_event(env):
    log("SNAPSHOT_TAMPERED", "CRITICAL", project="Apollo", label="w1")
    assert cor.get_incidents() == []
    log("SNAPSHOT_TAMPERED", "CRITICAL", project="Apollo", label="w2")
    [inc] = cor.get_incidents()
    assert inc["incident_type"] == "INTEGRITY_BREACH_PATTERN" and inc["severity"] == "CRITICAL"
    assert inc["project"] == "Apollo" and inc["matched_event_count"] == 2
    assert "'Apollo'" in inc["detail"]


def test_integrity_breach_is_per_project(env):
    log("SNAPSHOT_TAMPERED", "CRITICAL", project="A")
    log("SNAPSHOT_TAMPERED", "CRITICAL", project="B")
    assert cor.get_incidents() == []


# ── Rule 4: quiet anomaly escalation ────────────────────────────────────────
def test_quiet_escalation_after_three_warns(env):
    for _ in range(2):
        log("RISK_ALERT", "WARN", project="P", risk_id="R7")
    assert cor.get_incidents() == []
    log("RISK_ALERT", "WARN", project="P", risk_id="R7")
    [inc] = cor.get_incidents()
    assert inc["incident_type"] == "QUIET_ANOMALY_ESCALATION" and inc["severity"] == "WARN"
    assert inc["detail"] == "Risk R7 has triggered repeated WARN alerts — escalating for review"


def test_quiet_escalation_reset_by_critical(env):
    log("RISK_ALERT", "WARN", project="P", risk_id="R7")
    log("RISK_ALERT", "WARN", project="P", risk_id="R7")
    log("RISK_ALERT", "CRITICAL", project="P", risk_id="R7")
    log("RISK_ALERT", "WARN", project="P", risk_id="R7")
    assert cor.get_incidents() == []


# ── plumbing ────────────────────────────────────────────────────────────────
def test_incident_is_logged_as_correlation_incident(env):
    for _ in range(3):
        log("UPLOAD_REJECTED")
    [e] = sl.get_events(event_type_filter="CORRELATION_INCIDENT")
    assert e["severity"] == "CRITICAL" and e["metadata"]["incident_type"] == "BRUTE_FORCE_SUSPECTED"


def test_ingested_logs_do_not_trigger_or_match_rules(env):
    for _ in range(10):
        log("INGESTED_LOG", "INFO")
    assert cor.run_correlation() == []


def test_correlation_failure_never_breaks_logging(env, monkeypatch):
    def boom():
        raise RuntimeError("nope")
    monkeypatch.setattr(cor, "run_correlation", boom)
    assert log("UPLOAD_REJECTED") is not None
    assert len(sl.get_events()) == 1


def test_unwritable_incident_file_does_not_raise_or_refire(env, monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_INCIDENTS_PATH", str(tmp_path / "no" / "dir" / "i.jsonl"))
    for _ in range(3):
        log("UPLOAD_REJECTED")
    assert cor.get_incidents() == [] and cor.run_correlation() == []


def test_get_incidents_filters_and_summary(env):
    for _ in range(3):
        log("UPLOAD_REJECTED")
    for _ in range(3):
        log("RISK_ALERT", "WARN", project="P", risk_id="R1")
    assert [i["incident_type"] for i in cor.get_incidents(severity_filter="WARN")] == ["QUIET_ANOMALY_ESCALATION"]
    assert len(cor.get_incidents(limit=1)) == 1
    s = cor.get_incident_summary()
    assert s["all_time"]["total"] == 2 == s["last_24h"]["total"]
    assert s["all_time"]["by_severity"] == {"CRITICAL": 1, "WARN": 1}


def test_old_incidents_are_pruned_on_write(env, tmp_path):
    old = (datetime.now(timezone.utc) - timedelta(days=61)).isoformat(timespec="seconds")
    path = tmp_path / "incidents.jsonl"
    path.write_text(f'{{"timestamp": "{old}", "incident_type": "RATE_LIMIT_ABUSE", "severity": "CRITICAL"}}\n',
                    encoding="utf-8")
    for _ in range(3):
        log("UPLOAD_REJECTED")
    assert [i["incident_type"] for i in cor.get_incidents()] == ["BRUTE_FORCE_SUSPECTED"]


# ── routes + dashboard ──────────────────────────────────────────────────────
@pytest.fixture()
def client(env, monkeypatch):
    monkeypatch.setenv("RISK_DATA_DIR", str(env))
    monkeypatch.setenv("RISK_ALERTS_PATH", str(env / "alerts.jsonl"))
    import app as app_module
    app_module.limiter.reset()
    app_module.app.config["TESTING"] = False
    c = app_module.app.test_client()
    c.token = lambda: re.search(r'name="csrf_token" value="([^"]+)"',
                                c.get("/security").get_data(as_text=True)).group(1)
    return c


def test_correlate_route_and_rate_limit(client, monkeypatch):
    monkeypatch.setattr(cor, "TRIGGER_TYPES", frozenset())
    for _ in range(3):
        log("UPLOAD_REJECTED")
    h = {"X-CSRFToken": client.token()}
    r = client.post("/correlate", headers=h)
    assert r.status_code == 200 and r.get_json()["count"] == 1
    assert client.post("/correlate", headers=h).get_json() == {"count": 0, "incidents": []}
    assert client.post("/correlate").status_code == 400  # CSRF still enforced
    codes = [client.post("/correlate", headers=h).status_code for _ in range(22)]
    assert 429 in codes
    assert client.post("/correlate", headers=h).get_json().get("error")  # JSON, not an HTML page


def test_security_page_shows_new_sections(client):
    html = client.get("/security").get_data(as_text=True)
    assert "No correlated incidents in the last 72 hours" in html
    assert "Ingested log lines" in html and 'id="ingestForm"' in html
    assert html.index('id="incidents"') < html.index('id="alerts"') < html.index('id="ingest"')
    for _ in range(3):
        log("UPLOAD_REJECTED")
    html = client.get("/security").get_data(as_text=True)
    assert "BRUTE_FORCE_SUSPECTED" in html and "Repeated invalid submissions" in html
