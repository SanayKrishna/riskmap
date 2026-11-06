import io
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

import integrity
import security_logger as sl

RISKS = [
    {"id": "R1", "title": "Dev leaves", "category": "Resource", "probability": 4,
     "impact": 5, "description": "d", "triggers": ["R2"]},
    {"id": "R2", "title": "Slip", "category": "Schedule", "probability": 2,
     "impact": 2, "description": "d"},
]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_LOG_PATH", str(tmp_path / "events.jsonl"))
    monkeypatch.setenv("RISK_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RISK_ALERTS_PATH", str(tmp_path / "alerts.jsonl"))
    import app as app_module
    app_module.limiter.reset()
    app_module.limiter.enabled = True
    app_module.app.config["TESTING"] = False  # keep CSRF on
    c = app_module.app.test_client()
    c.get_token = lambda: re.search(
        r'name="csrf_token" value="([^"]+)"', c.get("/").get_data(as_text=True)).group(1)
    c.app_module = app_module
    return c


def _post(client, data, **kw):
    data = {"csrf_token": client.get_token(), **data}
    return client.post("/analyze", data=data, **kw)


def _types():
    return [e["event_type"] for e in sl.get_events()]


# ── logger ──────────────────────────────────────────────────────────────────
def test_logger_roundtrip_filters_and_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_LOG_PATH", str(tmp_path / "e.jsonl"))
    sl.log_event("RATE_LIMITED", "WARN", None, "x", {"a": 1})
    sl.log_event("CSRF_VIOLATION", "CRITICAL", None, "y")
    ev = sl.get_events()
    assert [e["event_type"] for e in ev] == ["CSRF_VIOLATION", "RATE_LIMITED"]  # newest first
    assert ev[1]["metadata"] == {"a": 1} and ev[0]["source_ip"] == "unknown"
    assert len(sl.get_events(severity_filter="WARN")) == 1
    s = sl.get_summary()
    assert s["all_time"]["total"] == 2 and s["last_24h"]["by_severity"]["CRITICAL"] == 1
    h = sl.hourly_counts(24)
    assert sum(h["series"]["WARN"]) == 1 and len(h["hours"]) == 24


def test_logger_prunes_old_and_never_raises(tmp_path, monkeypatch):
    path = tmp_path / "e.jsonl"
    monkeypatch.setenv("SECURITY_LOG_PATH", str(path))
    old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    path.write_text(json.dumps({"timestamp": old, "event_type": "X", "severity": "INFO"}) + "\n")
    sl.log_event("INVALID_JSON", "WARN", None, "new")
    assert [e["event_type"] for e in sl.get_events()] == ["INVALID_JSON"]
    # unwritable location: must return quietly
    monkeypatch.setenv("SECURITY_LOG_PATH", str(tmp_path / "no" / "such" / "dir" / "e.jsonl"))
    assert sl.log_event("INVALID_JSON", "WARN", None) is None
    assert sl.get_events() == []


# ── integrity ───────────────────────────────────────────────────────────────
def test_integrity():
    a = {"risks": [{"id": "R1", "p": 1}], "label": "W1"}
    b = {"label": "W1", "risks": [{"p": 1, "id": "R1"}]}  # key order differs
    h = integrity.sign_snapshot(a)
    assert h == integrity.sign_snapshot(b) and len(h) == 64
    assert integrity.verify_snapshot(b, h)
    b["risks"][0]["p"] = 5
    assert not integrity.verify_snapshot(b, h)
    assert integrity.check_snapshot(a, None) == "missing"
    assert integrity.check_snapshot(a, h) == "verified"
    assert integrity.check_snapshot(b, h) == "tampered"


# ── end to end ──────────────────────────────────────────────────────────────
def test_valid_analyze_still_works_and_headers(client, monkeypatch):
    monkeypatch.setattr(client.app_module, "generate_response_plans",
                        lambda *a, **k: {"available": False, "reason": "overloaded",
                                         "error": "503", "plans": {}})
    r = _post(client, {"pasted_json": json.dumps({"project_name": "P", "risks": RISKS})})
    assert r.status_code == 200 and "Dev leaves" in r.get_data(as_text=True)
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self' 'nonce-" in csp and "cdn.plot.ly" not in csp
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    body = r.get_data(as_text=True)
    assert all(f'nonce="{nonce}"' in t for t in re.findall(r"<script[^>]*>", body))
    assert "AI_FAILURE" in _types()


def test_csrf_missing_is_blocked_and_logged(client):
    r = client.post("/analyze", data={"pasted_json": "{}"})
    assert r.status_code == 400
    ev = sl.get_events()[0]
    assert ev["event_type"] == "CSRF_VIOLATION" and ev["severity"] == "CRITICAL"


@pytest.mark.parametrize("mutate,etype", [
    (lambda r: r.update(probability=6), "UPLOAD_REJECTED"),
    (lambda r: r.update(probability=True), "UPLOAD_REJECTED"),
    (lambda r: r.update(probability="3"), "UPLOAD_REJECTED"),
    (lambda r: r.update(category="Nope"), "UPLOAD_REJECTED"),
    (lambda r: r.update(id="x" * 21), "UPLOAD_REJECTED"),
    (lambda r: r.update(title="t" * 201), "UPLOAD_REJECTED"),
])
def test_schema_violations_rejected(client, mutate, etype):
    risks = json.loads(json.dumps(RISKS))
    mutate(risks[0])
    r = _post(client, {"pasted_json": json.dumps({"project_name": "P", "risks": risks})})
    assert r.status_code == 400 and 'class="error"' in r.get_data(as_text=True)
    assert _types()[0] == etype


def test_too_many_risks_and_bad_json(client):
    many = [{**RISKS[1], "id": f"R{i}", "triggers": []} for i in range(51)]
    r = _post(client, {"pasted_json": json.dumps({"risks": many})})
    assert r.status_code == 400 and "too many" in r.get_data(as_text=True)
    r = _post(client, {"pasted_json": "{nope"})
    assert r.status_code == 400 and _types()[0] == "INVALID_JSON"


def test_file_size_and_mime(client, monkeypatch):
    monkeypatch.setattr(client.app_module, "generate_response_plans",
                        lambda *a, **k: {"available": True, "reason": "", "plans": {}})
    big = json.dumps({"risks": RISKS, "pad": "x" * (513 * 1024)}).encode()
    r = _post(client, {"json_file": (io.BytesIO(big), "a.json", "application/json")},
              content_type="multipart/form-data")
    assert r.status_code == 413 and _types()[0] == "OVERSIZED_UPLOAD"
    ok = json.dumps({"project_name": "P", "risks": RISKS}).encode()
    r = _post(client, {"json_file": (io.BytesIO(ok), "a.json", "application/x-msdownload")},
              content_type="multipart/form-data")
    assert r.status_code == 400 and "unsupported file type" in r.get_data(as_text=True)
    r = _post(client, {"json_file": (io.BytesIO(ok), "../../a.json", "text/plain")},
              content_type="multipart/form-data")
    assert r.status_code == 200


def test_rate_limit(client):
    for _ in range(10):
        _post(client, {"pasted_json": "{}"})
    r = _post(client, {"pasted_json": "{}"})
    assert r.status_code == 429 and "Too many requests" in r.get_data(as_text=True)
    assert "RATE_LIMITED" in _types()


def test_snapshot_badges_and_tamper(client, tmp_path):
    tok = client.get_token()
    r = client.post("/snapshot", data={"csrf_token": tok, "project": "Proj", "label": "W1",
                                       "pasted_json": json.dumps(RISKS)})
    assert r.status_code == 302 and "SNAPSHOT_SAVED" in _types()
    page = client.get("/history?project=Proj").get_data(as_text=True)
    assert "integ-verified" in page and "SNAPSHOT_VERIFIED" in _types()
    f = tmp_path / "Proj.snapshots.json"
    d = json.loads(f.read_text())
    d["snapshots"][0]["risks"][0]["probability"] = 1
    f.write_text(json.dumps(d))
    page = client.get("/history?project=Proj").get_data(as_text=True)
    assert "integ-tampered" in page
    ev = sl.get_events(event_type_filter="SNAPSHOT_TAMPERED")[0]
    assert ev["severity"] == "CRITICAL"
    del d["snapshots"][0]["sha256"]
    f.write_text(json.dumps(d))
    assert "integ-missing" in client.get("/history?project=Proj").get_data(as_text=True)


def test_security_page_and_plotly_asset(client):
    sl.log_event("RATE_LIMITED", "WARN", None, "<b>x</b>")
    sl.log_event("CSRF_VIOLATION", "CRITICAL", None, "y")
    r = client.get("/security")
    body = r.get_data(as_text=True)
    assert r.status_code == 200 and "stat-strip" in body and "b-Critical" in body
    assert "&lt;b&gt;x" in body and "Security log" in body
    assert client.get("/plotly.min.js").status_code == 200
    assert client.get("/security_events.jsonl").status_code == 404


def test_hmac_key_change_reads_as_tampered(monkeypatch):
    d = {"risks": [1]}
    monkeypatch.setenv("SECRET_KEY", "key-one")
    h = integrity.sign_snapshot(d)
    assert integrity.check_snapshot(d, h) == "verified"
    monkeypatch.setenv("SECRET_KEY", "key-two")
    assert integrity.check_snapshot(d, h) == "tampered"
    assert integrity.check_snapshot(d, "caf\u00e9") == "missing"  # compare_digest error -> missing
