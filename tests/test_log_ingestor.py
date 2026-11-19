import io
import json
import re

import pytest

import log_ingestor as li
import security_logger as sl


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_LOG_PATH", str(tmp_path / "events.jsonl"))
    return tmp_path


# ── parse_line ──────────────────────────────────────────────────────────────
def test_parse_syslog():
    e = li.parse_line("Nov 19 10:23:01 web01 sshd[4242]: Failed password for root from 10.1.2.3 port 22")
    assert e["event_type"] == "INGESTED_LOG"
    assert e["source_ip"] == "10.1.2.3"
    assert e["timestamp"].endswith("T10:23:01+00:00")
    assert e["message"].startswith("Failed password")
    assert e["severity"] == "INFO"
    assert e["metadata"]["raw"].startswith("Nov 19 10:23:01")
    assert (e["metadata"]["app"], e["metadata"]["pid"], e["metadata"]["host"]) == ("sshd", "4242", "web01")


def test_parse_syslog_severity_from_words():
    assert li.parse_line("Nov 19 10:23:01 h app: fatal error in worker")["severity"] == "CRITICAL"
    assert li.parse_line("Nov 19 10:23:01 h app: warning: disk at 91%")["severity"] == "WARN"


def test_parse_common_log_format():
    e = li.parse_line('127.0.0.1 - - [19/Nov/2026:10:23:01 +0000] "POST /analyze HTTP/1.1" 200 512')
    assert e["source_ip"] == "127.0.0.1"
    assert e["timestamp"] == "2026-11-19T10:23:01+00:00"
    assert e["message"] == "POST /analyze HTTP/1.1 -> 200 (512 bytes)"
    assert e["severity"] == "INFO"
    assert e["metadata"]["status"] == 200


def test_clf_timestamp_is_normalised_to_utc():
    e = li.parse_line('10.0.0.9 - bob [19/Nov/2026:10:23:01 +0200] "GET / HTTP/1.1" 404 -')
    assert e["timestamp"] == "2026-11-19T08:23:01+00:00"
    assert e["metadata"]["user"] == "bob"


def test_parse_json_line():
    e = li.parse_line('{"timestamp": "2026-11-19T10:23:01Z", "level": "warn", "source": "10.9.8.7", "message": "slow query"}')
    assert (e["severity"], e["source_ip"], e["message"]) == ("WARN", "10.9.8.7", "slow query")
    assert e["timestamp"] == "2026-11-19T10:23:01+00:00"


@pytest.mark.parametrize("level,expected", [
    ("error", "CRITICAL"), ("critical", "CRITICAL"), ("fatal", "CRITICAL"),
    ("warn", "WARN"), ("warning", "WARN"), ("info", "INFO"), ("debug", "INFO"), (None, "INFO"),
])
def test_json_severity_mapping(level, expected):
    line = json.dumps({"timestamp": "2026-11-19T10:00:00Z", "level": level, "message": "m"})
    assert li.parse_line(line)["severity"] == expected


def test_json_non_ip_source_stays_in_metadata():
    e = li.parse_line('{"level": "info", "source": "auth-service", "message": "ok"}')
    assert e["source_ip"] is None and e["metadata"]["source"] == "auth-service"


@pytest.mark.parametrize("junk", [
    "", "   ", "this is not a log line", "{not json", "[1, 2, 3]", '{"no_message": 1}',
    "Xyz 19 10:23:01 host app: bad month", "Feb 31 10:23:01 host app: impossible date", None, 42,
])
def test_unparseable_lines_return_none(junk):
    assert li.parse_line(junk) is None


# ── ingestion ───────────────────────────────────────────────────────────────
def test_ingest_lines_counts_and_logs(env):
    res = li.ingest_lines([
        "Nov 19 10:23:01 h app: hello from 10.0.0.5",
        "garbage",
        '{"level": "error", "message": "boom"}',
    ])
    assert (res["ingested"], res["skipped"], res["errors"]) == (2, 1, [])
    events = sl.get_events(event_type_filter="INGESTED_LOG")
    assert {e["severity"] for e in events} == {"INFO", "CRITICAL"}
    assert "10.0.0.5" in {e["source_ip"] for e in events}   # the log's own IP, not the uploader's
    assert all("raw" in e["metadata"] for e in events)


def test_ingest_caps_lines(env):
    res = li.ingest_lines(['{"message": "x"}'] * 600)
    assert res["ingested"] == li.MAX_LINES
    assert any("line limit" in e for e in res["errors"])


def test_ingest_time_budget(env):
    res = li.ingest_lines(['{"message": "x"}'] * 50, time_budget=-1)
    assert res["ingested"] == 0 and any("time limit" in e for e in res["errors"])


def test_ingest_file_and_missing_file(env, tmp_path):
    f = tmp_path / "sample.log"
    f.write_text('127.0.0.1 - - [19/Nov/2026:10:23:01 +0000] "GET / HTTP/1.1" 200 5\nnope\n', encoding="utf-8")
    assert li.ingest_file(str(f)) == {"ingested": 1, "skipped": 1, "errors": []}
    res = li.ingest_file(str(tmp_path / "missing.log"))
    assert res["ingested"] == 0 and res["errors"]


def test_ingest_incoming_moves_processed_files(env, tmp_path):
    inc, done = tmp_path / "in", tmp_path / "done"
    inc.mkdir()
    (inc / "a.log").write_text('{"message": "hi"}\n', encoding="utf-8")
    (inc / "notes.pdf").write_text("ignored", encoding="utf-8")
    res = li.ingest_incoming(str(inc), str(done))
    assert res["ingested"] == 1
    assert [p.name for p in inc.iterdir()] == ["notes.pdf"]
    assert len(list(done.iterdir())) == 1
    assert li.ingest_incoming(str(inc), str(done))["ingested"] == 0  # not read twice


def test_ingest_incoming_creates_missing_dir(env, tmp_path):
    assert li.ingest_incoming(str(tmp_path / "new" / "in"), str(tmp_path / "p"))["ingested"] == 0
    assert (tmp_path / "new" / "in").is_dir()


def test_cli_runs_standalone(env, tmp_path, capsys):
    f = tmp_path / "s.log"
    f.write_text("Nov 19 10:23:01 h app: hi\nbad line\n", encoding="utf-8")
    assert li.main(["log_ingestor.py", str(f)]) == 0
    assert "ingested 1, skipped 1" in capsys.readouterr().out


# ── route ───────────────────────────────────────────────────────────────────
@pytest.fixture()
def client(env, monkeypatch):
    monkeypatch.setenv("RISK_DATA_DIR", str(env))
    monkeypatch.setenv("RISK_ALERTS_PATH", str(env / "alerts.jsonl"))
    import app as app_module
    app_module.limiter.reset()
    app_module.app.config["TESTING"] = False  # keep CSRF on
    c = app_module.app.test_client()
    c.token = lambda: re.search(r'name="csrf_token" value="([^"]+)"',
                                c.get("/security").get_data(as_text=True)).group(1)
    return c


def _upload(client, data, name="a.log", mime="text/plain"):
    return client.post("/ingest", data={"csrf_token": client.token(), "log_file": (io.BytesIO(data), name, mime)},
                       content_type="multipart/form-data")


def test_ingest_route_file(client):
    r = _upload(client, b"Nov 19 10:23:01 h app: hi\nbad\n")
    assert r.status_code == 200 and r.get_json() == {"ingested": 1, "skipped": 1, "errors": []}


def test_ingest_route_json_body(client):
    r = client.post("/ingest", json={"logs": ['{"message": "a"}', "junk"]}, headers={"X-CSRFToken": client.token()})
    assert r.get_json()["ingested"] == 1 and r.get_json()["skipped"] == 1


def test_ingest_route_rejects_bad_input(client):
    assert _upload(client, b"x", mime="image/png").status_code == 400
    assert _upload(client, b"x" * (512 * 1024 + 1)).status_code == 413
    r = client.post("/ingest", json={"nope": 1}, headers={"X-CSRFToken": client.token()})
    assert r.status_code == 400 and r.get_json()["errors"]
    assert client.post("/ingest", json={"logs": []}).status_code == 400  # no CSRF token
