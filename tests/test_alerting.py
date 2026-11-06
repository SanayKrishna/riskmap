import json
from datetime import datetime, timedelta, timezone

import pytest

import alerting
import security_logger as sl


@pytest.fixture(autouse=True)
def paths(tmp_path, monkeypatch):
    monkeypatch.setenv("RISK_ALERTS_PATH", str(tmp_path / "alerts.jsonl"))
    monkeypatch.setenv("SECURITY_LOG_PATH", str(tmp_path / "events.jsonl"))


def snap(**scores):
    """snap(R1=9, R2=14) -> a snapshot whose risks have those scores."""
    return {"risks": [{"id": k, "title": f"Risk {k}", "score": v} for k, v in scores.items()]}


def fire(old, new):
    return alerting.check_and_alert("Proj", old, new)


# ── thresholds ──────────────────────────────────────────────────────────────
def test_delta_5_is_warn():
    (a,) = fire(snap(R1=7), snap(R1=12))          # Medium -> Medium, +5
    assert (a["alert_type"], a["severity"]) == ("SCORE_INCREASE", "WARN")
    assert (a["previous_score"], a["new_score"]) == (7, 12)


def test_delta_6_is_critical():
    (a,) = fire(snap(R1=13), snap(R1=19))         # High -> High, +6
    assert (a["alert_type"], a["severity"]) == ("SCORE_INCREASE", "CRITICAL")


def test_delta_3_is_warn_and_delta_2_is_silent():
    assert fire(snap(R1=8), snap(R1=11))[0]["severity"] == "WARN"
    assert fire(snap(R1=8), snap(R1=10)) == []


def test_severity_worsened_is_critical_even_for_a_one_point_rise():
    (a,) = fire(snap(R1=12), snap(R1=13))          # Medium -> High, +1
    assert (a["alert_type"], a["severity"]) == ("SEVERITY_WORSENED", "CRITICAL")
    assert (a["previous_severity"], a["new_severity"]) == ("Medium", "High")
    (b,) = fire(snap(R1=19), snap(R1=20))          # High -> Critical
    assert b["alert_type"] == "SEVERITY_WORSENED" and b["new_severity"] == "Critical"


def test_falling_or_flat_scores_raise_nothing():
    assert fire(snap(R1=15), snap(R1=10)) == []
    assert fire(snap(R1=15), snap(R1=15)) == []


def test_new_high_or_critical_risk_is_critical():
    (a,) = fire(snap(R1=5), snap(R1=5, R2=15))
    assert (a["alert_type"], a["severity"], a["risk_id"]) == ("NEW_HIGH_RISK", "CRITICAL", "R2")
    assert a["previous_score"] is None and a["new_severity"] == "High"
    assert fire(snap(R1=5), snap(R1=5, R2=9)) == []   # new but only Medium


def test_no_previous_snapshot_means_no_alerts():
    assert fire(None, snap(R1=25)) == []
    assert fire(snap(R1=5), None) == []


def test_scores_come_from_probability_times_impact_for_raw_risks():
    old = {"risks": [{"id": "R1", "title": "t", "probability": 2, "impact": 2}]}
    new = {"risks": [{"id": "R1", "title": "t", "probability": 4, "impact": 5}]}
    (a,) = fire(old, new)
    assert (a["previous_score"], a["new_score"]) == (4, 20)


def test_bad_or_missing_fields_are_skipped_not_fatal():
    old = {"risks": [{"id": "R1", "title": "t"}, {"id": "R2", "title": "t", "score": 5}]}
    new = {"risks": [{"id": "R1", "title": "t", "score": 20}, {"id": "R2", "title": "t", "score": "x"}, "junk", None]}
    assert fire(old, new) == []


def test_alert_has_the_documented_fields():
    (a,) = fire(snap(R1=9), snap(R1=15))
    assert set(a) == {"timestamp", "project_name", "alert_type", "severity", "risk_id", "risk_title",
                      "previous_score", "new_score", "previous_severity", "new_severity", "detail"}
    assert a["project_name"] == "Proj" and a["detail"]


# ── storage, logging, reading ───────────────────────────────────────────────
def test_alerts_are_stored_logged_and_readable():
    fire(snap(R1=9, R2=7), snap(R1=15, R2=12))       # R1 severity worsened, R2 +5 warn
    got = alerting.get_alerts()
    assert {a["risk_id"] for a in got} == {"R1", "R2"}
    logged = sl.get_events(event_type_filter="RISK_ALERT")
    assert {e["severity"] for e in logged} == {"CRITICAL", "WARN"}
    assert all(e["metadata"]["project"] == "Proj" for e in logged)


def test_get_alerts_filters_and_orders_newest_first():
    alerting.check_and_alert("A", snap(R1=9), snap(R1=15))
    alerting.check_and_alert("B", snap(R1=7), snap(R1=12))
    assert [a["project_name"] for a in alerting.get_alerts()] == ["B", "A"]
    assert [a["project_name"] for a in alerting.get_alerts(project_name="A")] == ["A"]
    assert [a["severity"] for a in alerting.get_alerts(severity_filter="WARN")] == ["WARN"]
    assert len(alerting.get_alerts(limit=1)) == 1
    assert len(alerting.get_alerts(since_hours=48)) == 2


def test_summary_counts_by_type_and_severity():
    fire(snap(R1=9, R2=7), snap(R1=15, R2=12))
    s = alerting.get_alert_summary()
    assert s["all_time"]["total"] == 2 and s["last_24h"]["total"] == 2
    assert s["all_time"]["by_severity"] == {"CRITICAL": 1, "WARN": 1}
    assert s["all_time"]["by_type"] == {"SEVERITY_WORSENED": 1, "SCORE_INCREASE": 1}


def test_entries_older_than_60_days_are_pruned_on_write(tmp_path):
    old = (datetime.now(timezone.utc) - timedelta(days=61)).isoformat()
    (tmp_path / "alerts.jsonl").write_text(
        json.dumps({"timestamp": old, "project_name": "Old", "alert_type": "X", "severity": "WARN"}) + "\n")
    fire(snap(R1=9), snap(R1=15))
    assert [a["project_name"] for a in alerting.get_alerts()] == ["Proj"]


def test_storage_failure_never_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("RISK_ALERTS_PATH", str(tmp_path / "no" / "such" / "dir" / "a.jsonl"))
    got = fire(snap(R1=9), snap(R1=15))          # still returns what fired
    assert len(got) == 1
    assert alerting.get_alerts() == []
    assert alerting.get_alert_summary()["all_time"]["total"] == 0
