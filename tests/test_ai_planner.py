import os

import pytest

import ai_planner
from ai_planner import _classify_error, generate_response_plans


@pytest.fixture()
def no_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    assert ai_planner._api_key() == ""


def _crit():
    return {"id": "R1", "title": "t", "category": "Technical",
            "probability": 4, "impact": 5, "score": 20,
            "severity": "Critical", "description": "d"}


def test_no_key_reason(no_key):
    r = generate_response_plans("P", [_crit()])
    assert r["available"] is False
    assert r["reason"] == "no-key"
    assert r["plans"] == {}


def test_empty_risks_no_call(no_key):
    r = generate_response_plans("P", [])
    assert r["available"] is True
    assert r["plans"] == {}


def test_low_only_filtered_no_call(no_key):
    low = dict(_crit(), severity="Low", score=2)
    r = generate_response_plans("P", [low])
    assert r["available"] is True
    assert r["plans"] == {}


def test_classify_error():
    assert _classify_error("503 UNAVAILABLE... high demand") == "overloaded"
    assert _classify_error("model overloaded, try later") == "overloaded"
    assert _classify_error("400 bad request") == "error"
    assert _classify_error("") == "error"
