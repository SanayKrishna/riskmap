import pytest

from graph import build_graph, cascade_ranking, chains_text, validate_links


def _risks():
    return [
        {"id": "R1", "title": "Dev leaves", "category": "Resource",
         "probability": 4, "impact": 5, "score": 20, "severity": "Critical",
         "color": "#DC2626", "description": "d", "triggers": ["R2"]},
        {"id": "R2", "title": "Cost overrun", "category": "Cost",
         "probability": 3, "impact": 4, "score": 12, "severity": "Medium",
         "color": "#D97706", "description": "d", "triggers": ["R3"]},
        {"id": "R3", "title": "Minor", "category": "Cost",
         "probability": 1, "impact": 2, "score": 2, "severity": "Low",
         "color": "#16A34A", "description": "d", "triggers": []},
    ]


def test_validate_ok_and_rejects():
    assert validate_links(_risks()) is True
    bad_self = _risks()
    bad_self[0]["triggers"] = ["R1"]
    with pytest.raises(ValueError):
        validate_links(bad_self)
    bad_unknown = _risks()
    bad_unknown[0]["triggers"] = ["R99"]
    with pytest.raises(ValueError):
        validate_links(bad_unknown)


def test_cascade_ranking_transitive():
    ranked = cascade_ranking(_risks())
    assert ranked[0]["id"] == "R1"  # reaches R2 and R3
    assert ranked[0]["blast"] == 2
    assert ranked[0]["downstream"] == ["R2", "R3"]
    assert ranked[1]["id"] == "R2"
    assert all(c["id"] != "R3" for c in ranked)  # leaf, no downstream


def test_empty_when_no_links():
    risks = [{**r, "triggers": []} for r in _risks()]
    assert cascade_ranking(risks) == []
    assert chains_text(risks) == []


def test_chains_text_and_cycles():
    lines = chains_text(_risks())
    assert any("R1" in ln and "R3" in ln for ln in lines)
    cyc = _risks()
    cyc[2]["triggers"] = ["R1"]  # R3 -> R1 closes a cycle
    assert validate_links(cyc) is True
    assert cascade_ranking(cyc)  # terminates despite the cycle


def test_network_chart_div():
    from graph import network_chart
    div = network_chart({"project_name": "P", "risks": _risks()})
    assert "Dependency Map" in div and "R1" in div
    assert network_chart({"project_name": "P", "risks": []}) == ""
