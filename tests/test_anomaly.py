import copy

import anomaly
from anomaly import detect_anomalies, label_risks


def history(*scores, rid="R1"):
    """One risk's scores, oldest to newest, as a list of snapshots."""
    return [{"risks": [{"id": rid, "title": "Risk one", "score": s}]} for s in scores]


def one(snaps):
    out = detect_anomalies(snaps)
    return out[0] if out else None


# ── statistical outlier ─────────────────────────────────────────────────────
def test_z_score_above_2_is_flagged():
    a = one(history(5, 5, 6, 5, 14))
    assert a["anomaly_type"] == "STATISTICAL_OUTLIER"
    assert a["z_score"] > 2 and a["current_score"] == 14
    assert a["mean_score"] == 5.25 and a["std_dev"] > 0


def test_z_score_at_or_below_2_is_not_flagged():
    assert detect_anomalies(history(5, 9, 6, 10, 8)) == []     # z about 0.2
    assert detect_anomalies(history(6, 4, 6, 4, 7)) == []      # z exactly 2.0, strictly "more than"


def test_a_drop_is_never_flagged():
    assert detect_anomalies(history(10, 10, 11, 10, 2)) == []


# ── monotonic rise ──────────────────────────────────────────────────────────
def test_monotonic_rise_over_three_snapshots_is_flagged():
    a = one(history(10, 2, 8, 9, 10))      # z is low (0.9) but 8 -> 9 -> 10 keeps climbing
    assert a["anomaly_type"] == "MONOTONIC_RISE"
    assert a["consecutive_increases"] == 3                 # 2 -> 8 -> 9 -> 10
    assert a["z_score"] is not None and a["z_score"] <= 2


def test_a_dip_inside_the_last_three_breaks_the_rise():
    assert detect_anomalies(history(10, 2, 9, 8, 10)) == []


def test_rise_across_a_gap_in_snapshots_does_not_count():
    snaps = history(10, 2, 8, 9, 10)
    del snaps[3]["risks"][0]               # R1 missing from the 4th snapshot: not consecutive
    assert detect_anomalies(snaps) == []


# ── not enough data / edge cases ────────────────────────────────────────────
def test_fewer_than_three_points_are_skipped():
    assert detect_anomalies(history(5, 20)) == []
    assert detect_anomalies(history(20)) == []


def test_three_points_is_enough():
    assert one(history(5, 5, 20))["anomaly_type"] == "STATISTICAL_OUTLIER"


def test_identical_scores_have_no_z_score_and_are_not_flagged():
    assert detect_anomalies(history(6, 6, 6, 6)) == []


def test_jump_after_a_flat_history_is_flagged_without_a_z_score():
    a = one(history(6, 6, 6, 10))
    assert a["anomaly_type"] == "STATISTICAL_OUTLIER" and a["z_score"] is None
    assert a["std_dev"] == 0
    assert detect_anomalies(history(6, 6, 6, 8)) == []     # +2 is too small to call


def test_risk_only_in_the_latest_snapshot_is_ignored():
    snaps = history(5, 5, 5, 5)
    snaps[-1]["risks"].append({"id": "R2", "title": "New", "score": 25})
    assert detect_anomalies(snaps) == []


def test_only_risks_in_the_latest_snapshot_are_returned():
    snaps = history(5, 5, 6, 30)
    snaps[-1]["risks"].clear()             # R1 closed in the newest snapshot
    assert detect_anomalies(snaps) == []


def test_missing_or_bad_fields_do_not_crash():
    snaps = history(5, 5, 6, 5, 14)
    snaps[1]["risks"].append({"id": "R9"})                 # no score or P/I
    snaps[2]["risks"].append({"id": "R8", "score": "n/a"})
    snaps[3]["risks"].extend(["junk", None, {"title": "no id", "score": 3}])
    snaps.insert(0, None)
    assert [a["risk_id"] for a in detect_anomalies(snaps)] == ["R1"]


def test_empty_inputs():
    for bad in (None, [], [{}], [{"risks": None}]):
        assert detect_anomalies(bad) == []


def test_scores_fall_back_to_probability_times_impact():
    snaps = [{"risks": [{"id": "R1", "title": "t", "probability": 1, "impact": 5}]} for _ in range(3)]
    snaps.append({"risks": [{"id": "R1", "title": "t", "probability": 5, "impact": 5}]})
    assert one(snaps)["current_score"] == 25


def test_result_has_the_documented_fields():
    a = one(history(5, 5, 6, 5, 14))
    assert set(a) == {"risk_id", "risk_title", "anomaly_type", "current_score", "mean_score",
                      "std_dev", "z_score", "consecutive_increases", "detail"}
    assert a["risk_title"] == "Risk one" and a["detail"]


# ── label_risks ─────────────────────────────────────────────────────────────
def test_label_risks_adds_anomaly_field_without_mutating_input():
    risks = [{"id": "R1", "title": "a"}, {"id": "R2", "title": "b"}]
    before = copy.deepcopy(risks)
    anomalies = [{"risk_id": "R1", "anomaly_type": "MONOTONIC_RISE", "detail": "d"}]
    out = label_risks(risks, anomalies)
    assert out[0]["anomaly"] == anomalies[0] and out[1]["anomaly"] is None
    assert risks == before and out[0]["title"] == "a"


def test_label_risks_tolerates_missing_anomalies():
    assert label_risks([{"id": "R1"}], None)[0]["anomaly"] is None
    assert label_risks(None, []) == []
