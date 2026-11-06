"""Anomaly detection on risk score history. No Flask, no AI, no file I/O.

For each risk in the LATEST snapshot that has at least 3 data points, flag it when:

  1. STATISTICAL_OUTLIER: its latest score is more than 2 standard deviations above
     the mean of its EARLIER scores. The baseline deliberately excludes the latest
     point: if the latest score were part of its own baseline, a 3-point history could
     never reach z = 2 (the maximum possible is about 1.4), so real spikes would go
     unflagged. When the earlier scores are all identical (std = 0) no z-score exists,
     so a jump of 3 or more points above that flat line is flagged with z_score = None.
  2. MONOTONIC_RISE: its score rose at every step across the last 3 consecutive
     snapshots, which catches slow-burn risks that never spike.

A statistical outlier takes precedence if a risk qualifies for both.
"""

from statistics import mean, pstdev

Z_THRESHOLD = 2.0
FLAT_JUMP = 3        # points above a perfectly flat history that counts as an outlier
MIN_POINTS = 3       # data points needed before a risk is assessed


def _score(risk):
    """Score of a risk dict, or None. Uses 'score' if present, else probability x impact."""
    try:
        s = risk.get("score")
        if isinstance(s, (int, float)) and not isinstance(s, bool):
            return float(s)
        p, i = risk.get("probability"), risk.get("impact")
        if all(isinstance(v, int) and not isinstance(v, bool) for v in (p, i)):
            return float(p * i)
    except Exception:
        pass
    return None


def _history(snapshots):
    """{risk_id: [(snapshot_index, score), ...]} in snapshot order; bad data is skipped."""
    hist = {}
    for idx, snap in enumerate(snapshots or []):
        risks = snap.get("risks") if isinstance(snap, dict) else None
        for r in risks or []:
            if not isinstance(r, dict) or r.get("id") is None:
                continue
            sc = _score(r)
            if sc is not None:
                hist.setdefault(r["id"], []).append((idx, sc))
    return hist


def _rising_run(points):
    """How many consecutive increases end at the last point, only counting steps
    between adjacent snapshots (a gap in the history breaks the run)."""
    run = 0
    for k in range(len(points) - 1, 0, -1):
        (i0, s0), (i1, s1) = points[k - 1], points[k]
        if i1 - i0 == 1 and s1 > s0:
            run += 1
        else:
            break
    return run


def _fmt(x):
    return f"{x:.1f}".rstrip("0").rstrip(".")


def detect_anomalies(snapshots):
    """Anomalous risks in the latest snapshot. snapshots is ordered oldest to newest,
    each a dict with a 'risks' list. Returns a list of anomaly dicts (possibly empty)."""
    try:
        if not snapshots or not isinstance(snapshots[-1], dict):
            return []
        latest_idx = len(snapshots) - 1
        latest_titles = {
            r["id"]: r.get("title", "")
            for r in (snapshots[-1].get("risks") or [])
            if isinstance(r, dict) and r.get("id") is not None
        }
        found = []
        for rid, points in _history(snapshots).items():
            if len(points) < MIN_POINTS or points[-1][0] != latest_idx:
                continue  # too little history, or not in the latest snapshot
            scores = [s for _, s in points]
            current, baseline = scores[-1], scores[:-1]
            mu, sd = mean(baseline), pstdev(baseline)
            run = _rising_run(points)
            title = latest_titles.get(rid, "")
            result = None

            if sd > 0:
                z = (current - mu) / sd
                if z > Z_THRESHOLD:
                    result = ("STATISTICAL_OUTLIER", round(z, 2),
                              f"Score {_fmt(current)} is {z:.1f} standard deviations above its usual "
                              f"{_fmt(mu)} (std {sd:.1f}) over {len(baseline)} earlier snapshots.")
            elif current - mu >= FLAT_JUMP:
                result = ("STATISTICAL_OUTLIER", None,
                          f"Score jumped to {_fmt(current)} after holding steady at {_fmt(mu)} "
                          f"for {len(baseline)} snapshots.")

            if result is None and len(points) >= 3 and run >= 2:
                last3 = " → ".join(_fmt(s) for s in scores[-3:])
                result = ("MONOTONIC_RISE", round((current - mu) / sd, 2) if sd > 0 else None,
                          f"Score has risen at every step ({last3}). A steady climb, even without a spike.")

            if result:
                kind, z, detail = result
                found.append({
                    "risk_id": rid, "risk_title": title, "anomaly_type": kind,
                    "current_score": round(current, 2), "mean_score": round(mu, 2),
                    "std_dev": round(sd, 2), "z_score": z,
                    "consecutive_increases": run, "detail": detail,
                })
        found.sort(key=lambda a: (a["anomaly_type"] != "STATISTICAL_OUTLIER", str(a["risk_id"])))
        return found
    except Exception:
        return []


def label_risks(risks, anomalies):
    """The same risks, each with an 'anomaly' field: the anomaly dict or None."""
    by_id = {a["risk_id"]: a for a in (anomalies or []) if isinstance(a, dict) and "risk_id" in a}
    out = []
    for r in risks or []:
        if not isinstance(r, dict):
            out.append(r)
            continue
        labeled = dict(r)
        labeled["anomaly"] = by_id.get(r.get("id"))
        out.append(labeled)
    return out
