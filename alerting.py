"""Risk velocity alerting. No Flask, no AI.

After a snapshot is saved, compare it with the previous one for the same project
and raise an alert when a risk is getting worse quickly.

Rules (per risk present in both snapshots, delta = new score - old score):
  * severity worsened (e.g. Medium -> High)  -> CRITICAL  SEVERITY_WORSENED
  * delta >= 6                               -> CRITICAL  SCORE_INCREASE
  * delta 3..5                               -> WARN      SCORE_INCREASE
  * a new risk that is already High/Critical -> CRITICAL  NEW_HIGH_RISK
Risks that fell, stayed flat, or rose by 1-2 points raise nothing.

Alerts are appended to risk_alerts.jsonl (pruned to 60 days on each write) and each
one is also sent to security_logger as a RISK_ALERT event, so it shows up on the
/security dashboard. Every file operation is wrapped: an alerting failure must never
break a route.
"""

import json
import os
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone

RETENTION_DAYS = 60
WARN_DELTA = 3        # score increase that raises a WARN
CRITICAL_DELTA = 6    # score increase that raises a CRITICAL
_SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
_LOCK = threading.Lock()


def alerts_path():
    return os.getenv("RISK_ALERTS_PATH") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "risk_alerts.jsonl"
    )


def _now():
    return datetime.now(timezone.utc)


def _parse_ts(value):
    try:
        ts = datetime.fromisoformat(value)
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except Exception:
        return None


# ── scoring helpers ─────────────────────────────────────────────────────────
def _score(risk):
    """Score of a risk dict, or None if it can't be worked out.
    Uses 'score' when present (scored risks), else probability x impact (raw risks)."""
    try:
        s = risk.get("score")
        if isinstance(s, (int, float)) and not isinstance(s, bool):
            return int(s)
        p, i = risk.get("probability"), risk.get("impact")
        if all(isinstance(v, int) and not isinstance(v, bool) for v in (p, i)):
            return p * i
    except Exception:
        pass
    return None


def _severity(score):
    """Same bands as risk_engine: 20-25 Critical, 13-19 High, 7-12 Medium, 1-6 Low."""
    if score >= 20:
        return "Critical"
    if score >= 13:
        return "High"
    if score >= 7:
        return "Medium"
    return "Low"


def _by_id(snapshot):
    out = {}
    risks = snapshot.get("risks") if isinstance(snapshot, dict) else None
    for r in risks or []:
        if isinstance(r, dict) and r.get("id") is not None:
            out[r["id"]] = r
    return out


# ── core rule ───────────────────────────────────────────────────────────────
def compare_snapshots(project_name, old_snapshot, new_snapshot):
    """Pure function: the alerts this pair of snapshots would raise (nothing is stored)."""
    if not old_snapshot or not new_snapshot:
        return []  # nothing to compare against (first snapshot)
    old, new = _by_id(old_snapshot), _by_id(new_snapshot)
    ts = _now().isoformat(timespec="seconds")
    alerts = []

    def make(kind, sev, rid, risk, prev_score, new_score, prev_sev, new_sev, detail):
        return {
            "timestamp": ts, "project_name": project_name, "alert_type": kind,
            "severity": sev, "risk_id": rid, "risk_title": str(risk.get("title", "")),
            "previous_score": prev_score, "new_score": new_score,
            "previous_severity": prev_sev, "new_severity": new_sev, "detail": detail,
        }

    for rid, risk in new.items():
        new_score = _score(risk)
        if new_score is None:
            continue
        new_sev = _severity(new_score)
        if rid not in old:
            if new_sev in ("High", "Critical"):
                alerts.append(make(
                    "NEW_HIGH_RISK", "CRITICAL", rid, risk, None, new_score, None, new_sev,
                    f"{rid} is new and already {new_sev} (score {new_score}).",
                ))
            continue
        prev_score = _score(old[rid])
        if prev_score is None:
            continue
        prev_sev = _severity(prev_score)
        delta = new_score - prev_score
        if delta <= 0:
            continue
        title = risk.get("title", rid)
        if _SEVERITY_RANK[new_sev] > _SEVERITY_RANK[prev_sev]:
            alerts.append(make(
                "SEVERITY_WORSENED", "CRITICAL", rid, risk, prev_score, new_score, prev_sev, new_sev,
                f"{rid} ({title}) worsened from {prev_sev} to {new_sev}: score {prev_score} to {new_score} (+{delta}).",
            ))
        elif delta >= CRITICAL_DELTA:
            alerts.append(make(
                "SCORE_INCREASE", "CRITICAL", rid, risk, prev_score, new_score, prev_sev, new_sev,
                f"{rid} ({title}) jumped +{delta}: score {prev_score} to {new_score}.",
            ))
        elif delta >= WARN_DELTA:
            alerts.append(make(
                "SCORE_INCREASE", "WARN", rid, risk, prev_score, new_score, prev_sev, new_sev,
                f"{rid} ({title}) rose +{delta}: score {prev_score} to {new_score}.",
            ))
    return alerts


# ── storage ─────────────────────────────────────────────────────────────────
def _prune_if_needed(path):
    """Alerts are appended in time order, so only the first line can be stale."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        first = f.readline()
    try:
        first_ts = _parse_ts(json.loads(first).get("timestamp", ""))
    except Exception:
        first_ts = None
    cutoff = _now() - timedelta(days=RETENTION_DAYS)
    if first_ts is not None and first_ts >= cutoff:
        return
    keep = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                ts = _parse_ts(json.loads(line).get("timestamp", ""))
            except Exception:
                continue
            if ts is not None and ts >= cutoff:
                keep.append(line if line.endswith("\n") else line + "\n")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.writelines(keep)
    os.replace(tmp, path)


def _store(alerts):
    if not alerts:
        return
    try:
        path = alerts_path()
        lines = "".join(json.dumps(a, ensure_ascii=False) + "\n" for a in alerts)
        with _LOCK:
            try:
                _prune_if_needed(path)
            except Exception:
                pass
            with open(path, "a", encoding="utf-8") as f:
                f.write(lines)
    except Exception:
        pass


def _to_security_log(alerts, request):
    try:
        import security_logger
    except Exception:
        return
    for a in alerts:
        try:
            security_logger.log_event(
                "RISK_ALERT", a["severity"], request, a["detail"],
                {"project": a["project_name"], "risk_id": a["risk_id"],
                 "alert_type": a["alert_type"], "previous_score": a["previous_score"],
                 "new_score": a["new_score"]},
            )
        except Exception:
            pass


def check_and_alert(project_name, old_snapshot, new_snapshot, request=None):
    """Compare two snapshots, store and log any alerts, return the alerts fired.
    `request` is optional and only used to record the source IP in the security log."""
    try:
        alerts = compare_snapshots(project_name, old_snapshot, new_snapshot)
    except Exception:
        return []
    _store(alerts)
    _to_security_log(alerts, request)
    return alerts


# ── reading ─────────────────────────────────────────────────────────────────
def _read_all():
    out = []
    try:
        with _LOCK, open(alerts_path(), encoding="utf-8") as f:
            for line in f:
                try:
                    a = json.loads(line)
                    if isinstance(a, dict) and "timestamp" in a:
                        out.append(a)
                except Exception:
                    continue
    except Exception:
        pass
    return out


def get_alerts(project_name=None, limit=100, severity_filter=None, since_hours=None):
    """Newest first. since_hours limits to a recent window (e.g. 48)."""
    alerts = _read_all()
    if project_name:
        alerts = [a for a in alerts if a.get("project_name") == project_name]
    if severity_filter:
        alerts = [a for a in alerts if a.get("severity") == severity_filter]
    if since_hours is not None:
        cutoff = _now() - timedelta(hours=since_hours)
        alerts = [a for a in alerts if (_parse_ts(a.get("timestamp", "")) or cutoff) > cutoff]
    alerts.reverse()
    return alerts if limit is None else alerts[:max(0, int(limit))]


def _tally(alerts):
    return {
        "total": len(alerts),
        "by_type": dict(Counter(a.get("alert_type", "?") for a in alerts)),
        "by_severity": dict(Counter(a.get("severity", "?") for a in alerts)),
    }


def get_alert_summary():
    """Counts by alert_type and severity: {'last_24h': {...}, 'all_time': {...}}."""
    alerts = _read_all()
    cutoff = _now() - timedelta(hours=24)
    recent = [a for a in alerts if (_parse_ts(a.get("timestamp", "")) or cutoff) > cutoff]
    return {"last_24h": _tally(recent), "all_time": _tally(alerts)}
