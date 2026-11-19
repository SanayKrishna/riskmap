"""Correlation engine. No Flask, no AI.

Reads the security event log, looks for patterns across events, and records an
incident when a rule matches.

Rules
  BRUTE_FORCE_SUSPECTED      >= 3 UPLOAD_REJECTED / INVALID_JSON from one IP in 5 min   CRITICAL
  RATE_LIMIT_ABUSE           >= 5 RATE_LIMITED from one IP in 10 min                    CRITICAL
  INTEGRITY_BREACH_PATTERN   >= 2 SNAPSHOT_TAMPERED for one project (any window)        CRITICAL
  QUIET_ANOMALY_ESCALATION   3 RISK_ALERT WARNs in a row for one risk, never CRITICAL   WARN

A rule never fires twice for the same events. Every event that backs an incident is
"consumed" for that incident type (its id is stored in matched_event_ids), so
re-running the engine over the same log returns nothing new, and a later burst needs
fresh events of its own to fire again.

Incidents go to security_incidents.jsonl (entries older than 60 days are pruned on
write) and each one is also logged to security_logger as CORRELATION_INCIDENT. Every
file operation is wrapped: a correlation failure must never break logging or a route.
"""

import hashlib
import json
import os
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

RETENTION_DAYS = 60

BRUTE_FORCE = "BRUTE_FORCE_SUSPECTED"
RATE_LIMIT = "RATE_LIMIT_ABUSE"
INTEGRITY = "INTEGRITY_BREACH_PATTERN"
QUIET = "QUIET_ANOMALY_ESCALATION"
INCIDENT_TYPES = (BRUTE_FORCE, RATE_LIMIT, INTEGRITY, QUIET)

BRUTE_FORCE_COUNT, BRUTE_FORCE_WINDOW = 3, timedelta(minutes=5)
RATE_LIMIT_COUNT, RATE_LIMIT_WINDOW = 5, timedelta(minutes=10)
INTEGRITY_COUNT = 2
QUIET_COUNT = 3

# Event types the rules read. security_logger only calls the engine for these, so
# the high-volume INGESTED_LOG events don't trigger a log re-scan per line.
TRIGGER_TYPES = frozenset({
    "UPLOAD_REJECTED", "INVALID_JSON", "RATE_LIMITED", "SNAPSHOT_TAMPERED", "RISK_ALERT",
})

_LOCK = threading.Lock()      # guards the incidents file
_RUN_LOCK = threading.RLock()  # one correlation pass at a time
_STATE = threading.local()


def incidents_path():
    return os.getenv("SECURITY_INCIDENTS_PATH") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "security_incidents.jsonl"
    )


def _now():
    return datetime.now(timezone.utc)


def _parse_ts(value):
    try:
        ts = datetime.fromisoformat(value)
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except Exception:
        return None


class _Peer:
    """Minimal stand-in for a Flask request: security_logger only reads remote_addr."""

    def __init__(self, ip):
        self.remote_addr = ip


# ── events ──────────────────────────────────────────────────────────────────
def _chronological(events):
    """Oldest first, each event a copy tagged with a stable '_id' and parsed '_ts'.

    Events written by this version carry an 'id'. Older ones get a content hash, with
    a counter so identical lines stay distinct."""
    out, seen = [], Counter()
    for e in events:
        ts = _parse_ts(e.get("timestamp", ""))
        if ts is None:
            continue
        e = dict(e)
        eid = e.get("id")
        if not eid:
            base = "|".join(str(e.get(k, "")) for k in ("timestamp", "event_type", "source_ip", "detail"))
            digest = hashlib.sha1(base.encode("utf-8", "replace")).hexdigest()[:10]
            seen[digest] += 1
            eid = f"legacy-{digest}-{seen[digest]}"
        e["_id"], e["_ts"] = str(eid), ts
        out.append(e)
    out.sort(key=lambda x: x["_ts"])
    return out


def _groups(events, min_count, window):
    """Split chronological events into bursts of >= min_count that fit in `window`
    (None = no limit). Each burst is as large as the window allows."""
    i, n = 0, len(events)
    while i < n:
        j = i
        while j + 1 < n and (window is None or events[j + 1]["_ts"] - events[i]["_ts"] <= window):
            j += 1
        if j - i + 1 >= min_count:
            yield events[i:j + 1]
            i = j + 1
        else:
            i += 1


def _incident(itype, severity, group, detail, project="", risk_id=""):
    ips = Counter(e.get("source_ip") or "unknown" for e in group)
    return {
        "timestamp": _now().isoformat(timespec="seconds"),
        "incident_type": itype,
        "severity": severity,
        "source_ip": ips.most_common(1)[0][0],
        "matched_event_count": len(group),
        "detail": detail,
        "matched_event_ids": [e["_id"] for e in group],
        "project": project,
        "risk_id": risk_id,
    }


# ── rules: (chronological events, already-used ids) -> [incident, ...] ──────
def _burst_by_ip(events, used, types, count, window, itype, template):
    by_ip = defaultdict(list)
    for e in events:
        if e.get("event_type") in types and e["_id"] not in used:
            by_ip[e.get("source_ip") or "unknown"].append(e)
    found = []
    for ip, evs in by_ip.items():
        for g in _groups(evs, count, window):
            found.append(_incident(itype, "CRITICAL", g, template.format(ip=ip)))
    return found


def rule_brute_force(events, used):
    return _burst_by_ip(
        events, used, {"UPLOAD_REJECTED", "INVALID_JSON"}, BRUTE_FORCE_COUNT, BRUTE_FORCE_WINDOW,
        BRUTE_FORCE, "Repeated invalid submissions from {ip} — possible fuzzing or automated attack")


def rule_rate_limit_abuse(events, used):
    return _burst_by_ip(
        events, used, {"RATE_LIMITED"}, RATE_LIMIT_COUNT, RATE_LIMIT_WINDOW,
        RATE_LIMIT, "Sustained rate limit hits from {ip} — possible DoS attempt")


def _meta(e, key):
    m = e.get("metadata")
    return str(m.get(key) or "") if isinstance(m, dict) else ""


def rule_integrity_breach(events, used):
    by_project = defaultdict(list)
    for e in events:
        if e.get("event_type") == "SNAPSHOT_TAMPERED" and e["_id"] not in used:
            by_project[_meta(e, "project")].append(e)
    return [
        _incident(INTEGRITY, "CRITICAL", g,
                  f"Multiple tampered snapshots detected for project '{project}' — investigate immediately",
                  project=project)
        for project, evs in by_project.items()
        for g in _groups(evs, INTEGRITY_COUNT, None)
    ]


def rule_quiet_escalation(events, used):
    """Per (project, risk): a run of WARN risk alerts that never reached CRITICAL.
    A CRITICAL alert for the risk ends the run."""
    runs, found = defaultdict(list), []

    def flush(key):
        run = runs.pop(key, [])
        if len(run) >= QUIET_COUNT:
            project, risk_id = key
            found.append(_incident(
                QUIET, "WARN", run,
                f"Risk {risk_id} has triggered repeated WARN alerts — escalating for review",
                project=project, risk_id=risk_id))

    for e in events:
        if e.get("event_type") != "RISK_ALERT" or e["_id"] in used:
            continue
        key = (_meta(e, "project"), _meta(e, "risk_id"))
        if not key[1]:
            continue
        if e.get("severity") == "WARN":
            runs[key].append(e)
        elif e.get("severity") == "CRITICAL":
            flush(key)
    for key in list(runs):
        flush(key)
    return found


RULES = (
    (BRUTE_FORCE, rule_brute_force),
    (RATE_LIMIT, rule_rate_limit_abuse),
    (INTEGRITY, rule_integrity_breach),
    (QUIET, rule_quiet_escalation),
)


# ── storage ─────────────────────────────────────────────────────────────────
def _read_all():
    out = []
    try:
        with _LOCK, open(incidents_path(), encoding="utf-8") as f:
            for line in f:
                try:
                    i = json.loads(line)
                    if isinstance(i, dict) and "timestamp" in i:
                        out.append(i)
                except Exception:
                    continue
    except Exception:
        pass
    return out


def _prune_if_needed(path):
    """Incidents are appended chronologically, so only the first line can be stale."""
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


def _store(incidents):
    """Append incidents. Returns True if they were written."""
    if not incidents:
        return True
    try:
        path = incidents_path()
        lines = "".join(json.dumps(i, ensure_ascii=False, default=str) + "\n" for i in incidents)
        with _LOCK:
            try:
                _prune_if_needed(path)
            except Exception:
                pass
            with open(path, "a", encoding="utf-8") as f:
                f.write(lines)
        return True
    except Exception:
        return False


def _to_security_log(incidents):
    try:
        import security_logger
    except Exception:
        return
    for i in incidents:
        try:
            security_logger.log_event(
                "CORRELATION_INCIDENT", i["severity"], _Peer(i["source_ip"]), i["detail"],
                {"incident_type": i["incident_type"], "matched_event_count": i["matched_event_count"],
                 "project": i["project"], "risk_id": i["risk_id"]})
        except Exception:
            pass


# ── running ─────────────────────────────────────────────────────────────────
def run_correlation():
    """Run every rule over the current event log. Returns the new incidents fired
    (empty list if none, or if anything went wrong)."""
    if getattr(_STATE, "running", False):  # an incident being logged must not re-enter
        return []
    _STATE.running = True
    try:
        import security_logger
        with _RUN_LOCK:
            events = _chronological(security_logger.get_events(limit=None))
            used = defaultdict(set)
            for inc in _read_all():
                used[inc.get("incident_type")].update(inc.get("matched_event_ids") or [])
            fired = []
            for itype, rule in RULES:
                try:
                    fired.extend(rule(events, used[itype]))
                except Exception:
                    continue  # one broken rule must not silence the others
            # If the incidents can't be saved, report nothing: they would otherwise
            # be re-fired on every run.
            if fired and not _store(fired):
                return []
            _to_security_log(fired)
            return fired
    except Exception:
        return []
    finally:
        _STATE.running = False


def get_incidents(limit=100, severity_filter=None, since_hours=None):
    """Newest first. since_hours limits to a recent window (e.g. 72)."""
    found = _read_all()
    if severity_filter:
        found = [i for i in found if i.get("severity") == severity_filter]
    if since_hours is not None:
        cutoff = _now() - timedelta(hours=since_hours)
        found = [i for i in found if (_parse_ts(i.get("timestamp", "")) or cutoff) > cutoff]
    found.reverse()
    return found if limit is None else found[:max(0, int(limit))]


def _tally(incidents):
    return {
        "total": len(incidents),
        "by_type": dict(Counter(i.get("incident_type", "?") for i in incidents)),
        "by_severity": dict(Counter(i.get("severity", "?") for i in incidents)),
    }


def get_incident_summary():
    """Counts by incident_type and severity: {'last_24h': {...}, 'all_time': {...}}."""
    incidents = _read_all()
    cutoff = _now() - timedelta(hours=24)
    recent = [i for i in incidents if (_parse_ts(i.get("timestamp", "")) or cutoff) > cutoff]
    return {"last_24h": _tally(recent), "all_time": _tally(incidents)}
