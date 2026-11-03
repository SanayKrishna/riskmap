"""Security event logger — structured JSON lines. No Flask, no AI.

Every public function swallows its own I/O errors: a full disk or a
permission problem must never take a route down.
"""

import json
import os
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone

EVENT_TYPES = (
    "UPLOAD_REJECTED", "RATE_LIMITED", "OVERSIZED_UPLOAD", "INVALID_JSON",
    "CSRF_VIOLATION", "AI_FAILURE", "SNAPSHOT_SAVED", "SNAPSHOT_TAMPERED",
    "SNAPSHOT_VERIFIED",
)
SEVERITIES = ("INFO", "WARN", "CRITICAL")
RETENTION_DAYS = 30
MAX_DETAIL_CHARS = 500

_LOCK = threading.Lock()


def log_path():
    return os.getenv("SECURITY_LOG_PATH") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "security_events.jsonl"
    )


def _now():
    return datetime.now(timezone.utc)


def _parse_ts(value):
    try:
        ts = datetime.fromisoformat(value)
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _source_ip(request):
    """Peer address only. X-Forwarded-For is client-controlled, so not trusted."""
    try:
        return (getattr(request, "remote_addr", None) or "unknown")
    except Exception:  # e.g. request proxy used outside a request context
        return "unknown"


def _prune_if_needed(path):
    """Entries are appended chronologically, so only the first line can be stale.
    Rewrite the file (atomically) only when it is."""
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
                continue  # drop corrupt lines while we are rewriting anyway
            if ts is not None and ts >= cutoff:
                keep.append(line if line.endswith("\n") else line + "\n")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.writelines(keep)
    os.replace(tmp, path)


def log_event(event_type, severity, request=None, detail="", metadata=None):
    """Append one event. Returns the entry dict, or None if it could not be written."""
    try:
        severity = str(severity).upper()
        if severity not in SEVERITIES:
            severity = "WARN"
        entry = {
            "timestamp": _now().isoformat(timespec="seconds"),
            "event_type": str(event_type),
            "severity": severity,
            "source_ip": _source_ip(request),
            "detail": str(detail)[:MAX_DETAIL_CHARS],
            "metadata": metadata if isinstance(metadata, dict) else {},
        }
        line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
        path = log_path()
        with _LOCK:
            try:
                _prune_if_needed(path)
            except Exception:
                pass  # pruning is best-effort; still try to record the event
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
        return entry
    except Exception:
        return None


def _read_all():
    events = []
    try:
        with _LOCK, open(log_path(), encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                    if isinstance(e, dict) and "timestamp" in e:
                        events.append(e)
                except Exception:
                    continue
    except Exception:
        pass
    return events


def get_events(limit=200, severity_filter=None, event_type_filter=None):
    """Newest first. limit=None returns everything that matches."""
    events = _read_all()
    if severity_filter:
        events = [e for e in events if e.get("severity") == severity_filter]
    if event_type_filter:
        events = [e for e in events if e.get("event_type") == event_type_filter]
    events.reverse()
    return events if limit is None else events[:max(0, int(limit))]


def _tally(events):
    return {
        "total": len(events),
        "by_type": dict(Counter(e.get("event_type", "?") for e in events)),
        "by_severity": dict(Counter(e.get("severity", "?") for e in events)),
    }


def get_summary():
    """Counts by event_type and severity: {'last_24h': {...}, 'all_time': {...}}."""
    events = _read_all()
    cutoff = _now() - timedelta(hours=24)
    recent = [e for e in events if (_parse_ts(e.get("timestamp", "")) or cutoff) > cutoff]
    return {"last_24h": _tally(recent), "all_time": _tally(events)}


def count_today():
    """Events since local midnight."""
    midnight = datetime.now().astimezone().replace(hour=0, minute=0, second=0, microsecond=0)
    return sum(
        1 for e in _read_all()
        if (_parse_ts(e.get("timestamp", "")) or midnight - timedelta(days=1)) >= midnight
    )


def hourly_counts(hours=24):
    """Events per hour per severity for the trailing window (UTC hour buckets).

    Returns {'hours': [ISO hour starts, oldest first], 'series': {sev: [counts]}}."""
    end = _now().replace(minute=0, second=0, microsecond=0)
    starts = [end - timedelta(hours=hours - 1 - i) for i in range(hours)]
    series = {s: [0] * hours for s in SEVERITIES}
    for e in _read_all():
        ts = _parse_ts(e.get("timestamp", ""))
        sev = e.get("severity")
        if ts is None or sev not in series:
            continue
        idx = int((ts.replace(minute=0, second=0, microsecond=0) - starts[0]).total_seconds() // 3600)
        if 0 <= idx < hours:
            series[sev][idx] += 1
    return {"hours": [s.isoformat() for s in starts], "series": series}
