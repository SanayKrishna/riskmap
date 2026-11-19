"""External log ingestion. No Flask, no AI.

Parses log lines into security_logger events (event_type INGESTED_LOG). The format is
detected per line:

  A  syslog (RFC 3164)   Nov 19 10:23:01 host app[123]: message
  B  Common Log Format   127.0.0.1 - - [19/Nov/2026:10:23:01 +0000] "POST /analyze HTTP/1.1" 200 512
  C  JSON lines          {"timestamp": "...", "level": "warn", "source": "...", "message": "..."}

Severity: error / critical / fatal -> CRITICAL, warn / warning -> WARN, anything else INFO.
A line that matches no format is skipped, never raised on.

Command line (works without the web app):
  python log_ingestor.py sample.log     parse one file and print a summary
  python log_ingestor.py --scan         ingest everything in logs/incoming/, then move
                                        each file to logs/processed/
  python log_ingestor.py --watch        --scan, repeated every few seconds (Ctrl-C to stop)
"""

import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

import security_logger

EVENT_TYPE = "INGESTED_LOG"
MAX_LINES = 500           # per request / file
MAX_BYTES = 512 * 1024    # same cap as /analyze uploads
TIME_BUDGET = 2.0         # seconds a single ingest may spend writing events
MAX_RAW_CHARS = 2000

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INCOMING_DIR = os.path.join(BASE_DIR, "logs", "incoming")
PROCESSED_DIR = os.path.join(BASE_DIR, "logs", "processed")
SCAN_SUFFIXES = (".log", ".txt", ".json", ".jsonl")

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}

_SYSLOG = re.compile(
    r"^(?:<\d{1,3}>)?(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<app>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
_CLF = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?\s*$')
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_CRITICAL_WORDS = re.compile(r"\b(?:error|critical|crit|fatal|emerg|alert)\b", re.I)
_WARN_WORDS = re.compile(r"\b(?:warn|warning)\b", re.I)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


# ── helpers ─────────────────────────────────────────────────────────────────
def _iso(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _valid_ip(text):
    try:
        return str(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        return None


def _first_ip(text):
    for m in _IPV4.finditer(text or ""):
        ip = _valid_ip(m.group(0))
        if ip:
            return ip
    return None


def _severity_from_level(level):
    level = str(level or "").strip().lower()
    if level in ("error", "err", "critical", "crit", "fatal", "emerg", "emergency", "alert"):
        return "CRITICAL"
    if level in ("warn", "warning"):
        return "WARN"
    return "INFO"


def _severity_from_text(text):
    if _CRITICAL_WORDS.search(text):
        return "CRITICAL"
    if _WARN_WORDS.search(text):
        return "WARN"
    return "INFO"


def _json_timestamp(value):
    """ISO-8601 string, 'YYYY-MM-DD HH:MM:SS', or epoch seconds/milliseconds -> ISO UTC."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            if value > 1e11:  # milliseconds
                value = value / 1000
            return _iso(datetime.fromtimestamp(value, timezone.utc))
        return _iso(datetime.fromisoformat(str(value).strip().replace("Z", "+00:00")))
    except Exception:
        return None


def _syslog_timestamp(mon, day, hms, now=None):
    """RFC 3164 has no year or zone: assume the current year and UTC, stepping back a
    year when that would land more than a day in the future (a December log read in January)."""
    now = now or datetime.now(timezone.utc)
    h, m, s = (int(x) for x in hms.split(":"))
    dt = datetime(now.year, _MONTHS[mon], int(day), h, m, s, tzinfo=timezone.utc)
    if dt > now + timedelta(days=1):
        dt = dt.replace(year=now.year - 1)
    return _iso(dt)


def _clean(text):
    return _CONTROL.sub(" ", str(text)).strip()


def _event(fmt, raw, timestamp, ip, message, severity, **extra):
    meta = {"raw": raw[:MAX_RAW_CHARS], "format": fmt, "timestamp": timestamp}
    meta.update({k: v for k, v in extra.items() if v not in (None, "")})
    return {
        "timestamp": timestamp,
        "source_ip": ip,
        "message": _clean(message),
        "severity": severity,
        "event_type": EVENT_TYPE,
        "metadata": meta,
    }


# ── parsing ─────────────────────────────────────────────────────────────────
def _parse_json_line(raw):
    try:
        obj = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    if not isinstance(obj, dict):
        return None

    def pick(*keys):
        for k in keys:
            if obj.get(k) not in (None, ""):
                return obj[k]
        return None

    message = pick("message", "msg", "detail")
    if message is None:
        return None
    source = pick("source", "src", "host", "service", "logger")
    ip = next((_valid_ip(v) for v in (pick("source_ip", "src_ip", "ip", "client_ip", "remote_addr"), source)
               if v is not None and _valid_ip(v)), None)
    return _event(
        "json", raw, _json_timestamp(pick("timestamp", "time", "ts", "@timestamp")), ip,
        message if isinstance(message, str) else json.dumps(message, default=str),
        _severity_from_level(pick("level", "severity", "lvl")),
        source=None if source is None or _valid_ip(source) else str(source)[:100])


def _parse_syslog(raw):
    m = _SYSLOG.match(raw)
    if not m or m["mon"] not in _MONTHS:
        return None
    try:
        ts = _syslog_timestamp(m["mon"], m["day"], m["time"])
    except ValueError:  # e.g. Feb 31 or 25:00:00
        return None
    msg = m["msg"]
    return _event("syslog", raw, ts, _first_ip(msg) or _valid_ip(m["host"]), msg,
                  _severity_from_text(msg), host=m["host"], app=m["app"], pid=m["pid"])


def _parse_clf(raw):
    m = _CLF.match(raw)
    if not m:
        return None
    try:
        ts = _iso(datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z"))
    except ValueError:
        return None
    size = "" if m["size"] == "-" else f" ({m['size']} bytes)"
    return _event("clf", raw, ts, _valid_ip(m["ip"]), f"{m['req']} -> {m['status']}{size}", "INFO",
                  status=int(m["status"]), request=m["req"][:300], user=None if m["user"] == "-" else m["user"])


def parse_line(raw):
    """Parse one log line. Returns an event dict, or None if it matches no known format.

    {'timestamp': ISO-8601 UTC (None if the line has none), 'source_ip': str | None,
     'message': str, 'severity': INFO|WARN|CRITICAL, 'event_type': 'INGESTED_LOG',
     'metadata': {'raw': <original line>, 'format': ..., ...}}"""
    try:
        if not isinstance(raw, str):
            return None
        line = raw.strip()
        if not line:
            return None
        if line.startswith("{"):
            return _parse_json_line(line)
        return _parse_clf(line) or _parse_syslog(line)
    except Exception:
        return None


# ── ingestion ───────────────────────────────────────────────────────────────
class _Peer:
    """Stand-in for a Flask request so the event records the log's own source IP."""

    def __init__(self, ip):
        self.remote_addr = ip


def ingest_lines(lines, request=None, max_lines=MAX_LINES, time_budget=TIME_BUDGET):
    """Parse and log each line. Returns {'ingested': N, 'skipped': M, 'errors': [...]}.

    Blank lines are ignored. At most max_lines lines are read and at most time_budget
    seconds are spent; anything left over is reported in errors, not silently dropped."""
    result = {"ingested": 0, "skipped": 0, "errors": []}
    deadline = time.monotonic() + time_budget
    seen = 0
    try:
        for raw in lines:
            if not isinstance(raw, str) or not raw.strip():
                continue
            if seen >= max_lines:
                result["errors"].append(f"line limit reached: only the first {max_lines} lines were read")
                break
            if time.monotonic() > deadline:
                result["errors"].append(f"time limit reached after {seen} lines; the rest were not read")
                break
            seen += 1
            event = parse_line(raw)
            if event is None:
                result["skipped"] += 1
                continue
            try:
                ip = event["source_ip"]
                logged = security_logger.log_event(
                    EVENT_TYPE, event["severity"], _Peer(ip) if ip else request, event["message"], event["metadata"])
            except Exception:
                logged = None
            if logged is None:
                result["skipped"] += 1
                if "could not write to the security log" not in result["errors"]:
                    result["errors"].append("could not write to the security log")
            else:
                result["ingested"] += 1
    except Exception as exc:  # never let a bad input stream escape
        result["errors"].append(f"ingestion stopped: {type(exc).__name__}")
    return result


def ingest_file(filepath):
    """Ingest a log file. Returns {'ingested': N, 'skipped': M, 'errors': [...]}."""
    try:
        with open(filepath, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except Exception as exc:
        return {"ingested": 0, "skipped": 0, "errors": [f"could not read {os.path.basename(str(filepath))}: {type(exc).__name__}"]}
    errors = []
    if len(raw) > MAX_BYTES:
        raw = raw[:MAX_BYTES]
        errors.append(f"file is larger than {MAX_BYTES // 1024} KB: only the first {MAX_BYTES // 1024} KB were read")
    result = ingest_lines(raw.decode("utf-8-sig", errors="replace").splitlines())
    result["errors"] = errors + result["errors"]
    return result


def ingest_incoming(incoming=INCOMING_DIR, processed=PROCESSED_DIR):
    """Ingest every log file waiting in the incoming directory (created if missing),
    then move each into the processed directory so it is never read twice.
    Returns {'files': {name: result}, 'ingested': N, 'skipped': M, 'errors': [...]}."""
    total = {"files": {}, "ingested": 0, "skipped": 0, "errors": []}
    try:
        os.makedirs(incoming, exist_ok=True)
        names = sorted(n for n in os.listdir(incoming)
                       if n.lower().endswith(SCAN_SUFFIXES) and os.path.isfile(os.path.join(incoming, n)))
    except Exception as exc:
        total["errors"].append(f"could not read {incoming}: {type(exc).__name__}")
        return total
    for name in names:
        src = os.path.join(incoming, name)
        res = ingest_file(src)
        total["files"][name] = res
        total["ingested"] += res["ingested"]
        total["skipped"] += res["skipped"]
        total["errors"] += [f"{name}: {e}" for e in res["errors"]]
        if res["errors"] and res["ingested"] == 0 and res["skipped"] == 0:
            continue  # unreadable: leave it in place so the problem is visible
        try:
            os.makedirs(processed, exist_ok=True)
            dest = os.path.join(processed, f"{int(time.time())}-{name}")
            os.replace(src, dest)
        except Exception as exc:
            total["errors"].append(f"{name}: could not move to processed ({type(exc).__name__})")
    return total


# ── command line ────────────────────────────────────────────────────────────
def _print_summary(label, res):
    print(f"{label}: ingested {res['ingested']}, skipped {res['skipped']}")
    for e in res["errors"]:
        print(f"  ! {e}")


def main(argv):
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        print(__doc__.split("Command line", 1)[1].strip("\n:") if "Command line" in __doc__ else "")
        return 2
    arg = argv[1]
    if arg == "--scan":
        res = ingest_incoming()
        for name, r in res["files"].items():
            _print_summary(name, r)
        _print_summary(f"scanned {INCOMING_DIR}", res)
        return 0
    if arg == "--watch":
        os.makedirs(INCOMING_DIR, exist_ok=True)
        print(f"watching {INCOMING_DIR} (Ctrl-C to stop)")
        try:
            while True:
                res = ingest_incoming()
                for name, r in res["files"].items():
                    _print_summary(name, r)
                time.sleep(5)
        except KeyboardInterrupt:
            return 0
    res = ingest_file(arg)
    _print_summary(arg, res)
    return 1 if res["errors"] and res["ingested"] == 0 and res["skipped"] == 0 else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
