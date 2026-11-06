"""Flask routes only — no scoring/chart logic here."""

import io
import os
import re

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, send_file, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

load_dotenv()

from risk_engine import analyze_risks
from heatmap import generate_heatmap
from ai_planner import generate_response_plans
from exporter import to_csv_bytes
from graph import cascade_ranking, chains_text, isolated_nodes, network_chart, validate_links
from velocity import compute_trends, list_snapshots, save_snapshot, snapshot_integrity, trend_chart
from alerting import check_and_alert, get_alerts
from anomaly import detect_anomalies, label_risks
from security_logger import count_today, get_events, get_summary, log_event
from security_charts import timeline_chart, type_breakdown_chart
from validation import (
    MAX_UPLOAD_BYTES, parse_json, read_upload, validate_project_fields, validate_risks,
)

IS_PROD = os.getenv("FLASK_ENV", "").strip().lower() == "production"

app = Flask(__name__)
# Never fall back to the well-known dev key in production: a random per-process
# key is safe (it only invalidates sessions/CSRF tokens on restart).
app.secret_key = os.getenv("SECRET_KEY") or (os.urandom(32).hex() if IS_PROD else "dev-only-change-me")
# pick up template edits without a server restart
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True
# hard cap on the whole request body (file <= 512 KB plus form fields)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES * 2
# tokens live as long as the session, so an idle results page doesn't trip CSRF alerts
app.config["WTF_CSRF_TIME_LIMIT"] = None

# ── Security layer ──────────────────────────────────────────────────────────
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

# Scripts: same-origin only (inline plotly scripts get a per-request nonce).
# Styles: 'unsafe-inline' for plotly's inline styles, plus Google Fonts so the
# Inter / Newsreader typography keeps loading.
CSP = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "img-src": ["'self'", "data:"],
    "connect-src": "'self'",
    "object-src": "'none'",
    "base-uri": "'self'",
    "form-action": "'self'",
    "frame-ancestors": "'none'",
}
Talisman(
    app,
    content_security_policy=CSP,
    content_security_policy_nonce_in=["script-src"],
    force_https=IS_PROD,
    strict_transport_security=IS_PROD,
    session_cookie_secure=IS_PROD,
    frame_options="DENY",
    referrer_policy="strict-origin-when-cross-origin",
)

_SCRIPT_TAG = re.compile(r"<script(?![^>]*\bnonce=)", re.I)


@app.after_request
def _nonce_inline_scripts(resp):
    """Plotly divs and page scripts are rendered as inline <script>; stamp them with
    this request's CSP nonce so they run without allowing 'unsafe-inline'."""
    try:
        nonce = getattr(request, "csp_nonce", None)
        if nonce and resp.mimetype == "text/html" and not resp.direct_passthrough:
            resp.set_data(_SCRIPT_TAG.sub(f'<script nonce="{nonce}"', resp.get_data(as_text=True)))
    except Exception:
        pass
    return resp


@app.get("/plotly.min.js")
def plotly_js():
    """Serve plotly.js from the installed package so no external script origin is needed."""
    import plotly
    path = os.path.join(os.path.dirname(plotly.__file__), "package_data", "plotly.min.js")
    return send_file(path, mimetype="application/javascript", max_age=86400)


# last successful analysis for /export, /snapshot and /results
# (single-user standalone tool)
LAST = {
    "analysis": None,
    "ai": None,
    "raw_risks": None,
    "currency": "$",
    "cascade": [],
    "network_div": "",
    "heatmap_div": "",
    "unlinked": [],
}


def _safe_log(event_type, severity, detail="", **metadata):
    """Logging must never break a route."""
    try:
        log_event(event_type, severity, request, detail, metadata)
    except Exception:
        pass


def _upload_name():
    try:
        f = request.files.get("json_file")
        return secure_filename(f.filename) if f and f.filename else ""
    except Exception:
        return ""


def _log_ai_failure(ai):
    err = str(ai.get("error", ""))
    for key in (os.getenv("GEMINI_API_KEY"), os.getenv("GOOGLE_API_KEY")):
        if key:
            err = err.replace(key, "***")
    _safe_log("AI_FAILURE", "WARN", f"AI response plans unavailable ({ai.get('reason', 'error')})",
              reason=ai.get("reason", "error"), error=err[:200])


# Alerting and anomaly detection are non-critical extras: any failure in them is
# swallowed so it can never block a route.
def _anomalies_for(project, current_risks=None):
    """Anomalies in a project's latest snapshot. When current_risks is given (the
    analysis being viewed, not yet saved) it counts as the newest data point."""
    try:
        snaps = list_snapshots(project)
        # Skip the current analysis if it matches the newest saved snapshot, otherwise
        # the same data point would be counted twice and dilute a real spike.
        if current_risks is not None and not (snaps and _same_scores(snaps[-1].get("risks"), current_risks)):
            snaps = snaps + [{"label": "current", "risks": current_risks}]
        return detect_anomalies(snaps)
    except Exception:
        return []


def _same_scores(a, b):
    def key(risks):
        return sorted((str(r.get("id")), r.get("probability"), r.get("impact"))
                      for r in (risks or []) if isinstance(r, dict))
    return key(a) == key(b)


def _alert_on_snapshot(project, snaps):
    """Compare the snapshot just saved with the one before it. Returns alerts fired."""
    try:
        if len(snaps) < 2:
            return []
        old, new = snaps[-2], snaps[-1]
        # only alert on a verified new snapshot, and never against a tampered baseline
        if snapshot_integrity(new) != "verified" or snapshot_integrity(old) == "tampered":
            return []
        return check_and_alert(project, old, new, request)
    except Exception:
        return []


def _active_alerts():
    try:
        return get_alerts(limit=20, since_hours=48)
    except Exception:
        return []


def _parse_incoming(form, files):
    """Return (project_name, manager, date, currency, risks_list). Raises ValueError."""
    pasted = (form.get("pasted_json") or "").strip()
    manual = (form.get("manual_json") or "").strip()
    uploaded = files.get("json_file")

    if uploaded and getattr(uploaded, "filename", ""):
        name, text = read_upload(uploaded)  # size + MIME + filename checks
        payload = parse_json(text, f"uploaded file {name!r}")
    elif pasted:
        payload = parse_json(pasted, "pasted JSON")
    elif manual:
        payload = parse_json(manual, "manual risk data")
    else:
        raise ValueError("upload a JSON file, paste JSON, or add risks manually.")

    if isinstance(payload, list):
        # manual JS may send a bare list — wrap with form project fields
        risks = payload
        project_name = form.get("project_name", "").strip() or "Untitled Project"
        manager = form.get("project_manager", "").strip()
        date = form.get("date", "").strip()
        currency = form.get("currency", "").strip() or "$"
    elif isinstance(payload, dict):
        risks = payload.get("risks")
        project_name = payload.get("project_name") or form.get("project_name", "").strip() or "Untitled Project"
        manager = payload.get("project_manager", "") or form.get("project_manager", "").strip() or ""
        date = payload.get("date", "") or form.get("date", "").strip() or ""
        currency = payload.get("currency") or form.get("currency", "").strip() or "$"
        if risks is None:
            raise ValueError("JSON must contain a 'risks' list.")
    else:
        raise ValueError("JSON must be an object with project_name and risks.")

    validate_project_fields(project_name=project_name, manager=manager, date=date, currency=currency)
    validate_risks(risks)  # schema + 50-risk cap
    return project_name, manager, date, currency, risks


@app.get("/")
def index():
    return render_template("upload.html", error=None)


@app.post("/analyze")
@limiter.limit("10/minute")
def analyze():
    try:
        project_name, manager, date, currency, risks = _parse_incoming(request.form, request.files)
        validate_links(risks)
        analysis = analyze_risks(project_name, manager, date, risks, currency=currency)
        try:  # flag risks that deviate from their own history (needs saved snapshots)
            analysis["risks"] = label_risks(analysis["risks"], _anomalies_for(project_name, risks))
        except Exception:
            pass
        heatmap_div = generate_heatmap(analysis)
        cascade = cascade_ranking(analysis["risks"])
        network_div = network_chart(analysis)
        unlinked = isolated_nodes(analysis["risks"])
        high_crit = [r for r in analysis["risks"] if r["severity"] in ("High", "Critical")]
        ai = generate_response_plans(project_name, high_crit, chains=chains_text(analysis["risks"]))
        if not ai.get("available", True):
            _log_ai_failure(ai)
        LAST["analysis"] = analysis
        LAST["ai"] = ai
        LAST["cascade"] = cascade
        LAST["network_div"] = network_div
        LAST["heatmap_div"] = heatmap_div
        LAST["unlinked"] = unlinked
        LAST["raw_risks"] = risks
        LAST["currency"] = currency
        return render_template(
            "results.html",
            analysis=analysis,
            heatmap_div=heatmap_div,
            ai=ai,
            cascade=cascade,
            network_div=network_div,
            unlinked=unlinked,
        )
    except ValueError as exc:
        etype = getattr(exc, "event_type", "UPLOAD_REJECTED")
        _safe_log(etype, getattr(exc, "severity", "WARN"), str(exc),
                  endpoint="analyze", filename=_upload_name())
        return render_template("upload.html", error=str(exc)), (413 if etype == "OVERSIZED_UPLOAD" else 400)
    except Exception:  # never leak tracebacks
        return render_template("upload.html", error="Something went wrong analyzing risks. Check your JSON and try again."), 500


@app.get("/results")
def results():
    """Re-open the last analysis (used by the history page)."""
    analysis = LAST.get("analysis")
    if not analysis:
        return redirect(url_for("index"))
    project = (request.args.get("project") or "").strip()
    if project and project != analysis.get("project_name"):
        return redirect(url_for("history", project=project))
    return render_template(
        "results.html",
        analysis=analysis,
        heatmap_div=LAST.get("heatmap_div", ""),
        ai=LAST.get("ai") or {"available": True, "reason": "", "plans": {}},
        cascade=LAST.get("cascade", []),
        network_div=LAST.get("network_div", ""),
        unlinked=LAST.get("unlinked", []),
    )


@app.get("/export")
def export():
    analysis = LAST.get("analysis")
    ai = LAST.get("ai") or {}
    if not analysis:
        return redirect(url_for("index"))
    csv_bytes = to_csv_bytes(analysis, ai.get("plans", {}))
    name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in analysis.get("project_name", "risks"))
    return send_file(
        io.BytesIO(csv_bytes),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"risk_register_{name or 'export'}.csv",
    )


@app.errorhandler(500)
def _500(_e):
    return render_template("upload.html", error="Internal error. Please try again."), 500


def _history_view(project, error=None):
    data = compute_trends(project)
    _log_integrity(project, data["snapshots"])
    div = trend_chart(project) if data["snapshots"] else ""
    return render_template("history.html", project=project, data=data,
                           trend_div=div, error=error, anomalies=_anomalies_for(project))


def _log_integrity(project, snapshots):
    verified = [s["label"] for s in snapshots if s.get("integrity") == "verified"]
    for s in snapshots:
        if s.get("integrity") == "tampered":
            _safe_log("SNAPSHOT_TAMPERED", "CRITICAL",
                      f"snapshot {s['label']!r} of {project!r} does not match its stored hash",
                      project=project, label=s["label"])
    if verified:
        _safe_log("SNAPSHOT_VERIFIED", "INFO", f"{len(verified)} snapshot(s) of {project!r} verified",
                  project=project, labels=verified[:20])


@app.get("/history")
def history():
    project = (request.args.get("project") or "").strip()
    if not project and LAST.get("analysis"):
        project = LAST["analysis"]["project_name"]
    if not project:
        return redirect(url_for("index"))
    return _history_view(project)


@app.post("/snapshot")
@limiter.limit("20/minute")
def snapshot():
    try:
        project = (request.form.get("project") or "").strip()
        label = (request.form.get("label") or "").strip()
        snap_date = (
            request.form.get("date") or request.form.get("snapshot_date") or ""
        ).strip()
        pasted = (request.form.get("pasted_json") or "").strip()
        uploaded = request.files.get("json_file")
        if uploaded and getattr(uploaded, "filename", ""):
            name, text = read_upload(uploaded)
            payload = parse_json(text, f"uploaded file {name!r}")
            risks = payload.get("risks") if isinstance(payload, dict) else payload
            currency = (payload.get("currency") if isinstance(payload, dict) else None) or "$"
            project = project or (payload.get("project_name") if isinstance(payload, dict) else "")
        elif pasted:
            payload = parse_json(pasted, "pasted JSON")
            risks = payload.get("risks") if isinstance(payload, dict) else payload
            currency = (payload.get("currency") if isinstance(payload, dict) else None) or "$"
            project = project or (payload.get("project_name") if isinstance(payload, dict) else "")
        else:
            # snapshot the last analysis straight from the results page
            if not LAST.get("analysis"):
                raise ValueError("analyze a project first, then save it as a snapshot.")
            project = project or LAST["analysis"]["project_name"]
            risks = LAST["raw_risks"]
            currency = LAST.get("currency", "$")
            snap_date = snap_date or LAST["analysis"].get("date", "")
        if not project:
            raise ValueError("project name is missing.")
        snaps = save_snapshot(project, label, snap_date, risks, currency=currency)
        _safe_log("SNAPSHOT_SAVED", "INFO", f"snapshot {label!r} saved for {project!r}",
                  project=project, label=label, risks=len(risks))
        _alert_on_snapshot(project, snaps)
        return redirect(url_for("history", project=project))
    except ValueError as exc:
        etype = getattr(exc, "event_type", "UPLOAD_REJECTED")
        _safe_log(etype, getattr(exc, "severity", "WARN"), str(exc),
                  endpoint="snapshot", filename=_upload_name())
        project = (request.form.get("project") or "").strip() or "project"
        return _history_view(project, error=str(exc)), (413 if etype == "OVERSIZED_UPLOAD" else 400)


# ── Security dashboard ──────────────────────────────────────────────────────
def _security_view(error=None):
    summary = get_summary()
    recent = summary["last_24h"]["by_severity"]
    return render_template(
        "security.html",
        error=error,
        total=summary["all_time"]["total"],
        critical_24h=recent.get("CRITICAL", 0),
        warn_24h=recent.get("WARN", 0),
        today=count_today(),
        timeline_div=timeline_chart(),
        types_div=type_breakdown_chart(),
        events=get_events(limit=100),
        active_alerts=_active_alerts(),
    )


@app.get("/security")
@limiter.limit("30/minute")
def security():
    return _security_view()


@app.get("/alerts")
@limiter.limit("30/minute")
def alerts():
    """Read-only JSON API: risk alert history, newest first (max 200).
    ?project=<name> narrows it to one project."""
    project = (request.args.get("project") or "").strip() or None
    found = get_alerts(project_name=project, limit=200)
    return jsonify({"project": project, "count": len(found), "alerts": found})


# ── Security error handlers ─────────────────────────────────────────────────
def _error_page(message, status):
    """Re-render the page the request came from, with an inline error."""
    if request.endpoint == "snapshot":
        project = (request.form.get("project") or "").strip() or "project"
        try:
            return _history_view(project, error=message), status
        except Exception:
            pass
    elif request.endpoint == "security":
        return _security_view(error=message), status
    elif request.endpoint == "alerts":  # API endpoint: answer in JSON, not HTML
        return jsonify({"error": message}), status
    return render_template("upload.html", error=message), status


@app.errorhandler(429)
def _rate_limited(e):
    _safe_log("RATE_LIMITED", "WARN", f"rate limit hit on {request.path}",
              endpoint=request.endpoint, limit=str(getattr(e, "description", "")))
    return _error_page("Too many requests — please wait a minute and try again.", 429)


@app.errorhandler(RequestEntityTooLarge)
def _too_large(_e):
    _safe_log("OVERSIZED_UPLOAD", "WARN", f"request body over {MAX_UPLOAD_BYTES * 2 // 1024} KB",
              endpoint=request.endpoint, length=request.content_length)
    return _error_page(f"That upload is too large (limit {MAX_UPLOAD_BYTES // 1024} KB).", 413)


@app.errorhandler(CSRFError)
def _csrf_error(e):
    _safe_log("CSRF_VIOLATION", "CRITICAL", f"CSRF check failed on {request.path}: {e.description}",
              endpoint=request.endpoint, method=request.method)
    return _error_page("Your session expired or the form could not be verified. Reload the page and try again.", 400)


if __name__ == "__main__":
    # debug stays off (no interactive debugger); the reloader restarts the server when
    # Python files change, so the running process can't drift from the code on disk.
    app.run(debug=False, use_reloader=True)
