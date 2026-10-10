"""Flask routes only — no scoring/chart logic here."""

import io
import json
import os

from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, redirect, url_for

load_dotenv()

from risk_engine import analyze_risks
from heatmap import generate_heatmap
from ai_planner import generate_response_plans
from exporter import to_csv_bytes
from graph import cascade_ranking, chains_text, isolated_nodes, network_chart, validate_links
from velocity import compute_trends, list_snapshots, save_snapshot, trend_chart

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-only-change-me")
# pick up template edits without a server restart
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True

# last successful analysis for /export and /snapshot (single-user standalone tool)
LAST = {"analysis": None, "ai": None, "raw_risks": None, "currency": "$"}


def _parse_incoming(form, files):
    """Return (project_name, manager, date, currency, risks_list). Raises ValueError."""
    pasted = (form.get("pasted_json") or "").strip()
    manual = (form.get("manual_json") or "").strip()
    uploaded = files.get("json_file")

    payload = None
    if uploaded and getattr(uploaded, "filename", ""):
        try:
            payload = json.load(uploaded.stream)
        except Exception as exc:
            raise ValueError(f"uploaded file is not valid JSON: {exc}")
    elif pasted:
        try:
            payload = json.loads(pasted)
        except Exception as exc:
            raise ValueError(f"pasted JSON is invalid: {exc}")
    elif manual:
        try:
            payload = json.loads(manual)
        except Exception as exc:
            raise ValueError(f"manual risk data is invalid: {exc}")
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

    if not isinstance(risks, list) or not risks:
        raise ValueError("at least one risk is required.")
    return project_name, manager, date, currency, risks


@app.get("/")
def index():
    return render_template("upload.html", error=None)


@app.post("/analyze")
def analyze():
    try:
        project_name, manager, date, currency, risks = _parse_incoming(request.form, request.files)
        validate_links(risks)
        analysis = analyze_risks(project_name, manager, date, risks, currency=currency)
        heatmap_div = generate_heatmap(analysis)
        cascade = cascade_ranking(analysis["risks"])
        network_div = network_chart(analysis)
        unlinked = isolated_nodes(analysis["risks"])
        high_crit = [r for r in analysis["risks"] if r["severity"] in ("High", "Critical")]
        ai = generate_response_plans(project_name, high_crit, chains=chains_text(analysis["risks"]))
        LAST["analysis"] = analysis
        LAST["ai"] = ai
        LAST["cascade"] = cascade
        LAST["network_div"] = network_div
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
        return render_template("upload.html", error=str(exc)), 400
    except Exception:  # never leak tracebacks
        return render_template("upload.html", error="Something went wrong analyzing risks. Check your JSON and try again."), 500


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
    div = trend_chart(project) if data["snapshots"] else ""
    return render_template("history.html", project=project, data=data,
                           trend_div=div, error=error)


@app.get("/history")
def history():
    project = (request.args.get("project") or "").strip()
    if not project and LAST.get("analysis"):
        project = LAST["analysis"]["project_name"]
    if not project:
        return redirect(url_for("index"))
    return _history_view(project)


@app.post("/snapshot")
def snapshot():
    try:
        project = (request.form.get("project") or "").strip()
        label = (request.form.get("label") or "").strip()
        snap_date = (request.form.get("date") or "").strip()
        pasted = (request.form.get("pasted_json") or "").strip()
        uploaded = request.files.get("json_file")
        if uploaded and getattr(uploaded, "filename", ""):
            try:
                payload = json.load(uploaded.stream)
            except Exception as exc:
                raise ValueError(f"uploaded file is not valid JSON: {exc}")
            risks = payload.get("risks") if isinstance(payload, dict) else payload
            currency = (payload.get("currency") if isinstance(payload, dict) else None) or "$"
            project = project or (payload.get("project_name") if isinstance(payload, dict) else "")
        elif pasted:
            try:
                payload = json.loads(pasted)
            except Exception as exc:
                raise ValueError(f"pasted JSON is invalid: {exc}")
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
        save_snapshot(project, label, snap_date, risks, currency=currency)
        return redirect(url_for("history", project=project))
    except ValueError as exc:
        project = (request.form.get("project") or "").strip() or "project"
        return _history_view(project, error=str(exc)), 400


if __name__ == "__main__":
    app.run(debug=False)
