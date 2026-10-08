"""AI response planner — the ONLY module that calls the AI API (Gemini)."""

import json
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai_log.txt")
ALLOWED_STRATEGIES = ("Avoid", "Mitigate", "Transfer", "Accept")


def _api_key():
    return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or ""


def build_prompt(project_name, risks):
    lines = [
        f'You are a senior project risk manager. Project: "{project_name}".',
        "For EACH risk below, propose a response plan.",
        "Return STRICT JSON only, no markdown, no extra text, with this shape:",
        '{"responses": [{"risk_id": "R1", "strategy": "Mitigate", '
        '"strategy_justification": "one sentence", '
        '"actions": ["step 1", "step 2", "step 3"], '
        '"owner": "role", "contingency": "one sentence"}]}',
        "Rules:",
        "- strategy must be exactly one of: Avoid, Mitigate, Transfer, Accept.",
        "- actions: 2-3 SPECIFIC concrete steps tied to the risk description.",
        "  Never generic advice like 'monitor the risk'.",
        "- owner: a role like Tech Lead, Project Manager, Procurement.",
        "- contingency: one sentence on what to do if the risk occurs anyway.",
        "",
        "RISKS:",
    ]
    for r in risks:
        lines.append(
            f"- {r.get('id')}: \"{r.get('title')}\" "
            f"[{r.get('category')}] P={r.get('probability')} "
            f"I={r.get('impact')} score={r.get('score')} "
            f"({r.get('severity')}). {r.get('description')}"
        )
    return "\n".join(lines)


def _log(prompt, raw):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("=== PROMPT ===\n" + prompt + "\n=== RESPONSE ===\n" + str(raw)[:8000] + "\n\n")
    except Exception:
        pass


def _normalize(data):
    """Validate AI JSON into {risk_id: plan}. Raises ValueError if bad."""
    if not isinstance(data, dict) or "responses" not in data:
        raise ValueError("missing 'responses' key")
    if not isinstance(data["responses"], list):
        raise ValueError("'responses' must be a list")
    plans = {}
    for item in data["responses"]:
        rid = item.get("risk_id")
        if not rid:
            raise ValueError("response missing risk_id")
        strategy = item.get("strategy", "")
        if strategy not in ALLOWED_STRATEGIES:
            raise ValueError(f"bad strategy {strategy!r} for {rid}")
        actions = item.get("actions", [])
        if not isinstance(actions, list) or not actions:
            raise ValueError(f"bad actions for {rid}")
        plans[rid] = {
            "strategy": strategy,
            "strategy_justification": str(item.get("strategy_justification", "")),
            "actions": [str(a) for a in actions][:4],
            "owner": str(item.get("owner", "Project Manager")),
            "contingency": str(item.get("contingency", "")),
        }
    return plans


def generate_response_plans(project_name, high_critical_risks, model_name="gemini-3.5-flash"):
    """Call Gemini for High/Critical risks only. Never raises — returns fallback dict."""
    # safety filter: never send Low/Medium even if caller slips
    risks = [r for r in (high_critical_risks or []) if r.get("severity") in ("High", "Critical")]
    if not risks:
        return {"available": True, "plans": {}, "model": model_name}

    prompt = build_prompt(project_name, risks)
    key = _api_key()
    if not key:
        _log(prompt, "ERROR: missing GEMINI_API_KEY")
        return {"available": False, "error": "Missing GEMINI_API_KEY in .env", "plans": {}}

    try:
        from google import genai
        from google.genai import types
        client = genai.Client(api_key=key)
        resp = client.models.generate_content(
            model=model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.3,
            ),
        )
        raw = getattr(resp, "text", "") or ""
        _log(prompt, raw)
        # strip code fences if model adds them despite instructions
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            # remove leading 'json' marker
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.strip()
        plans = _normalize(json.loads(cleaned))
        return {"available": True, "plans": plans, "model": model_name}
    except Exception as exc:  # noqa: BLE001 — fallback must never crash the page
        try:
            _log(prompt, f"ERROR: {exc}")
        except Exception:
            pass
        return {"available": False, "error": str(exc)[:300], "plans": {}}
