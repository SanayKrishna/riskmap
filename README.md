# Risk Register & Response Planner

Standalone Flask app: score project risks with a 5×5 matrix, visualize on an interactive Plotly heat map, and generate Gemini response plans for High/Critical risks.

## Setup

Requires Python 3.10+.

```bash
pip install -r requirements.txt
cp .env.example .env   # then put your real key in .env
python app.py          # http://127.0.0.1:5000
```

`.env` (never committed — covered by `.gitignore`):

```
GEMINI_API_KEY=your_google_ai_studio_key
SECRET_KEY=any_random_string
```

> Key ethics: the key lives only in local `.env`, read via `os.getenv` in `ai_planner.py`. It is never hardcoded, never logged, and never pushed. `ai_log.txt` records only the prompt + model response text.

## Use

- `GET /` — Upload JSON tab (drag-drop / file picker / paste + example) or Add Risks Manually tab (title, category, description, P/I sliders, removable cards).
- `POST /analyze` — validates (integers 1–5, required fields), runs engine → heat map → AI, renders results.
- `GET /export` — CSV download of the last analysis.

Try: paste `sample_risks.json` or upload it.

## Scoring (`risk_engine.py`, pure Python)

Score = probability × impact. Critical 20–25, High 13–19, Medium 7–12, Low 1–6.
Overall: any Critical → Critical; else High > 2 → High; else Medium > total/2 → Medium; else Low.

Sample actuals: R1/R3 Critical (20), R2 High (15), R4/R7/R5/R6/R8 Medium, R9/R10 Low → overall Critical, AI gets 3 risks.

## Modules

- `risk_engine.py` — scoring/ranking, no Flask/AI
- `heatmap.py` — Plotly 5×5 div only, same-cell jitter, hover details
- `ai_planner.py` — only Gemini caller; High/Critical only; strict-JSON prompt; `try/except` fallback renders "AI response plan unavailable" without crashing
- `exporter.py` — pandas CSV: Risk ID, Title, Category, Probability, Impact, Score, Severity, Strategy, Actions (; -joined), Owner, Contingency
- `app.py` — thin routes + validation

## Tests

```bash
python -m pytest tests/test_risk_engine.py -v
```

Covers score math, severity boundaries (6→Low, 7→Medium, 12→Medium, 13→High, 20→Critical), overall-level branches, ranking, matrix grouping, float/out-of-range rejection.
