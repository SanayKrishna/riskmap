# Risk Register & Response Planner

I built this for a project management assignment: a small standalone Flask app that takes a list of project risks, scores them on a 5×5 matrix, plots them on an interactive heat map, and asks Gemini for concrete response plans for the serious ones.

No shared code with anything else — everything here was written from scratch for this tool.

## Getting it running

You'll need Python 3.10 or newer. Then:

```bash
pip install -r requirements.txt
cp .env.example .env   # then drop your real key into .env
python app.py          # opens on http://127.0.0.1:5000
```

Your `.env` should look like this:

```
GEMINI_API_KEY=your_google_ai_studio_key
SECRET_KEY=any_random_string
```

One thing I was careful about: the API key only ever lives in your local `.env`. It's read with `os.getenv` inside `ai_planner.py`, never hardcoded, never printed to the page, and never pushed to git (`.gitignore` covers `.env`). The debug log `ai_log.txt` records the prompt and the model's reply so I could write up what happened — but never the key itself.

## How to use it

Open `/` and you've got two options, both ending up on the same results page:

- **Upload JSON** — drag and drop a file, pick one with the file browser, or paste straight into the text box. There's a collapsible example if you want the shape.
- **Add Risks Manually** — fill in title, category, description, drag the probability/impact sliders, hit Add Risk. Each one shows up as a little card you can remove before submitting.

`POST /analyze` checks everything (probability and impact have to be whole numbers 1–5, all fields present), then runs the scoring engine, builds the heat map, and calls Gemini. `GET /export` downloads the last analysis as CSV. `POST /snapshot` and `GET /history` save the register as a labeled time point (Week 1, Week 2…) and chart how scores move over time.

Easiest first run: upload or paste `sample_risks.json`. The Example JSON box on the upload page has a Randomize button if you want something smaller to play with.

## How scoring works

All of this lives in `risk_engine.py`, plain Python with no Flask or AI mixed in. Score is just probability × impact, then:

- 20–25 → Critical, 13–19 → High, 7–12 → Medium, 1–6 → Low

Overall project level: if anything is Critical, the project is Critical. Otherwise more than two Highs means High; more than half Medium means Medium; everything else is Low.

Worth knowing about the sample file: the brief describes R4 and R5 as High, but the math says otherwise (3×4=12 and 2×5=10 are both Medium by the rules above). I kept the JSON exactly as specified, so the real split is R1/R3 Critical, R2 High, R4/R7/R5/R6/R8 Medium, R9/R10 Low — overall Critical, which means Gemini gets 3 risks to work with.

## What's where

- `risk_engine.py` — scoring, severity, ranking, plus EMV math (`cost_impact` → expected value at P÷5, total exposure). Importable on its own, no Flask, no AI.
- `heatmap.py` — Plotly 5×5 grid returned as an inline HTML div. Risks sharing a cell get nudged apart so you can actually see them; hovering shows the details.
- `velocity.py` — snapshot storage (JSON files under `data/`, one per project) and trend computation: per-risk score series with Worsened / Improved / Stable / New / Closed status, plus a Plotly trend chart.
- `graph.py` — `triggers` link validation, cascade ranking by downstream blast radius (networkx for the math, Plotly for the map), and chain text fed into the AI prompt.
- `ai_planner.py` — the only file that touches the AI API. Sends High and Critical risks only (no point paying tokens on Lows), demands strict JSON back, and if the call fails or the JSON is garbage it just returns an "unavailable" flag so the page still renders.
- `exporter.py` — pandas CSV with Risk ID, Title, Category, Probability, Impact, Score, Severity, Cost Impact, EMV, Linked Risks, Strategy, Actions (semicolon-joined), Owner, Contingency.
- `app.py` — route handlers only, kept thin on purpose. Bad input re-renders the upload page with an inline message instead of a traceback.

## Going further: costs, links, history

Two optional fields per risk, both ignored when absent so old files keep working:

```json
{"id": "R1", "probability": 4, "impact": 5,
 "cost_impact": 80000, "triggers": ["R4"], "...": "..."}
```

- `cost_impact` — estimated financial hit. EMV = (P÷5) × cost; the results page shows a total exposure figure (sample: $168,600.00 across 6 costed risks).
- `triggers` — ids this risk can set off. Unknown ids and self-links are rejected with a plain message. Linked risks render as a dependency map plus a cascade table, and the AI sees the chains when planning.
- History: hit Save snapshot on any results page (label it Week 1…), then `/history` shows the trend chart and what got better or worse. Snapshots live in `data/`, which is gitignored.

## Tests

```bash
python -m pytest tests/test_risk_engine.py -v
```

Covers the score math, the boundary values that matter (6 stays Low, 7 tips into Medium, 12 stays Medium, 13 tips into High, 20 into Critical), each overall-level branch, ranking order, the matrix grouping, and rejection of floats and out-of-range values.

Heads-up on the AI setup: the old `google-generativeai` package is deprecated and `gemini-2.0/2.5-flash` are retired for new keys, so this uses the `google-genai` SDK with `gemini-3.5-flash`, which I verified end to end.
