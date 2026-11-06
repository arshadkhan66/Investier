# Investier

Universal automated testing & diagnostic platform with a local ~1B LLM brain.

## What this is

FastAPI service + single-page UI. Give it a target and a plain-English
instruction; it plans tests with a local model, runs read-only probes, scores
the result, and writes a diagnostic report.

## Run

```bash
python3 -m pip install -r requirements.txt
./scripts/download_model.sh   # optional; rules fallback works without it
PORT=8000 ./run.sh
```

Health: `curl localhost:8000/api/health`

## Layout

- `app/main.py` — FastAPI app, routes: `/api/health`, `/api/model`,
  `/api/models`, `/api/model/load`, `/api/model/select`, `/api/plan`,
  `/api/test`, `/`, `/static`.
- `app/runner.py` — `run_test(target, instruction, options, use_llm)`.
- `app/agent.py` — planning + narrative; grounded summary with contradiction
  checks; falls back to rules/template.
- `app/llm.py` — llama.cpp wrapper; model registry (`MODEL_REGISTRY`,
  `_resolve_exact`, `available_models`), `LLM.status()`, `LLM.chat()`,
  `LLM.json_chat()`, `LLM.select()`; JSON repair helpers.
- `app/analyzer.py` — scoring, defects, missing, risks, verdict, report text
  (includes a NOTES & DETECTIONS section for `status="info"` results).
- `app/checks/{web,api,load,infra,browser}.py` — suites. `browser` uses
  Playwright; when absent it emits a single `info` result and the rest runs.
- `app/static/` — UI (model picker, screenshot, notes panel).

## Conventions

- Check result shape: `{id, category, name, status, severity, detail, evidence,
  duration_ms}`; `status` in `pass|warn|fail|info`.
- Keep the rules fallback authoritative: the platform must work with no model.
- Tests: `python3 -m pytest tests/ -q` (no network needed; uses a local server).
- Probes are read-only and non-destructive; the load probe is a small burst.

## Model

Default `Llama-3.2-1B-Instruct-Q4_K_M.gguf` in `models/` (git-ignored). Override
with `MODEL_FILE` / `MODEL_DIR`. Switch at runtime via `/api/model/select`; any
GGUF in `models/` works. Narrative grounding: `_grounding_facts` builds the fact
sheet, `_contradictions` rejects unsupported claims per clause, then retries at
temp 0 before falling back to `_template_narrative`. `narrate()` returns
`(text, source)` where source is `local-llm|template|rules`.
