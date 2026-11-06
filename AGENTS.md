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
  `/api/model/load`, `/api/plan`, `/api/test`, `/`, `/static`.
- `app/runner.py` — `run_test(target, instruction, options, use_llm)`.
- `app/agent.py` — planning + narrative; falls back to rules.
- `app/llm.py` — llama.cpp wrapper; `LLM.status()`, `LLM.chat()`,
  `LLM.json_chat()`; JSON repair helpers.
- `app/analyzer.py` — scoring, defects, missing, risks, verdict, report text.
- `app/checks/{web,api,load,infra}.py` — suites.
- `app/static/` — UI.

## Conventions

- Check result shape: `{id, category, name, status, severity, detail, evidence,
  duration_ms}`; `status` in `pass|warn|fail|info`.
- Keep the rules fallback authoritative: the platform must work with no model.
- Tests: `python3 -m pytest tests/ -q` (no network needed; uses a local server).
- Probes are read-only and non-destructive; the load probe is a small burst.

## Model

Default `Llama-3.2-1B-Instruct-Q4_K_M.gguf` in `models/` (git-ignored). Override
with `MODEL_FILE` / `MODEL_DIR`.
