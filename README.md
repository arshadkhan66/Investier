# Investier

A universal automated testing and diagnostic platform. Give it a target — a
website, web app, API or GraphQL endpoint — and a plain-English instruction,
and it runs real tests and returns a scored diagnostic report with defects,
missing capabilities, risk predictions and a ship / no-ship verdict.

A local ~1B parameter language model reads your instruction, builds the test
plan and writes the executive summary. Everything runs on CPU, offline, with
no external API keys.

## What it does

1. **Understands the instruction.** A local LLM (with a deterministic rules
   fallback) turns "test my whole app, especially security and the API" into a
   concrete plan: which suites to run, whether it is a web or API target, and
   whether to run the load probe.
2. **Runs the checks.** Read-only, non-destructive probes across many suites.
3. **Diagnoses.** Produces a weighted 0-100 health score, a severity-ranked
   defect list with evidence, a missing-capability catalogue, predicted risk,
   a verdict and a full readable report.

## Check suites

| Suite | Covers |
|---|---|
| Availability | Reachability, status codes, redirect chains, HTML detection |
| Security | HTTPS, TLS certificate and expiry, HSTS/CSP/X-Frame-Options and other headers, cookie flags, server-banner disclosure, mixed content, CAA |
| Performance | Latency (avg/p95), TTFB, page weight, compression, caching, third-party scripts |
| Stability | Gentle concurrent burst, success rate and latency under load |
| Mobile | Responsive viewport, PWA manifest |
| Accessibility | Landmarks, `lang`, `h1`, skip links, image alt text |
| SEO | Title, meta description, Open Graph, JSON-LD, robots.txt, sitemap, link inventory |
| Functionality | Internal link health, form well-formedness, JS error markers |
| Content | Placeholder / unfinished copy detection |
| Rendering | Real headless-browser load (Playwright/Chromium): JavaScript execution, rendered title and content, console errors, uncaught exceptions, failed requests, framework detection, full-page screenshot |
| API | JSON validity, content-type, response shape, latency, CORS, auth rejection, 404 shape, rate-limit signalling, GraphQL probe |
| Infrastructure / Email | DNS A/AAAA/NS/MX, SPF, DMARC, CAA |

## The local model

- Default: **Llama-3.2-1B-Instruct**, Q4_K_M quantisation (~0.8 GB).
- Runs on CPU through `llama.cpp` (`llama-cpp-python`). No GPU, no API keys.
- Used for: test-plan generation, the executive narrative, and per-defect
  explanations.
- **Graceful degradation:** if the model is missing or the library is absent,
  every feature falls back to deterministic rules, so the platform always works.
  The UI shows which brain is active.

### Model registry and switching

Any GGUF in `models/` is usable. Known models are recognised by filename, and
you can switch at runtime from the UI model picker or the API:

```bash
curl -s localhost:8000/api/models                       # list installed + active
curl -s -X POST localhost:8000/api/model/select \
  -H 'Content-Type: application/json' -d '{"name":"3b"}'
```

Download a larger model (better prose, still CPU-only):

```bash
./scripts/download_model.sh 3b     # Qwen 2.5 3B
./scripts/download_model.sh 1.5b   # Qwen 2.5 1.5B
./scripts/download_model.sh 0.5b   # Qwen 2.5 0.5B
```

Or point at any Hugging Face GGUF:

```bash
MODEL_REPO=Qwen/Qwen2.5-1.5B-Instruct-GGUF \
MODEL_FILE=qwen2.5-1.5b-instruct-q4_k_m.gguf \
  ./scripts/download_model.sh
```

### Grounded summaries (anti-hallucination)

Small models invent findings. The narrative is therefore constrained:

1. The prompt is **extractive** — the model may only restate facts it is given.
2. The fact sheet lists what **passed** as explicitly *not* a problem, so the
   model cannot claim a passing check failed.
3. The output is scanned for **contradictions** against the report (per clause,
   so "headers failed; TLS passed" is not misread); on a hit the model retries
   once at temperature 0.
4. If it still contradicts, a deterministic **template** narrative is used.

The report exposes `narrative_source` (`local-llm`, `template`, `rules` or
`disabled`) so you always know who wrote the summary.

## Quick start

```bash
python3 -m pip install -r requirements.txt
./scripts/download_model.sh      # optional but recommended
PORT=8000 ./run.sh
```

Open http://localhost:8000, type an instruction, point it at a target, run.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Service and model status |
| GET | `/api/model` | Local model status |
| GET | `/api/models` | List installed models and the active one |
| POST | `/api/model/load` | Force-load the model |
| POST | `/api/model/select` | Switch to an installed model by alias/filename |
| POST | `/api/plan` | Return the plan for an instruction + target |
| POST | `/api/test` | Run a full diagnostic and return the report |

```bash
curl -s localhost:8000/api/test -H 'Content-Type: application/json' \
  -d '{"target":"https://example.com",
       "instruction":"test everything and find anything missing"}' | jq .score
```

Request body: `target`, `instruction`, `options` (`samples`, `max_links`,
`timeout`, `concurrency`, `auth_header`, `insecure`, `check_links`, `render`,
`render_wait`), and `use_llm`.

The report includes `artifacts` — when rendering ran, `artifacts.screenshot`
holds a base64 PNG of what a real browser saw.

## Tests

```bash
python3 -m pytest tests/ -q
```

Covers the analyzer, planning fallback, JSON salvage, and a real end-to-end
scan against a local HTTP server (no network required).

## Layout

```
app/
  main.py         FastAPI server and routes
  runner.py       orchestrator: plan -> run -> analyze
  agent.py        LLM agent + deterministic planning fallback
  llm.py          llama.cpp wrapper, JSON salvage, graceful degradation
  analyzer.py     scoring, defects, missing, risks, verdict, report
  checks/         web, api, load, infra suites
  static/         single-page UI
models/           local GGUF model (downloaded, not committed)
tests/            pytest suite
```

## Safety

Investier performs **read-only, non-destructive** probes. The load probe is a
small burst (default 10 concurrent requests), not a stress or denial-of-service
tool. Only test systems you own or are explicitly authorised to test.

## License

MIT
 
