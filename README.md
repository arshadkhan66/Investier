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

Swap models with environment variables:

```bash
MODEL_REPO=Qwen/Qwen2.5-1.5B-Instruct-GGUF \
MODEL_FILE=qwen2.5-1.5b-instruct-q4_k_m.gguf \
  ./scripts/download_model.sh
```

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
| POST | `/api/model/load` | Force-load the model |
| POST | `/api/plan` | Return the plan for an instruction + target |
| POST | `/api/test` | Run a full diagnostic and return the report |

```bash
curl -s localhost:8000/api/test -H 'Content-Type: application/json' \
  -d '{"target":"https://example.com",
       "instruction":"test everything and find anything missing"}' | jq .score
```

Request body: `target`, `instruction`, `options` (`samples`, `max_links`,
`timeout`, `concurrency`, `auth_header`, `insecure`, `check_links`), and
`use_llm`.

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
 
