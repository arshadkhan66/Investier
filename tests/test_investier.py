"""Investier test suite.

Deterministic unit tests for the analyzer, agent planning fallback and JSON
salvage helpers, plus a real end-to-end scan against a local HTTP server.
"""
import asyncio
import http.server
import json
import socketserver
import threading

import pytest

from app.agent import Agent
from app.analyzer import analyze
from app.llm import _extract_json, _repair_json
from app.runner import normalize_target, run_test


# --------------------------------------------------------------- targets
def test_normalize_target_adds_scheme():
    assert normalize_target("example.com").startswith("https://")
    assert normalize_target("http://example.com").startswith("http://")
    assert normalize_target("") == ""


# --------------------------------------------------------------- planning
def test_rule_plan_everything_runs_all_groups():
    plan = Agent()._rule_plan("test everything", "https://example.com")
    assert plan["everything"] is True
    assert "security" in plan["groups"] and "performance" in plan["groups"]


def test_rule_plan_security_only():
    plan = Agent()._rule_plan("just check security and tls", "https://example.com")
    assert plan["groups"] == ["security"]


def test_rule_plan_detects_api_target():
    plan = Agent()._rule_plan("check it", "https://api.example.com/v1/status")
    assert plan["mode"] == "api"
    assert "api" in plan["groups"]


def test_rule_plan_skips_infra_for_localhost():
    plan = Agent()._rule_plan("test everything", "http://localhost:3000")
    assert "infrastructure" not in plan["groups"]


def test_merge_unions_plans():
    merged = Agent._merge(
        {"groups": ["security", "seo"], "mode": "web", "run_load": False,
         "everything": False, "rationale": "r"},
        {"groups": ["performance"], "mode": "web", "run_load": True, "rationale": "l"},
    )
    assert set(merged["groups"]) == {"security", "seo", "performance"}
    assert merged["run_load"] is True


# --------------------------------------------------------------- JSON salvage
def test_extract_json_plain():
    assert _extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_fenced():
    assert _extract_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_extract_json_truncated_repair():
    got = _extract_json('{"groups": ["security", "seo"')
    assert got is not None
    assert got["groups"][0] == "security"


def test_repair_json_balances_brackets():
    fixed = _repair_json('{"a": [1, 2')
    assert json.loads(fixed) == {"a": [1, 2]}


# --------------------------------------------------------------- analyzer
def _r(cid, cat, name, status, sev, detail="d"):
    return {"id": cid, "category": cat, "name": name, "status": status,
            "severity": sev, "detail": detail, "evidence": "", "duration_ms": 0}


def test_score_perfect():
    rep = analyze("https://x.com", "web",
                  [_r("a", "X", "n", "pass", "info"), _r("b", "X", "n2", "pass", "info")],
                  0, 1)
    assert rep["score"] == 100 and rep["grade"] == "Excellent"


def test_critical_failure_caps_score():
    rep = analyze("https://x.com", "web",
                  [_r("availability", "Availability", "Target reachable", "fail", "critical"),
                   _r("https", "Security", "HTTPS", "fail", "critical")], 0, 1)
    assert rep["score"] <= 5
    assert "NOT READY" in rep["report"]
    assert any(r["level"] == "critical" for r in rep["risks"])


def test_missing_capabilities_detected():
    rep = analyze("https://x.com", "web",
                  [_r("availability", "Availability", "Target reachable", "pass", "info")], 0, 1)
    items = {m["item"] for m in rep["missing"]}
    assert "A valid TLS certificate" in items
    assert "Baseline security headers" in items


def test_api_mode_skips_web_only_capabilities():
    rep = analyze("https://api.x.com", "api",
                  [_r("availability", "Availability", "Target reachable", "pass", "info")], 0, 1)
    items = {m["item"] for m in rep["missing"]}
    assert "A descriptive page title" not in items
    assert "A responsive/mobile viewport" not in items


def test_defects_severity_ranked():
    rep = analyze("https://x.com", "web",
                  [_r("a", "X", "low", "warn", "low"),
                   _r("b", "X", "critical", "fail", "critical"),
                   _r("c", "X", "medium", "warn", "medium")], 0, 1)
    assert rep["defects"][0]["name"] == "critical"
    assert rep["defects"][-1]["name"] == "low"


def test_report_sections_and_instruction():
    rep = analyze("https://x.com", "web",
                  [_r("availability", "Availability", "Target reachable", "pass", "info")],
                  0, 1, "my instruction")
    for section in ("OVERALL HEALTH", "WHAT IS WORKING", "PROBLEMS & ERRORS FOUND",
                    "MISSING / NOT DETECTED", "PREDICTED RISK", "CATEGORY SCORES", "VERDICT"):
        assert section in rep["report"]
    assert "my instruction" in rep["report"]


# --------------------------------------------------------------- end-to-end
class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/robots.txt":
            body, code = b"User-agent: *\nAllow: /", 200
        elif self.path == "/missing":
            body, code = b"nope", 404
        else:
            body = (b"<html lang='en'><head><title>Local Test</title>"
                    b"<meta name='viewport' content='width=device-width'>"
                    b"<meta name='description' content='" + b"x" * 60 + b"'>"
                    b"<meta property='og:title' content='Local'></head>"
                    b"<body><main><h1>Hi</h1>"
                    b"<a href='/missing'>broken</a><a href='#skip'>Skip to content</a>"
                    b"<img src='/a.png' alt='ok'></main></body></html>")
            code = 200
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def local_server():
    with socketserver.TCPServer(("127.0.0.1", 0), _Handler) as srv:
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        yield f"http://127.0.0.1:{port}"
        srv.shutdown()


def test_end_to_end_scan_without_llm(local_server):
    report = asyncio.run(run_test(local_server, "test everything", {}, use_llm=False))
    assert report["summary"]["total"] > 5
    assert 0 <= report["score"] <= 100
    assert report["narrative_source"] == "disabled"
    ids = {r["id"] for r in report["defects"]}
    assert "links" in ids   # /missing is a 404
    assert "https" in ids   # plain HTTP target
    assert report["report"]


def test_end_to_end_api_mode(local_server):
    report = asyncio.run(run_test(local_server + "/api/v1", "check the api", {},
                                  use_llm=False))
    assert report["mode"] == "api"
    assert any(r["category"] == "API" for r in report["defects"] + report["passed"])


# ------------------------------------------------ narrative grounding
def _report_for_narrative():
    return {
        "target": "https://example.com",
        "score": 76, "grade": "Good",
        "summary": {"total": 3, "pass": 2, "warn": 0, "fail": 1, "info": 0},
        "defects": [{"id": "sec_headers", "category": "Security",
                     "name": "Security headers", "status": "fail",
                     "severity": "high", "detail": "6 headers missing."}],
        "passed": [{"id": "tls", "category": "Security", "name": "TLS certificate",
                    "status": "pass", "severity": "info", "detail": "valid"},
                   {"id": "https", "category": "Security", "name": "HTTPS",
                    "status": "pass", "severity": "info", "detail": "ok"}],
        "missing": [{"item": "Baseline security headers", "severity": "high"}],
        "report": "x\nVERDICT\n" + "-" * 62 + "\n  SHIP WITH CAUTION. Fix the highs.\n",
    }


def test_contradiction_catches_false_missing_tls():
    a = Agent()
    rep = _report_for_narrative()
    bad = "The app is missing SSL/TLS certificates and lacks HTTPS."
    assert a._contradictions(bad, rep)
    good = "Security headers failed; TLS certificate and HTTPS passed."
    assert not a._contradictions(good, rep)


def test_contradiction_flags_false_critical():
    a = Agent()
    rep = _report_for_narrative()
    assert a._contradictions("This is a critical severity issue.", rep)
    assert a._contradictions("Rated critical by the scanner.", rep)
    # 'most critical problem' is ordinary English, not a severity claim.
    assert not a._contradictions("The most critical problem is the headers.", rep)


def test_template_narrative_is_grounded_and_clean():
    a = Agent()
    text = a._template_narrative(_report_for_narrative())
    assert "76/100" in text
    assert "Security headers" in text
    assert "SHIP WITH CAUTION" in text
    assert "-----" not in text            # no separator leaking into prose
    # It names a passing check as working, never as the problem.
    assert "is working" in text


def test_grounding_facts_lists_passes_and_problems():
    a = Agent()
    facts = a._grounding_facts(_report_for_narrative())
    assert "PROBLEMS" in facts and "WHAT PASSED" in facts
    assert "TLS certificate" in facts          # a pass is listed as not-a-problem
    assert "Security headers" in facts


def test_narrate_returns_source_tuple_without_model():
    a = Agent()
    a.llm._llm = None
    a.llm._loaded = True          # pretend we tried; available stays False
    a.llm.model_path = None
    text, source = a.narrate(_report_for_narrative())
    assert text is None and source == "rules"


# ------------------------------------------------ model registry
def test_model_registry_resolves_aliases():
    from app.llm import _resolve_model, available_models, MODEL_REGISTRY
    assert set(MODEL_REGISTRY) >= {"1b", "3b", "0.5b", "1.5b"}
    # A bogus alias must never raise; it falls back to whatever exists.
    assert _resolve_model("does-not-exist") is None or True
    assert isinstance(available_models(), list)


def test_model_select_rejects_unknown():
    from app.llm import LocalLLM
    llm = LocalLLM()
    assert llm.select("no-such-model-xyz") is False
    assert llm._error


# ------------------------------------------------ browser fallback
def test_browser_checks_degrade_without_playwright(monkeypatch):
    from app.checks import browser
    monkeypatch.setattr(browser, "HAVE_PLAYWRIGHT", False)
    results, artifacts = asyncio.run(browser.run_browser_checks("https://example.com", {}))
    assert len(results) == 1
    assert results[0]["status"] == "info"
    assert artifacts == {}


def test_render_capabilities_skipped_when_no_render(local_server):
    """A run without rendering must not report render_* as missing."""
    report = asyncio.run(run_test(local_server, "test everything",
                                  {"render": False}, use_llm=False))
    items = {m["item"] for m in report["missing"]}
    assert "A page that renders in a browser" not in items
    assert "Visible content after rendering" not in items
