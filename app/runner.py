"""Orchestrator: plan -> run suites -> analyze -> (optional) LLM narrative."""
from __future__ import annotations

import time
from urllib.parse import urlparse

from .agent import AGENT
from .analyzer import analyze
from .checks import web, api, load, infra

KNOWN_SUITES = {"web", "api", "load", "infra"}


def normalize_target(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if not raw.lower().startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


async def run_test(target: str, instruction: str = "", options: dict | None = None,
                   use_llm: bool = True) -> dict:
    options = options or {}
    target = normalize_target(target)

    plan = AGENT.plan(instruction, target)
    groups = set(plan["groups"])
    mode = plan["mode"]

    opts = {
        "timeout": options.get("timeout", 20),
        "samples": options.get("samples", 5),
        "check_links": options.get("check_links", True),
        "max_links": options.get("max_links", 15),
        "auth_header": options.get("auth_header"),
        "extra_headers": options.get("extra_headers"),
        "insecure": options.get("insecure", False),
        "concurrency": options.get("concurrency", 10),
    }

    started = time.time()
    results: list[dict] = []

    if mode == "api":
        results += await api.run_api_checks(target, opts)
        subset = await web.run_web_checks(target, opts)
        results += [r for r in subset
                    if r["category"] in ("Availability", "Security", "Performance")]
    else:
        results += await web.run_web_checks(target, opts)

    reachable = not any(r["id"] == "availability" and r["status"] == "fail"
                        for r in results)

    if plan.get("run_load") and reachable:
        results += await load.run_load_check(target, opts)

    if "infrastructure" in groups and reachable:
        results += infra.run_infra_checks(urlparse(target).hostname, opts)

    finished = time.time()
    report = analyze(target, mode, results, started, finished, instruction)
    report["plan"] = plan

    if use_llm:
        narrative = AGENT.narrate(report)
        report["narrative"] = narrative
        report["narrative_source"] = "local-llm" if narrative else "rules"
    else:
        report["narrative"] = None
        report["narrative_source"] = "disabled"

    report["llm"] = AGENT.llm.status()
    return report
