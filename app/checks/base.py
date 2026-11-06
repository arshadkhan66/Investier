"""Shared helpers for all check suites.

A *check result* is a dict with the keys:
    id, category, name, status, severity, detail, evidence, duration_ms

status   in {pass, warn, fail, info}
severity in {info, low, medium, high, critical}
"""
from __future__ import annotations

import time
from typing import Any

import httpx

USER_AGENT = "Investier/2.0 (+universal-test-agent)"
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def result(cid: str, category: str, name: str, status: str, severity: str,
           detail: str, evidence: str = "", duration_ms: float = 0.0) -> dict:
    return {
        "id": cid, "category": category, "name": name, "status": status,
        "severity": severity, "detail": detail, "evidence": str(evidence),
        "duration_ms": round(duration_ms, 1),
    }


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((pct / 100) * (len(ordered) - 1))))
    return ordered[idx]


def make_client(opts: dict) -> httpx.AsyncClient:
    headers = {"User-Agent": USER_AGENT}
    if opts.get("auth_header"):
        headers["Authorization"] = opts["auth_header"]
    if opts.get("extra_headers"):
        headers.update(opts["extra_headers"])
    return httpx.AsyncClient(
        timeout=float(opts.get("timeout", 20)),
        headers=headers,
        verify=not opts.get("insecure", False),
        follow_redirects=True,
    )


async def timed_get(client: httpx.AsyncClient, url: str, **kw) -> tuple[httpx.Response | None, float, str]:
    start = time.perf_counter()
    try:
        resp = await client.get(url, **kw)
        return resp, (time.perf_counter() - start) * 1000, ""
    except Exception as exc:  # noqa: BLE001
        return None, (time.perf_counter() - start) * 1000, f"{type(exc).__name__}: {exc}"
