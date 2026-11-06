"""Gentle concurrency / stability probe (not a stress or DoS tool)."""
from __future__ import annotations

import asyncio
import time

from .base import result, percentile, make_client


async def run_load_check(target: str, opts: dict) -> list[dict]:
    concurrency = max(1, min(int(opts.get("concurrency", 10)), 50))
    latencies: list[float] = []
    errors: list[str] = []

    async with make_client(opts) as client:
        async def one():
            s = time.perf_counter()
            try:
                r = await client.get(target)
                latencies.append((time.perf_counter() - s) * 1000)
                if r.status_code >= 500:
                    errors.append(f"HTTP {r.status_code}")
            except Exception as exc:  # noqa: BLE001
                errors.append(type(exc).__name__)

        start = time.perf_counter()
        await asyncio.gather(*(one() for _ in range(concurrency)))
        wall = time.perf_counter() - start

    success = concurrency - len(errors)
    rate = success / concurrency * 100
    rps = concurrency / wall if wall else 0
    avg = sum(latencies) / len(latencies) if latencies else 0
    p95 = percentile(latencies, 95)

    return [
        result("load_success", "Stability", f"Concurrent burst ({concurrency} requests)",
               "pass" if rate == 100 else ("warn" if rate >= 90 else "fail"),
               "info" if rate == 100 else ("medium" if rate >= 90 else "high"),
               f"{success}/{concurrency} succeeded ({rate:.0f}%); {rps:.1f} req/s.",
               "; ".join(errors[:10])),
        result("load_latency", "Stability", "Latency under concurrency",
               "pass" if p95 < 1000 else ("warn" if p95 < 3000 else "fail"),
               "info" if p95 < 1000 else ("medium" if p95 < 3000 else "high"),
               f"avg {avg:.0f} ms, p95 {p95:.0f} ms at {concurrency} concurrent."),
    ]
