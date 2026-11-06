"""API / REST endpoint checks."""
from __future__ import annotations

import json
import time
from urllib.parse import urlparse

from .base import result, percentile, make_client, timed_get


async def run_api_checks(target: str, opts: dict) -> list[dict]:
    results: list[dict] = []
    samples = int(opts.get("samples", 5))

    async with make_client(opts) as client:
        client.headers["Accept"] = "application/json"
        resp, ms, err = await timed_get(client, target)
        if resp is None:
            results.append(result("api_reach", "API", "Endpoint reachable", "fail",
                                  "critical", f"Request failed: {err}", err, ms))
            return results

        ok = resp.status_code < 400
        results.append(result("api_reach", "API", "Endpoint reachable",
                              "pass" if ok else "fail", "info" if ok else "high",
                              f"HTTP {resp.status_code} in {ms:.0f} ms.",
                              resp.http_version, ms))

        ctype = resp.headers.get("content-type", "")
        is_json = "json" in ctype.lower()
        results.append(result("api_ctype", "API", "Content-Type is JSON",
                              "pass" if is_json else "warn", "info" if is_json else "medium",
                              f"Content-Type: {ctype or '(none)'}", ctype))

        parsed_json = None
        if is_json:
            try:
                parsed_json = resp.json()
                results.append(result("api_json", "API", "Response is valid JSON",
                                      "pass", "info",
                                      f"Parsed successfully ({type(parsed_json).__name__})."))
            except Exception as exc:  # noqa: BLE001
                results.append(result("api_json", "API", "Response is valid JSON",
                                      "fail", "high",
                                      f"Declared JSON but failed to parse: {exc}",
                                      resp.text[:200]))
        else:
            results.append(result("api_json", "API", "Response is valid JSON", "warn",
                                  "medium", "Skipped: not JSON.", resp.text[:120]))

        if isinstance(parsed_json, dict):
            keys = list(parsed_json.keys())
            results.append(result("api_shape", "API", "Top-level response shape", "info",
                                  "info", f"Object with {len(keys)} key(s): {', '.join(keys[:10])}."))

        latencies = [ms]
        for _ in range(max(0, samples - 1)):
            _, m, _ = await timed_get(client, target)
            if m:
                latencies.append(m)
        avg = sum(latencies) / len(latencies)
        results.append(result("api_latency", "Performance", "API latency",
                              "pass" if avg < 300 else ("warn" if avg < 1000 else "fail"),
                              "info" if avg < 300 else ("medium" if avg < 1000 else "high"),
                              f"avg {avg:.0f} ms, p95 {percentile(latencies, 95):.0f} ms "
                              f"over {len(latencies)} calls.",
                              ", ".join(f"{x:.0f}ms" for x in latencies)))

        cors = {k.lower(): v for k, v in resp.headers.items()
                if k.lower().startswith("access-control-")}
        if cors:
            acao = cors.get("access-control-allow-origin", "")
            wildcard = acao == "*"
            results.append(result("api_cors", "Security", "CORS policy",
                                  "warn" if wildcard else "pass",
                                  "medium" if wildcard else "info",
                                  "Wildcard CORS origin (*) exposes the API to any site."
                                  if wildcard else f"CORS restricted to: {acao}",
                                  json.dumps(cors)))
        else:
            results.append(result("api_cors", "API", "CORS headers", "info", "info",
                                  "No CORS headers (fine for server-to-server)."))

        cache = resp.headers.get("cache-control", "")
        results.append(result("api_cache", "Performance", "Cache-Control header",
                              "pass" if cache else "warn", "info" if cache else "low",
                              f"Cache-Control: {cache}" if cache else "No Cache-Control.", cache))

        rl = {k: v for k, v in resp.headers.items()
              if k.lower().startswith(("x-ratelimit", "ratelimit"))}
        results.append(result("api_ratelimit", "Security", "Rate-limit signalling",
                              "pass" if rl else "warn", "info" if rl else "low",
                              "Rate-limit headers present." if rl
                              else "No rate-limit headers; abuse protection unverified.",
                              json.dumps(rl)))

        if not opts.get("auth_header"):
            r, _, _ = await timed_get(client, target,
                                      headers={"Authorization": "Bearer invalid-token-probe"})
            if r is not None:
                if r.status_code in (401, 403):
                    results.append(result("api_auth", "Security", "Rejects invalid credentials",
                                          "pass", "info",
                                          f"Invalid token rejected with HTTP {r.status_code}."))
                elif r.status_code < 400:
                    results.append(result("api_auth", "Security", "Rejects invalid credentials",
                                          "warn", "high",
                                          "Returned success for an invalid bearer token.",
                                          f"HTTP {r.status_code}"))

        bogus = target.rstrip("/") + "/__investier_not_found__"
        r, _, _ = await timed_get(client, bogus)
        if r is not None:
            consistent = r.status_code >= 400 and (
                "json" in r.headers.get("content-type", "").lower() or not r.text.strip())
            results.append(result("api_404", "API", "Unknown routes fail cleanly",
                                  "pass" if consistent else "warn",
                                  "info" if consistent else "low",
                                  f"Unknown path -> HTTP {r.status_code}.", r.text[:200]))

        # -- GraphQL probe --------------------------------------------------
        if "graphql" in urlparse(target).path.lower():
            results.append(result("api_graphql", "API", "GraphQL endpoint shape", "info",
                                  "info",
                                  "Endpoint path looks like GraphQL; introspection not run.",
                                  ""))
            r, _, _ = await timed_get(client, target, params={"query": "{__typename}"})
            if r is not None:
                results.append(result("api_graphql_query", "API", "GraphQL query executes",
                                      "pass" if r.status_code < 400 else "warn",
                                      "info" if r.status_code < 400 else "medium",
                                      f"__typename probe -> HTTP {r.status_code}.",
                                      r.text[:150]))

    return results
