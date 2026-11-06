"""Real-browser checks using Playwright (headless Chromium).

Renders the page like a user would: runs JavaScript, executes the app's own
scripts, records console errors, uncaught exceptions and failed network
requests, then inspects the *rendered* DOM. This is what lets Investier test
JavaScript-heavy single-page apps, which a plain HTTP fetch cannot see.

Degrades gracefully: if Playwright or its browser is unavailable, a single
informational result is returned and the rest of the run continues.
"""
from __future__ import annotations

import asyncio
import base64
from urllib.parse import urlparse

from .base import result

try:
    from playwright.async_api import async_playwright  # type: ignore
    HAVE_PLAYWRIGHT = True
except Exception:  # noqa: BLE001
    HAVE_PLAYWRIGHT = False

FRAMEWORK_MARKERS = {
    "React": ("__REACT_DEVTOOLS_GLOBAL_HOOK__", "_reactRootContainer", "data-reactroot"),
    "Next.js": ("__NEXT_DATA__", "_next/static"),
    "Vue": ("__VUE__", "data-v-app", "vue.runtime"),
    "Angular": ("ng-version", "ng-app"),
    "Svelte": ("svelte",),
}


async def run_browser_checks(target: str, opts: dict) -> tuple[list[dict], dict]:
    """Return (results, artifacts). artifacts may contain a screenshot."""
    if not HAVE_PLAYWRIGHT:
        return [result("render_engine", "Rendering", "Browser rendering", "info",
                       "info", "Playwright not installed; rendered-DOM checks skipped.")], {}

    timeout_ms = int(float(opts.get("timeout", 20)) * 1000)
    width = int(opts.get("viewport_width", 1280))
    height = int(opts.get("viewport_height", 800))
    results: list[dict] = []
    artifacts: dict = {}

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(args=["--no-sandbox"])
            context = await browser.new_context(
                viewport={"width": width, "height": height},
                ignore_https_errors=bool(opts.get("insecure", False)),
                user_agent="Investier/2.0 (+universal-test-agent)",
            )
            if opts.get("auth_header"):
                await context.set_extra_http_headers(
                    {"Authorization": opts["auth_header"]})
            page = await context.new_page()

            console_errors: list[str] = []
            console_warnings: list[str] = []
            page_errors: list[str] = []
            failed_requests: list[str] = []
            responses: list[tuple[str, int, int]] = []

            page.on("console", lambda m: (
                console_errors.append(f"{m.text[:180]}") if m.type == "error"
                else console_warnings.append(f"{m.text[:120]}") if m.type == "warning"
                else None))
            page.on("pageerror", lambda e: page_errors.append(str(e)[:200]))
            page.on("requestfailed",
                    lambda r: failed_requests.append(
                        f"{r.url[:140]} ({r.failure or 'failed'})"))
            page.on("response", lambda r: responses.append(
                (r.url, r.status, 0)))

            try:
                resp = await page.goto(target, wait_until="load", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001
                await browser.close()
                return [result("render_load", "Rendering", "Page renders", "fail",
                               "high", f"Browser could not load the page: {exc}")], {}

            # Let late async work (data fetching, hydration) settle.
            try:
                await page.wait_for_load_state("networkidle", timeout=6000)
            except Exception:  # noqa: BLE001
                pass

            status = resp.status if resp else 0
            results.append(result("render_load", "Rendering", "Page renders in a browser",
                                  "pass" if status and status < 400 else "warn",
                                  "info" if status and status < 400 else "medium",
                                  f"Headless Chromium loaded HTTP {status}.",
                                  str(page.url)))

            title = await page.title()
            results.append(result("render_title", "Rendering", "Title after JavaScript runs",
                                  "pass" if title else "warn",
                                  "info" if title else "medium",
                                  f"Rendered title: '{title[:80]}'" if title
                                  else "No title after rendering."))

            html = await page.content()
            text = (await page.inner_text("body"))[:4000] if await page.query_selector("body") else ""

            markers = [fw for fw, sigs in FRAMEWORK_MARKERS.items()
                       if any(s in html for s in sigs)]
            is_spa = bool(markers) or (len(text.strip()) > 50 and len(html) < 6000)
            results.append(result("render_spa", "Rendering", "JavaScript app detected",
                                  "info", "info",
                                  f"Framework markers: {', '.join(markers)}."
                                  if markers else
                                  ("Client-rendered content detected." if is_spa
                                   else "Server-rendered HTML.")))

            if not text.strip():
                results.append(result("render_empty", "Rendering", "Content visible to users",
                                      "fail", "critical",
                                      "The rendered page has no visible text; users would "
                                      "see a blank screen."))
            else:
                results.append(result("render_empty", "Rendering", "Content visible to users",
                                      "pass", "info",
                                      f"{len(text.split())} words visible after rendering."))

            # -- console & runtime errors ----------------------------------
            results.append(result(
                "render_console", "Rendering", "No console errors",
                "pass" if not console_errors else ("warn" if len(console_errors) < 4 else "fail"),
                "info" if not console_errors else ("medium" if len(console_errors) < 4 else "high"),
                f"{len(console_errors)} console error(s)." if console_errors
                else "Clean console.",
                " | ".join(console_errors[:6])))

            results.append(result("render_pageerror", "Rendering", "No uncaught exceptions",
                                  "pass" if not page_errors else "fail",
                                  "info" if not page_errors else "high",
                                  f"{len(page_errors)} uncaught JS exception(s)."
                                  if page_errors else "No uncaught exceptions.",
                                  " | ".join(page_errors[:4])))

            if failed_requests:
                results.append(result("render_requests", "Rendering",
                                      "No failed network requests",
                                      "warn" if len(failed_requests) < 4 else "fail",
                                      "medium" if len(failed_requests) < 4 else "high",
                                      f"{len(failed_requests)} request(s) failed.",
                                      " | ".join(failed_requests[:6])))

            server_errors = [f"{u[:120]} -> {s}" for u, s, _ in responses if s >= 500]
            if server_errors:
                results.append(result("render_5xx", "Rendering", "No server errors on assets",
                                      "fail", "high",
                                      f"{len(server_errors)} resource(s) returned 5xx.",
                                      " | ".join(server_errors[:5])))

            # -- rendered DOM checks ---------------------------------------
            a11y = []
            if not await page.query_selector("main, [role=main]"):
                a11y.append("no <main> landmark")
            if not await page.query_selector("h1"):
                a11y.append("no <h1>")
            if not await page.query_selector("html[lang]"):
                a11y.append("no <html lang>")
            results.append(result("render_a11y", "Accessibility",
                                  "Rendered accessibility landmarks",
                                  "pass" if not a11y else "warn",
                                  "info" if not a11y else "medium",
                                  "Core landmarks present after render." if not a11y
                                  else f"{len(a11y)} issue(s): {', '.join(a11y)}."))

            links = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href).filter(h => h && !h.startsWith('javascript:'))")
            results.append(result("render_links", "Rendering", "Links present after render",
                                  "info", "info",
                                  f"{len(links)} link(s) in the rendered DOM."))

            # -- mixed content (real requests over http on an https page) ---
            if urlparse(page.url).scheme == "https":
                mixed = sorted({u for u, _, _ in responses
                                if u.startswith("http://")})
                if mixed:
                    results.append(result("render_mixed", "Security",
                                          "No mixed content in the browser", "fail", "high",
                                          f"{len(mixed)} resource(s) loaded over plain HTTP.",
                                          " | ".join(m[:100] for m in mixed[:5])))

            # -- timing -----------------------------------------------------
            try:
                timing = await page.evaluate(
                    "() => { const t = performance.timing; "
                    "return { dcl: t.domContentLoadedEventEnd - t.navigationStart, "
                    "load: t.loadEventEnd - t.navigationStart }; }")
                load_ms = timing.get("load") or timing.get("dcl") or 0
                if load_ms:
                    results.append(result(
                        "render_timing", "Performance", "Full page load time",
                        "pass" if load_ms < 3000 else ("warn" if load_ms < 7000 else "fail"),
                        "info" if load_ms < 3000 else ("medium" if load_ms < 7000 else "high"),
                        f"Rendered page finished loading in {load_ms:.0f} ms.",
                        f"DOMContentLoaded {timing.get('dcl', 0)} ms", load_ms))
            except Exception:  # noqa: BLE001
                pass

            # -- screenshot -------------------------------------------------
            if opts.get("screenshot", True):
                try:
                    shot = await page.screenshot(type="jpeg", quality=60, full_page=False)
                    artifacts["screenshot"] = (
                        "data:image/jpeg;base64," + base64.b64encode(shot).decode())
                    results.append(result("render_screenshot", "Rendering", "Screenshot captured",
                                          "pass", "info",
                                          f"Captured {width}x{height} viewport."))
                except Exception as exc:  # noqa: BLE001
                    results.append(result("render_screenshot", "Rendering",
                                          "Screenshot captured", "info", "info",
                                          f"Screenshot failed: {exc}"))

            await browser.close()
    except Exception as exc:  # noqa: BLE001
        results.append(result("render_engine", "Rendering", "Browser rendering",
                              "info", "info",
                              f"Browser check skipped: {type(exc).__name__}: {exc}"))
    return results, artifacts
