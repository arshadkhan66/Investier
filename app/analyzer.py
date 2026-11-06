"""Deterministic diagnostic engine.

Produces the weighted health score, severity-ranked defect list, a
missing-capability catalogue, risk predictions, a verdict and a plain-text
report. The local LLM can add an executive narrative on top, but every finding
here is produced by rules and is reproducible.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

SEVERITY_WEIGHT = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}

EXPECTED = [
    ("tls", "A valid TLS certificate", "critical"),
    ("https", "HTTPS transport", "critical"),
    ("sec_headers", "Baseline security headers", "high"),
    ("cookies", "Cookie security flags", "high"),
    ("compression", "Compressed responses", "medium"),
    ("cache_control", "Cache-Control headers", "low"),
    ("title", "A descriptive page title", "medium"),
    ("meta_desc", "A meta description", "low"),
    ("og_tags", "Social share (Open Graph) tags", "low"),
    ("structured_data", "Structured data (JSON-LD)", "low"),
    ("viewport", "A responsive/mobile viewport", "medium"),
    ("favicon", "A favicon", "low"),
    ("a11y", "Accessibility landmarks", "medium"),
    ("img_alt", "Alt text on images", "medium"),
    ("robots", "robots.txt", "low"),
    ("sitemap", "A sitemap", "low"),
    ("links", "Working internal links", "high"),
    ("placeholders", "Production-ready (non-placeholder) copy", "medium"),
    ("render_load", "A page that renders in a browser", "critical"),
    ("render_console", "A clean browser console", "medium"),
    ("render_pageerror", "No uncaught JavaScript exceptions", "high"),
    ("render_empty", "Visible content after rendering", "critical"),
    ("email_spf", "An SPF record", "medium"),
    ("email_dmarc", "A DMARC policy", "medium"),
    ("dns_caa", "A CAA record", "low"),
]

WEB_ONLY = {"title", "meta_desc", "og_tags", "structured_data", "viewport", "favicon",
            "a11y", "img_alt", "robots", "sitemap", "links", "placeholders",
            "render_load", "render_console", "render_pageerror", "render_empty"}


def band(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 55:
        return "Fair"
    if score >= 35:
        return "Poor"
    return "Critical"


def analyze(target: str, mode: str, results: list[dict], started: float, finished: float,
            instruction: str = "") -> dict:
    counts: dict[str, int] = defaultdict(int)
    for r in results:
        counts[r["status"]] += 1

    penalty = 0.0
    for r in results:
        if r["status"] == "fail":
            penalty += SEVERITY_WEIGHT.get(r["severity"], 3)
        elif r["status"] == "warn":
            penalty += SEVERITY_WEIGHT.get(r["severity"], 3) / 2.0
    score = max(0, min(100, round(100 - penalty)))
    if any(r["id"] == "availability" and r["status"] == "fail" for r in results):
        score = min(score, 5)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    defects = sorted([r for r in results if r["status"] in ("fail", "warn")],
                     key=lambda r: (order.get(r["severity"], 5), r["status"] != "fail"))
    passes = [r for r in results if r["status"] == "pass"]
    infos = [r for r in results if r["status"] == "info"]

    seen = {r["id"] for r in results}
    failed = {r["id"] for r in results if r["status"] in ("fail", "warn")}
    rendered = any(r["category"] == "Rendering" for r in results)
    missing = []
    for cid, label, sev in EXPECTED:
        if cid.startswith("render_") and not rendered:
            continue  # rendering was skipped or unavailable, so do not flag it
        if cid in seen:
            if cid in failed:
                missing.append({"item": label, "severity": sev,
                                "reason": "Detected as absent or deficient."})
        else:
            if mode == "api" and cid in WEB_ONLY:
                continue
            if cid.startswith(("email_", "dns_")) and not any(
                    r["category"] in ("Email", "Infrastructure") for r in results):
                continue
            missing.append({"item": label, "severity": sev,
                            "reason": "Not detected in this run."})

    categories: dict[str, dict] = defaultdict(lambda: {"pass": 0, "warn": 0, "fail": 0,
                                                       "info": 0, "total": 0})
    for r in results:
        c = categories[r["category"]]
        c[r["status"]] += 1
        c["total"] += 1

    risks = _risks(results, mode)
    duration = round(finished - started, 2)
    report_text = _compose(target, mode, score, counts, len(results), defects, missing,
                           risks, categories, duration, instruction, passes, infos)

    return {
        "target": target, "mode": mode, "instruction": instruction,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_s": duration, "score": score, "grade": band(score),
        "summary": {"total": len(results), "pass": counts["pass"], "warn": counts["warn"],
                    "fail": counts["fail"], "info": counts["info"]},
        "categories": {k: dict(v) for k, v in categories.items()},
        "defects": defects, "passed": passes, "missing": missing, "risks": risks,
        "info": infos,
        "report": report_text,
    }


def _risks(results: list[dict], mode: str) -> list[dict]:
    ids = {r["id"]: r for r in results}
    risks: list[dict] = []

    def st(cid):
        return ids.get(cid, {}).get("status")

    if st("https") == "fail":
        risks.append({"level": "critical", "text":
                      "Traffic is unencrypted: credentials, tokens and personal data "
                      "can be read or altered in transit."})
    if st("tls") == "fail":
        risks.append({"level": "critical", "text":
                      "A broken or expired certificate triggers browser warnings and "
                      "blocks users from reaching the product."})
    if st("mixed_content") == "fail":
        risks.append({"level": "high", "text":
                      "Mixed content (HTTP scripts on an HTTPS page) lets attackers "
                      "inject code into a supposedly secure page."})
    if st("sec_headers") in ("fail", "warn"):
        risks.append({"level": "high", "text":
                      "Missing security headers leave the app exposed to clickjacking, "
                      "XSS and MIME-sniffing attacks."})
    if st("cookies") == "fail":
        risks.append({"level": "high", "text":
                      "Cookies without Secure/HttpOnly/SameSite can be stolen via "
                      "script or plain HTTP, enabling session hijacking."})
    if st("forms") == "fail":
        risks.append({"level": "high", "text":
                      "A form submits over HTTP, exposing submitted data to interception."})
    if st("api_auth") == "fail":
        risks.append({"level": "high", "text":
                      "The API accepted an invalid token, suggesting missing "
                      "authentication checks on that route."})
    if st("load_success") in ("fail", "warn"):
        risks.append({"level": "high", "text":
                      "The service returned errors under modest concurrency, so real "
                      "traffic spikes may cause outages."})
    if st("api_cors") == "warn":
        risks.append({"level": "medium", "text":
                      "Wildcard CORS lets any website call the API from a victim's browser."})
    if st("email_dmarc") == "warn":
        risks.append({"level": "medium", "text":
                      "Without DMARC your domain can be spoofed in phishing emails, "
                      "damaging brand trust and deliverability."})
    if st("links") in ("fail", "warn"):
        risks.append({"level": "medium", "text":
                      "Broken links frustrate users and can block signup, checkout or "
                      "documentation journeys."})
    if st("viewport") in ("fail", "warn"):
        risks.append({"level": "medium", "text":
                      "Without a responsive viewport most users (mobile) see a broken layout."})
    if st("render_empty") == "fail":
        risks.append({"level": "critical", "text":
                      "The page renders blank in a real browser: users on JavaScript-enabled "
                      "devices would see nothing."})
    if st("render_pageerror") == "fail":
        risks.append({"level": "high", "text":
                      "Uncaught JavaScript exceptions break parts of the app for real users."})
    if st("render_load") == "fail":
        risks.append({"level": "high", "text":
                      "The page failed to render in a real browser, which is what most "
                      "users actually run."})
    if st("render_console") == "fail":
        risks.append({"level": "medium", "text":
                      "Repeated console errors usually indicate broken features or failed "
                      "data loads."})
    if st("a11y") in ("fail", "warn"):
        risks.append({"level": "medium", "text":
                      "Accessibility gaps exclude users with assistive technology and "
                      "can breach accessibility compliance."})
    if not risks:
        risks.append({"level": "low", "text":
                      "No high-impact risks detected in this pass. Re-run after each "
                      "deployment."})
    return risks


def _compose(target, mode, score, counts, total, defects, missing, risks,
             categories, duration, instruction, passes, results_info) -> str:
    L = []
    L.append("Investier Diagnostic Report")
    L.append("=" * 62)
    L.append(f"Target      : {target}")
    L.append(f"Test profile: {mode}")
    if instruction:
        L.append(f"Instruction : {instruction}")
    L.append(f"Duration    : {duration}s")
    L.append("")
    L.append(f"OVERALL HEALTH: {score}/100  ({band(score)})")
    L.append(f"Checks run    : {total}  (pass {counts['pass']}, warn {counts['warn']}, "
             f"fail {counts['fail']}, info {counts['info']})")
    L.append("")

    L.append("WHAT IS WORKING")
    L.append("-" * 62)
    if passes:
        for r in passes[:25]:
            L.append(f"  [ok]   {r['category']} :: {r['name']} - {r['detail']}")
    else:
        L.append("  No passing checks recorded.")
    L.append("")

    infos = [r for r in results_info]
    if infos:
        L.append("NOTES & DETECTIONS")
        L.append("-" * 62)
        for r in infos[:15]:
            L.append(f"  [..]   {r['category']} :: {r['name']} - {r['detail']}")
        L.append("")

    L.append("PROBLEMS & ERRORS FOUND (ranked by severity)")
    L.append("-" * 62)
    if defects:
        for i, d in enumerate(defects, 1):
            tag = "FAIL" if d["status"] == "fail" else "WARN"
            L.append(f"  {i:>2}. [{tag}/{d['severity'].upper()}] {d['category']} :: {d['name']}")
            L.append(f"      -> {d['detail']}")
            if d.get("evidence"):
                L.append(f"      evidence: {str(d['evidence'])[:180]}")
    else:
        L.append("  None. Every check passed.")
    L.append("")

    L.append("MISSING / NOT DETECTED")
    L.append("-" * 62)
    if missing:
        for m in missing:
            L.append(f"  [{m['severity'].upper()}] {m['item']} - {m['reason']}")
    else:
        L.append("  Nothing material appears to be missing.")
    L.append("")

    L.append("PREDICTED RISK IF SHIPPED AS-IS")
    L.append("-" * 62)
    for r in risks:
        L.append(f"  [{r['level'].upper()}] {r['text']}")
    L.append("")

    L.append("CATEGORY SCORES")
    L.append("-" * 62)
    for cat, c in sorted(categories.items()):
        pct = round(c["pass"] / c["total"] * 100) if c["total"] else 0
        L.append(f"  {cat:<16} {c['pass']}/{c['total']} passing ({pct}%)")
    L.append("")

    L.append("VERDICT")
    L.append("-" * 62)
    L.append("  " + _verdict(defects, counts))
    L.append("")
    L.append("Generated by Investier - universal test & diagnostic platform.")
    return "\n".join(L)


def _verdict(defects, counts) -> str:
    crit = [d for d in defects if d["severity"] == "critical"]
    high = [d for d in defects if d["severity"] == "high"]
    if crit:
        return ("NOT READY TO SHIP. Critical issues must be fixed first: "
                + "; ".join(d["name"] for d in crit[:3]) + ".")
    if high:
        return ("SHIP WITH CAUTION. No blockers, but high-severity issues should be "
                "resolved before wide release.")
    if counts["warn"]:
        return ("REASONABLY HEALTHY. Only minor/low issues remain - safe to ship with a "
                "follow-up cleanup pass.")
    return "HEALTHY. No material issues detected in this test pass."
