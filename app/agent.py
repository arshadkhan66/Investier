"""AI agent.

Uses the local LLM to interpret a free-form instruction and to reason about
findings. Every method has a deterministic rule-based fallback so the platform
is fully functional even when the model cannot be loaded.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from .llm import LLM

# ---------------------------------------------------------------- keywords
KEYWORDS = {
    "security": ["security", "secure", "vulnerab", "hack", "exploit", "tls", "ssl",
                 "certificate", "https", "auth", "cors", "xss", "csrf", "cookie",
                 "header", "mixed content"],
    "performance": ["performance", "speed", "fast", "slow", "latency", "load time",
                    "response time", "optimiz", "cache", "compress", "payload"],
    "mobile": ["mobile", "responsive", "phone", "tablet", "viewport"],
    "accessibility": ["accessib", "a11y", "wcag", "screen reader", "alt text"],
    "seo": ["seo", "search engine", "ranking", "meta", "sitemap", "robots", "crawl",
            "structured data", "open graph", "schema"],
    "functionality": ["function", "link", "form", "button", "broken", "click",
                      "feature", "workflow", "user flow", "404"],
    "content": ["content", "copy", "text", "typo", "placeholder", "spelling",
                "lorem", "grammar"],
    "api": ["api", "endpoint", "rest", "graphql", "json", "backend", "service"],
    "stability": ["stability", "stress", "concurren", "load test", "crash", "uptime",
                  "reliab", "scale"],
    "infrastructure": ["dns", "domain", "email", "spf", "dmarc", "dkim", "mx",
                       "nameserver", "caa", "infra"],
}

WEB_GROUPS = ["availability", "security", "performance", "mobile", "accessibility",
              "seo", "functionality", "content", "stability", "infrastructure"]

PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "groups": {
            "type": "array",
            "items": {"type": "string",
                      "enum": ["availability", "security", "performance", "mobile",
                               "accessibility", "seo", "functionality", "content",
                               "api", "stability", "infrastructure"]},
        },
        "mode": {"type": "string", "enum": ["web", "api"]},
        "run_load": {"type": "boolean"},
        "rationale": {"type": "string"},
    },
    "required": ["groups", "mode", "run_load"],
}

PLAN_SYSTEM = (
    "You are a precise test-planning assistant. Choose which test groups to run "
    "for the target. Reply with ONLY a JSON object, no prose."
)


class Agent:
    def __init__(self) -> None:
        self.llm = LLM

    # ------------------------------------------------------------ planning
    def plan(self, instruction: str, target: str) -> dict:
        rule_plan = self._rule_plan(instruction, target)
        if self.llm.available or self.llm.load():
            llm_plan = self._llm_plan(instruction, target, rule_plan)
            if llm_plan:
                merged = self._merge(rule_plan, llm_plan)
                merged["source"] = "local-llm"
                merged["model"] = self.llm.model_name
                return merged
        rule_plan["source"] = "rules"
        return rule_plan

    def _rule_plan(self, instruction: str, target: str) -> dict:
        text = (instruction or "").lower()
        everything = bool(re.search(
            r"\b(everything|all|full|complete|comprehensive|thorough|deep|entire|"
            r"each and every|anything)\b", text))
        groups = {g for g, words in KEYWORDS.items() if any(w in text for w in words)}
        if everything or not groups:
            groups = set(WEB_GROUPS)

        parsed = urlparse(target)
        path = parsed.path.lower()
        host = (parsed.hostname or "").lower()
        looks_api = (any(s in path for s in ("/api", "/v1", "/v2", "/v3", "/graphql", "/rest"))
                     or host.startswith("api.") or ".api." in host)
        if looks_api:
            groups.add("api")

        # Infrastructure/email checks only make sense for a real domain.
        if not host or host.replace(".", "").isdigit() or "localhost" in host:
            groups.discard("infrastructure")

        return {
            "groups": sorted(groups),
            "mode": "api" if looks_api else "web",
            "run_load": "stability" in groups,
            "everything": everything,
            "rationale": "Derived from keywords in the instruction.",
        }

    def _llm_plan(self, instruction: str, target: str, rule_plan: dict) -> dict | None:
        user = (f"Instruction: {instruction or '(none given)'}\n"
                f"Target: {target}\n"
                f"Detected hints: mode={rule_plan['mode']}, "
                f"candidate groups={', '.join(rule_plan['groups'])}.\n"
                "Produce the JSON test plan now.")
        data = self.llm.json_chat(PLAN_SYSTEM, user, max_tokens=160, schema=PLAN_SCHEMA)
        groups = list(data.get("groups", [])) if data else []
        # Even if JSON parsing failed entirely, salvage group names from the raw text.
        if not groups:
            raw = self.llm.chat(PLAN_SYSTEM, user, max_tokens=160, temperature=0.0) or ""
            groups = re.findall(
                r"\b(availability|security|performance|mobile|accessibility|seo|"
                r"functionality|content|api|stability|infrastructure)\b", raw)
        valid = set(WEB_GROUPS) | {"api"}
        groups = [g for g in dict.fromkeys(groups) if g in valid]
        if not groups:
            return None
        mode = (data or {}).get("mode") if data else None
        if mode not in ("web", "api"):
            mode = "api" if "api" in groups else "web"
        return {
            "groups": groups,
            "mode": mode,
            "run_load": bool((data or {}).get("run_load")) or "stability" in groups,
            "rationale": str((data or {}).get("rationale", ""))[:300],
        }

    @staticmethod
    def _merge(rule_plan: dict, llm_plan: dict) -> dict:
        """Union the two plans so nothing the rules caught is lost."""
        groups = sorted(set(rule_plan["groups"]) | set(llm_plan["groups"]))
        mode = llm_plan["mode"] if "api" in groups or llm_plan["mode"] == "api" \
            else rule_plan["mode"]
        return {
            "groups": groups,
            "mode": mode,
            "run_load": rule_plan["run_load"] or llm_plan["run_load"] or "stability" in groups,
            "everything": rule_plan["everything"],
            "rationale": llm_plan.get("rationale") or rule_plan["rationale"],
        }

    # ------------------------------------------------------------- analysis
    def narrate(self, report: dict) -> tuple[str | None, str]:
        """Write an executive summary that is strictly grounded in findings.

        Returns (text, source) where source is 'local-llm' when the model wrote
        it, or 'template' when the deterministic fallback was used.

        Guardrails against a small model inventing claims:
          1. The prompt is extractive: it may only restate facts it is given.
          2. The prompt explicitly lists what is *not* a problem, so it cannot
             claim a passing check failed.
          3. The output is checked for contradictions against the report; on a
             contradiction the model is asked once more with a stricter prompt.
          4. If it still fails, we return a deterministic template narrative.
        """
        if not self.llm.available and not self.llm.load():
            return None, "rules"

        facts = self._grounding_facts(report)
        user = (
            "You are writing an executive summary. Use ONLY the facts listed "
            "below. Do not add, infer, or invent any problem, cause or fix that "
            "is not listed. Never say a check failed if it appears under "
            "WHAT PASSED. If unsure, say less.\n\n"
            f"{facts}\n\n"
            "Write 3 to 4 sentences: (1) the overall state and score, "
            "(2) the single most important problem from PROBLEMS, "
            "(3) one thing that is working, (4) the most valuable next action. "
            "Plain prose, no lists, no markdown."
        )
        system = ("You are a factual QA summariser. You may only restate the "
                  "provided facts. Inventing findings is a serious error.")

        for attempt in range(2):
            out = self.llm.chat(system, user, max_tokens=220,
                                temperature=0.1 if attempt == 0 else 0.0)
            if not out:
                break
            text = out.strip()
            problems = self._contradictions(text, report)
            if not problems:
                return text, "local-llm"
            # Retry with an explicit correction naming the invented claims.
            user += ("\n\nYour previous answer made claims that contradict the "
                     "facts: " + "; ".join(problems) + ". Rewrite it using only "
                     "the listed facts.")

        return self._template_narrative(report), "template"

    @staticmethod
    def _verdict_line(report: dict) -> str:
        """Pull the human verdict sentence out of the composed report."""
        if "VERDICT" not in report.get("report", ""):
            return ""
        for line in report["report"].split("VERDICT")[-1].splitlines():
            line = line.strip().strip("-").strip()
            if len(line) > 12 and not set(line) <= {"-", " "}:
                return line
        return ""

    def _grounding_facts(self, report: dict) -> str:
        """Assemble a compact, unambiguous fact sheet for the summariser."""
        top = report["defects"][:5]
        passed = [r["name"] for r in report.get("passed", [])][:12]
        missing = [m["item"] for m in report["missing"][:6]]
        lines = [
            f"TARGET: {report['target']}",
            f"SCORE: {report['score']}/100 ({report['grade']})",
            f"COUNTS: {report['summary']['fail']} failed, "
            f"{report['summary']['warn']} warned, {report['summary']['pass']} passed.",
            "",
            "PROBLEMS (the only problems that exist):",
        ]
        lines += ([f"- {d['name']} [{d['severity']}]: {d['detail']}" for d in top]
                  or ["- none"])
        lines += ["", "WHAT PASSED (these are NOT problems):"]
        lines += ([f"- {p}" for p in passed] or ["- (nothing recorded)"])
        if missing:
            lines += ["", "MISSING:"] + [f"- {m}" for m in missing]
        verdict = self._verdict_line(report)
        if verdict:
            lines += ["", f"VERDICT: {verdict}"]
        return "\n".join(lines)

    def _contradictions(self, text: str, report: dict) -> list[str]:
        """Detect claims that contradict the report.

        Catches the common small-model failure of asserting a passing check
        failed (e.g. "missing SSL/TLS certificate" when TLS passed). Works per
        clause, so "security headers failed; TLS passed" is not misread as a
        claim that TLS failed.
        """
        import re
        low = text.lower()
        passed = {r["id"] for r in report.get("passed", [])}
        failed_ids = {r["id"] for r in report["defects"]}

        negative = ("missing", "lacks", "without", "absent", "no ", "not ",
                    "failed", "fails", "broken", "unavailable", "none")
        topics = {
            "tls": ("certificate", "ssl", "tls"),
            "https": ("https", "encryption", "encrypted transport"),
            "compression": ("compression", "gzip", "brotli"),
            "title": ("page title", "title tag"),
            "viewport": ("viewport", "responsive"),
        }
        # Split into clauses so a negative in one clause cannot taint a topic
        # mentioned in another.
        clauses = [c for c in re.split(r"[.;!?\n]|,\s|\band\b|\bbut\b", low) if c.strip()]
        problems = []
        for cid, words in topics.items():
            if cid not in passed or cid in failed_ids:
                continue
            for clause in clauses:
                hit = next((w for w in words if w in clause), None)
                if hit and any(neg in clause for neg in negative):
                    problems.append(f"claimed '{hit}' is a problem but it passed")
                    break
        # Only flag 'critical' when it is used as a severity claim. Small models
        # often write "the most critical problem", meaning "most important".
        if re.search(r"critical[\s-]?(severity|level|risk|issue|vulnerabilit)"
                     r"|severity[\s:]+critical|\brated critical\b", low) and not any(
                d["severity"] == "critical" for d in report["defects"]):
            problems.append("called something 'critical' but nothing is critical")
        return problems[:4]

    def _template_narrative(self, report: dict) -> str:
        """Deterministic fallback narrative: always correct, never invents."""
        s = report["summary"]
        top = report["defects"][0] if report["defects"] else None
        worked = report.get("passed", [])
        parts = [f"{report['target']} scored {report['score']}/100 ({report['grade']}) "
                 f"across {s['total']} checks: {s['pass']} passed, {s['warn']} warned, "
                 f"{s['fail']} failed."]
        if top:
            parts.append(f"The most important problem is {top['name']} "
                         f"({top['severity']}): {top['detail']}")
        else:
            parts.append("No problems were detected in this pass.")
        if worked:
            parts.append(f"{worked[0]['name']} is working, among other checks.")
        verdict = self._verdict_line(report)
        if verdict:
            parts.append(verdict)
        return " ".join(parts)

    def explain_defect(self, defect: dict) -> str | None:
        """Optional: a plain-language explanation + fix hint for one defect."""
        if not self.llm.available and not self.llm.load():
            return None
        user = (f"A test found this issue:\n"
                f"Name: {defect['name']}\nCategory: {defect['category']}\n"
                f"Severity: {defect['severity']}\nDetail: {defect['detail']}\n"
                f"Evidence: {str(defect.get('evidence',''))[:300]}\n\n"
                "In 2 short sentences: explain the real-world impact, then give the "
                "concrete fix. No preamble.")
        return self.llm.chat(
            "You are a pragmatic engineer. Be specific and brief.",
            user, max_tokens=120, temperature=0.2)


AGENT = Agent()
