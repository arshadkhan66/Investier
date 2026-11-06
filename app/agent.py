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
    def narrate(self, report: dict) -> str | None:
        """Ask the local model for a short executive narrative of the findings."""
        if not self.llm.available and not self.llm.load():
            return None
        defects = report["defects"][:8]
        lines = [f"- [{d['severity']}/{d['status']}] {d['name']}: {d['detail']}"
                 for d in defects]
        missing = [m["item"] for m in report["missing"][:8]]
        user = (
            f"Target: {report['target']}\n"
            f"Health score: {report['score']}/100 ({report['grade']})\n"
            f"Instruction from the user: {report.get('instruction') or '(none)'}\n"
            f"Problems found:\n" + ("\n".join(lines) or "- none") + "\n"
            f"Missing or not detected: {', '.join(missing) or 'none'}\n\n"
            "Write a short executive summary (max 90 words) for the person who "
            "asked for this test. State the overall state, the most important "
            "problem, and the single most valuable next action. Plain prose, no lists."
        )
        system = ("You are a senior software QA engineer writing a concise, "
                  "factual test summary. Never invent findings that are not listed.")
        out = self.llm.chat(system, user, max_tokens=200, temperature=0.3)
        if out:
            return out.strip()
        return None

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
