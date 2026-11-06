"""Infrastructure checks: DNS records and email authentication posture.

These are optional: they run only when the `dnspython` package is present and
degrade to an informational result otherwise.
"""
from __future__ import annotations

from .base import result

try:
    import dns.resolver  # type: ignore
    import dns.exception  # type: ignore
    HAVE_DNS = True
except Exception:  # noqa: BLE001
    HAVE_DNS = False


def _resolve(domain: str, rtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=8)
        return [a.to_text().strip('"') for a in answers]
    except Exception:  # noqa: BLE001
        return []


def run_infra_checks(domain: str | None, opts: dict) -> list[dict]:
    if not domain:
        return []
    if not HAVE_DNS:
        return [result("dns_engine", "Infrastructure", "DNS resolution", "info", "info",
                       "dnspython not installed; DNS/email checks skipped.")]

    results: list[dict] = []

    a = _resolve(domain, "A")
    aaaa = _resolve(domain, "AAAA")
    results.append(result("dns_a", "Infrastructure", "DNS address records",
                          "pass" if (a or aaaa) else "fail",
                          "info" if (a or aaaa) else "high",
                          f"A: {', '.join(a[:4]) or 'none'}; AAAA: {', '.join(aaaa[:2]) or 'none'}.",
                          ", ".join(a[:4])))

    ns = _resolve(domain, "NS")
    results.append(result("dns_ns", "Infrastructure", "Authoritative nameservers",
                          "pass" if len(ns) >= 2 else "warn",
                          "info" if len(ns) >= 2 else "medium",
                          f"{len(ns)} nameserver(s): {', '.join(ns[:4])}.", ", ".join(ns[:4])))

    mx = _resolve(domain, "MX")
    results.append(result("dns_mx", "Infrastructure", "Mail routing (MX)",
                          "pass" if mx else "warn", "info" if mx else "low",
                          f"{len(mx)} MX record(s)." if mx else "No MX records.",
                          ", ".join(mx[:4])))

    txt = _resolve(domain, "TXT")
    joined = " ".join(txt).lower()
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    results.append(result("email_spf", "Email", "SPF record",
                          "pass" if spf else "warn", "info" if spf else "medium",
                          f"SPF present: {spf[0][:120]}" if spf
                          else "No SPF record; domain is spoofable in email.",
                          spf[0][:200] if spf else ""))

    dmarc = _resolve("_dmarc." + domain, "TXT")
    dmarc_v = [t for t in dmarc if "v=dmarc1" in t.lower()]
    if dmarc_v:
        policy = "none"
        low = dmarc_v[0].lower()
        if "p=reject" in low:
            policy = "reject"
        elif "p=quarantine" in low:
            policy = "quarantine"
        results.append(result("email_dmarc", "Email", "DMARC policy",
                              "pass" if policy in ("reject", "quarantine") else "warn",
                              "info" if policy in ("reject", "quarantine") else "medium",
                              f"DMARC policy p={policy}.", dmarc_v[0][:200]))
    else:
        results.append(result("email_dmarc", "Email", "DMARC policy", "warn", "medium",
                              "No DMARC record; spoofed mail is not rejected."))

    dkim_note = "DKIM selectors are domain-specific; not probed."
    if "v=spf1" not in joined and not spf:
        dkim_note = "No SPF found, so DKIM alignment cannot be assumed."
    results.append(result("email_dkim", "Email", "DKIM (informational)", "info", "info",
                          dkim_note))

    caa = _resolve(domain, "CAA")
    results.append(result("dns_caa", "Security", "CAA record (cert issuance control)",
                          "pass" if caa else "warn", "info" if caa else "low",
                          f"CAA present: {', '.join(caa[:3])}" if caa
                          else "No CAA record; any CA may issue certificates.",
                          ", ".join(caa[:3])))

    return results
