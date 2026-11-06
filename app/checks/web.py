"""HTTP / web-surface checks: availability, TLS, security, performance, SEO,
mobile, accessibility, functionality and content."""
from __future__ import annotations

import re
import ssl
import socket
import asyncio
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .base import result, percentile, make_client, timed_get

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "high",
        "Prevents protocol-downgrade and cookie-hijacking attacks."),
    "content-security-policy": ("CSP", "high",
        "Mitigates XSS and data-injection attacks."),
    "x-content-type-options": ("X-Content-Type-Options", "medium",
        "Stops MIME-type sniffing."),
    "x-frame-options": ("X-Frame-Options", "medium", "Blocks clickjacking."),
    "referrer-policy": ("Referrer-Policy", "low", "Limits referrer leakage."),
    "permissions-policy": ("Permissions-Policy", "low",
        "Restricts powerful browser features."),
}

PLACEHOLDER_PATTERNS = [
    r"lorem ipsum", r"your name here", r"\btodo\b", r"\bfixme\b",
    r"coming soon", r"placeholder", r"xxxxx", r"example\.com", r"changeme",
]

VIEWPORT_RE = re.compile(r"width\s*=\s*device-width", re.I)


async def run_web_checks(target: str, opts: dict) -> list[dict]:
    results: list[dict] = []
    samples = int(opts.get("samples", 5))
    parsed = urlparse(target)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    async with make_client(opts) as client:
        resp, ms, err = await timed_get(client, target)
        if resp is None:
            results.append(result("availability", "Availability", "Target reachable",
                                  "fail", "critical",
                                  f"Could not reach the target. {err}", err, ms))
            return results

        ok = resp.status_code < 400
        results.append(result("availability", "Availability", "Target reachable",
                              "pass" if ok else "fail", "info" if ok else "critical",
                              f"HTTP {resp.status_code} in {ms:.0f} ms.",
                              f"{resp.http_version} {resp.status_code}", ms))
        results.append(result("status_code", "Availability", "Healthy status code",
                              "pass" if resp.status_code == 200 else "warn",
                              "info" if resp.status_code == 200 else "medium",
                              f"Root returned HTTP {resp.status_code}.",
                              str(resp.status_code)))

        body = resp.text
        ctype = resp.headers.get("content-type", "")
        is_html = "html" in ctype.lower() or "<html" in body[:2000].lower()

        # -- transport ------------------------------------------------------
        if parsed.scheme == "https":
            results.append(result("https", "Security", "Encrypted transport (HTTPS)",
                                  "pass", "info", "Served over HTTPS.", parsed.scheme))
            results.append(await _tls_check(parsed.hostname, parsed.port or 443,
                                            float(opts.get("timeout", 20))))
        else:
            results.append(result("https", "Security", "Encrypted transport (HTTPS)",
                                  "fail", "high",
                                  "Served over plain HTTP; traffic can be intercepted.",
                                  target))

        if resp.history:
            chain = " -> ".join(f"{r.status_code}:{r.url}" for r in resp.history[:5])
            results.append(result("redirects", "Availability", "Redirect chain",
                                  "pass", "info",
                                  f"{len(resp.history)} redirect(s) before final page.",
                                  chain))
            for r in resp.history:
                if r.status_code in (301, 302, 307, 308) and r.url.scheme == "http":
                    loc = r.headers.get("location", "")
                    if urlparse(urljoin(str(r.url), loc)).scheme != "https":
                        results.append(result("redirect_insecure", "Security",
                                              "No insecure redirect", "warn", "medium",
                                              "Redirect stays on plain HTTP.", str(r.url)))

        # -- performance ----------------------------------------------------
        latencies = [ms]
        for _ in range(max(0, samples - 1)):
            _, m, _ = await timed_get(client, target)
            if m:
                latencies.append(m)
        avg = sum(latencies) / len(latencies)
        p95 = percentile(latencies, 95)
        results.append(result(
            "latency", "Performance", "Response latency",
            "pass" if avg < 500 else ("warn" if avg < 1500 else "fail"),
            "info" if avg < 500 else ("medium" if avg < 1500 else "high"),
            f"avg {avg:.0f} ms, p95 {p95:.0f} ms over {len(latencies)} requests.",
            ", ".join(f"{x:.0f}ms" for x in latencies)))
        results.append(result("ttfb", "Performance", "Time to first byte",
                              "pass" if ms < 800 else "warn",
                              "info" if ms < 800 else "medium",
                              f"Initial TTFB {ms:.0f} ms.", "", ms))

        payload_kb = len(resp.content) / 1024
        results.append(result(
            "payload", "Performance", "Page weight",
            "pass" if payload_kb < 500 else ("warn" if payload_kb < 2000 else "fail"),
            "info" if payload_kb < 500 else ("medium" if payload_kb < 2000 else "high"),
            f"HTML document is {payload_kb:.1f} KB."))

        # -- compression & caching -----------------------------------------
        enc = resp.headers.get("content-encoding", "")
        results.append(result(
            "compression", "Performance", "Compressed transfer",
            "pass" if enc else "warn", "info" if enc else "medium",
            f"Content-Encoding: {enc}" if enc else
            "No compression; payloads are sent uncompressed.", enc))
        cc = resp.headers.get("cache-control", "")
        results.append(result("cache_control", "Performance", "Cache-Control header",
                              "pass" if cc else "warn", "info" if cc else "low",
                              f"Cache-Control: {cc}" if cc else "No Cache-Control header.", cc))

        # -- security headers ----------------------------------------------
        present, missing = [], []
        for hkey, (label, sev, why) in SECURITY_HEADERS.items():
            (present if hkey in resp.headers else missing).append(
                label if hkey in resp.headers else (label, sev, why))
        if missing:
            top = max(missing, key=lambda x: ["low", "medium", "high"].index(x[1]))[1]
            results.append(result(
                "sec_headers", "Security", "Security headers",
                "fail" if top == "high" else "warn", top,
                f"{len(missing)} of {len(SECURITY_HEADERS)} recommended headers missing.",
                "; ".join(f"{l} ({s}) - {w}" for l, s, w in missing)))
        else:
            results.append(result("sec_headers", "Security", "Security headers",
                                  "pass", "info", "All recommended headers present.",
                                  ", ".join(present)))

        # -- cookies --------------------------------------------------------
        raw_cookies = (resp.headers.get_list("set-cookie")
                       if hasattr(resp.headers, "get_list")
                       else ([resp.headers["set-cookie"]] if "set-cookie" in resp.headers else []))
        if raw_cookies:
            bad = set()
            for c in raw_cookies:
                low = c.lower()
                if "secure" not in low:
                    bad.add("missing Secure")
                if "httponly" not in low:
                    bad.add("missing HttpOnly")
                if "samesite" not in low:
                    bad.add("missing SameSite")
            results.append(result("cookies", "Security", "Cookie security flags",
                                  "fail" if bad else "pass", "high" if bad else "info",
                                  "Cookies missing protective flags." if bad
                                  else "All cookies carry Secure/HttpOnly/SameSite.",
                                  "; ".join(sorted(bad)) if bad else f"{len(raw_cookies)} cookie(s)"))

        banner = [resp.headers.get(h) for h in ("server", "x-powered-by", "x-aspnet-version")
                  if resp.headers.get(h)]
        if banner:
            results.append(result("banner", "Security", "Server banner disclosure",
                                  "warn", "low",
                                  "Server advertises software/version.",
                                  " | ".join(banner)))

        # -- robots & sitemap ----------------------------------------------
        for path, cid, name in (("/robots.txt", "robots", "robots.txt present"),
                                ("/sitemap.xml", "sitemap", "sitemap.xml present")):
            r, _, _ = await timed_get(client, origin + path)
            found = r is not None and r.status_code == 200 and r.text.strip()
            results.append(result(cid, "SEO", name, "pass" if found else "warn",
                                  "info" if found else "low",
                                  "Found." if found else f"Not found at {path}.",
                                  r.text[:200] if found else ""))

        if not is_html:
            results.append(result("non_html", "Availability", "HTML document served",
                                  "info", "info",
                                  f"Content-Type '{ctype}'; deep HTML analysis skipped.",
                                  ctype))
            return results

        soup = BeautifulSoup(body, "lxml")

        title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
        results.append(result("title", "SEO", "Page title", "pass" if title else "fail",
                              "info" if title else "medium",
                              f"Title: '{title}'" if title else "Missing <title> tag.", title))

        desc = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
        desc_c = (desc.get("content") or "").strip() if desc else ""
        results.append(result("meta_desc", "SEO", "Meta description",
                              "pass" if len(desc_c) >= 50 else "warn",
                              "info" if len(desc_c) >= 50 else "low",
                              f"{len(desc_c)} chars." if desc_c else "No meta description.",
                              desc_c[:160]))

        og = soup.find("meta", attrs={"property": re.compile("^og:title$", re.I)})
        results.append(result("og_tags", "SEO", "Social share tags (Open Graph)",
                              "pass" if og else "warn", "info" if og else "low",
                              "og:title present." if og else "No Open Graph tags; links share poorly.",
                              og.get("content", "") if og else ""))

        ld = soup.find("script", attrs={"type": "application/ld+json"})
        results.append(result("structured_data", "SEO", "Structured data (JSON-LD)",
                              "pass" if ld else "warn", "info" if ld else "low",
                              "JSON-LD found." if ld else "No JSON-LD structured data.",
                              (ld.string or "")[:200] if ld else ""))

        viewport = soup.find("meta", attrs={"name": re.compile("^viewport$", re.I)})
        vp = viewport.get("content", "") if viewport else ""
        responsive = bool(VIEWPORT_RE.search(vp))
        results.append(result("viewport", "Mobile", "Responsive viewport meta",
                              "pass" if responsive else "warn",
                              "info" if responsive else "medium",
                              "Device-width viewport declared." if responsive
                              else "No responsive viewport meta.", vp))

        icon = soup.find("link", attrs={"rel": re.compile("icon", re.I)})
        results.append(result("favicon", "Polish", "Favicon declared",
                              "pass" if icon else "warn", "info" if icon else "low",
                              "Favicon link found." if icon else "No favicon link.",
                              icon.get("href", "") if icon else ""))

        manifest = soup.find("link", attrs={"rel": re.compile("manifest", re.I)})
        results.append(result("pwa_manifest", "Polish", "PWA manifest",
                              "pass" if manifest else "warn", "info" if manifest else "low",
                              "Web app manifest found." if manifest else "No web app manifest.",
                              manifest.get("href", "") if manifest else ""))

        imgs = soup.find_all("img")
        if imgs:
            no_alt = [i for i in imgs if not (i.get("alt") or "").strip()]
            ratio = len(no_alt) / len(imgs)
            results.append(result("img_alt", "Accessibility", "Image alt text",
                                  "pass" if ratio == 0 else ("warn" if ratio < 0.3 else "fail"),
                                  "info" if ratio == 0 else ("medium" if ratio < 0.3 else "high"),
                                  f"{len(no_alt)}/{len(imgs)} images lack alt text.",
                                  "; ".join((i.get("src") or "?")[:80] for i in no_alt[:5])))
            lazy = [i for i in imgs if i.get("loading") == "lazy"]
            if len(imgs) > 5 and not lazy:
                results.append(result("img_lazy", "Performance", "Lazy-loaded images",
                                      "warn", "low",
                                      f"{len(imgs)} images, none lazy-loaded.", ""))

        forms = soup.find_all("form")
        if forms:
            insecure = [f for f in forms if (f.get("action") or "").startswith("http://")]
            no_label = 0
            for f in forms:
                for field in f.find_all(["input", "select", "textarea"]):
                    if field.get("type") in ("hidden", "submit", "button"):
                        continue
                    fid = field.get("id")
                    if not (fid and soup.find("label", attrs={"for": fid})) \
                            and not field.get("aria-label") and not field.get("placeholder"):
                        no_label += 1
            results.append(result("forms", "Functionality", "Forms well-formed",
                                  "fail" if insecure else ("warn" if no_label else "pass"),
                                  "high" if insecure else ("medium" if no_label else "info"),
                                  f"{len(forms)} form(s); {len(insecure)} over HTTP; "
                                  f"{no_label} unlabelled input(s).",
                                  "; ".join(f.get("action", "?") for f in insecure)))
        else:
            results.append(result("forms", "Functionality", "Forms present", "info", "info",
                                  "No <form> elements (may be JS-driven)."))

        anchors = [a.get("href") for a in soup.find_all("a", href=True)]
        internal = sorted({urljoin(target, h) for h in anchors
                           if h and not h.startswith(("#", "mailto:", "tel:", "javascript:"))})
        if opts.get("check_links", True):
            to_test = internal[: int(opts.get("max_links", 15))]
            broken = []
            for link in to_test:
                r, _, _ = await timed_get(client, link)
                if r is None or r.status_code >= 400:
                    broken.append(f"{link} -> {r.status_code if r else 'ERR'}")
            results.append(result("links", "Functionality", "Internal link health",
                                  "pass" if not broken else ("warn" if len(broken) < 3 else "fail"),
                                  "info" if not broken else ("medium" if len(broken) < 3 else "high"),
                                  f"{len(broken)}/{len(to_test)} sampled links broken.",
                                  "; ".join(broken[:10])))
            results.append(result("links_count", "SEO", "Link inventory", "info", "info",
                                  f"{len(anchors)} links ({len(internal)} unique)."))

        text_low = soup.get_text(" ", strip=True).lower()
        hits = [p for p in PLACEHOLDER_PATTERNS if re.search(p, text_low)]
        results.append(result("placeholders", "Content", "No placeholder/unfinished text",
                              "pass" if not hits else "warn", "info" if not hits else "medium",
                              "No placeholder markers found." if not hits
                              else f"Placeholder markers: {', '.join(hits)}.", ", ".join(hits)))

        inline = " ".join(s.string for s in soup.find_all("script") if s.string)
        markers = [m for m in ("console.error", "throw new Error", "TODO", "FIXME")
                   if m in inline]
        results.append(result("js_markers", "Functionality", "No JS error markers in inline code",
                              "pass" if not markers else "warn", "info" if not markers else "low",
                              "Clean inline scripts." if not markers
                              else f"Markers in inline JS: {', '.join(markers)}.", ""))

        a11y = []
        if not soup.find("html", attrs={"lang": True}):
            a11y.append("missing <html lang>")
        if not soup.find("main") and not soup.find(attrs={"role": "main"}):
            a11y.append("no <main> landmark")
        if not soup.find("h1"):
            a11y.append("no <h1> heading")
        if not soup.find("a", href=re.compile("#", re.I), string=re.compile("skip", re.I)):
            a11y.append("no skip-to-content link")
        results.append(result("a11y", "Accessibility", "Accessibility landmarks",
                              "pass" if not a11y else "warn", "info" if not a11y else "medium",
                              "Core landmarks present." if not a11y
                              else f"{len(a11y)} issue(s): {', '.join(a11y)}."))

        ext = sorted({urlparse(urljoin(target, s.get("src"))).netloc
                      for s in soup.find_all("script", src=True)
                      if urlparse(urljoin(target, s.get("src"))).netloc != parsed.netloc})
        if ext:
            results.append(result("third_party", "Performance", "Third-party script footprint",
                                  "warn" if len(ext) > 4 else "info", "low",
                                  f"{len(ext)} external script domain(s).",
                                  ", ".join(ext[:8])))

        mixed = [s.get("src") for s in soup.find_all("script", src=True)
                 if (s.get("src") or "").startswith("http://")]
        if mixed:
            results.append(result("mixed_content", "Security", "No mixed content",
                                  "fail", "high",
                                  f"{len(mixed)} script(s) loaded over plain HTTP.", "; ".join(mixed[:5])))

    return results


async def _tls_check(host: str | None, port: int, timeout: float) -> dict:
    if not host:
        return result("tls", "Security", "TLS certificate", "warn", "medium",
                      "Could not determine host for TLS inspection.")
    loop = asyncio.get_event_loop()

    def _probe():
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert(), ssock.version()

    try:
        cert, version = await loop.run_in_executor(None, _probe)
    except ssl.SSLCertVerificationError as exc:
        return result("tls", "Security", "TLS certificate", "fail", "critical",
                      f"Certificate verification failed: {exc.verify_message}", str(exc))
    except Exception as exc:  # noqa: BLE001
        return result("tls", "Security", "TLS certificate", "fail", "high",
                      f"TLS handshake failed: {type(exc).__name__}: {exc}")

    not_after = cert.get("notAfter")
    days = None
    if not_after:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
    status, sev = "pass", "info"
    detail = f"TLS {version}, valid."
    if days is not None and days < 0:
        status, sev, detail = "fail", "critical", "Certificate has expired."
    elif days is not None and days < 14:
        status, sev, detail = "warn", "high", f"Certificate expires in {days} days."
    elif days is not None:
        detail = f"TLS {version}; certificate valid for {days} more days."
    return result("tls", "Security", "TLS certificate", status, sev, detail,
                  str(cert.get("subject", "")))
