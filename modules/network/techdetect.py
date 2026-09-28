"""Website technology fingerprinting from headers, cookies and HTML."""

from __future__ import annotations

import re

from rich.table import Table

from core import http
from core import report as reportlib
from core.console import console, err, info, is_quiet

#: (category, label, regex) matched against headers and body text.
SIGNATURES = [
    ("server", "Nginx", r"\bnginx\b"),
    ("server", "Apache", r"\bapache\b"),
    ("server", "IIS", r"\biis\b|microsoft-iis"),
    ("server", "LiteSpeed", r"\blitespeed\b"),
    ("server", "Caddy", r"\bcaddy\b"),
    ("server", "OpenResty", r"\bopenresty\b"),
    ("server", "Tomcat", r"\btomcat|jasper\b"),
    ("server", "Gunicorn", r"\bgunicorn\b"),
    ("server", "Werkzeug", r"\bwerkzeug\b"),
    ("server", "Kestrel", r"\bkestrel\b"),
    ("platform", "Cloudflare", r"\bcloudflare\b"),
    ("platform", "CloudFront", r"\bcloudfront\b"),
    ("platform", "Fastly", r"\bfastly\b"),
    ("platform", "Akamai", r"\bakamai\b"),
    ("platform", "Varnish", r"\bvarnish\b"),
    ("platform", "Sucuri", r"\bsucuri\b"),
    ("platform", "GitHub Pages", r"github\.io|github\.com"),
    ("framework", "Next.js", r"__next_data__|_next/static|next\.js"),
    ("framework", "Nuxt", r"__nuxt__|_nuxt/"),
    ("framework", "React", r"react\.production|data-reactroot|react-dom"),
    ("framework", "Vue.js", r"vue(\.min)?\.js|__vue__|data-v-[0-9a-f]{8}"),
    ("framework", "Angular", r"ng-version|angular(\.min)?\.js"),
    ("framework", "Svelte", r"svelte-[0-9a-z]{6}|__svelte"),
    ("framework", "jQuery", r"jquery(\.min)?\.js|jquery-"),
    ("framework", "Bootstrap", r"bootstrap(\.min)?\.(css|js)"),
    ("framework", "Tailwind", r"tailwind"),
    ("framework", "Laravel", r"laravel_session|laravel"),
    ("framework", "Django", r"csrfmiddlewaretoken|django"),
    ("framework", "Rails", r"rails|_rails_session"),
    ("framework", "ASP.NET", r"asp\.net|__viewstate|aspnet_sessionid"),
    ("framework", "Flask", r"\bflask\b"),
    ("framework", "Express", r"\bexpress\b|connect\.sid"),
    ("cms", "WordPress", r"wp-content|wp-includes|wordpress|wp-json"),
    ("cms", "Drupal", r"drupal|sites/default/files"),
    ("cms", "Joomla", r"joomla|/components/com_"),
    ("cms", "Ghost", r"ghost(-content)?/|ghost\.org"),
    ("cms", "Magento", r"magento|mage/cookies"),
    ("cms", "Shopify", r"cdn\.shopify\.com|shopify"),
    ("cms", "Wix", r"wix\.com|wixstatic"),
    ("cms", "Squarespace", r"squarespace"),
    ("cms", "Blogger", r"blogger\.com|blogspot"),
    ("language", "PHP", r"\.php|x-powered-by:\s*php"),
    ("language", "Python", r"python"),
    ("analytics", "Google Analytics", r"google-analytics\.com|gtag\(|googletagmanager"),
    ("analytics", "Plausible", r"plausible\.io"),
    ("analytics", "Hotjar", r"hotjar\.com"),
    ("analytics", "Clarity", r"clarity\.ms"),
    ("ads", "Google AdSense", r"adsbygoogle|doubleclick"),
    ("chat", "Intercom", r"intercom(cdn|\.io)"),
    ("chat", "Crisp", r"crisp\.chat"),
    ("chat", "Tawk.to", r"tawk\.to"),
    ("payment", "Stripe", r"js\.stripe\.com"),
    ("payment", "PayPal", r"paypal(object)?\.com"),
    ("security", "reCAPTCHA", r"recaptcha|gstatic\.com/recaptcha"),
    ("security", "hCaptcha", r"hcaptcha\.com"),
]

_HEADER_SIGNATURES = [
    ("WordPress", "x-powered-by", r"wordpress"),
    ("PHP", "x-powered-by", r"php"),
    ("ASP.NET", "x-powered-by", r"asp\.net"),
    ("ASP.NET MVC", "x-aspnetmvc-version", r".+"),
    ("Next.js", "x-powered-by", r"next\.js"),
    ("Express", "x-powered-by", r"express"),
    ("Shopify", "x-shopify-stage|x-sorting-hat", r".+"),
    ("Cloudflare", "cf-ray|cf-cache-status", r".+"),
    ("Vercel", "x-vercel-id|server", r"vercel"),
    ("Netlify", "server", r"netlify"),
    ("GitHub Pages", "server", r"github\.com"),
    ("AWS S3", "server", r"amazons3"),
    ("Google", "server", r"gws|gse"),
    ("Envoy", "server", r"envoy"),
    ("Django", "x-frame-options", r"deny"),  # weak hint, only with csrf cookie
]

def detect(url: str | None = None, timeout: float = 10) -> dict:
    """Fingerprint the technology stack behind ``url``."""
    if not url:
        from core.utils import ask

        url = ask("Website URL")

    url = http.normalize_url(url)
    report = reportlib.new_report("technology_detection", url)
    info(f"Fingerprinting {url}...")

    try:
        response = http.get(url, timeout=timeout)
    except Exception as exc:
        reportlib.add_error(report, str(exc))
        reportlib.finish(report, reachable=False, technologies=0)
        return _present(report)

    body = response.text[:200_000].lower()
    header_blob = "\n".join(f"{k}: {v}" for k, v in response.headers.items()).lower()

    hits: dict[str, set[str]] = {}

    for category, label, pattern in SIGNATURES:
        if re.search(pattern, header_blob) or re.search(pattern, body):
            hits.setdefault(label, set()).add(category)

    for label, header, pattern in _HEADER_SIGNATURES:
        value = header_blob
        names = header.split("|")
        for name in names:
            if re.search(rf"^{re.escape(name)}\s*:", value, re.MULTILINE):
                match = re.search(rf"^{re.escape(name)}\s*:\s*(.+)$", value, re.MULTILINE)
                if match and re.search(pattern, match.group(1)):
                    hits.setdefault(label, set()).add("header")
                break

    for cookie in getattr(response, "cookies", []) or []:
        name = cookie.name.lower()
        if "wordpress" in name or name.startswith("wp-"):
            hits.setdefault("WordPress", set()).add("cookie")
        elif "laravel" in name:
            hits.setdefault("Laravel", set()).add("cookie")
        elif "django" in name or name == "csrftoken":
            hits.setdefault("Django", set()).add("cookie")
        elif "phpsessid" in name:
            hits.setdefault("PHP", set()).add("cookie")
        elif "jsessionid" in name:
            hits.setdefault("Java", set()).add("cookie")
        elif "asp.net" in name or name.startswith(".aspnet"):
            hits.setdefault("ASP.NET", set()).add("cookie")
        elif "connect.sid" in name:
            hits.setdefault("Express", set()).add("cookie")
        elif "_rails" in name or "rails" in name:
            hits.setdefault("Rails", set()).add("cookie")

    for label in sorted(hits):
        reportlib.add_finding(
            report,
            technology=label,
            category=", ".join(sorted(hits[label])),
        )

    report["meta"]["status"] = response.status_code
    report["meta"]["server"] = response.headers.get("Server", "")
    reportlib.finish(report, reachable=True, technologies=len(hits))
    return _present(report)


def _present(report: dict) -> dict:
    if is_quiet():
        return report
    findings = report.get("findings", [])
    if findings:
        table = Table(title=f"Technology - {report['target']}", header_style="bold cyan")
        table.add_column("TECHNOLOGY", style="green")
        table.add_column("DETECTED VIA", style="cyan")
        for finding in findings:
            table.add_row(finding["technology"], finding.get("category", ""))
        console.print(table)
    else:
        console.print("[yellow][!][/yellow] No signatures matched.")
    for error in report.get("errors", []):
        err(error)
    return report
