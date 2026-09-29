import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html import escape
from io import BytesIO
from typing import Any, Callable

from xhtml2pdf import pisa

from app.models.dns_models import SecurityFinding
from app.services import checks
from app.services.ai_summary import generate_plain_english_summary
from app.services.mitre_mapping import map_findings_to_mitre

logger = logging.getLogger(__name__)

_COLORS = {"critical": "#dc2626", "warning": "#d97706", "info": "#2563eb"}

_CSS = """
body { font-family: Helvetica, Arial, sans-serif; margin: 40px; color: #111827; font-size: 12px; }
h1 { color: #1e3a8a; border-bottom: 3px solid #1e3a8a; padding-bottom: 8px; }
h2 { color: #1e40af; margin-top: 22px; border-bottom: 1px solid #d1d5db; padding-bottom: 4px; font-size: 15px; }
.meta { color: #6b7280; font-size: 11px; }
.summary-box { background: #eff6ff; border-left: 4px solid #2563eb; padding: 12px; margin: 12px 0; }
td { padding: 2px 10px 2px 0; vertical-align: top; }
td.k { color: #6b7280; width: 120px; }
ul { line-height: 1.6; }
"""


def _safe(fn: Callable[..., Any], *args: Any) -> Any:
    """Run one check; if it blows up, that section is marked unavailable instead of failing the whole report."""
    try:
        return fn(*args)
    except Exception:
        logger.exception("Report section failed: %s", getattr(fn, "__name__", fn))
        return None


def _findings_of(result: Any) -> list[SecurityFinding]:
    if result is None:
        return []
    return list(result["findings"] if isinstance(result, dict) else result.findings)


def _findings_html(findings: list[SecurityFinding]) -> str:
    if not findings:
        return ""
    items = ""
    for f in findings:
        color = _COLORS.get(f.severity, "#374151")
        items += (
            f'<li><span style="color:{color}; font-weight:bold;">[{escape(f.severity.upper())}]</span> '
            f"{escape(f.message)}</li>"
        )
    return f"<ul>{items}</ul>"


def _kv(rows: list[tuple[str, Any]]) -> str:
    cells = ""
    for key, value in rows:
        shown = "unavailable" if value in (None, "") else str(value)
        cells += f'<tr><td class="k">{escape(key)}</td><td>{escape(shown)}</td></tr>'
    return f"<table>{cells}</table>"


def _section(title: str, body: str, findings: list[SecurityFinding] | None = None) -> str:
    return f"<h2>{escape(title)}</h2>{body}{_findings_html(findings or [])}"


def _unavailable() -> str:
    return "<p>This check could not be completed.</p>"


def generate_full_report(domain: str) -> bytes:
    # Independent checks run in parallel. Most come straight from the cache
    # if the domain was just scanned in the UI.
    with ThreadPoolExecutor(max_workers=6) as pool:
        f_dns = pool.submit(_safe, checks.dns_check, domain)
        f_whois = pool.submit(_safe, checks.whois_check, domain)
        f_subs = pool.submit(_safe, checks.subdomain_check, domain)
        f_ssl = pool.submit(_safe, checks.ssl_check, domain)
        f_headers = pool.submit(_safe, checks.headers_check, domain)
        f_email = pool.submit(_safe, checks.email_check, domain)
        f_url = pool.submit(_safe, checks.url_check, f"https://{domain}")

        dns = f_dns.result()
        whois = f_whois.result()
        subs = f_subs.result()
        ssl = f_ssl.result()
        headers = f_headers.result()
        email = f_email.result()
        url = f_url.result()

    first_ip = dns.records.A[0] if dns and dns.records.A else None
    ip = _safe(checks.ip_check, first_ip) if first_ip else None

    all_findings: list[SecurityFinding] = []
    for result in (dns, whois, subs, ip, ssl, headers, email, url):
        all_findings += _findings_of(result)

    mitre = map_findings_to_mitre(all_findings)
    summary = generate_plain_english_summary(domain, all_findings)

    sections: list[str] = []

    sections.append(_section("Summary", f'<div class="summary-box">{escape(summary)}</div>'))

    if dns:
        r = dns.records
        sections.append(_section("DNS records", _kv([
            ("A", ", ".join(r.A) or "none"), ("AAAA", ", ".join(r.AAAA) or "none"),
            ("MX", ", ".join(r.MX) or "none"), ("NS", ", ".join(r.NS) or "none"),
            ("CNAME", ", ".join(r.CNAME) or "none"),
        ]), dns.findings))
    else:
        sections.append(_section("DNS records", _unavailable()))

    if whois:
        age = f"{whois.domain_age_days:,} days" if whois.domain_age_days is not None else None
        sections.append(_section("WHOIS / domain age", _kv([
            ("Registrar", whois.registrar),
            ("Created", (whois.creation_date or "")[:10]),
            ("Expires", (whois.expiration_date or "")[:10]),
            ("Age", age),
        ]), whois.findings))
    else:
        sections.append(_section("WHOIS / domain age", _unavailable()))

    if subs:
        found = str(len(subs["subdomains"])) if subs["lookup_ok"] else "lookup unavailable"
        listing = ", ".join(subs["subdomains"][:15])
        rows = [("Found", found)]
        if listing:
            rows.append(("First 15", listing))
        sections.append(_section("Subdomains", _kv(rows), subs["findings"]))
    else:
        sections.append(_section("Subdomains", _unavailable()))

    if ip:
        place = ", ".join(p for p in (ip.city, ip.country) if p)
        score = f"{ip.abuse_confidence_score}/100" if ip.abuse_confidence_score is not None else None
        sections.append(_section("IP reputation", _kv([
            ("IP", ip.ip), ("Location", place), ("ISP", ip.isp),
            ("Abuse score", score), ("Reports", ip.total_reports),
        ]), ip.findings))

    if ssl:
        sections.append(_section("SSL / TLS certificate", _kv([
            ("Issuer", ssl["issuer"]), ("Expires", ssl["expiry_date"]),
            ("Days left", ssl["days_until_expiry"]),
        ]), ssl["findings"]))
    else:
        sections.append(_section("SSL / TLS certificate", _unavailable()))

    if headers:
        sections.append(_section(f"Security headers (score {headers['score']})", _kv([
            ("Present", ", ".join(headers["headers_present"].keys()) or "none"),
            ("Missing", ", ".join(headers["headers_missing"]) or "none"),
        ]), headers["findings"]))
    else:
        sections.append(_section("Security headers", _unavailable()))

    if email:
        sections.append(_section("Email authentication (SPF / DMARC)", _kv([
            ("SPF", email["spf_record"] or email["spf_status"]),
            ("DMARC", email["dmarc_record"] or email["dmarc_status"]),
            ("DMARC policy", email["dmarc_policy"]),
        ]), email["findings"]))
    else:
        sections.append(_section("Email authentication (SPF / DMARC)", _unavailable()))

    if url and url.get("status") == "analyzed":
        sections.append(_section("URL reputation (VirusTotal)", _kv([
            ("URL", url["url"]), ("Malicious", url.get("malicious_count")),
            ("Suspicious", url.get("suspicious_count")), ("Harmless", url.get("harmless_count")),
            ("Undetected", url.get("undetected_count")),
        ]), url["findings"]))
    elif url:
        sections.append(_section("URL reputation (VirusTotal)", "", url["findings"]))

    if mitre:
        items = "".join(
            f"<li><b>{escape(t['technique_id'])}</b> {escape(t['technique_name'])} "
            f"({escape(t['tactic'])}), triggered by: {escape(t['matched_finding'])}</li>"
            for t in mitre
        )
        sections.append(_section("MITRE ATT&CK mapping", f"<ul>{items}</ul>"))
    else:
        sections.append(_section("MITRE ATT&CK mapping", "<p>No techniques mapped from the findings.</p>"))

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html_content = (
        f"<html><head><style>{_CSS}</style></head><body>"
        f"<h1>CyberScope Security Report</h1>"
        f'<p class="meta">Domain: <b>{escape(domain)}</b> | Generated: {generated}</p>'
        + "".join(sections)
        + '<p class="meta" style="margin-top:30px;">Generated by CyberScope, an automated OSINT and security recon tool.</p>'
        "</body></html>"
    )

    output = BytesIO()
    result = pisa.CreatePDF(html_content, dest=output)
    if result.err:
        raise RuntimeError("PDF rendering failed")
    return output.getvalue()