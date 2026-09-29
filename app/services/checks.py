from app.core.cache import get_or_compute
from app.models.dns_models import DNSInvestigationResult
from app.models.ip_models import IPResult
from app.models.whois_models import WhoisResult
from app.services.dns_lookup import analyze_dns_security, get_dns_records
from app.services.email_auth_lookup import check_email_authentication
from app.services.headers_lookup import analyze_security_headers, get_security_headers
from app.services.ip_lookup import investigate_ip
from app.services.ssl_lookup import analyze_ssl_certificate
from app.services.subdomain_lookup import investigate_subdomains
from app.services.virustotal_lookup import check_url_reputation
from app.services.whois_lookup import get_whois_info

# Results are reused for 10 minutes so a re-scan (or the PDF report) does not
# hit the outside services again. Failed lookups are never cached.
TTL = 600


def dns_check(domain: str) -> DNSInvestigationResult:
    def compute() -> DNSInvestigationResult:
        records = get_dns_records(domain)
        return DNSInvestigationResult(
            domain=domain, records=records, findings=analyze_dns_security(records)
        )
    return get_or_compute(f"dns:{domain}", TTL, compute, lambda r: not r.records.failed)


def whois_check(domain: str) -> WhoisResult:
    return get_or_compute(
        f"whois:{domain}", TTL, lambda: get_whois_info(domain),
        lambda r: r.creation_date is not None,
    )


def subdomain_check(domain: str) -> dict:
    return get_or_compute(
        f"subdomains:{domain}", TTL, lambda: investigate_subdomains(domain),
        lambda r: r["lookup_ok"],
    )


def ssl_check(domain: str) -> dict:
    return get_or_compute(
        f"ssl:{domain}", TTL, lambda: analyze_ssl_certificate(domain),
        lambda r: r["days_until_expiry"] is not None,
    )


def headers_check(domain: str) -> dict:
    def compute() -> dict:
        raw = get_security_headers(domain)
        result = analyze_security_headers(raw)
        result["reachable"] = bool(raw)
        return result
    return get_or_compute(f"headers:{domain}", TTL, compute, lambda r: r["reachable"])


def email_check(domain: str) -> dict:
    return get_or_compute(
        f"email:{domain}", TTL, lambda: check_email_authentication(domain),
        lambda r: r["spf_status"] != "unknown" and r["dmarc_status"] != "unknown",
    )


def ip_check(ip: str) -> IPResult:
    return get_or_compute(
        f"ip:{ip}", TTL, lambda: investigate_ip(ip),
        lambda r: r.country is not None and r.abuse_confidence_score is not None,
    )


def url_check(url: str) -> dict:
    return get_or_compute(
        f"url:{url}", TTL, lambda: check_url_reputation(url),
        lambda r: r.get("status") == "analyzed",
    )