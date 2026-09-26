import re
from fastapi import APIRouter, HTTPException, Query
from app.services.dns_lookup import get_dns_records, analyze_dns_security
from app.services.whois_lookup import get_whois_info
from app.services.subdomain_lookup import get_subdomains, analyze_subdomain_security
from app.services.ip_lookup import investigate_ip
from app.services.ssl_lookup import analyze_ssl_certificate
from app.services.headers_lookup import get_security_headers, analyze_security_headers
from app.services.email_auth_lookup import check_email_authentication
from app.services.virustotal_lookup import check_url_reputation
from app.services.mitre_mapping import map_findings_to_mitre
from app.models.dns_models import DNSInvestigationResult

router = APIRouter()

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


@router.get("/investigate/{domain}", response_model=DNSInvestigationResult)
def investigate_domain(domain: str):
    if not DOMAIN_PATTERN.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    records = get_dns_records(domain)
    findings = analyze_dns_security(records)

    return DNSInvestigationResult(domain=domain, records=records, findings=findings)


@router.get("/whois/{domain}")
def investigate_whois(domain: str):
    if not DOMAIN_PATTERN.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    return get_whois_info(domain)


@router.get("/subdomains/{domain}")
def investigate_subdomains(domain: str):
    if not DOMAIN_PATTERN.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    subdomains = get_subdomains(domain)
    findings = analyze_subdomain_security(subdomains)

    return {
        "domain": domain,
        "subdomains": subdomains,
        "findings": findings
    }


@router.get("/ip/{ip}")
def investigate_ip_route(ip: str):
    return investigate_ip(ip)


@router.get("/ssl/{domain}")
def investigate_ssl(domain: str):
    if not DOMAIN_PATTERN.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    return analyze_ssl_certificate(domain)


@router.get("/headers/{domain}")
def investigate_headers(domain: str):
    if not DOMAIN_PATTERN.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    headers = get_security_headers(domain)
    return analyze_security_headers(headers)


@router.get("/email-auth/{domain}")
def investigate_email_auth(domain: str):
    if not DOMAIN_PATTERN.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    return check_email_authentication(domain)


@router.get("/url-reputation")
def investigate_url_reputation(url: str = Query(..., description="Full URL to check, e.g. https://example.com")):
    return check_url_reputation(url)


@router.get("/mitre/{domain}")
def investigate_mitre(domain: str):
    if not DOMAIN_PATTERN.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    dns_records = get_dns_records(domain)
    dns_findings = analyze_dns_security(dns_records)

    email_result = check_email_authentication(domain)
    email_findings = email_result["findings"]

    all_findings = dns_findings + email_findings
    mapped = map_findings_to_mitre(all_findings)

    return {
        "domain": domain,
        "mapped_techniques": mapped
    }