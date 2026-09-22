import re
from fastapi import APIRouter, HTTPException
from app.services.dns_lookup import get_dns_records, analyze_dns_security
from app.services.whois_lookup import get_whois_info
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