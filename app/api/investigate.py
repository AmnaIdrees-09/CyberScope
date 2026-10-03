import ipaddress
import logging
import re
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response

from app.core.limiter import limiter
from app.models.analysis_models import AnalysisRequest
from app.models.dns_models import DNSInvestigationResult, SecurityFinding
from app.services import checks
from app.services.ai_summary import generate_plain_english_summary
from app.services.mitre_mapping import map_findings_to_mitre
from app.services.report_generator import generate_full_report

logger = logging.getLogger(__name__)

router = APIRouter()

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _require_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if not DOMAIN_PATTERN.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    return domain


@router.get("/investigate/{domain}", response_model=DNSInvestigationResult)
@limiter.limit("20/minute")
def investigate_domain(request: Request, domain: str):
    return checks.dns_check(_require_domain(domain))


@router.get("/whois/{domain}")
@limiter.limit("20/minute")
def investigate_whois(request: Request, domain: str):
    return checks.whois_check(_require_domain(domain))


@router.get("/subdomains/{domain}")
@limiter.limit("10/minute")
def investigate_subdomains(request: Request, domain: str):
    return checks.subdomain_check(_require_domain(domain))


@router.get("/ip/{ip}")
@limiter.limit("20/minute")
def investigate_ip_route(request: Request, ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")
    return checks.ip_check(ip)


@router.get("/ssl/{domain}")
@limiter.limit("20/minute")
def investigate_ssl(request: Request, domain: str):
    return checks.ssl_check(_require_domain(domain))


@router.get("/headers/{domain}")
@limiter.limit("20/minute")
def investigate_headers(request: Request, domain: str):
    return checks.headers_check(_require_domain(domain))


@router.get("/email-auth/{domain}")
@limiter.limit("20/minute")
def investigate_email_auth(request: Request, domain: str):
    return checks.email_check(_require_domain(domain))


@router.get("/url-reputation")
@limiter.limit("10/minute")
def investigate_url_reputation(request: Request, url: str = Query(..., description="Full URL to check, e.g. https://example.com")):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or len(url) > 2048:
        raise HTTPException(status_code=400, detail="Enter a full http:// or https:// URL")
    return checks.url_check(url)


@router.post("/summary")
@limiter.limit("10/minute")
def investigate_summary(request: Request, payload: AnalysisRequest):
    domain = _require_domain(payload.domain)
    findings = [SecurityFinding(severity=f.severity, message=f.message) for f in payload.findings]
    return {
        "domain": domain,
        "summary": generate_plain_english_summary(domain, findings),
        "findings_analyzed": len(findings),
    }


@router.post("/mitre")
@limiter.limit("20/minute")
def investigate_mitre(request: Request, payload: AnalysisRequest):
    domain = _require_domain(payload.domain)
    findings = [SecurityFinding(severity=f.severity, message=f.message) for f in payload.findings]
    return {"domain": domain, "mapped_techniques": map_findings_to_mitre(findings)}


@router.get("/report/{domain}")
@limiter.limit("5/minute")
def generate_report(request: Request, domain: str):
    domain = _require_domain(domain)
    try:
        pdf_bytes = generate_full_report(domain)
    except Exception:
        logger.exception("Report generation failed for %s", domain)
        raise HTTPException(status_code=500, detail="Report generation failed. Check the server logs.")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={domain}_report.pdf"},
    )