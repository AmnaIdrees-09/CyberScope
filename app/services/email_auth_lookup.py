import dns.resolver
import logging
from app.models.dns_models import SecurityFinding

logger = logging.getLogger(__name__)


def _get_txt_records(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT")
        return [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except Exception as e:
        logger.error(f"TXT lookup failed for {name}: {e}")
        return []


def check_email_authentication(domain: str) -> dict:
    findings = []

    # --- SPF: lives directly on the domain's own TXT records ---
    domain_txt = _get_txt_records(domain)
    spf_record = next((r for r in domain_txt if "v=spf1" in r), None)

    if spf_record:
        findings.append(SecurityFinding(
            severity="info",
            message="SPF record found — this domain declares which mail servers are authorized to send on its behalf."
        ))
    else:
        findings.append(SecurityFinding(
            severity="critical",
            message="No SPF record found — anyone can send email pretending to be from this domain."
        ))

    # --- DMARC: lives on a special subdomain, _dmarc.<domain> ---
    dmarc_txt = _get_txt_records(f"_dmarc.{domain}")
    dmarc_record = next((r for r in dmarc_txt if "v=DMARC1" in r), None)

    dmarc_policy = None
    if dmarc_record:
        # The policy tag looks like p=none, p=quarantine, or p=reject
        # somewhere inside the record string — extract it directly.
        if "p=reject" in dmarc_record:
            dmarc_policy = "reject"
        elif "p=quarantine" in dmarc_record:
            dmarc_policy = "quarantine"
        elif "p=none" in dmarc_record:
            dmarc_policy = "none"

        if dmarc_policy == "reject":
            findings.append(SecurityFinding(
                severity="info",
                message="DMARC record found with policy 'reject' — spoofed emails are actively blocked."
            ))
        elif dmarc_policy == "quarantine":
            findings.append(SecurityFinding(
                severity="info",
                message="DMARC record found with policy 'quarantine' — spoofed emails are sent to spam."
            ))
        elif dmarc_policy == "none":
            findings.append(SecurityFinding(
                severity="warning",
                message="DMARC record exists but policy is 'none' — spoofed emails are only monitored, not blocked."
            ))
    else:
        findings.append(SecurityFinding(
            severity="critical",
            message="No DMARC record found — no instructions exist for handling spoofed email from this domain."
        ))

    return {
        "domain": domain,
        "spf_record": spf_record,
        "dmarc_record": dmarc_record,
        "dmarc_policy": dmarc_policy,
        "findings": findings
    }