import whois
import logging
from datetime import datetime
from app.models.dns_models import SecurityFinding
from app.models.whois_models import WhoisResult

logger = logging.getLogger(__name__)

# Domains registered under this many days ago are treated as suspicious.
# This threshold is a judgment call, not a hard security standard — most
# legitimate domains are older, but new businesses do exist. We flag,
# not block.
NEW_DOMAIN_THRESHOLD_DAYS = 30


def _first_date(value):
    """
    python-whois sometimes returns a single datetime, sometimes a list of
    them (some registries return multiple historical dates). We always
    want the earliest one for age calculation, so this normalizes both
    shapes into one datetime or None.
    """
    if value is None:
        return None
    if isinstance(value, list):
        dates = [v for v in value if isinstance(v, datetime)]
        return min(dates) if dates else None
    if isinstance(value, datetime):
        return value
    return None


def get_whois_info(domain: str) -> WhoisResult:
    try:
        w = whois.whois(domain)
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {e}")
        return WhoisResult(
            domain=domain,
            findings=[SecurityFinding(
                severity="warning",
                message="WHOIS data could not be retrieved for this domain."
            )]
        )

    creation = _first_date(w.creation_date)
    expiration = _first_date(w.expiration_date)

    age_days = None
    if creation:
        # Use timezone-naive comparison since registries are inconsistent
        # about including timezone info in these dates.
        age_days = (datetime.now() - creation.replace(tzinfo=None)).days

    result = WhoisResult(
        domain=domain,
        registrar=w.registrar,
        creation_date=str(creation) if creation else None,
        expiration_date=str(expiration) if expiration else None,
        domain_age_days=age_days,
    )

    result.findings = analyze_whois_security(result)
    return result


def analyze_whois_security(result: WhoisResult) -> list[SecurityFinding]:
    findings = []

    if result.domain_age_days is None:
        findings.append(SecurityFinding(
            severity="info",
            message="Domain registration date unavailable — could not assess domain age."
        ))
    elif result.domain_age_days < NEW_DOMAIN_THRESHOLD_DAYS:
        findings.append(SecurityFinding(
            severity="critical",
            message=f"Domain was registered only {result.domain_age_days} days ago — very recently "
                    f"registered domains are commonly used in phishing campaigns."
        ))
    elif result.domain_age_days < 365:
        findings.append(SecurityFinding(
            severity="info",
            message=f"Domain is under a year old ({result.domain_age_days} days) — not necessarily "
                    f"malicious, but worth noting for newer or less-established sites."
        ))

    if not result.registrar:
        findings.append(SecurityFinding(
            severity="info",
            message="Registrar information is hidden or unavailable (may indicate privacy protection)."
        ))

    if not findings:
        findings.append(SecurityFinding(severity="info", message="No domain-age-related issues detected."))

    return findings