import os
import requests
import logging
from app.models.dns_models import SecurityFinding
from app.models.ip_models import IPResult

logger = logging.getLogger(__name__)

# Abuse confidence scores from AbuseIPDB range 0-100. This threshold is a
# judgment call: below it, minor/old reports are common and not necessarily
# meaningful; above it, the IP has a real pattern of reported bad behavior.
ABUSE_SCORE_THRESHOLD = 50


def get_geolocation(ip: str) -> dict:
    """
    ipapi.co's free tier works without an API key for reasonable personal
    use, which is why this function needs no credentials.
    """
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"ipapi.co lookup failed for {ip}: {e}")
        return {}


def get_abuse_reputation(ip: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.warning("ABUSEIPDB_API_KEY not set — skipping reputation check.")
        return {}

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        response.raise_for_status()
        return response.json().get("data", {})
    except requests.exceptions.RequestException as e:
        logger.error(f"AbuseIPDB lookup failed for {ip}: {e}")
        return {}


def investigate_ip(ip: str) -> IPResult:
    geo = get_geolocation(ip)
    abuse = get_abuse_reputation(ip)

    result = IPResult(
        ip=ip,
        country=geo.get("country_name"),
        city=geo.get("city"),
        isp=geo.get("org"),
        abuse_confidence_score=abuse.get("abuseConfidenceScore"),
        total_reports=abuse.get("totalReports"),
    )

    result.findings = analyze_ip_security(result)
    return result


def analyze_ip_security(result: IPResult) -> list[SecurityFinding]:
    findings = []

    if result.abuse_confidence_score is None:
        findings.append(SecurityFinding(
            severity="info",
            message="Reputation data unavailable for this IP (missing API key or lookup failed)."
        ))
    elif result.abuse_confidence_score >= ABUSE_SCORE_THRESHOLD:
        findings.append(SecurityFinding(
            severity="critical",
            message=f"IP has a high abuse confidence score ({result.abuse_confidence_score}/100) "
                    f"with {result.total_reports} report(s) — this IP has a track record of malicious activity."
        ))
    elif result.abuse_confidence_score > 0:
        findings.append(SecurityFinding(
            severity="info",
            message=f"IP has a low abuse confidence score ({result.abuse_confidence_score}/100) — "
                    f"minor or old reports exist but no strong pattern of abuse."
        ))

    if not result.country:
        findings.append(SecurityFinding(
            severity="info",
            message="Geolocation data unavailable for this IP."
        ))

    if not findings:
        findings.append(SecurityFinding(severity="info", message="No reputation issues detected for this IP."))

    return findings