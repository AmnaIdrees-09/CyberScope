import ipaddress
import logging
import os

import requests

from app.models.dns_models import SecurityFinding
from app.models.ip_models import IPResult

logger = logging.getLogger(__name__)

# AbuseIPDB scores run 0-100. Below the threshold, old or minor reports are
# common and not meaningful; above it there is a real pattern of abuse.
ABUSE_SCORE_THRESHOLD = 50
TIMEOUT = 8


def _from_ipwho(ip: str) -> dict:
    response = requests.get(f"https://ipwho.is/{ip}", timeout=TIMEOUT)
    response.raise_for_status()
    data = response.json()
    if data.get("success") is False:
        raise ValueError(data.get("message", "lookup failed"))
    connection = data.get("connection") or {}
    return {
        "country": data.get("country"),
        "city": data.get("city"),
        "isp": connection.get("isp") or connection.get("org") or data.get("isp") or data.get("org"),
    }


def _from_ip_api(ip: str) -> dict:
    # The free tier of ip-api.com is HTTP only, which is fine server-to-server.
    response = requests.get(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,message,country,city,isp,org"},
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    data = response.json()
    if data.get("status") != "success":
        raise ValueError(data.get("message", "lookup failed"))
    return {"country": data.get("country"), "city": data.get("city"), "isp": data.get("isp") or data.get("org")}


def _from_ipapi_co(ip: str) -> dict:
    response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=TIMEOUT)
    response.raise_for_status()
    data = response.json()
    if data.get("error"):
        raise ValueError(data.get("reason", "lookup failed"))
    return {"country": data.get("country_name"), "city": data.get("city"), "isp": data.get("org")}


# Tried in order. If one is rate-limited or down, the next one answers.
PROVIDERS = [("ipwho.is", _from_ipwho), ("ip-api.com", _from_ip_api), ("ipapi.co", _from_ipapi_co)]


def get_geolocation(ip: str) -> dict:
    for name, lookup in PROVIDERS:
        try:
            info = lookup(ip)
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.warning("%s geolocation failed for %s: %s", name, ip, e)
            continue
        if info.get("country"):
            return info
    return {}


def get_abuse_reputation(ip: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.warning("ABUSEIPDB_API_KEY not set, skipping reputation check.")
        return {}

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        return response.json().get("data", {})
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.error("AbuseIPDB lookup failed for %s: %s", ip, e)
        return {}


def investigate_ip(ip: str) -> IPResult:
    # Private, loopback and reserved addresses have no public data to look up.
    if not ipaddress.ip_address(ip).is_global:
        return IPResult(ip=ip, findings=[SecurityFinding(
            severity="info",
            message="This is a private or reserved address, so no public geolocation or reputation data exists."
        )])

    geo = get_geolocation(ip)
    abuse = get_abuse_reputation(ip)

    result = IPResult(
        ip=ip,
        country=geo.get("country"),
        city=geo.get("city"),
        isp=geo.get("isp"),
        abuse_confidence_score=abuse.get("abuseConfidenceScore"),
        total_reports=abuse.get("totalReports"),
    )
    result.findings = analyze_ip_security(result)
    return result


def analyze_ip_security(result: IPResult) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []

    if result.abuse_confidence_score is None:
        findings.append(SecurityFinding(
            severity="info",
            message="Reputation data unavailable for this IP (missing API key or lookup failed)."
        ))
    elif result.abuse_confidence_score >= ABUSE_SCORE_THRESHOLD:
        findings.append(SecurityFinding(
            severity="critical",
            message=f"IP has a high abuse confidence score ({result.abuse_confidence_score}/100) "
                    f"with {result.total_reports} report(s): a track record of malicious activity."
        ))
    elif result.abuse_confidence_score > 0:
        findings.append(SecurityFinding(
            severity="info",
            message=f"IP has a low abuse confidence score ({result.abuse_confidence_score}/100): "
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