import logging
import re
import time

import requests

from app.models.dns_models import SecurityFinding

logger = logging.getLogger(__name__)

# Whole-word tokens that suggest a less-maintained or non-production host.
# Matching whole tokens (not substrings) avoids flagging "developers" or "gold".
RISKY_KEYWORDS = {"dev", "staging", "test", "admin", "old", "backup", "internal"}

CRT_URL = "https://crt.sh/"
HOSTNAME_CHARS = re.compile(r"^[a-z0-9_.-]+$")
MAX_ATTEMPTS = 2
REQUEST_TIMEOUT = 15


def _extract_names(data: object, domain: str) -> list[str]:
    """
    crt.sh returns every name on each matching certificate, including names
    that belong to other domains. Keep only real subdomains of this domain,
    and drop wildcards and anything that isn't a plain hostname.
    """
    if not isinstance(data, list):
        return []

    suffix = f".{domain}"
    names: set[str] = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for raw in str(entry.get("name_value", "")).split("\n"):
            name = raw.strip().lower()
            if name.endswith(suffix) and HOSTNAME_CHARS.match(name):
                names.add(name)
    return sorted(names)


def fetch_subdomains(domain: str) -> tuple[list[str], bool]:
    """
    Returns (subdomains, lookup_ok). lookup_ok is False when crt.sh could not
    be reached or answered badly, which is different from "no subdomains exist".
    """
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = requests.get(
                CRT_URL,
                params={"q": f"%.{domain}", "output": "json"},
                headers={"User-Agent": "CyberScope/0.1"},
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return _extract_names(response.json(), domain), True
            logger.warning("crt.sh returned HTTP %s for %s (attempt %s)", response.status_code, domain, attempt)
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.warning("crt.sh lookup failed for %s (attempt %s): %s", domain, attempt, e)

        if attempt < MAX_ATTEMPTS:
            time.sleep(1.5)

    return [], False


def _is_risky(hostname: str) -> bool:
    # "dev-api.corp.example.com" -> ["dev", "api", "corp", ...]. Trailing digits
    # are ignored so "test1" and "dev02" still count.
    tokens = re.split(r"[^a-z0-9]+", hostname.lower())
    return any(t.rstrip("0123456789") in RISKY_KEYWORDS for t in tokens if t)


def analyze_subdomain_security(subdomains: list[str], lookup_ok: bool = True) -> list[SecurityFinding]:
    if not lookup_ok:
        return [SecurityFinding(
            severity="info",
            message="Subdomain lookup unavailable: crt.sh did not respond. This does not mean there are none."
        )]

    findings: list[SecurityFinding] = []

    risky_found = [s for s in subdomains if _is_risky(s)]
    if risky_found:
        examples = ", ".join(risky_found[:3])
        findings.append(SecurityFinding(
            severity="warning",
            message=f"Found {len(risky_found)} subdomain(s) with names suggesting dev, staging, or admin use "
                    f"(e.g. {examples}). These are often less monitored than production."
        ))

    if len(subdomains) > 50:
        findings.append(SecurityFinding(
            severity="info",
            message=f"Large attack surface: {len(subdomains)} subdomains discovered."
        ))

    if not subdomains:
        findings.append(SecurityFinding(
            severity="info",
            message="No subdomains found in certificate transparency logs."
        ))

    if not findings:
        findings.append(SecurityFinding(severity="info", message="No subdomain-related issues detected."))

    return findings


def investigate_subdomains(domain: str) -> dict:
    subdomains, lookup_ok = fetch_subdomains(domain)
    return {
        "domain": domain,
        "subdomains": subdomains,
        "lookup_ok": lookup_ok,
        "findings": analyze_subdomain_security(subdomains, lookup_ok),
    }