import logging

import requests

from app.core.security import UnsafeHostError, resolve_public_ip
from app.models.dns_models import SecurityFinding

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "Content-Security-Policy": "prevents cross-site scripting (XSS) and code injection attacks",
    "Strict-Transport-Security": "forces browsers to only use HTTPS, preventing downgrade attacks",
    "X-Frame-Options": "prevents clickjacking by controlling if the site can be embedded in a frame",
    "X-Content-Type-Options": "prevents browsers from MIME-sniffing a response away from its declared type",
    "Referrer-Policy": "controls how much referrer information is leaked to other sites",
    "Permissions-Policy": "restricts which browser features (camera, mic, geolocation) the site can use",
}

MAX_REDIRECTS = 3


def get_security_headers(domain: str) -> dict:
    """
    Fetches the live response headers, but never follows a redirect blindly.
    Each hop is re-resolved and re-validated as a public address before
    being followed, so a public domain can't redirect our server into a
    private network as a second step.
    """
    url = f"https://{domain}"

    try:
        resolve_public_ip(domain)
    except UnsafeHostError as e:
        logger.warning(f"Blocked unsafe host for headers check: {e}")
        return {}

    try:
        for _ in range(MAX_REDIRECTS + 1):
            response = requests.get(url, timeout=10, allow_redirects=False)
            if response.is_redirect or response.is_permanent_redirect:
                next_url = response.headers.get("Location")
                if not next_url:
                    break
                from urllib.parse import urlparse
                next_host = urlparse(next_url).hostname
                if not next_host:
                    break
                try:
                    resolve_public_ip(next_host)
                except UnsafeHostError as e:
                    logger.warning(f"Blocked redirect to unsafe host: {e}")
                    return {}
                url = next_url
                continue
            return dict(response.headers)
        return {}
    except requests.exceptions.RequestException as e:
        logger.error(f"Header fetch failed for {domain}: {e}")
        return {}


def analyze_security_headers(headers: dict) -> dict:
    findings = []
    present = {}
    missing = []

    for header_name, purpose in SECURITY_HEADERS.items():
        found_value = next((v for k, v in headers.items() if k.lower() == header_name.lower()), None)
        if found_value:
            present[header_name] = found_value
        else:
            missing.append(header_name)

    for header_name in missing:
        findings.append(SecurityFinding(
            severity="warning",
            message=f"Missing '{header_name}' header: {SECURITY_HEADERS[header_name]}."
        ))

    if not headers:
        findings.append(SecurityFinding(
            severity="critical",
            message="Could not retrieve headers: site may be unreachable, or the request was blocked for safety."
        ))
    elif not missing:
        findings.append(SecurityFinding(severity="info", message="All checked security headers are present."))

    score = len(present)
    total = len(SECURITY_HEADERS)

    return {
        "headers_present": present,
        "headers_missing": missing,
        "score": f"{score}/{total}",
        "findings": findings,
    }