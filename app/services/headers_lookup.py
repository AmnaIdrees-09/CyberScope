import requests
import logging
from app.models.dns_models import SecurityFinding

logger = logging.getLogger(__name__)

# Each entry: header name -> what it's for, used to build a clear finding
# message. This list follows OWASP's Secure Headers Project baseline.
SECURITY_HEADERS = {
    "Content-Security-Policy": "prevents cross-site scripting (XSS) and code injection attacks",
    "Strict-Transport-Security": "forces browsers to only use HTTPS, preventing downgrade attacks",
    "X-Frame-Options": "prevents clickjacking by controlling if the site can be embedded in a frame",
    "X-Content-Type-Options": "prevents browsers from MIME-sniffing a response away from its declared type",
    "Referrer-Policy": "controls how much referrer information is leaked to other sites",
    "Permissions-Policy": "restricts which browser features (camera, mic, geolocation) the site can use",
}


def get_security_headers(domain: str) -> dict:
    url = f"https://{domain}"
    try:
        # allow_redirects=True because many sites redirect to www or add
        # a trailing slash — we want the headers of the final real page.
        response = requests.get(url, timeout=10, allow_redirects=True)
        return dict(response.headers)
    except requests.exceptions.RequestException as e:
        logger.error(f"Header fetch failed for {domain}: {e}")
        return {}


def analyze_security_headers(headers: dict) -> dict:
    findings = []
    present = {}
    missing = []

    for header_name, purpose in SECURITY_HEADERS.items():
        # Header names are case-insensitive per HTTP spec, but Python dicts
        # are case-sensitive — so we search case-insensitively here rather
        # than assuming the server sent the exact casing we expect.
        found_value = next((v for k, v in headers.items() if k.lower() == header_name.lower()), None)
        if found_value:
            present[header_name] = found_value
        else:
            missing.append(header_name)

    for header_name in missing:
        findings.append(SecurityFinding(
            severity="warning",
            message=f"Missing '{header_name}' header — {SECURITY_HEADERS[header_name]}."
        ))

    if not headers:
        findings.append(SecurityFinding(
            severity="critical",
            message="Could not retrieve headers — site may be unreachable."
        ))
    elif not missing:
        findings.append(SecurityFinding(
            severity="info",
            message="All checked security headers are present."
        ))

    score = len(present)
    total = len(SECURITY_HEADERS)

    return {
        "headers_present": present,
        "headers_missing": missing,
        "score": f"{score}/{total}",
        "findings": findings
    }