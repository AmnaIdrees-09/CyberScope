import ssl
import socket
import logging
from datetime import datetime

from app.core.security import UnsafeHostError, resolve_public_ip
from app.models.dns_models import SecurityFinding

logger = logging.getLogger(__name__)

EXPIRY_WARNING_DAYS = 30


def get_ssl_certificate(domain: str, port: int = 443) -> dict:
    try:
        safe_ip = resolve_public_ip(domain)
    except UnsafeHostError as e:
        logger.warning(f"Blocked unsafe host for SSL check: {e}")
        return {}

    context = ssl.create_default_context()

    try:
        # Connect to the already-validated IP directly (not the hostname
        # again), so a DNS record that changes between the check above and
        # the connection below can't slip an unsafe address through.
        with socket.create_connection((safe_ip, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert()
    except socket.timeout:
        logger.warning(f"SSL connection to {domain} timed out")
        return {}
    except ssl.SSLCertVerificationError as e:
        logger.warning(f"SSL certificate verification failed for {domain}: {e}")
        return {"_verification_error": str(e)}
    except (socket.gaierror, ConnectionRefusedError, OSError) as e:
        logger.error(f"Could not connect to {domain} on port {port}: {e}")
        return {}


def analyze_ssl_certificate(domain: str) -> dict:
    cert = get_ssl_certificate(domain)
    findings = []

    if not cert:
        findings.append(SecurityFinding(
            severity="critical",
            message="Could not retrieve an SSL certificate: site may not support HTTPS, be unreachable, or the request was blocked for safety."
        ))
        return {"domain": domain, "issuer": None, "expiry_date": None, "days_until_expiry": None, "findings": findings}

    if "_verification_error" in cert:
        findings.append(SecurityFinding(
            severity="critical",
            message=f"SSL certificate failed verification: {cert['_verification_error']}"
        ))
        return {"domain": domain, "issuer": None, "expiry_date": None, "days_until_expiry": None, "findings": findings}

    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
    issuer_name = issuer_dict.get("organizationName", "Unknown")

    expiry_str = cert.get("notAfter")
    expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
    days_left = (expiry_date - datetime.utcnow()).days

    if days_left < 0:
        findings.append(SecurityFinding(severity="critical", message=f"SSL certificate expired {abs(days_left)} day(s) ago."))
    elif days_left <= EXPIRY_WARNING_DAYS:
        findings.append(SecurityFinding(severity="warning", message=f"SSL certificate expires in {days_left} day(s): renewal is due soon."))
    else:
        findings.append(SecurityFinding(severity="info", message=f"SSL certificate is valid for {days_left} more day(s)."))

    return {
        "domain": domain,
        "issuer": issuer_name,
        "expiry_date": expiry_date.strftime("%Y-%m-%d"),
        "days_until_expiry": days_left,
        "findings": findings,
    }