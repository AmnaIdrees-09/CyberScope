import ssl
import socket
import logging
from datetime import datetime
from app.models.dns_models import SecurityFinding

logger = logging.getLogger(__name__)

EXPIRY_WARNING_DAYS = 30


def get_ssl_certificate(domain: str, port: int = 443) -> dict:
    """
    Opens a real TLS connection to the domain and pulls the certificate
    it presents. This is the same handshake your browser does when you
    visit an HTTPS site — we're just reading the certificate instead of
    rendering a page.
    """
    context = ssl.create_default_context()

    try:
        # A 10-second timeout prevents this from hanging forever on a
        # domain with no HTTPS or a firewall silently dropping the connection.
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except socket.timeout:
        logger.warning(f"SSL connection to {domain} timed out")
        return {}
    except ssl.SSLCertVerificationError as e:
        # This means the cert exists but is invalid/expired/wrong-domain —
        # itself an important security finding, not just a failure to ignore.
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
            message="Could not retrieve an SSL certificate — site may not support HTTPS, or is unreachable."
        ))
        return {
            "domain": domain,
            "issuer": None,
            "expiry_date": None,
            "days_until_expiry": None,
            "findings": findings
        }

    if "_verification_error" in cert:
        findings.append(SecurityFinding(
            severity="critical",
            message=f"SSL certificate failed verification: {cert['_verification_error']}"
        ))
        return {
            "domain": domain,
            "issuer": None,
            "expiry_date": None,
            "days_until_expiry": None,
            "findings": findings
        }

    # The certificate's issuer is a tuple of tuples — extract the
    # organizationName field, which is what a human would recognize
    # (e.g. "Let's Encrypt", "DigiCert Inc").
    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
    issuer_name = issuer_dict.get("organizationName", "Unknown")

    # Certificate dates come in a specific string format like:
    # 'Jan 1 00:00:00 2030 GMT' — this parses that exact format.
    expiry_str = cert.get("notAfter")
    expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
    days_left = (expiry_date - datetime.utcnow()).days

    if days_left < 0:
        findings.append(SecurityFinding(
            severity="critical",
            message=f"SSL certificate expired {abs(days_left)} day(s) ago."
        ))
    elif days_left <= EXPIRY_WARNING_DAYS:
        findings.append(SecurityFinding(
            severity="warning",
            message=f"SSL certificate expires in {days_left} day(s) — renewal is due soon."
        ))
    else:
        findings.append(SecurityFinding(
            severity="info",
            message=f"SSL certificate is valid for {days_left} more day(s)."
        ))

    return {
        "domain": domain,
        "issuer": issuer_name,
        "expiry_date": expiry_date.strftime("%Y-%m-%d"),
        "days_until_expiry": days_left,
        "findings": findings
    }