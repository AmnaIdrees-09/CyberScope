import requests
import logging
from app.models.dns_models import SecurityFinding

logger = logging.getLogger(__name__)

# Keywords that suggest a subdomain might be less-maintained or higher-risk
# than production infrastructure. This list is a heuristic, not a guarantee —
# a "dev" subdomain isn't automatically insecure, but it's worth flagging.
RISKY_KEYWORDS = ["dev", "staging", "test", "admin", "old", "backup", "internal"]


def get_subdomains(domain: str) -> list[str]:
    """
    Query crt.sh's JSON endpoint for certificate transparency logs.
    Every subdomain that ever had an SSL certificate issued shows up here,
    including ones the owner might have forgotten about.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.Timeout:
        logger.warning(f"crt.sh timed out for {domain}")
        return []
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.error(f"crt.sh lookup failed for {domain}: {e}")
        return []

    # crt.sh returns duplicate entries and sometimes multiple names per
    # entry separated by newlines — dedupe and flatten into a clean set.
    # We also filter out email addresses, which occasionally show up
    # embedded in certificate fields and aren't actually subdomains.
    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*.") and "@" not in name:
                subdomains.add(name)

    return sorted(subdomains)


def analyze_subdomain_security(subdomains: list[str]) -> list[SecurityFinding]:
    findings = []

    risky_found = [s for s in subdomains if any(kw in s for kw in RISKY_KEYWORDS)]
    if risky_found:
        findings.append(SecurityFinding(
            severity="warning",
            message=f"Found {len(risky_found)} subdomain(s) with risky-sounding names "
                    f"(e.g. dev/staging/admin) — these are often less monitored than production."
        ))

    if len(subdomains) > 50:
        findings.append(SecurityFinding(
            severity="info",
            message=f"Large attack surface: {len(subdomains)} subdomains discovered."
        ))

    if not subdomains:
        findings.append(SecurityFinding(
            severity="info",
            message="No subdomains found via certificate transparency logs."
        ))

    if not findings:
        findings.append(SecurityFinding(severity="info", message="No subdomain-related issues detected."))

    return findings