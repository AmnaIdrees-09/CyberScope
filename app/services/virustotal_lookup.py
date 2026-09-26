import os
import base64
import requests
import logging
from app.models.dns_models import SecurityFinding

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _get_headers() -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    return {"x-apikey": api_key} if api_key else {}


def _url_to_id(url: str) -> str:
    """
    VirusTotal identifies URLs by a base64 encoding of the URL itself
    (URL-safe, with padding stripped) — this is their scheme, not ours,
    documented in the VirusTotal API v3 docs.
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_url_reputation(url: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {
            "url": url,
            "status": "error",
            "findings": [SecurityFinding(
                severity="info",
                message="VirusTotal API key not configured — reputation check skipped."
            )]
        }

    url_id = _url_to_id(url)
    headers = _get_headers()

    try:
        response = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers, timeout=15)
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal lookup failed for {url}: {e}")
        return {
            "url": url,
            "status": "error",
            "findings": [SecurityFinding(severity="info", message="Could not reach VirusTotal.")]
        }

    if response.status_code == 404:
        # VirusTotal hasn't seen this URL before — submit it for a first-time scan.
        return _submit_new_url(url, headers)

    if response.status_code != 200:
        logger.error(f"VirusTotal returned {response.status_code} for {url}")
        return {
            "url": url,
            "status": "error",
            "findings": [SecurityFinding(severity="info", message="VirusTotal lookup failed unexpectedly.")]
        }

    data = response.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return _build_result(url, stats)


def _submit_new_url(url: str, headers: dict) -> dict:
    try:
        response = requests.post(
            f"{VT_BASE_URL}/urls", headers=headers, data={"url": url}, timeout=15
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal submission failed for {url}: {e}")
        return {
            "url": url,
            "status": "error",
            "findings": [SecurityFinding(severity="info", message="Could not submit URL to VirusTotal.")]
        }

    return {
        "url": url,
        "status": "submitted",
        "findings": [SecurityFinding(
            severity="info",
            message="This URL hadn't been scanned before — it's been submitted to VirusTotal. Check again in a minute for results."
        )]
    }


def _build_result(url: str, stats: dict) -> dict:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total_scanned = malicious + suspicious + harmless + undetected
    malicious_ratio = malicious / total_scanned if total_scanned > 0 else 0

    findings = []

    # A couple of stray flags out of dozens of vendors is a common false
    # positive on VirusTotal, especially for huge, well-known sites.
    # We only treat it as a strong signal once enough vendors agree.
    if malicious >= 5 or malicious_ratio > 0.1:
        findings.append(SecurityFinding(
            severity="critical",
            message=f"{malicious} security vendor(s) flagged this URL as malicious — this is a strong signal."
        ))
    elif malicious > 0:
        findings.append(SecurityFinding(
            severity="info",
            message=f"{malicious} vendor(s) flagged this URL, but this is likely a false positive (out of {total_scanned} total scans)."
        ))
    elif suspicious > 0:
        findings.append(SecurityFinding(
            severity="warning",
            message=f"{suspicious} security vendor(s) flagged this URL as suspicious."
        ))
    else:
        findings.append(SecurityFinding(
            severity="info",
            message=f"No security vendors flagged this URL as malicious ({harmless} marked it clean)."
        ))

    return {
        "url": url,
        "status": "analyzed",
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "harmless_count": harmless,
        "undetected_count": undetected,
        "findings": findings
    }