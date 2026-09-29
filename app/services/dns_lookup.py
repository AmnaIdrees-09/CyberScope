from concurrent.futures import ThreadPoolExecutor

from app.models.dns_models import DNSRecordSet, SecurityFinding
from app.services.dns_client import query

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


def get_dns_records(domain: str) -> DNSRecordSet:
    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(lambda t: query(domain, t), RECORD_TYPES))

    results: dict[str, list[str]] = {}
    failed: list[str] = []
    for record_type, (values, status) in zip(RECORD_TYPES, outcomes):
        results[record_type] = values
        if status == "failed":
            failed.append(record_type)

    return DNSRecordSet(**results, failed=failed)


def analyze_dns_security(records: DNSRecordSet) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    failed = set(records.failed)

    if failed:
        findings.append(SecurityFinding(
            severity="info",
            message="Some DNS lookups did not complete (" + ", ".join(records.failed) +
                    "), so these results may be incomplete. Try again in a moment."
        ))

    # Only judge SPF when the TXT lookup actually worked.
    has_spf = any("v=spf1" in txt.lower() for txt in records.TXT)
    if "TXT" not in failed and not has_spf:
        if records.MX and "MX" not in failed:
            findings.append(SecurityFinding(
                severity="critical",
                message="Domain receives mail (MX present) but has no SPF protection."
            ))
        else:
            findings.append(SecurityFinding(
                severity="warning",
                message="No SPF record found: this domain's email can more easily be spoofed."
            ))

    addresses_checked = "A" not in failed and "AAAA" not in failed

    if records.CNAME and not records.A and "A" not in failed:
        findings.append(SecurityFinding(
            severity="info",
            message="Domain relies on a CNAME with no direct A record. Verify the CNAME target is still "
                    "valid to rule out subdomain takeover."
        ))

    if addresses_checked and not records.A and not records.AAAA:
        findings.append(SecurityFinding(
            severity="critical",
            message="No A or AAAA records found: the domain may not resolve to any live host."
        ))

    if not findings:
        findings.append(SecurityFinding(severity="info", message="No immediate DNS-based issues detected."))

    return findings