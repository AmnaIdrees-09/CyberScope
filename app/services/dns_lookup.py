import dns.resolver
import logging
from app.models.dns_models import DNSRecordSet, SecurityFinding

logger = logging.getLogger(__name__)

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


def get_dns_records(domain: str) -> DNSRecordSet:
    results = {}
    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(r) for r in answers]
        except dns.resolver.NXDOMAIN:
            logger.warning(f"{domain} does not exist (NXDOMAIN)")
            results[record_type] = []
        except dns.resolver.NoAnswer:
            results[record_type] = []
        except dns.resolver.NoNameservers:
            logger.warning(f"No reachable nameservers for {domain}")
            results[record_type] = []
        except Exception as e:
            logger.error(f"Unexpected error resolving {record_type} for {domain}: {e}")
            results[record_type] = []

    return DNSRecordSet(**results)


def analyze_dns_security(records: DNSRecordSet) -> list[SecurityFinding]:
    findings = []

    has_spf = any(txt.startswith('"v=spf1') or txt.startswith('v=spf1') for txt in records.TXT)
    if not has_spf:
        findings.append(SecurityFinding(
            severity="warning",
            message="No SPF record found — this domain's email can more easily be spoofed."
        ))

    has_mx_no_spf = records.MX and not has_spf
    if has_mx_no_spf:
        findings.append(SecurityFinding(
            severity="critical",
            message="Domain actively receives mail (MX present) but has no SPF protection."
        ))

    if records.CNAME and not records.A:
        findings.append(SecurityFinding(
            severity="info",
            message="Domain relies on a CNAME with no direct A record — verify the CNAME target is still valid to rule out subdomain takeover."
        ))

    if not records.A and not records.AAAA:
        findings.append(SecurityFinding(
            severity="critical",
            message="No A or AAAA records found — domain may not resolve to any live host."
        ))

    if not findings:
        findings.append(SecurityFinding(severity="info", message="No immediate DNS-based issues detected."))

    return findings