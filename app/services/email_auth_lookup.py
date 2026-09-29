import re

from app.models.dns_models import SecurityFinding
from app.services.dns_client import query


def _clean_txt(value: str) -> str:
    # TXT values arrive as '"chunk1" "chunk2"'. Join the chunks, drop the quotes.
    return re.sub(r'"\s+"', "", value).strip().strip('"')


def _dmarc_policy(record: str) -> str | None:
    # Read the tags properly. A substring test would mistake "sp=reject"
    # (the subdomain policy) for "p=reject".
    for part in record.split(";"):
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "p":
            value = value.strip().lower()
            if value in ("none", "quarantine", "reject"):
                return value
    return None


def check_email_authentication(domain: str) -> dict:
    findings: list[SecurityFinding] = []

    # ---------- SPF: a TXT record on the domain itself ----------
    txt_values, txt_status = query(domain, "TXT")
    spf_records = [_clean_txt(v) for v in txt_values if "v=spf1" in v.lower()]

    if txt_status == "failed":
        spf_status = "unknown"
        findings.append(SecurityFinding(
            severity="info",
            message="The SPF check could not complete (DNS lookup failed). Try again in a moment."
        ))
    elif spf_records:
        spf_status = "found"
        findings.append(SecurityFinding(
            severity="info",
            message="SPF record found: this domain declares which mail servers are authorized to send on its behalf."
        ))
        if len(spf_records) > 1:
            findings.append(SecurityFinding(
                severity="warning",
                message="Multiple SPF records found. Receivers may treat this as an error; a domain should publish exactly one."
            ))
    else:
        spf_status = "missing"
        findings.append(SecurityFinding(
            severity="critical",
            message="No SPF record found: anyone can send email pretending to be from this domain."
        ))

    # ---------- DMARC: a TXT record on _dmarc.<domain> ----------
    dmarc_values, dmarc_lookup = query(f"_dmarc.{domain}", "TXT")
    dmarc_records = [_clean_txt(v) for v in dmarc_values if "v=dmarc1" in v.lower()]
    dmarc_record = dmarc_records[0] if dmarc_records else None
    dmarc_policy = _dmarc_policy(dmarc_record) if dmarc_record else None

    if dmarc_lookup == "failed":
        dmarc_status = "unknown"
        findings.append(SecurityFinding(
            severity="info",
            message="The DMARC check could not complete (DNS lookup failed). Try again in a moment."
        ))
    elif dmarc_record is None:
        dmarc_status = "missing"
        findings.append(SecurityFinding(
            severity="critical",
            message="No DMARC record found: no instructions exist for handling spoofed email from this domain."
        ))
    else:
        dmarc_status = "found"
        if dmarc_policy == "reject":
            findings.append(SecurityFinding(
                severity="info",
                message="DMARC record found with policy 'reject': spoofed emails are actively blocked."
            ))
        elif dmarc_policy == "quarantine":
            findings.append(SecurityFinding(
                severity="info",
                message="DMARC record found with policy 'quarantine': spoofed emails are sent to spam."
            ))
        elif dmarc_policy == "none":
            findings.append(SecurityFinding(
                severity="warning",
                message="DMARC record exists but policy is 'none': spoofed emails are only monitored, not blocked."
            ))
        else:
            findings.append(SecurityFinding(
                severity="warning",
                message="A DMARC record exists but has no valid policy (p=) tag, so it is not enforcing anything."
            ))

    return {
        "domain": domain,
        "spf_record": spf_records[0] if spf_records else None,
        "spf_status": spf_status,
        "dmarc_record": dmarc_record,
        "dmarc_status": dmarc_status,
        "dmarc_policy": dmarc_policy,
        "findings": findings,
    }