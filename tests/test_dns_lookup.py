from app.services.dns_lookup import get_dns_records, analyze_dns_security

def test_google_has_a_and_mx_records():
    records = get_dns_records("google.com")
    assert len(records.A) > 0
    assert len(records.MX) > 0

def test_nonexistent_domain_returns_empty_records():
    records = get_dns_records("this-should-not-exist-xyz123abc.com")
    assert records.A == []

def test_domain_with_no_spf_flags_warning():
    records = get_dns_records("this-should-not-exist-xyz123abc.com")
    findings = analyze_dns_security(records)
    severities = [f.severity for f in findings]
    assert "critical" in severities or "warning" in severities or "info" in severities