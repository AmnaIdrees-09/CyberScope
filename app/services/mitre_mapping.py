from app.models.dns_models import SecurityFinding

# A small, curated set of real MITRE ATT&CK technique IDs, mapped to the
# keywords in our own findings that indicate that technique might apply.
# This is a simplified, illustrative mapping — MITRE's full framework has
# hundreds of techniques; we're connecting the ones our tool can actually
# detect evidence for.
MITRE_MAPPINGS = [
    {
        "keywords": ["spf", "spoof", "dmarc"],
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/"
    },
    {
        "keywords": ["registered", "days ago", "recently registered"],
        "technique_id": "T1583.001",
        "technique_name": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1583/001/"
    },
    {
        "keywords": ["subdomain", "dev/staging", "attack surface"],
        "technique_id": "T1590",
        "technique_name": "Gather Victim Network Information",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1590/"
    },
    {
        "keywords": ["expired", "certificate", "ssl"],
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1557/"
    },
    {
        "keywords": ["malicious", "flagged", "abuse"],
        "technique_id": "T1584",
        "technique_name": "Compromise Infrastructure",
        "tactic": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1584/"
    },
    {
        "keywords": ["missing", "header", "clickjacking", "xss"],
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1189/"
    },
]


def map_findings_to_mitre(all_findings: list[SecurityFinding]) -> list[dict]:
    """
    Takes findings gathered from ANY of your other features and matches
    them against known attack technique keywords. Only warning/critical
    findings are considered — an 'info' finding (like 'SPF record found')
    often describes a protection being present, not a risk, so mapping
    it to an attack technique would be misleading.
    """
    matched_techniques = {}

    for finding in all_findings:
        if finding.severity == "info":
            continue

        message_lower = finding.message.lower()
        for mapping in MITRE_MAPPINGS:
            if any(keyword in message_lower for keyword in mapping["keywords"]):
                technique_id = mapping["technique_id"]
                if technique_id not in matched_techniques:
                    matched_techniques[technique_id] = {
                        "technique_id": technique_id,
                        "technique_name": mapping["technique_name"],
                        "tactic": mapping["tactic"],
                        "url": mapping["url"],
                        "matched_finding": finding.message
                    }

    return list(matched_techniques.values())