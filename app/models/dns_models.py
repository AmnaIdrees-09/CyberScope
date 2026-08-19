from pydantic import BaseModel
from typing import List

class DNSRecordSet(BaseModel):
    A: List[str] = []
    AAAA: List[str] = []
    MX: List[str] = []
    TXT: List[str] = []
    NS: List[str] = []
    CNAME: List[str] = []
    SOA: List[str] = []

class SecurityFinding(BaseModel):
    severity: str        # "info" | "warning" | "critical"
    message: str

class DNSInvestigationResult(BaseModel):
    domain: str
    records: DNSRecordSet
    findings: List[SecurityFinding]