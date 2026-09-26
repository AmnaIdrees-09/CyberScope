from pydantic import BaseModel
from typing import List, Optional
from app.models.dns_models import SecurityFinding

class IPResult(BaseModel):
    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    abuse_confidence_score: Optional[int] = None
    total_reports: Optional[int] = None
    findings: List[SecurityFinding] = []