from pydantic import BaseModel
from typing import List, Optional
from app.models.dns_models import SecurityFinding

class WhoisResult(BaseModel):
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    findings: List[SecurityFinding] = []