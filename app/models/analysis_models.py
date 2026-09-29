from typing import Literal

from pydantic import BaseModel, Field


class FindingIn(BaseModel):
    severity: Literal["critical", "warning", "info"]
    message: str = Field(min_length=1, max_length=1000)


class AnalysisRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    findings: list[FindingIn] = Field(default_factory=list, max_length=200)