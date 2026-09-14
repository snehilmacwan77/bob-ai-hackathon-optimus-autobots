"""Pydantic schemas for request/response models."""
from pydantic import BaseModel, ConfigDict, field_validator
from datetime import datetime
from typing import Any, Optional


class AnalyzeRequest(BaseModel):
    value: str
    indicator_type: Optional[str] = None

    @field_validator("value")
    @classmethod
    def value_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Indicator value must not be empty.")
        if len(v) > 512:
            raise ValueError("Indicator value must be ≤512 characters.")
        return v

    @field_validator("indicator_type")
    @classmethod
    def valid_type(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        allowed = {"ip", "domain", "url", "hash", "email", "unknown"}
        if v.lower() not in allowed:
            raise ValueError(f"indicator_type must be one of {allowed}")
        return v.lower()


class AnalysisResult(BaseModel):
    value: str
    indicator_type: str
    risk_score: float
    severity: str
    confidence: float
    category: str
    analysis_summary: str
    recommendations: list[str]
    mitre_techniques: list[str]
    tags: list[str]
    is_demo_data: bool = True


class IndicatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    value: str
    indicator_type: str
    risk_score: float
    severity: str
    confidence: float
    category: Optional[str]
    tags: list[str]
    source: str
    analysis_summary: Optional[str]
    recommendations: list[str]
    mitre_techniques: list[str]
    is_demo_data: bool
    is_false_positive: bool
    is_active: bool
    first_seen: datetime
    last_seen: datetime
    hit_count: int
    investigation_count: int


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    risk_score: float
    confidence: float
    mitre_techniques: list[str]
    attack_vector: Optional[str]
    bluf_summary: Optional[str]
    recommended_actions: list[str]
    containment_steps: list[str]
    affected_assets: list[str]
    is_demo_data: bool
    detected_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]


class DashboardStats(BaseModel):
    total_indicators: int
    active_indicators: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    false_positive_count: int
    total_incidents: int
    open_incidents: int
    severity_distribution: dict[str, int]
    top_categories: list[dict[str, Any]]
    recent_indicators: list[IndicatorOut]
    recent_incidents: list[IncidentOut]
    is_demo_data: bool = True


class StatusResponse(BaseModel):
    status: str
    detail: str = ""
    data: Optional[dict[str, Any]] = None
