"""SQLAlchemy ORM models for threat indicators and IOCs."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, JSON
from app.core.database import Base


class ThreatIndicator(Base):
    """A single threat indicator (IP, domain, URL, file hash, etc.)."""

    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, index=True)
    value = Column(String(512), unique=True, index=True, nullable=False)
    indicator_type = Column(String(32), index=True, nullable=False)
    # ip / domain / url / hash / email

    # Risk assessment
    risk_score = Column(Float, default=0.0)        # 0–100
    severity = Column(String(16), default="low")   # critical/high/medium/low/info
    confidence = Column(Float, default=0.0)        # 0–1

    # Classification
    category = Column(String(64), nullable=True)    # malware-c2 / phishing / scanner etc.
    tags = Column(JSON, default=list)

    # Context
    source = Column(String(64), default="DEMO")    # feed source
    country = Column(String(64), nullable=True)
    asn = Column(String(128), nullable=True)

    # Analysis output
    analysis_summary = Column(Text, nullable=True)
    recommendations = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    related_indicators = Column(JSON, default=list)  # list of indicator IDs/values

    # Flags
    is_demo_data = Column(Boolean, default=True)
    is_false_positive = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)

    # Timestamps
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Hit counters
    hit_count = Column(Integer, default=1)
    investigation_count = Column(Integer, default=0)
