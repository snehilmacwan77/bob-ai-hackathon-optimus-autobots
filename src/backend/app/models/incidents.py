"""SQLAlchemy ORM models for security incidents."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, JSON
from app.core.database import Base


class Incident(Base):
    """A correlated security incident grouping multiple indicators."""

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), default="medium")
    status = Column(String(32), default="open")   # open / investigating / contained / resolved

    # Scoring
    risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)

    # Linked data
    indicator_ids = Column(JSON, default=list)     # list of ThreatIndicator IDs
    affected_assets = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    attack_vector = Column(String(128), nullable=True)

    # Response
    bluf_summary = Column(Text, nullable=True)
    recommended_actions = Column(JSON, default=list)
    containment_steps = Column(JSON, default=list)

    # Timestamps
    detected_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

    is_demo_data = Column(Boolean, default=True)
