"""Threat indicator analysis and management routes."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from datetime import datetime

from app.core.database import get_db
from app.models.indicators import ThreatIndicator
from app.services.analysis import analyze_indicator, detect_indicator_type
from app.routers.schemas import AnalyzeRequest, AnalysisResult, IndicatorOut, StatusResponse

router = APIRouter(prefix="/indicators", tags=["Threat Indicators"])


@router.post("/analyze", response_model=AnalysisResult)
def analyze(req: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    Analyze a threat indicator and return risk score + recommendations.
    Supports: IP addresses, domains, URLs, file hashes.

    **Note:** All analysis results are simulated demo data.
    No real threat intelligence feeds are queried.
    """
    result = analyze_indicator(req.value, req.indicator_type)
    itype = result["indicator_type"]

    # Persist or update indicator in DB
    existing = db.query(ThreatIndicator).filter(
        ThreatIndicator.value == req.value
    ).first()

    if existing:
        existing.last_seen = datetime.utcnow()
        existing.hit_count += 1
        existing.investigation_count += 1
        db.commit()
    else:
        indicator = ThreatIndicator(
            value=req.value,
            indicator_type=itype,
            risk_score=result["risk_score"],
            severity=result["severity"],
            confidence=result["confidence"],
            category=result.get("category", "unclassified"),
            tags=result.get("tags", []),
            source="USER-SUBMISSION",
            analysis_summary=result.get("analysis_summary", ""),
            recommendations=result.get("recommendations", []),
            mitre_techniques=result.get("mitre_techniques", []),
            related_indicators=[],
            is_demo_data=True,
        )
        db.add(indicator)
        db.commit()

    return AnalysisResult(
        value=result["value"],
        indicator_type=itype,
        risk_score=result["risk_score"],
        severity=result["severity"],
        confidence=result["confidence"],
        category=result.get("category", "unclassified"),
        analysis_summary=result.get("analysis_summary", ""),
        recommendations=result.get("recommendations", []),
        mitre_techniques=result.get("mitre_techniques", []),
        tags=result.get("tags", []),
        is_demo_data=True,
    )


@router.get("/", response_model=list[IndicatorOut])
def list_indicators(
    skip: int = 0,
    limit: int = Query(default=100, le=500),
    severity: str | None = None,
    indicator_type: str | None = None,
    is_active: bool | None = None,
    db: Session = Depends(get_db),
):
    """List all tracked threat indicators with optional filters."""
    q = db.query(ThreatIndicator)
    if severity:
        q = q.filter(ThreatIndicator.severity == severity)
    if indicator_type:
        q = q.filter(ThreatIndicator.indicator_type == indicator_type)
    if is_active is not None:
        q = q.filter(ThreatIndicator.is_active == is_active)
    return q.order_by(ThreatIndicator.risk_score.desc()).offset(skip).limit(limit).all()


@router.get("/{indicator_id}", response_model=IndicatorOut)
def get_indicator(indicator_id: int, db: Session = Depends(get_db)):
    """Retrieve a specific indicator by ID."""
    ind = db.query(ThreatIndicator).filter(ThreatIndicator.id == indicator_id).first()
    if not ind:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return ind


@router.patch("/{indicator_id}/false-positive", response_model=IndicatorOut)
def mark_false_positive(indicator_id: int, db: Session = Depends(get_db)):
    """Mark an indicator as a false positive."""
    ind = db.query(ThreatIndicator).filter(ThreatIndicator.id == indicator_id).first()
    if not ind:
        raise HTTPException(status_code=404, detail="Indicator not found")
    ind.is_false_positive = not ind.is_false_positive
    db.commit()
    db.refresh(ind)
    return ind
