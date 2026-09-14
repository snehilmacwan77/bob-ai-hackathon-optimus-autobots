"""Dashboard statistics and demo-data management routes."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.models.indicators import ThreatIndicator
from app.models.incidents import Incident
from app.services.demo_data import seed_all
from app.routers.schemas import DashboardStats, IndicatorOut, IncidentOut, StatusResponse

router = APIRouter(tags=["Dashboard"])


@router.get("/dashboard", response_model=DashboardStats)
def get_dashboard(db: Session = Depends(get_db)):
    """Return aggregated dashboard statistics."""
    total = db.query(ThreatIndicator).count()
    active = db.query(ThreatIndicator).filter(ThreatIndicator.is_active == True).count()  # noqa

    sev_counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    rows = db.query(ThreatIndicator.severity, func.count()).group_by(ThreatIndicator.severity).all()
    for sev, cnt in rows:
        if sev in sev_counts:
            sev_counts[sev] = cnt

    fp_count = db.query(ThreatIndicator).filter(ThreatIndicator.is_false_positive == True).count()  # noqa

    # Category breakdown
    cat_rows = (
        db.query(ThreatIndicator.category, func.count())
        .group_by(ThreatIndicator.category)
        .order_by(func.count().desc())
        .limit(8)
        .all()
    )
    top_categories = [{"category": cat or "unknown", "count": cnt} for cat, cnt in cat_rows]

    recent_indicators = (
        db.query(ThreatIndicator)
        .order_by(ThreatIndicator.last_seen.desc())
        .limit(10)
        .all()
    )

    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(Incident.status.in_(["open", "investigating"])).count()
    recent_incidents = db.query(Incident).order_by(Incident.detected_at.desc()).limit(5).all()

    def _inc_out(inc: Incident) -> IncidentOut:
        return IncidentOut.model_validate(inc)

    return DashboardStats(
        total_indicators=total,
        active_indicators=active,
        critical_count=sev_counts["critical"],
        high_count=sev_counts["high"],
        medium_count=sev_counts["medium"],
        low_count=sev_counts["low"],
        info_count=sev_counts["info"],
        false_positive_count=fp_count,
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        severity_distribution=sev_counts,
        top_categories=top_categories,
        recent_indicators=[IndicatorOut.model_validate(i) for i in recent_indicators],
        recent_incidents=[_inc_out(i) for i in recent_incidents],
        is_demo_data=True,
    )


@router.post("/demo/seed", response_model=StatusResponse)
def seed_demo(db: Session = Depends(get_db)):
    """Seed the database with synthetic demo threat data."""
    result = seed_all(db)
    return StatusResponse(
        status="ok",
        detail=f"Seeded {result['indicators_seeded']} indicators and {result['incidents_seeded']} incidents.",
        data=result,
    )
