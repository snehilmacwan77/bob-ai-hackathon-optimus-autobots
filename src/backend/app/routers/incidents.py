"""Security incident management routes."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from datetime import datetime

from app.core.database import get_db
from app.models.incidents import Incident
from app.routers.schemas import IncidentOut, StatusResponse

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("/", response_model=list[IncidentOut])
def list_incidents(
    skip: int = 0,
    limit: int = Query(default=50, le=200),
    status: str | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
):
    """List all security incidents with optional filters."""
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    return q.order_by(Incident.risk_score.desc()).offset(skip).limit(limit).all()


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    """Retrieve a specific incident by ID."""
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@router.patch("/{incident_id}/status", response_model=IncidentOut)
def update_status(incident_id: int, status: str, db: Session = Depends(get_db)):
    """Update the status of an incident."""
    allowed = {"open", "investigating", "contained", "resolved"}
    if status not in allowed:
        raise HTTPException(status_code=400, detail=f"Status must be one of {allowed}")
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc.status = status
    if status == "resolved":
        inc.resolved_at = datetime.utcnow()
    inc.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(inc)
    return inc
