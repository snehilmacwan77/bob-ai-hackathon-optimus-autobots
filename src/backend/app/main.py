"""FastAPI application entry point for ThreatFusion AI – Threat Intelligence System."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import init_db
from app.routers import indicators, incidents, dashboard

app = FastAPI(
    title="ThreatFusion AI – Threat Intelligence System",
    description=(
        "AI-powered threat intelligence platform that analyzes indicators of compromise (IOCs), "
        "scores risk, correlates threats, and provides actionable security recommendations.\n\n"
        "**Note:** This is a demonstration system. All threat data is synthetic. "
        "No real threat intelligence feeds are queried."
    ),
    version="1.0.0",
    contact={
        "name": "Optimus Autobots",
        "email": "23dce113@charusat.edu.in",
    },
)

# CORS – allow the Vite dev server and any localhost origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    import os
    init_db()
    # Auto-seed demo data on first run (skip when running under pytest)
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return
    from app.core.database import SessionLocal
    from app.models.indicators import ThreatIndicator
    from app.services.demo_data import seed_all
    db = SessionLocal()
    try:
        if db.query(ThreatIndicator).count() == 0:
            seed_all(db)
    finally:
        db.close()


app.include_router(indicators.router, prefix="/api/v1")
app.include_router(incidents.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
def health():
    return {
        "status": "ok",
        "service": "ThreatFusion AI",
        "version": "1.0.0",
        "note": "All threat data is simulated for demonstration purposes.",
    }
