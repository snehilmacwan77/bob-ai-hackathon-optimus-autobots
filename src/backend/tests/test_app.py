"""Tests for ThreatFusion AI backend."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, StaticPool
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, get_db
from app.main import app

# ── Shared in-memory engine (same connection for all sessions) ────────────────
# StaticPool ensures the same in-memory DB is reused across connections.

_TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_TestSession = sessionmaker(autocommit=False, autoflush=False, bind=_TEST_ENGINE)
Base.metadata.create_all(bind=_TEST_ENGINE)


def _get_test_db():
    db = _TestSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _get_test_db


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ── Health check ──────────────────────────────────────────────────────────────

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── Indicator type detection ──────────────────────────────────────────────────

def test_detect_ip():
    from app.services.analysis import detect_indicator_type
    assert detect_indicator_type("185.220.101.45") == "ip"
    assert detect_indicator_type("192.168.1.1") == "ip"


def test_detect_domain():
    from app.services.analysis import detect_indicator_type
    assert detect_indicator_type("example.com") == "domain"
    assert detect_indicator_type("sub.domain.co.uk") == "domain"


def test_detect_url():
    from app.services.analysis import detect_indicator_type
    assert detect_indicator_type("http://example.com/path") == "url"
    assert detect_indicator_type("https://evil.xyz/payload") == "url"


def test_detect_hash():
    from app.services.analysis import detect_indicator_type
    assert detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"
    assert detect_indicator_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"


# ── Analysis engine ───────────────────────────────────────────────────────────

def test_analyze_known_malicious_ip():
    from app.services.analysis import analyze_indicator
    result = analyze_indicator("185.220.101.45")
    assert result["severity"] == "critical"
    assert result["risk_score"] >= 80
    assert len(result["recommendations"]) > 0
    assert len(result["mitre_techniques"]) > 0


def test_analyze_private_ip():
    from app.services.analysis import analyze_indicator
    result = analyze_indicator("192.168.1.1")
    assert result["severity"] == "info"
    assert result["risk_score"] < 10


def test_analyze_known_malicious_domain():
    from app.services.analysis import analyze_indicator
    result = analyze_indicator("update.microsofft.com")
    assert result["severity"] in {"critical", "high"}
    assert result["risk_score"] >= 60


def test_analyze_known_hash():
    from app.services.analysis import analyze_indicator
    result = analyze_indicator("44d88612fea8a8f36de82e1278abb02f")
    assert result["severity"] == "critical"


def test_analyze_unknown_url():
    from app.services.analysis import analyze_indicator
    result = analyze_indicator("http://example.com")
    assert "risk_score" in result
    assert "severity" in result


# ── API routes ────────────────────────────────────────────────────────────────

def test_post_analyze_ip(client):
    r = client.post("/api/v1/indicators/analyze", json={"value": "185.220.101.45"})
    assert r.status_code == 200
    data = r.json()
    assert data["indicator_type"] == "ip"
    assert data["severity"] == "critical"
    assert data["is_demo_data"] is True


def test_post_analyze_domain(client):
    r = client.post("/api/v1/indicators/analyze", json={"value": "secure-login.paypa1.com"})
    assert r.status_code == 200
    data = r.json()
    assert data["indicator_type"] == "domain"
    assert data["risk_score"] >= 60


def test_post_analyze_hash(client):
    r = client.post("/api/v1/indicators/analyze", json={"value": "d41d8cd98f00b204e9800998ecf8427e"})
    assert r.status_code == 200
    data = r.json()
    assert data["indicator_type"] == "hash"


def test_post_analyze_empty_value(client):
    r = client.post("/api/v1/indicators/analyze", json={"value": "  "})
    assert r.status_code == 422


def test_list_indicators(client):
    # Seed first
    client.post("/api/v1/demo/seed")
    r = client.get("/api/v1/indicators/")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert len(r.json()) > 0


def test_dashboard(client):
    r = client.get("/api/v1/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert "total_indicators" in data
    assert "severity_distribution" in data
    assert data["is_demo_data"] is True


def test_list_incidents(client):
    r = client.get("/api/v1/incidents/")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_seed_endpoint(client):
    r = client.post("/api/v1/demo/seed")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
