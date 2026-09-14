"""
Synthetic demo data seeder.
Generates realistic-looking (but entirely fabricated) threat intelligence data.
All generated data is marked with is_demo_data=True.
"""
import random
import uuid
from datetime import datetime, timedelta
from faker import Faker

from sqlalchemy.orm import Session
from app.models.indicators import ThreatIndicator
from app.models.incidents import Incident
from app.services.analysis import analyze_indicator

fake = Faker()
random.seed(2024)

# ── Synthetic datasets ────────────────────────────────────────────────────────

MALICIOUS_IPS = [
    "185.220.101.45", "195.54.160.100", "91.108.4.200",
    "45.33.32.156", "198.20.69.74", "104.21.80.1",
    "2.56.57.100", "103.235.46.172", "194.165.16.76", "31.13.65.36",
]

MALICIOUS_DOMAINS = [
    "update.microsofft.com", "cdn-telemetry.cloudflare-cdn.net",
    "analytics.googlle.com", "d1zx4oq7s9ls6e.cloudfront.net",
    "backup.dropboxx.com", "secure-login.paypa1.com",
    "microsoft-support-center.com", "update-flash-player.net",
    "freevbucks.xyz", "coinminer-pool.cc",
]

MALICIOUS_HASHES = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "aabbccddeeff00112233445566778899",
    "44d88612fea8a8f36de82e1278abb02f",
]

MALICIOUS_URLS = [
    "http://secure-login.paypa1.com/login?redirect=account",
    "https://update.microsofft.com/patch/kb12345.exe",
    "http://185.220.101.45:4444/payload.bin",
    "https://cdn-telemetry.cloudflare-cdn.net/track?id=abc123",
    "http://freevbucks.xyz/claim?user=admin&token=XXXXXX",
]

SUSPICIOUS_IPS = [
    "192.168.1.1", "10.0.0.1", "172.16.0.5",  # internal
]

INCIDENT_TEMPLATES = [
    {
        "title": "Ransomware C2 Beacon Detected",
        "description": "Multiple endpoints beaconing to known ransomware C2 infrastructure. "
                       "Initial access likely via phishing email attachment.",
        "severity": "critical",
        "attack_vector": "Phishing → Execution → C2 Communication",
        "mitre_techniques": ["T1566", "T1059", "T1071", "T1486"],
        "recommended_actions": [
            "Immediately isolate affected endpoints from the network.",
            "Block C2 IPs/domains at perimeter firewall and DNS resolver.",
            "Initiate incident response – engage IR team.",
            "Preserve forensic images of affected systems.",
            "Notify stakeholders per IR playbook.",
        ],
        "containment_steps": [
            "Disconnect affected hosts from network segments.",
            "Revoke and rotate all credentials used on affected systems.",
            "Deploy emergency EDR policy to block execution of unknown binaries.",
        ],
        "risk_score": 94.0,
        "confidence": 0.91,
    },
    {
        "title": "Phishing Campaign – Credential Harvesting",
        "description": "Coordinated phishing campaign targeting employee credentials. "
                       "Lookalike domains observed collecting Microsoft 365 login credentials.",
        "severity": "high",
        "attack_vector": "Phishing Email → Credential Harvesting",
        "mitre_techniques": ["T1566", "T1598", "T1539"],
        "recommended_actions": [
            "Block identified phishing domains at email gateway and proxy.",
            "Force password reset for users who clicked phishing links.",
            "Enable MFA on all Microsoft 365 accounts immediately.",
            "Send user awareness alert to all staff.",
        ],
        "containment_steps": [
            "Quarantine phishing emails from all mailboxes.",
            "Block sender domains and IPs at email gateway.",
            "Review audit logs for suspicious sign-in activity.",
        ],
        "risk_score": 78.0,
        "confidence": 0.87,
    },
    {
        "title": "Cryptominer Infection – Coinminer-Pool C2",
        "description": "Hosts communicating with coinminer-pool.cc. "
                       "CPU/GPU utilisation anomalies suggest active mining activity.",
        "severity": "medium",
        "attack_vector": "Drive-by Download → Persistence → Resource Hijacking",
        "mitre_techniques": ["T1105", "T1547", "T1496"],
        "recommended_actions": [
            "Terminate mining processes and quarantine malware binaries.",
            "Block coinminer-pool.cc and related domains at DNS.",
            "Scan all endpoints for coinminer variants.",
            "Review browser extension and software installations.",
        ],
        "containment_steps": [
            "Kill identified mining processes.",
            "Remove persistence mechanisms (scheduled tasks, registry keys).",
            "Patch browser/OS vulnerabilities used for initial access.",
        ],
        "risk_score": 56.0,
        "confidence": 0.82,
    },
    {
        "title": "Port Scan from External IP",
        "description": "Systematic TCP SYN port scan from known scanner node. "
                       "Likely reconnaissance preceding an exploitation attempt.",
        "severity": "low",
        "attack_vector": "External Reconnaissance",
        "mitre_techniques": ["T1595", "T1046"],
        "recommended_actions": [
            "Block scanning IP at perimeter firewall.",
            "Review firewall rules to ensure minimal attack surface.",
            "Monitor for follow-up exploitation attempts.",
        ],
        "containment_steps": [
            "Add scanning IP to block-list.",
            "Audit exposed services and close unnecessary ports.",
        ],
        "risk_score": 28.0,
        "confidence": 0.75,
    },
    {
        "title": "Lateral Movement – Pass-the-Hash Detected",
        "description": "NTLM authentication with stolen hash credentials detected. "
                       "Attacker appears to be moving laterally across domain-joined systems.",
        "severity": "critical",
        "attack_vector": "Credential Access → Lateral Movement",
        "mitre_techniques": ["T1550", "T1021", "T1078"],
        "recommended_actions": [
            "Reset all NTLM hashes and enforce Kerberos authentication.",
            "Enable Protected Users security group for privileged accounts.",
            "Deploy Microsoft LAPS for local admin password management.",
            "Review all lateral movement pathways (SMB, WMI, RDP).",
        ],
        "containment_steps": [
            "Disable NTLM where Kerberos is available.",
            "Isolate systems showing lateral movement patterns.",
            "Revoke affected credential hashes immediately.",
        ],
        "risk_score": 89.0,
        "confidence": 0.88,
    },
]


def _random_past_time(days: int = 7) -> datetime:
    return datetime.utcnow() - timedelta(
        seconds=random.randint(0, days * 86400)
    )


def seed_indicators(db: Session) -> int:
    """Create synthetic threat indicators. Returns count inserted."""
    count = 0
    all_values = (
        MALICIOUS_IPS + MALICIOUS_DOMAINS + MALICIOUS_HASHES + MALICIOUS_URLS
    )

    for value in all_values:
        existing = db.query(ThreatIndicator).filter(
            ThreatIndicator.value == value
        ).first()
        if existing:
            continue

        result = analyze_indicator(value)
        ts = _random_past_time(14)

        indicator = ThreatIndicator(
            value=value,
            indicator_type=result["indicator_type"],
            risk_score=result["risk_score"],
            severity=result["severity"],
            confidence=result["confidence"],
            category=result.get("category", "unclassified"),
            tags=result.get("tags", []),
            source="DEMO-FEED",
            analysis_summary=result.get("analysis_summary", ""),
            recommendations=result.get("recommendations", []),
            mitre_techniques=result.get("mitre_techniques", []),
            related_indicators=[],
            is_demo_data=True,
            first_seen=ts,
            last_seen=ts + timedelta(hours=random.randint(1, 48)),
            hit_count=random.randint(1, 150),
        )
        db.add(indicator)
        count += 1

    db.commit()
    return count


def seed_incidents(db: Session) -> int:
    """Create synthetic security incidents."""
    count = 0
    for tmpl in INCIDENT_TEMPLATES:
        existing = db.query(Incident).filter(
            Incident.title == tmpl["title"]
        ).first()
        if existing:
            continue

        ts = _random_past_time(5)
        incident = Incident(
            title=tmpl["title"],
            description=tmpl["description"],
            severity=tmpl["severity"],
            status=random.choice(["open", "investigating", "open", "contained"]),
            risk_score=tmpl["risk_score"],
            confidence=tmpl["confidence"],
            mitre_techniques=tmpl["mitre_techniques"],
            attack_vector=tmpl["attack_vector"],
            recommended_actions=tmpl["recommended_actions"],
            containment_steps=tmpl["containment_steps"],
            bluf_summary=_generate_bluf(tmpl),
            affected_assets=_random_assets(),
            is_demo_data=True,
            detected_at=ts,
            updated_at=ts + timedelta(hours=random.randint(0, 12)),
        )
        db.add(incident)
        count += 1

    db.commit()
    return count


def _random_assets() -> list[str]:
    assets = [
        f"ws-finance-{random.randint(1,5):02d}",
        f"srv-web-{random.randint(1,3):02d}",
        f"laptop-{fake.last_name().lower()}-01",
    ]
    return random.sample(assets, k=random.randint(1, 3))


def _generate_bluf(tmpl: dict) -> str:
    sev = tmpl["severity"].upper()
    return (
        f"[{sev}] {tmpl['title']}: {tmpl['description']} "
        f"Risk score: {tmpl['risk_score']:.0f}/100. "
        f"Confidence: {tmpl['confidence']*100:.0f}%. "
        f"Attack vector: {tmpl['attack_vector']}."
    )


def seed_all(db: Session) -> dict:
    indicators = seed_indicators(db)
    incidents = seed_incidents(db)
    return {"indicators_seeded": indicators, "incidents_seeded": incidents}
