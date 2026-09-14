"""
Threat analysis engine.

NOTE: All analysis is performed using rule-based heuristics and synthetic data.
This is a DEMONSTRATION system. No real threat intelligence feeds are queried.
All indicators marked with is_demo_data=True are entirely fabricated.
"""
import re
import ipaddress
from typing import Any

# ── Indicator type detection ─────────────────────────────────────────────────

_MD5_RE  = re.compile(r'^[a-fA-F0-9]{32}$')
_SHA1_RE = re.compile(r'^[a-fA-F0-9]{40}$')
_SHA256_RE = re.compile(r'^[a-fA-F0-9]{64}$')
_URL_RE = re.compile(r'^https?://', re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def detect_indicator_type(value: str) -> str:
    value = value.strip()
    if _MD5_RE.match(value) or _SHA1_RE.match(value) or _SHA256_RE.match(value):
        return "hash"
    if _EMAIL_RE.match(value):
        return "email"
    if _URL_RE.match(value):
        return "url"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if _DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


# ── Risk scoring ─────────────────────────────────────────────────────────────

# Suspicious TLDs known to be abused
_SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz",
                    ".click", ".club", ".work", ".download", ".stream"}

# Known malicious keywords in URLs/domains
_MALICIOUS_KEYWORDS = [
    "login", "secure", "account", "verify", "update", "bank", "paypal", "apple",
    "microsoft", "support", "help", "service", "auth", "signin", "credential",
]

# Suspicious port ranges in URLs
_HIGH_RISK_PORTS = {4444, 8080, 8443, 1337, 31337, 6666, 9090}

# Private/reserved IP prefixes
_PRIVATE_PREFIXES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "192.168.", "127.", "::1", "0.0.0.0"]

# Synthetic threat intel data for demonstration
_KNOWN_MALICIOUS_IPS = {
    "185.220.101.45": ("critical", "Tor exit node / malware C2", ["T1090", "T1071"]),
    "195.54.160.100": ("high",     "Known scanner / exploit kit", ["T1595", "T1190"]),
    "91.108.4.200":   ("critical", "Ransomware C2 infrastructure", ["T1071", "T1486"]),
    "45.33.32.156":   ("high",     "Phishing campaign host", ["T1566", "T1598"]),
    "198.20.69.74":   ("medium",   "Port scanner / recon node", ["T1595"]),
    "104.21.80.1":    ("high",     "Bulletproof hosting provider IP", ["T1583"]),
    "2.56.57.100":    ("critical", "Botnet C2 server", ["T1071", "T1105"]),
    "103.235.46.172": ("high",     "APT-affiliated infrastructure", ["T1071", "T1041"]),
    "194.165.16.76":  ("medium",   "Spam / phishing relay", ["T1566"]),
    "31.13.65.36":    ("low",      "Flagged by multiple feeds", ["T1595"]),
}

_KNOWN_MALICIOUS_DOMAINS = {
    "update.microsofft.com":             ("critical", "Typosquatting Microsoft domain – phishing"),
    "cdn-telemetry.cloudflare-cdn.net":  ("critical", "Lookalike CDN – malware delivery"),
    "analytics.googlle.com":             ("high",     "Google lookalike – credential harvesting"),
    "d1zx4oq7s9ls6e.cloudfront.net":     ("high",     "Random-subdomain DGA C2"),
    "backup.dropboxx.com":               ("high",     "Typosquatting Dropbox – phishing"),
    "secure-login.paypa1.com":           ("critical", "PayPal phishing domain"),
    "microsoft-support-center.com":      ("high",     "Fake support site – tech scam"),
    "update-flash-player.net":           ("medium",   "Fake software update – malware dropper"),
    "freevbucks.xyz":                    ("medium",   "Gaming credential phishing"),
    "coinminer-pool.cc":                 ("critical", "Cryptominer C2 domain"),
}

_KNOWN_MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        ("critical", "Ransomware payload – Lockbit family"),
    "d41d8cd98f00b204e9800998ecf8427e":
        ("high",     "Dropper malware – downloader stage"),
    "da39a3ee5e6b4b0d3255bfef95601890afd80709":
        ("high",     "Remote access trojan (RAT)"),
    "aabbccddeeff00112233445566778899":
        ("medium",   "Suspicious unsigned executable"),
    "44d88612fea8a8f36de82e1278abb02f":
        ("critical", "WannaCry ransomware hash"),
}

MITRE_RECOMMENDATIONS = {
    "T1071": "Block suspicious outbound connections on non-standard ports; monitor DNS for DGA patterns.",
    "T1566": "Enable advanced email filtering; train staff on phishing indicators.",
    "T1090": "Block Tor exit nodes at perimeter; monitor for unusual proxy usage.",
    "T1595": "Implement rate-limiting; alert on systematic port scan patterns.",
    "T1190": "Patch all public-facing services; deploy WAF with virtual patching.",
    "T1486": "Ensure offline backups; restrict VSS/shadow copy deletion.",
    "T1105": "Block outbound connections to unknown IPs; inspect encrypted channels.",
    "T1041": "Deploy DLP; monitor for large outbound data transfers.",
    "T1583": "Track passive DNS for new registrations; monitor BGP hijacking.",
    "T1598": "Monitor for credential exposure; enable MFA on all externally-facing services.",
}

GENERAL_RECOMMENDATIONS = {
    "critical": [
        "Immediately block this indicator at all perimeter controls (firewall, proxy, DNS).",
        "Initiate an incident response investigation – escalate to Tier 3 SOC.",
        "Isolate any endpoint that communicated with this indicator.",
        "Preserve forensic artefacts for post-incident analysis.",
    ],
    "high": [
        "Block this indicator at the perimeter firewall and DNS resolver.",
        "Review logs for any past communication with this indicator.",
        "Alert the security team and open a formal investigation ticket.",
        "Scan all endpoints for related indicators of compromise.",
    ],
    "medium": [
        "Add this indicator to your watch-list for ongoing monitoring.",
        "Correlate with other recent alerts to identify patterns.",
        "Review user/system activity logs for the past 7 days.",
        "Consider soft-blocking with alert on trigger.",
    ],
    "low": [
        "Log the indicator for future reference.",
        "Include in periodic threat hunting queries.",
        "No immediate action required; monitor for escalation.",
    ],
    "info": [
        "Informational indicator – no immediate action required.",
        "Retain in threat intelligence database for correlation.",
    ],
}


def _score_ip(value: str) -> dict[str, Any]:
    """Score an IP address indicator."""
    # Check known malicious
    if value in _KNOWN_MALICIOUS_IPS:
        sev, reason, techniques = _KNOWN_MALICIOUS_IPS[value]
        base = {"critical": 92, "high": 75, "medium": 50, "low": 25}[sev]
        return {
            "risk_score": float(base),
            "severity": sev,
            "confidence": 0.92,
            "category": reason.split(" – ")[0].lower().replace(" ", "-"),
            "analysis_summary": f"[DEMO DATA] {value} is associated with known malicious activity: {reason}. "
                                 f"This indicator has been observed in multiple threat intelligence feeds.",
            "mitre_techniques": techniques,
            "tags": [sev, "known-bad", "demo"],
        }

    # Check private
    for prefix in _PRIVATE_PREFIXES:
        if value.startswith(prefix):
            return {
                "risk_score": 2.0,
                "severity": "info",
                "confidence": 0.99,
                "category": "internal",
                "analysis_summary": f"{value} is a private/reserved IP address. No threat intelligence available.",
                "mitre_techniques": [],
                "tags": ["internal", "rfc1918"],
            }

    # Heuristic scoring for unknown IPs
    score = 15.0
    tags = ["unknown"]
    notes = []

    # Simple geo-heuristic: certain /8 blocks historically higher abuse
    first_octet = int(value.split(".")[0]) if "." in value else 0
    if first_octet in {185, 195, 91, 45, 104, 2, 103, 194, 31}:
        score += 20
        tags.append("suspicious-asn-range")
        notes.append("IP falls in an ASN range with elevated abuse history.")

    sev = "low" if score < 40 else "medium"
    return {
        "risk_score": min(score, 100.0),
        "severity": sev,
        "confidence": 0.45,
        "category": "unclassified",
        "analysis_summary": f"[DEMO DATA] {value} is not in any known threat feed. "
                             + (" ".join(notes) if notes else "No specific threat intelligence available."),
        "mitre_techniques": [],
        "tags": tags,
    }


def _score_domain(value: str) -> dict[str, Any]:
    """Score a domain indicator."""
    lower = value.lower()

    if lower in _KNOWN_MALICIOUS_DOMAINS:
        sev, reason = _KNOWN_MALICIOUS_DOMAINS[lower]
        base = {"critical": 93, "high": 76, "medium": 52}[sev]
        techniques = ["T1566"] if "phishing" in reason.lower() else ["T1071", "T1105"]
        return {
            "risk_score": float(base),
            "severity": sev,
            "confidence": 0.90,
            "category": "phishing" if "phishing" in reason.lower() else "malware-c2",
            "analysis_summary": f"[DEMO DATA] {value} is a known malicious domain: {reason}.",
            "mitre_techniques": techniques,
            "tags": [sev, "known-bad", "demo"],
        }

    score = 10.0
    tags = []
    notes = []

    # Suspicious TLD
    for tld in _SUSPICIOUS_TLDS:
        if lower.endswith(tld):
            score += 25
            tags.append("suspicious-tld")
            notes.append(f"Domain uses high-abuse TLD '{tld}'.")
            break

    # Keyword matching
    keyword_hits = [kw for kw in _MALICIOUS_KEYWORDS if kw in lower]
    if keyword_hits:
        score += min(len(keyword_hits) * 12, 35)
        tags.append("suspicious-keywords")
        notes.append(f"Domain contains suspicious keywords: {', '.join(keyword_hits[:3])}.")

    # Subdomain depth
    parts = lower.split(".")
    if len(parts) > 4:
        score += 15
        tags.append("deep-subdomain")
        notes.append("Unusually deep subdomain structure.")

    # Length
    if len(lower) > 40:
        score += 10
        tags.append("long-domain")

    score = min(score, 100.0)
    sev = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
    return {
        "risk_score": score,
        "severity": sev,
        "confidence": min(0.3 + score / 200, 0.85),
        "category": "suspicious-domain",
        "analysis_summary": f"[DEMO DATA] {value} analysis: " + (" ".join(notes) if notes else "No specific threat signals detected."),
        "mitre_techniques": ["T1566"] if score > 40 else [],
        "tags": tags or ["unclassified"],
    }


def _score_url(value: str) -> dict[str, Any]:
    """Score a URL indicator."""
    lower = value.lower()
    score = 12.0
    tags = []
    notes = []

    # Check if domain portion is known malicious
    try:
        from urllib.parse import urlparse
        parsed = urlparse(value)
        domain = parsed.hostname or ""
        domain_result = _score_domain(domain)
        score = max(score, domain_result["risk_score"] * 0.9)
        tags.extend(domain_result.get("tags", []))
    except Exception:
        pass

    # Check for non-standard port
    try:
        port = int(parsed.port or 0)
        if port in _HIGH_RISK_PORTS:
            score = min(score + 20, 100.0)
            tags.append("suspicious-port")
            notes.append(f"URL uses high-risk port {port}.")
    except Exception:
        pass

    # Suspicious path patterns
    for kw in ["cmd=", "exec=", "shell=", "../", "%2e%2e", "eval(", "base64"]:
        if kw in lower:
            score = min(score + 15, 100.0)
            tags.append("suspicious-path")
            notes.append("URL path contains suspicious parameter/pattern.")
            break

    # Long URL heuristic (common in phishing)
    if len(value) > 200:
        score = min(score + 10, 100.0)
        tags.append("long-url")

    sev = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
    return {
        "risk_score": score,
        "severity": sev,
        "confidence": min(0.4 + score / 200, 0.88),
        "category": "malicious-url",
        "analysis_summary": f"[DEMO DATA] URL analysis for {value[:80]}{'...' if len(value) > 80 else ''}: "
                             + (" ".join(notes) if notes else "Heuristic scan complete – no strong signals."),
        "mitre_techniques": ["T1566", "T1105"] if score > 50 else [],
        "tags": tags or ["unclassified"],
    }


def _score_hash(value: str) -> dict[str, Any]:
    """Score a file hash indicator."""
    lower = value.lower()
    if lower in _KNOWN_MALICIOUS_HASHES:
        sev, reason = _KNOWN_MALICIOUS_HASHES[lower]
        base = {"critical": 96, "high": 78, "medium": 55}[sev]
        return {
            "risk_score": float(base),
            "severity": sev,
            "confidence": 0.95,
            "category": "malware",
            "analysis_summary": f"[DEMO DATA] File hash {value[:16]}... matches known malicious file: {reason}.",
            "mitre_techniques": ["T1059", "T1055"],
            "tags": [sev, "known-malware", "demo"],
        }

    hash_len = len(value)
    hash_type = "MD5" if hash_len == 32 else "SHA-1" if hash_len == 40 else "SHA-256"
    return {
        "risk_score": 5.0,
        "severity": "info",
        "confidence": 0.3,
        "category": "unknown-file",
        "analysis_summary": f"[DEMO DATA] {hash_type} hash {value[:16]}... not found in known threat databases. File appears clean or is unknown.",
        "mitre_techniques": [],
        "tags": ["unknown-file", hash_type.lower()],
    }


def analyze_indicator(value: str, indicator_type: str | None = None) -> dict[str, Any]:
    """
    Main entry point for threat indicator analysis.
    Returns a complete analysis result dict.
    All results are DEMO DATA – no real intelligence is queried.
    """
    value = value.strip()
    itype = indicator_type or detect_indicator_type(value)

    if itype == "ip":
        result = _score_ip(value)
    elif itype == "domain":
        result = _score_domain(value)
    elif itype == "url":
        result = _score_url(value)
    elif itype == "hash":
        result = _score_hash(value)
    else:
        result = {
            "risk_score": 0.0,
            "severity": "info",
            "confidence": 0.0,
            "category": "unknown",
            "analysis_summary": f"[DEMO DATA] Unable to classify indicator: '{value}'. Supported types: IP, domain, URL, hash.",
            "mitre_techniques": [],
            "tags": ["unclassified"],
        }

    # Build recommendations
    sev = result["severity"]
    recommendations = list(GENERAL_RECOMMENDATIONS.get(sev, []))
    for tech in result.get("mitre_techniques", []):
        rec = MITRE_RECOMMENDATIONS.get(tech)
        if rec:
            recommendations.append(f"[{tech}] {rec}")

    result["recommendations"] = recommendations[:6]
    result["indicator_type"] = itype
    result["value"] = value
    return result
