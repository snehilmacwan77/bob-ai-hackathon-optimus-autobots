# Solution Overview

## What We Built

Threat Intelligence System is a web platform for turning threat indicators into a clear,
prioritized investigation view. A user can submit an IP address, domain, URL, or file
hash and immediately receive an indicator type, risk score, severity, analysis summary,
MITRE ATT&CK techniques, and security recommendations. The result is stored and made
available through the dashboard, indicator list, and incident views.

The current demonstration uses synthetic threat intelligence data and an explainable,
rule-based analysis engine. This makes the workflow deterministic and easy to inspect
while leaving a clear integration point for production threat intelligence feeds.

## How It Works

The core workflow is:

1. The user submits an IP address, domain, URL, or file hash through the React frontend.
2. The FastAPI backend detects the indicator type and evaluates known demo intelligence
   and heuristic signals.
3. The analysis engine calculates a risk score, severity, confidence, category, tags,
   MITRE ATT&CK techniques, and recommendations.
4. The backend persists the indicator in SQLite and returns the result to the frontend.
5. The dashboard aggregates indicator and incident data so analysts can review trends,
   investigate incidents, and update incident status.

## Architecture Diagram

> See [`architecture.md`](architecture.md) for the detailed diagram.

```
[User]
   ↓
[React + Vite Frontend]
   ↓  /api/v1 requests
[FastAPI Backend]
   ├── [Indicator Detection and Explainable Risk Analysis]
   ├── [Incident and Dashboard API]
   └── [SQLite Database]
```

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Used an explainable rule-based analysis engine for the demonstration | Deterministic scoring makes the output reproducible, easy to test, and easy for an analyst to understand. |
| Used FastAPI with a React and Vite frontend | A separate API and frontend keep the user interface responsive while making the analysis endpoints easy to test and deploy. |
| Used SQLite for the demonstration database | SQLite keeps the project self-contained and simple to run locally without requiring a separate database service. |

## IBM Technologies Used

IBM Bob was used as the AI-assisted development environment for designing, implementing,
debugging, testing, and preparing the full-stack application and deployment workflow.
It is part of the development workflow rather than a runtime dependency of the deployed
application.

- **IBM Bob:** Used for AI-assisted coding, repository analysis, debugging, test
  verification, documentation, and deployment configuration.
