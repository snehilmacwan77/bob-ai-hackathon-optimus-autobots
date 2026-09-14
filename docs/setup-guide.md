# Setup Guide

> **This file is read by the automated evaluation pipeline. Be precise and complete.**

## Prerequisites

Before you begin, ensure you have the following installed:

- [x] Python 3.11+
- [x] Node.js 18+ (with npm)
- [x] Git

> **No external API keys are required.** All threat intelligence data is synthetic.

## Environment Variables

No mandatory environment variables are required for the demo.  
Optional: copy `src/.env.example` to `src/.env` to customise the database path.

```bash
cp src/.env.example src/.env
```

| Variable | Description | Required |
|---|---|---|
| `DATABASE_URL` | SQLite connection string (default: `sqlite:///threat_intel.db`) | No |
| `APP_PORT` | Backend port (default: 9000) | No |

## Installation

```bash
# 1. Clone the repository
git clone <repo-url>
cd bob-ai-hackathon-optimus-autobots

# 2. Install backend dependencies
cd src/backend
pip install -r requirements.txt

# 3. Install frontend dependencies
cd ../frontend
npm install
```

## Running the Application

### Backend

```bash
cd src/backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 9000
```

The API will be available at: `http://localhost:9000`  
Interactive API docs: `http://localhost:9000/docs`

Demo data is **automatically seeded on first startup** — no manual step needed.

### Frontend

```bash
cd src/frontend
npm run dev
```

The UI will be available at: `http://localhost:5174`

> The Vite dev server proxies `/api` requests to `http://localhost:9000` automatically.

## Running Tests

```bash
cd src/backend
python -m pytest tests/ -v
```

Expected output: **18 passed** in < 2 seconds.

## Building for Production

```bash
# Frontend
cd src/frontend
npm run build
# Output: src/frontend/dist/

# Backend (serve with any WSGI/ASGI host)
cd src/backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 9000 --workers 2
```

## Quick Demo

1. Start the backend (`uvicorn`) and frontend (`npm run dev`)
2. Open `http://localhost:5174`
3. The **Dashboard** loads immediately with 30 pre-seeded threat indicators and 5 incidents
4. Navigate to **Analyze IOC** and enter:
   - IP: `185.220.101.45` → critical Tor exit node
   - Domain: `update.microsofft.com` → critical phishing domain
   - Hash: `44d88612fea8a8f36de82e1278abb02f` → WannaCry ransomware
5. Navigate to **Incidents** → click **Ransomware C2 Beacon Detected** for the full investigation view

## Troubleshooting

| Issue | Solution |
|---|---|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` from `src/backend/` |
| `npm ERR! Cannot find module` | Run `npm install` from `src/frontend/` |
| Backend port already in use | Change port: `uvicorn app.main:app --port 9001` |
| Frontend can't reach API | Ensure backend runs on port 9000; check `vite.config.ts` proxy |
| Empty dashboard | Call `POST /api/v1/demo/seed` or restart the backend |
