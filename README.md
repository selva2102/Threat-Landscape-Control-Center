# Cyber Threat Platform (MVP)

## Quick Start

### Backend

```bash
cd apps/backend
python -m venv .venv
. .venv/Scripts/Activate.ps1
pip install -r requirements.txt
python main.py
```

### Dashboard

```bash
cd apps/dashboard
pnpm install
pnpm dev
```

Open the dashboard at `http://localhost:3000` and the API at `http://localhost:8000`.

## API

- `GET /health`
- `GET /indicators?q=search`

## Structure

- apps/dashboard: Next.js 15 UI
- apps/backend: FastAPI API
- packages/types: shared indicator schema
- packages/threat-intel: mock connector
- infra: honeypot + scripts

### Docker Compose

```bash
docker compose up --build
```

Dashboard: `http://localhost:3000`
Backend: `http://localhost:8000`
