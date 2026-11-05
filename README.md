# Sentinel API

Sentinel API is an API security governance workbench. Import an OpenAPI 3.x document, inspect its routes, run a deterministic baseline security review, track findings, and export a JSON report. It also serves a small dashboard and includes Docker and Render deployment manifests.

## Features

- OpenAPI 3.x JSON/YAML import with validation and normalized route inventory
- Security review for missing authentication, permissive CORS, missing rate limits, unsafe HTTP methods, unbounded collection responses, missing input schemas, and sensitive route patterns
- Severity, category, route, and remediation details for each finding
- SQLite persistence for projects and scans; optional PostgreSQL using `DATABASE_URL`
- JSON export, health endpoint, API docs, and a responsive dashboard
- Docker image, Docker Compose, Render Blueprint, and GitHub Actions CI workflow

## Run locally

Python 3.11+ is recommended.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. Interactive API docs are at `/docs`.

Alternatively, run `docker compose up --build` and visit the same address.

## API

- `GET /api/health` — liveness and storage status
- `GET /api/projects` — list projects
- `POST /api/projects` — create a project (`{"name":"Payments API","description":"..."}`)
- `POST /api/projects/{id}/scans` — analyze an OpenAPI file (multipart field `file`)
- `GET /api/projects/{id}/scans` — list scans
- `GET /api/scans/{id}` — scan details and findings
- `GET /api/scans/{id}/report` — download JSON report

The scanner analyzes the supplied API description only. It does not send requests to or test a live target. Findings are advisory and should be reviewed by a security engineer.

## Deployment

The repository includes `render.yaml` for a free Render demo web service. Its SQLite database uses the container's ephemeral filesystem, so project and scan data can be lost when the service restarts or redeploys. For durable production data, connect PostgreSQL with `DATABASE_URL` or use a paid service with persistent storage. The GitHub Actions workflow runs Python compilation checks on each push and pull request.

## Configuration

- `DATABASE_URL` — optional SQLAlchemy URL; defaults to SQLite at `./data/sentinel.db`
- `CORS_ORIGINS` — comma-separated allowed dashboard origins; defaults to same-origin only
- `MAX_UPLOAD_MB` — maximum OpenAPI upload size (default 5)
- `APP_ENV` — `development` or `production`

## Scope and production notes

This is a functional foundation for the concept in the supplied brief, not a certified compliance product. Phase two live traffic analysis, identity integrations, GraphQL introspection, machine-learning anomaly detection, and enterprise policy workflows are extension points. Add SSO, tenant isolation, managed database backups, audit retention, and a security review before exposing sensitive production API definitions.
