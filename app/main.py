import os
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .database import Base, DATABASE_URL, engine, get_db
from .models import Project, Scan
from .scanner import SpecError, inspect_spec, parse_spec, summarize

Base.metadata.create_all(bind=engine)
app = FastAPI(title="Sentinel API", version="1.0.0",
              description="API security governance workbench for OpenAPI 3.x documents.")
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_MB", "5")) * 1024 * 1024


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=140)
    description: str = Field(default="", max_length=2000)


def project_view(project: Project):
    return {"id": project.id, "name": project.name, "description": project.description,
            "created_at": project.created_at.isoformat(), "scan_count": len(project.scans),
            "latest_scan": scan_view(project.scans[-1]) if project.scans else None}


def scan_view(scan: Scan):
    return {"id": scan.id, "project_id": scan.project_id, "api_title": scan.api_title,
            "api_version": scan.api_version, "source_filename": scan.source_filename,
            "endpoint_count": scan.endpoint_count, "findings_count": scan.findings_count,
            "summary": summarize(scan.findings), "created_at": scan.created_at.isoformat()}


@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status": "ok", "service": "sentinel-api", "storage": "connected"}


@app.get("/api/projects")
def list_projects(db: Session = Depends(get_db)):
    projects = db.scalars(select(Project).order_by(Project.created_at.desc())).all()
    return [project_view(p) for p in projects]


@app.post("/api/projects", status_code=201)
def create_project(body: ProjectCreate, db: Session = Depends(get_db)):
    project = Project(name=body.name.strip(), description=body.description.strip())
    if not project.name:
        raise HTTPException(422, "Project name cannot be blank.")
    db.add(project)
    db.commit()
    db.refresh(project)
    return project_view(project)


@app.delete("/api/projects/{project_id}", status_code=204)
def delete_project(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found.")
    db.delete(project)
    db.commit()


@app.get("/api/projects/{project_id}/scans")
def list_scans(project_id: int, db: Session = Depends(get_db)):
    if not db.get(Project, project_id):
        raise HTTPException(404, "Project not found.")
    scans = db.scalars(select(Scan).where(Scan.project_id == project_id).order_by(Scan.created_at.desc())).all()
    return [scan_view(s) for s in scans]


@app.post("/api/projects/{project_id}/scans", status_code=201)
async def create_scan(project_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found.")
    filename = Path(file.filename or "openapi.yaml").name
    if Path(filename).suffix.lower() not in {".yaml", ".yml", ".json"}:
        raise HTTPException(415, "Upload an OpenAPI .json, .yaml, or .yml file.")
    content = await file.read(MAX_UPLOAD + 1)
    if len(content) > MAX_UPLOAD:
        raise HTTPException(413, f"File exceeds the {MAX_UPLOAD // (1024 * 1024)} MB upload limit.")
    try:
        spec = parse_spec(content, filename)
    except SpecError as exc:
        raise HTTPException(422, str(exc)) from exc
    endpoints, findings = inspect_spec(spec)
    info = spec.get("info") or {}
    scan = Scan(project_id=project.id, api_title=str(info.get("title", "Untitled API"))[:200],
                api_version=str(info.get("version", ""))[:60], source_filename=filename[:255],
                endpoint_count=len(endpoints), findings_count=len(findings), findings=findings,
                endpoints=endpoints)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return {**scan_view(scan), "findings": scan.findings, "endpoints": scan.endpoints}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return {**scan_view(scan), "findings": scan.findings, "endpoints": scan.endpoints}


@app.get("/api/scans/{scan_id}/report")
def scan_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found.")
    return {**scan_view(scan), "findings": scan.findings, "endpoints": scan.endpoints,
            "report_type": "openapi-static-analysis", "limitations": "Advisory static analysis; no live target traffic was tested."}


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse("app/static/index.html")


app.mount("/static", StaticFiles(directory="app/static"), name="static")
