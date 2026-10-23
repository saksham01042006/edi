from __future__ import annotations

from typing import Any, Dict, List

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import FRONTEND_ORIGIN, PROJECT_NAME
from app.database import Base, SessionLocal, engine, get_db
from app.models import AnalysisRun, Finding, Policy, Project, SourceFile
from app.schemas import (
    AnalysisReport,
    AnalyzeRequest,
    GraphResponse,
    PolicyCreate,
    PolicyRead,
    ProjectCreate,
    ProjectRead,
    SourceFileCreate,
    SourceFileRead,
)
from app.services import (
    build_graph_response,
    create_policy,
    create_project,
    export_analysis_report,
    get_analysis,
    get_analysis_findings,
    get_project,
    get_projects,
    list_policies,
    list_project_analyses,
    run_analysis,
    save_source_file,
)

Base.metadata.create_all(bind=engine)

app = FastAPI(title=PROJECT_NAME, version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, "http://localhost:3000", "http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health_check() -> Dict[str, Any]:
    return {"status": "ok", "service": PROJECT_NAME, "database": "sqlite"}


@app.post("/api/projects", response_model=ProjectRead)
def create_project_endpoint(payload: ProjectCreate, db: Session = Depends(get_db)) -> Project:
    project = create_project(db, payload.name, payload.description)
    return project


@app.get("/api/projects", response_model=List[ProjectRead])
def list_projects_endpoint(db: Session = Depends(get_db)) -> List[Project]:
    return get_projects(db)


@app.get("/api/projects/{project_id}", response_model=ProjectRead)
def get_project_endpoint(project_id: str, db: Session = Depends(get_db)) -> Project:
    return get_project(db, project_id)


@app.post("/api/projects/{project_id}/files", response_model=SourceFileRead)
def create_source_file_endpoint(project_id: str, payload: SourceFileCreate, db: Session = Depends(get_db)) -> SourceFile:
    try:
        return save_source_file(db, project_id, payload.filename, payload.content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/projects/{project_id}/policies", response_model=List[PolicyRead])
def list_policies_endpoint(project_id: str, db: Session = Depends(get_db)) -> List[Policy]:
    return list_policies(db, project_id)


@app.post("/api/projects/{project_id}/policies", response_model=PolicyRead)
def create_policy_endpoint(project_id: str, payload: PolicyCreate, db: Session = Depends(get_db)) -> Policy:
    return create_policy(db, project_id, payload.model_dump())


@app.post("/api/projects/{project_id}/analyze")
def run_analysis_endpoint(project_id: str, payload: AnalyzeRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    try:
        analysis = run_analysis(
            db,
            project_id,
            payload.source_code,
            payload.file_name,
            payload.policies,
            payload.approved_destinations,
        )
        findings = get_analysis_findings(db, analysis.id)
        return {
            "analysis_id": analysis.id,
            "status": analysis.status,
            "message": analysis.summary,
            "findings": [
                {
                    "id": item.id,
                    "title": item.title,
                    "severity": item.severity,
                    "status": item.status,
                    "policy_name": item.policy_name,
                    "data_category": item.data_category,
                    "source": item.source,
                    "destination": item.destination,
                    "intermediate_path": item.intermediate_path,
                    "file_path": item.file_path,
                    "line_numbers": item.line_numbers,
                    "explanation": item.explanation,
                    "remediation": item.remediation,
                    "limitations": item.limitations,
                }
                for item in findings
            ],
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/analyses/{analysis_id}/graph", response_model=GraphResponse)
def analysis_graph_endpoint(analysis_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    analysis = get_analysis(db, analysis_id)
    findings = get_analysis_findings(db, analysis_id)
    return build_graph_response(findings)


@app.get("/api/analyses/{analysis_id}/findings")
def analysis_findings_endpoint(analysis_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    get_analysis(db, analysis_id)
    findings = get_analysis_findings(db, analysis_id)
    return {
        "analysis_id": analysis_id,
        "findings": [
            {
                "id": item.id,
                "title": item.title,
                "severity": item.severity,
                "status": item.status,
                "policy_name": item.policy_name,
                "data_category": item.data_category,
                "source": item.source,
                "destination": item.destination,
                "intermediate_path": item.intermediate_path,
                "file_path": item.file_path,
                "line_numbers": item.line_numbers,
                "explanation": item.explanation,
                "remediation": item.remediation,
                "limitations": item.limitations,
            }
            for item in findings
        ],
    }


@app.get("/api/projects/{project_id}/analyses")
def project_analyses_endpoint(project_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    get_project(db, project_id)
    analyses = list_project_analyses(db, project_id)
    return {
        "project_id": project_id,
        "analyses": [
            {
                "id": item.id,
                "status": item.status,
                "summary": item.summary,
                "findings_count": item.findings_count,
                "created_at": item.created_at.isoformat(),
            }
            for item in analyses
        ],
    }


@app.get("/api/analyses/{analysis_id}/report")
def analysis_report_endpoint(analysis_id: str, format: str = "json", db: Session = Depends(get_db)) -> Dict[str, Any]:
    if format.lower() != "json":
        raise HTTPException(status_code=400, detail="Only JSON export is currently supported.")
    return export_analysis_report(db, analysis_id)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
