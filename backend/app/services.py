from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .analyzer import analyze_python_source
from .config import MAX_FILE_SIZE_BYTES
from .models import AnalysisRun, Finding, Policy, Project, SourceFile
from .policies import DEFAULT_POLICIES

VALID_EXTENSIONS = {".py"}


def create_project(db: Session, name: str, description: str = "") -> Project:
    project = Project(name=name.strip(), description=description.strip())
    db.add(project)
    db.commit()
    db.refresh(project)
    for policy in DEFAULT_POLICIES:
        db.add(
            Policy(
                project_id=project.id,
                name=policy["name"],
                description=policy["description"],
                category=policy["category"],
                config=policy.get("config", {}),
            )
        )
    db.commit()
    return project


def get_projects(db: Session) -> List[Project]:
    return db.query(Project).order_by(Project.created_at.desc()).all()


def get_project(db: Session, project_id: str) -> Project:
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def validate_python_filename(filename: str) -> str:
    clean_name = Path(filename).name
    if not clean_name or clean_name != filename:
        raise ValueError("Provided filename is invalid and may be unsafe.")
    suffix = Path(clean_name).suffix.lower()
    if suffix not in VALID_EXTENSIONS:
        raise ValueError("Only Python source files (.py) are supported.")
    return clean_name


def save_source_file(db: Session, project_id: str, filename: str, content: str) -> SourceFile:
    project = get_project(db, project_id)
    clean_name = validate_python_filename(filename)
    if len(content.encode("utf-8")) > MAX_FILE_SIZE_BYTES:
        raise ValueError("Source file is larger than the allowed limit.")
    internal_name = f"{project.id}-{uuid4().hex}{Path(clean_name).suffix}"
    file_record = SourceFile(project_id=project.id, filename=clean_name, internal_name=internal_name, content=content)
    db.add(file_record)
    db.commit()
    db.refresh(file_record)
    return file_record


def list_policies(db: Session, project_id: str) -> List[Policy]:
    get_project(db, project_id)
    return db.query(Policy).filter(Policy.project_id == project_id).all()


def create_policy(db: Session, project_id: str, payload: Dict[str, Any]) -> Policy:
    get_project(db, project_id)
    policy = Policy(
        project_id=project_id,
        name=payload["name"],
        description=payload.get("description", ""),
        category=payload["category"],
        config=payload.get("config", {}),
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


def list_project_analyses(db: Session, project_id: str) -> List[AnalysisRun]:
    get_project(db, project_id)
    return db.query(AnalysisRun).filter(AnalysisRun.project_id == project_id).order_by(AnalysisRun.created_at.desc()).all()


def run_analysis(db: Session, project_id: str, source_code: str, file_name: str, policy_names: Optional[List[str]] = None, approved_destinations: Optional[List[str]] = None) -> AnalysisRun:
    get_project(db, project_id)
    selected_policies = policy_names or [policy["name"] for policy in DEFAULT_POLICIES]
    approved = approved_destinations or [
        item["config"].get("approved_destinations", [])
        for item in DEFAULT_POLICIES
        if item["name"] == "approved-api-destination"
    ]
    flat_approved = []
    for entry in approved:
        if isinstance(entry, list):
            flat_approved.extend(entry)
        else:
            flat_approved.append(entry)

    result = analyze_python_source(source_code, file_name=file_name, approved_destinations=flat_approved)
    analysis_run = AnalysisRun(project_id=project_id, status="completed" if result["ok"] else "failed", summary=result.get("error", {}).get("message", "Analysis completed") if not result["ok"] else "Analysis completed", findings_count=0)
    db.add(analysis_run)
    db.commit()
    db.refresh(analysis_run)
    findings = result.get("findings", [])
    for item in findings:
        finding_record = Finding(
            analysis_id=analysis_run.id,
            title=item["title"],
            severity=item["severity"],
            status=item["status"],
            policy_name=item["policy_name"],
            data_category=item["data_category"],
            source=item["source"],
            destination=item["destination"],
            intermediate_path=item["intermediate_path"],
            file_path=item["file_path"],
            line_numbers=item["line_numbers"],
            explanation=item["explanation"],
            remediation=item["remediation"],
            limitations=item["limitations"],
            graph_payload=item["graph_payload"],
        )
        db.add(finding_record)
    db.commit()
    analysis_run.findings_count = len(findings)
    analysis_run.summary = f"Detected {len(findings)} potential issues." if findings else "No issues detected in the submitted source code."
    db.commit()
    return analysis_run


def get_analysis(db: Session, analysis_id: str) -> AnalysisRun:
    analysis = db.query(AnalysisRun).filter(AnalysisRun.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis


def get_analysis_findings(db: Session, analysis_id: str) -> List[Finding]:
    get_analysis(db, analysis_id)
    return db.query(Finding).filter(Finding.analysis_id == analysis_id).order_by(Finding.created_at.asc()).all()


def build_graph_response(findings: List[Finding]) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    for finding in findings:
        payload = finding.graph_payload or {"nodes": [], "edges": []}
        for node in payload.get("nodes", []):
            nodes.append(node)
        for edge in payload.get("edges", []):
            edges.append(edge)
    return {"nodes": nodes, "edges": edges}


def export_analysis_report(db: Session, analysis_id: str) -> Dict[str, Any]:
    analysis = get_analysis(db, analysis_id)
    findings = get_analysis_findings(db, analysis_id)
    payload = {
        "project_id": analysis.project_id,
        "analysis_id": analysis.id,
        "status": analysis.status,
        "summary": analysis.summary,
        "findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "policy_name": finding.policy_name,
                "data_category": finding.data_category,
                "source": finding.source,
                "destination": finding.destination,
                "intermediate_path": finding.intermediate_path,
                "file_path": finding.file_path,
                "line_numbers": finding.line_numbers,
                "explanation": finding.explanation,
                "remediation": finding.remediation,
                "limitations": finding.limitations,
            }
            for finding in findings
        ],
        "graph": build_graph_response(findings),
    }
    return payload
