from __future__ import annotations

import ast
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker


PROJECT_NAME = "PrivTrace"
MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_FILE_SIZE_BYTES", "1048576"))
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{Path(__file__).resolve().with_name('privtrace.db').as_posix()}",
)
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

DEFAULT_POLICIES = [
    {
        "name": "no-password-logging",
        "description": "Passwords must not be logged or written to logs.",
        "category": "password",
        "config": {"approved_destinations": []},
    },
    {
        "name": "approved-api-destination",
        "description": "API keys must not be sent to unapproved external destinations.",
        "category": "api_key",
        "config": {"approved_destinations": ["api.example.com", "api.trusted.example.com"]},
    },
    {
        "name": "sensitive-email-logs",
        "description": "Email addresses must not be written to configured sensitive logs.",
        "category": "email",
        "config": {"approved_destinations": []},
    },
]


class Project(Base):
    __tablename__ = "projects"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    name = Column(String, nullable=False)
    description = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    files = relationship("SourceFile", back_populates="project", cascade="all, delete-orphan")
    policies = relationship("Policy", back_populates="project", cascade="all, delete-orphan")
    analyses = relationship("AnalysisRun", back_populates="project", cascade="all, delete-orphan")


class SourceFile(Base):
    __tablename__ = "source_files"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    filename = Column(String, nullable=False)
    internal_name = Column(String, nullable=False)
    content = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    project = relationship("Project", back_populates="files")


class Policy(Base):
    __tablename__ = "policies"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    name = Column(String, nullable=False)
    description = Column(String, default="")
    category = Column(String, nullable=False)
    config = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    project = relationship("Project", back_populates="policies")


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    status = Column(String, default="completed")
    summary = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    findings_count = Column(Integer, default=0)
    project = relationship("Project", back_populates="analyses")
    findings = relationship("Finding", back_populates="analysis", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    analysis_id = Column(String, ForeignKey("analysis_runs.id"), nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    status = Column(String, default="open")
    policy_name = Column(String, nullable=False)
    data_category = Column(String, nullable=False)
    source = Column(String, nullable=False)
    destination = Column(String, nullable=False)
    intermediate_path = Column(JSON, default=list)
    file_path = Column(String, default="")
    line_numbers = Column(JSON, default=list)
    explanation = Column(Text, default="")
    remediation = Column(Text, default="")
    limitations = Column(Text, default="")
    graph_payload = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    analysis = relationship("AnalysisRun", back_populates="findings")


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1)
    description: str = ""


class SourceFileCreate(BaseModel):
    filename: str
    content: str


class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    category: str
    config: dict[str, Any] = Field(default_factory=dict)


class AnalyzeRequest(BaseModel):
    source_code: str
    file_name: str = "main.py"
    policies: Optional[list[str]] = None
    approved_destinations: Optional[list[str]] = None


@dataclass
class TraceValue:
    category: str
    source: str
    path: list[str]
    lines: list[int] = field(default_factory=list)
    file: str = ""


SENSITIVE_KEYS = {
    "password": "password",
    "api_key": "api_key",
    "key": "api_key",
    "token": "api_key",
    "email": "email",
    "user_email": "email",
}
REQUEST_SINKS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
    "urllib.request.urlopen",
}
FILE_WRITE_SINKS = {"write", "writelines"}
LOGGING_CALLS = {"logger.info", "logging.info", "logger.warning", "logging.warning"}


def unique_preserve_order(items: list[Any]) -> list[Any]:
    seen = set()
    result = []
    for item in items:
        key = repr(item)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def get_attribute_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{get_attribute_name(node.value)}.{node.attr}"
    return ""


def find_sensitive_key(value: str) -> Optional[str]:
    lower = value.lower()
    for key, category in SENSITIVE_KEYS.items():
        if lower == key or lower.endswith(key) or lower.startswith(key):
            return category
    return None


def get_call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return f"{get_attribute_name(node.func.value)}.{node.func.attr}"
    return "call"


def safe_literal(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            literal = safe_literal(value)
            if literal is not None:
                parts.append(literal)
        return "".join(parts)
    if isinstance(node, ast.FormattedValue):
        return "{}"
    return None


def evaluate_expr(node: Optional[ast.AST], env: dict[str, TraceValue], file_name: str) -> Optional[TraceValue]:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        trace = env.get(node.id)
        return TraceValue(trace.category, trace.source, list(trace.path), list(trace.lines), trace.file) if trace else None
    if isinstance(node, ast.Attribute):
        base = evaluate_expr(node.value, env, file_name)
        if base is None:
            return None
        attribute_name = f"{base.source}.{node.attr}"
        return TraceValue(base.category, attribute_name, unique_preserve_order(base.path + [attribute_name]), list(base.lines), file_name)
    if isinstance(node, ast.Call):
        call_name = get_call_name(node)
        if ".get" in call_name and node.args:
            root_name = call_name.lower().split(".")[0]
            supported_roots = {"request", "req", "form", "payload", "params", "context"}
            if root_name not in supported_roots and "request" not in call_name.lower():
                return None
            key = safe_literal(node.args[0])
            category = find_sensitive_key(key) if key else None
            if category:
                label = f'{call_name}("{key}")'
                return TraceValue(category, label, [label], [node.lineno], file_name)
        return None
    if isinstance(node, ast.Subscript):
        return evaluate_expr(node.value, env, file_name)
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            literal_key = safe_literal(key)
            category = find_sensitive_key(literal_key) if literal_key else None
            if category:
                traced = evaluate_expr(value, env, file_name)
                return traced or TraceValue(category, literal_key, [literal_key], [node.lineno], file_name)
        return None
    if isinstance(node, ast.BinOp):
        left = evaluate_expr(node.left, env, file_name)
        right = evaluate_expr(node.right, env, file_name)
        if left and right:
            return TraceValue(left.category, left.source, unique_preserve_order(left.path + right.path),
                              unique_preserve_order(left.lines + right.lines), file_name)
        return left or right
    return None


def find_sensitive_reference_in_node(node: ast.AST, env: dict[str, TraceValue]) -> Optional[TraceValue]:
    if isinstance(node, (ast.Name, ast.Attribute, ast.Call, ast.Dict)):
        return evaluate_expr(node, env, "")
    if isinstance(node, ast.Subscript):
        return find_sensitive_reference_in_node(node.value, env)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        for item in node.elts:
            trace = find_sensitive_reference_in_node(item, env)
            if trace:
                return trace
    return None


def assign_name_to_env(target: ast.AST, trace: Optional[TraceValue], env: dict[str, TraceValue],
                       file_name: str, line_no: int) -> None:
    if not isinstance(target, ast.Name):
        return
    category = find_sensitive_key(target.id) or (trace.category if trace else "unknown")
    if trace:
        path = list(trace.path)
        if target.id not in path:
            path.append(target.id)
        env[target.id] = TraceValue(category, trace.source or target.id, path,
                                    unique_preserve_order([*trace.lines, line_no]), file_name)
    else:
        env.pop(target.id, None)


def build_graph_path(path_items: list[str], file_name: str, lines: list[int]) -> dict[str, Any]:
    nodes = []
    edges = []
    for index, item in enumerate(path_items):
        nodes.append({
            "id": f"n{index}", "label": item,
            "kind": "source" if index == 0 else "sink" if index == len(path_items) - 1 else "assignment",
            "file": file_name, "line": lines[index] if index < len(lines) else 0,
        })
        if index:
            edges.append({"id": f"e{index-1}-{index}", "source": f"n{index-1}", "target": f"n{index}"})
    return {"nodes": nodes, "edges": edges}


def get_request_destination(call: ast.Call) -> str:
    if call.args:
        destination = safe_literal(call.args[0])
        if destination:
            return destination
        if isinstance(call.args[0], ast.Name):
            return call.args[0].id
    for keyword in call.keywords:
        if keyword.arg == "url":
            return safe_literal(keyword.value) or "unknown"
    return "unknown"


def is_unapproved_destination(destination: str, approved: Iterable[str]) -> bool:
    parsed = urlparse(destination if "://" in destination else f"https://{destination}")
    host = (parsed.netloc or parsed.path).lower()
    approved_hosts = {
        entry.lower().replace("https://", "").replace("http://", "")
        for entry in approved
    }
    return bool(host) and host not in approved_hosts


def evaluate_call(call: ast.Call, env: dict[str, TraceValue], file_name: str,
                  approved_destinations: Iterable[str]) -> list[dict[str, Any]]:
    findings = []
    call_name = get_call_name(call)

    def add_finding(title: str, severity: str, policy_name: str, category: str, trace: TraceValue,
                    destination: str, explanation: str, remediation: str, limitations: str) -> None:
        path_items = [*trace.path, destination]
        lines = unique_preserve_order([*trace.lines, call.lineno])
        findings.append({
            "title": title, "severity": severity, "status": "open", "policy_name": policy_name,
            "data_category": category, "source": trace.source, "destination": destination,
            "intermediate_path": path_items, "file_path": file_name, "line_numbers": lines,
            "explanation": explanation, "remediation": remediation, "limitations": limitations,
            "graph_payload": build_graph_path(path_items, file_name, lines),
        })

    if call_name in LOGGING_CALLS:
        for arg in call.args:
            trace = find_sensitive_reference_in_node(arg, env)
            if trace and trace.category == "password":
                add_finding("Password value logged", "high", "no-password-logging", "password", trace,
                            call_name, "A sensitive password value flows into a logging sink without a redaction policy.",
                            "Remove the password from log arguments or mask it before logging.",
                            "This conservative analysis supports direct variable and alias propagation only.")
    if call_name in FILE_WRITE_SINKS:
        for arg in call.args:
            trace = find_sensitive_reference_in_node(arg, env)
            if trace:
                add_finding("Sensitive data written to file", "medium", "sensitive-email-logs", trace.category,
                            trace, call_name, "Sensitive data is written to a sink without explicit approval.",
                            "Review the write target and ensure the value is sanitized or encrypted.",
                            "Only direct writes and simple alias propagation are tracked.")
    if call_name in REQUEST_SINKS:
        destination = get_request_destination(call)
        traces = [find_sensitive_reference_in_node(node, env)
                  for node in [*call.args, *(kw.value for kw in call.keywords)]]
        for trace in traces:
            if trace and trace.category == "api_key" and is_unapproved_destination(destination, approved_destinations):
                add_finding("API key sent to unapproved destination", "high", "approved-api-destination",
                            "api_key", trace, destination,
                            "The API key value is sent to a destination that is not in the approved allowlist.",
                            "Use an approved endpoint or add the destination to the policy allowlist.",
                            "The analyzer operates on static syntax trees and cannot resolve dynamic URLs.")
    return findings


def analyze_python_source(source_code: str, file_name: str = "main.py",
                          approved_destinations: Optional[Iterable[str]] = None) -> dict[str, Any]:
    try:
        tree = ast.parse(source_code)
    except SyntaxError as exc:
        return {
            "ok": False,
            "error": {"title": "Syntax error", "message": f"Invalid Python syntax at line {exc.lineno}: {exc.msg}",
                      "line": exc.lineno},
            "findings": [], "graph": {"nodes": [], "edges": []},
        }
    env: dict[str, TraceValue] = {}
    findings: list[dict[str, Any]] = []
    approved = list(approved_destinations or [])

    def visit(statements: list[ast.stmt]) -> None:
        for statement in statements:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    assign_name_to_env(target, evaluate_expr(statement.value, env, file_name), env,
                                       file_name, statement.lineno)
            elif isinstance(statement, ast.AnnAssign):
                assign_name_to_env(statement.target, evaluate_expr(statement.value, env, file_name), env,
                                   file_name, statement.lineno)
            elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                findings.extend(evaluate_call(statement.value, env, file_name, approved))
            elif isinstance(statement, (ast.If, ast.With, ast.Try, ast.For, ast.While)):
                visit(list(getattr(statement, "body", [])))
                visit(list(getattr(statement, "orelse", [])))
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(statement.body)

    visit(tree.body)
    nodes, edges = [], []
    for finding_index, finding in enumerate(findings):
        path = finding["intermediate_path"]
        lines = finding["line_numbers"]
        for index, label in enumerate(path):
            node_id = f"finding-{finding_index}-{index}"
            nodes.append({
                "id": node_id, "label": label,
                "kind": "source" if index == 0 else "sink" if index == len(path) - 1 else "assignment",
                "file": file_name, "line": lines[index] if index < len(lines) else 0,
            })
            if index:
                edges.append({"id": f"edge-{finding_index}-{index}",
                              "source": f"finding-{finding_index}-{index-1}", "target": node_id})
    return {"ok": True, "findings": findings, "graph": {"nodes": nodes, "edges": edges}, "error": None}


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_project(db: Session, project_id: str) -> Project:
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def get_analysis(db: Session, analysis_id: str) -> AnalysisRun:
    analysis = db.query(AnalysisRun).filter(AnalysisRun.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis


def serialize_finding(item: Finding) -> dict[str, Any]:
    return {
        "id": item.id, "title": item.title, "severity": item.severity, "status": item.status,
        "policy_name": item.policy_name, "data_category": item.data_category, "source": item.source,
        "destination": item.destination, "intermediate_path": item.intermediate_path,
        "file_path": item.file_path, "line_numbers": item.line_numbers, "explanation": item.explanation,
        "remediation": item.remediation, "limitations": item.limitations,
    }


def get_findings(db: Session, analysis_id: str) -> list[Finding]:
    get_analysis(db, analysis_id)
    return db.query(Finding).filter(Finding.analysis_id == analysis_id).order_by(Finding.created_at.asc()).all()


def create_project(db: Session, name: str, description: str) -> Project:
    project = Project(name=name.strip(), description=description.strip())
    db.add(project)
    db.commit()
    db.refresh(project)
    for item in DEFAULT_POLICIES:
        db.add(Policy(project_id=project.id, **item))
    db.commit()
    return project


Base.metadata.create_all(bind=engine)
app = FastAPI(title=PROJECT_NAME, version="0.1.0")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard() -> str:
    return DASHBOARD_HTML


@app.get("/api/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": PROJECT_NAME, "database": "sqlite"}


@app.post("/api/projects")
def create_project_endpoint(payload: ProjectCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    if not payload.name.strip():
        raise HTTPException(status_code=422, detail="Project name cannot be empty.")
    project = create_project(db, payload.name, payload.description)
    return {
        "id": project.id, "name": project.name, "description": project.description,
        "created_at": project.created_at, "updated_at": project.updated_at,
    }


@app.get("/api/projects")
def list_projects_endpoint(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    projects = db.query(Project).order_by(Project.created_at.desc()).all()
    return [{"id": p.id, "name": p.name, "description": p.description,
             "created_at": p.created_at, "updated_at": p.updated_at} for p in projects]


@app.get("/api/projects/{project_id}")
def get_project_endpoint(project_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    p = get_project(db, project_id)
    return {"id": p.id, "name": p.name, "description": p.description,
            "created_at": p.created_at, "updated_at": p.updated_at}


@app.post("/api/projects/{project_id}/files")
def create_source_file_endpoint(project_id: str, payload: SourceFileCreate,
                                db: Session = Depends(get_db)) -> dict[str, Any]:
    project = get_project(db, project_id)
    filename = Path(payload.filename).name
    if not filename or filename != payload.filename or Path(filename).suffix.lower() != ".py":
        raise HTTPException(status_code=400, detail="Only safe Python source filenames (.py) are supported.")
    if len(payload.content.encode("utf-8")) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=400, detail="Source file is larger than the allowed limit.")
    file_record = SourceFile(project_id=project.id, filename=filename,
                             internal_name=f"{project.id}-{uuid4().hex}.py", content=payload.content)
    db.add(file_record)
    db.commit()
    db.refresh(file_record)
    return {"id": file_record.id, "project_id": file_record.project_id, "filename": filename,
            "internal_name": file_record.internal_name, "content": file_record.content,
            "created_at": file_record.created_at}


@app.get("/api/projects/{project_id}/policies")
def list_policies_endpoint(project_id: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    get_project(db, project_id)
    policies = db.query(Policy).filter(Policy.project_id == project_id).all()
    return [{"id": p.id, "project_id": p.project_id, "name": p.name, "description": p.description,
             "category": p.category, "config": p.config, "created_at": p.created_at} for p in policies]


@app.post("/api/projects/{project_id}/policies")
def create_policy_endpoint(project_id: str, payload: PolicyCreate,
                           db: Session = Depends(get_db)) -> dict[str, Any]:
    get_project(db, project_id)
    policy = Policy(project_id=project_id, name=payload.name, description=payload.description,
                    category=payload.category, config=payload.config)
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return {"id": policy.id, "project_id": policy.project_id, "name": policy.name,
            "description": policy.description, "category": policy.category,
            "config": policy.config, "created_at": policy.created_at}


@app.post("/api/projects/{project_id}/analyze")
def run_analysis_endpoint(project_id: str, payload: AnalyzeRequest,
                          db: Session = Depends(get_db)) -> dict[str, Any]:
    get_project(db, project_id)
    approved = payload.approved_destinations
    if approved is None:
        approved = DEFAULT_POLICIES[1]["config"]["approved_destinations"]
    result = analyze_python_source(payload.source_code, payload.file_name, approved)
    analysis = AnalysisRun(
        project_id=project_id, status="completed" if result["ok"] else "failed",
        summary="Analysis completed", findings_count=0,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    for item in result["findings"]:
        db.add(Finding(analysis_id=analysis.id, **item))
    db.commit()
    analysis.findings_count = len(result["findings"])
    analysis.summary = (f"Detected {analysis.findings_count} potential issues."
                        if analysis.findings_count else "No issues detected in the submitted source code.")
    db.commit()
    return {
        "analysis_id": analysis.id, "status": analysis.status, "message": analysis.summary,
        "findings": [serialize_finding(item) for item in get_findings(db, analysis.id)],
    }


@app.get("/api/analyses/{analysis_id}/graph")
def analysis_graph_endpoint(analysis_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    findings = get_findings(db, analysis_id)
    nodes, edges = [], []
    for finding in findings:
        graph = finding.graph_payload or {"nodes": [], "edges": []}
        nodes.extend(graph.get("nodes", []))
        edges.extend(graph.get("edges", []))
    return {"nodes": nodes, "edges": edges}


@app.get("/api/analyses/{analysis_id}/findings")
def analysis_findings_endpoint(analysis_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"analysis_id": analysis_id, "findings": [serialize_finding(f) for f in get_findings(db, analysis_id)]}


@app.get("/api/projects/{project_id}/analyses")
def project_analyses_endpoint(project_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    get_project(db, project_id)
    analyses = db.query(AnalysisRun).filter(AnalysisRun.project_id == project_id) \
        .order_by(AnalysisRun.created_at.desc()).all()
    return {"project_id": project_id, "analyses": [
        {"id": a.id, "status": a.status, "summary": a.summary,
         "findings_count": a.findings_count, "created_at": a.created_at.isoformat()}
        for a in analyses
    ]}


@app.get("/api/analyses/{analysis_id}/report")
def analysis_report_endpoint(analysis_id: str, format: str = "json",
                             db: Session = Depends(get_db)) -> dict[str, Any]:
    if format.lower() != "json":
        raise HTTPException(status_code=400, detail="Only JSON export is currently supported.")
    analysis = get_analysis(db, analysis_id)
    findings = get_findings(db, analysis_id)
    graph = {"nodes": [], "edges": []}
    for finding in findings:
        graph["nodes"].extend((finding.graph_payload or {}).get("nodes", []))
        graph["edges"].extend((finding.graph_payload or {}).get("edges", []))
    return {"project_id": analysis.project_id, "analysis_id": analysis.id,
            "status": analysis.status, "summary": analysis.summary,
            "findings": [serialize_finding(f) for f in findings], "graph": graph}


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PrivTrace</title>
<style>
:root{font-family:Inter,system-ui,Segoe UI,sans-serif;color:#0f172a;background:#edf4ff;line-height:1.5}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:linear-gradient(180deg,#f8fbff,#edf4ff)}
button,input,select,textarea{font:inherit}button{cursor:pointer}
.layout{display:flex;min-height:100vh}.sidebar{width:250px;background:#fff;border-right:1px solid #e2e8f0;padding:24px 18px}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:30px}.mark{width:42px;height:42px;border-radius:12px;
display:grid;place-items:center;background:linear-gradient(135deg,#0ea5e9,#38bdf8);color:white;font-weight:800}
.brand small{display:block;color:#475569;font-size:12px}.nav{padding:10px 12px;border-radius:10px;color:#334155;background:#e0f2fe;font-weight:600}
main{flex:1;padding:28px;max-width:1600px;margin:auto;width:100%}.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:22px}
.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:#0369a1}h1{margin:4px 0 0;font-size:clamp(25px,3vw,38px)}
h2{font-size:18px;margin:0}.badge{border:1px solid #bae6fd;background:#f0f9ff;color:#0369a1;border-radius:999px;padding:8px 12px;font-size:13px}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:18px}
.card,.stat{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:18px;box-shadow:0 8px 20px #0f172a08}
.stat span{color:#475569;font-size:13px}.stat strong{display:block;font-size:32px;margin-top:6px}
.grid{display:grid;grid-template-columns:2fr 1fr;gap:18px;margin-bottom:18px}.grid.lower{grid-template-columns:1.15fr .85fr}
.card h2{margin-bottom:15px}.toolbar{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:12px}
input,select,textarea{border:1px solid #cbd5e1;border-radius:9px;background:white;color:#0f172a;padding:10px 12px}
input,select{min-width:150px}.primary{border:0;border-radius:9px;background:linear-gradient(135deg,#0284c7,#38bdf8);color:#fff;padding:10px 15px;font-weight:700}
button:disabled{opacity:.55;cursor:wait}textarea{width:100%;min-height:270px;resize:vertical;font-family:Consolas,monospace;line-height:1.6}
.list{display:grid;gap:10px}.item{border:1px solid #e2e8f0;border-radius:11px;padding:12px;background:#f8fafc}
.finding{width:100%;text-align:left;color:#0f172a;cursor:pointer}.finding.selected{border-color:#38bdf8;background:#f0f9ff}
.topline{display:flex;justify-content:space-between;gap:10px;align-items:center;font-size:13px;margin-bottom:5px}
.pill{border-radius:999px;padding:3px 8px;text-transform:uppercase;font-size:11px;font-weight:700}
.high{background:#fee2e2;color:#b91c1c}.medium{background:#fef3c7;color:#a16207}.low{background:#dcfce7;color:#166534}
.empty{padding:14px;color:#64748b}.error{margin-top:10px;background:#fee2e2;color:#b91c1c;padding:10px;border-radius:9px}
#graph{height:340px;overflow:auto;border-radius:12px;background:linear-gradient(#f8fbff,#eef6ff);position:relative}
#graph svg{min-width:100%;height:100%}.node{fill:#dbeafe;stroke:#60a5fa;stroke-width:1.5}.node.source{fill:#cffafe;stroke:#0891b2}.node.sink{fill:#fee2e2;stroke:#ef4444}
.node-label{font-size:12px;fill:#0f172a}.edge{stroke:#94a3b8;stroke-width:2;marker-end:url(#arrow)}
.details{display:grid;grid-template-columns:1fr 1fr;gap:18px}.detail{padding:8px 0;border-bottom:1px solid #e2e8f0;display:flex;justify-content:space-between;gap:12px}
.detail span{color:#64748b}.summary{display:flex;gap:24px;flex-wrap:wrap}.notice{color:#64748b;font-size:12px;margin-top:12px}
@media(max-width:900px){.layout{display:block}.sidebar{width:100%;padding:16px}.brand{margin-bottom:12px}.grid,.grid.lower{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}main{padding:18px}.details{grid-template-columns:1fr}.top{align-items:flex-start;gap:10px;flex-direction:column}}
</style></head>
<body><div class="layout"><aside class="sidebar"><div class="brand"><div class="mark">P</div><div><strong>PrivTrace</strong><small>Policy-aware leakage analysis</small></div></div><div class="nav">Dashboard</div></aside>
<main><header class="top"><div><div class="eyebrow">System status</div><h1>PrivTrace security dashboard</h1></div><div id="health" class="badge">Checking backend...</div></header>
<section class="stats"><div class="stat"><span>Projects</span><strong id="project-count">0</strong></div><div class="stat"><span>Analyses</span><strong id="analysis-count">0</strong></div><div class="stat"><span>High severity</span><strong id="high-count">0</strong></div><div class="stat"><span>Medium severity</span><strong id="medium-count">0</strong></div></section>
<section class="grid"><div class="card"><h2>Code Analyzer</h2><div class="toolbar"><input id="project-name" placeholder="New project name"><button id="create-project" class="primary">Create project</button><select id="projects"></select><button id="analyze" class="primary">Analyze</button></div>
<textarea id="source">def login(request):
    password = request.get("password")
    attempted_value = password
    logger.info("Login attempt: %s", attempted_value)
</textarea><div id="error"></div><div class="notice">Source code is parsed statically and is never executed.</div></div>
<div class="card"><h2>Recent analysis history</h2><div id="history" class="list"><div class="empty">No analysis history yet.</div></div></div></section>
<section class="grid lower"><div class="card"><h2>Graph explorer</h2><div id="graph"><div class="empty">Run an analysis to visualize the flow.</div></div></div>
<div class="card"><h2>Findings</h2><div id="findings" class="list"><div class="empty">No findings detected.</div></div></div></section>
<section id="finding-detail" class="card" hidden><h2>Finding detail</h2><div id="detail-grid" class="details"></div><p id="explanation"></p><p><b>Remediation:</b> <span id="remediation"></span></p><p><b>Limitations:</b> <span id="limitations"></span></p></section>
<section class="card"><h2>Analysis summary</h2><div id="summary" class="summary"><span>Total findings: 0</span><span>High: 0</span><span>Medium: 0</span></div></section></main></div>
<script>
const $=id=>document.getElementById(id);let projects=[],analyses=[],findings=[],selectedId='';
async function api(path,options={}){const response=await fetch(path,{headers:{'Content-Type':'application/json'},...options});const data=await response.json().catch(()=>({}));if(!response.ok)throw Error(data.detail||'Request failed');return data}
function setError(message=''){ $('error').className=message?'error':'';$('error').textContent=message}
async function loadProjects(){projects=await api('/api/projects');$('project-count').textContent=projects.length;$('projects').replaceChildren(...projects.map(p=>{const o=document.createElement('option');o.value=p.id;o.textContent=p.name;return o}));if(projects.length)await loadAnalyses($('projects').value)}
async function loadAnalyses(id){if(!id)return;const r=await api(`/api/projects/${id}/analyses`);analyses=r.analyses||[];$('analysis-count').textContent=analyses.length;$('history').replaceChildren();if(!analyses.length){$('history').innerHTML='<div class="empty">No analysis history yet.</div>';return}
for(const a of analyses){const el=document.createElement('div');el.className='item';el.textContent=`${a.status} · ${a.findings_count} findings · ${a.summary}`;$('history').append(el)}
for(const a of analyses){const f=await api(`/api/analyses/${a.id}/findings`);if(f.findings?.length){findings=f.findings;const g=await api(`/api/analyses/${a.id}/graph`);renderFindings();renderGraph(g);return}}findings=[];renderFindings()}
$('projects').addEventListener('change',()=>loadAnalyses($('projects').value).catch(e=>setError(e.message)));
$('create-project').addEventListener('click',async()=>{const name=$('project-name').value.trim();if(!name)return;try{const p=await api('/api/projects',{method:'POST',body:JSON.stringify({name,description:'PrivTrace project'})});$('project-name').value='';await loadProjects();$('projects').value=p.id;await loadAnalyses(p.id)}catch(e){setError(e.message)}});
$('analyze').addEventListener('click',async()=>{if(!$('projects').value){setError('Create or select a project first.');return}setError('');$('analyze').disabled=true;$('analyze').textContent='Analyzing...';try{const r=await api(`/api/projects/${$('projects').value}/analyze`,{method:'POST',body:JSON.stringify({source_code:$('source').value,file_name:'demo_login.py',policies:['no-password-logging'],approved_destinations:['api.example.com']})});findings=r.findings||[];selectedId=findings[0]?.id||'';renderFindings();const g=await api(`/api/analyses/${r.analysis_id}/graph`);renderGraph(g);await loadAnalyses($('projects').value)}catch(e){setError(e.message)}finally{$('analyze').disabled=false;$('analyze').textContent='Analyze'}});
function renderFindings(){$('findings').replaceChildren();if(!findings.length){$('findings').innerHTML='<div class="empty">No findings detected.</div>'}for(const f of findings){const b=document.createElement('button');b.className=`item finding ${selectedId===f.id?'selected':''}`;const top=document.createElement('div');top.className='topline';const pill=document.createElement('span');pill.className=`pill ${f.severity}`;pill.textContent=f.severity;const policy=document.createElement('span');policy.textContent=f.policy_name;top.append(pill,policy);const title=document.createElement('b');title.textContent=f.title;const path=document.createElement('div');path.textContent=`${f.source} → ${f.destination}`;b.append(top,title,path);b.addEventListener('click',()=>{selectedId=f.id;renderFindings();showDetail(f)});$('findings').append(b)}const high=findings.filter(f=>f.severity==='high').length,medium=findings.filter(f=>f.severity==='medium').length;$('high-count').textContent=high;$('medium-count').textContent=medium;$('summary').innerHTML=`<span>Total findings: <b>${findings.length}</b></span><span>High: <b>${high}</b></span><span>Medium: <b>${medium}</b></span>`;if(findings.length)showDetail(findings.find(f=>f.id===selectedId)||findings[0]);else $('finding-detail').hidden=true}
function showDetail(f){$('finding-detail').hidden=false;const fields=[['Title',f.title],['Severity',f.severity],['Policy',f.policy_name],['Category',f.data_category],['Source',f.source],['Destination',f.destination],['Line(s)',(f.line_numbers||[]).join(', ')||'n/a'],['Path',(f.intermediate_path||[]).join(' → ')]];$('detail-grid').replaceChildren();for(const [label,value] of fields){const row=document.createElement('div');row.className='detail';const a=document.createElement('span');a.textContent=label;const b=document.createElement('strong');b.textContent=value;row.append(a,b);$('detail-grid').append(row)}$('explanation').textContent=f.explanation;$('remediation').textContent=f.remediation;$('limitations').textContent=f.limitations}
function renderGraph(graph){const wrap=$('graph');wrap.replaceChildren();if(!graph.nodes?.length){wrap.innerHTML='<div class="empty">No graph data yet. Run an analysis to visualize the flow.</div>';return}const nodes=graph.nodes,w=Math.max(wrap.clientWidth, nodes.length*190),h=300;const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox',`0 0 ${w} ${h}`);const defs=document.createElementNS(svg.namespaceURI,'defs'),marker=document.createElementNS(svg.namespaceURI,'marker');marker.setAttribute('id','arrow');marker.setAttribute('markerWidth','10');marker.setAttribute('markerHeight','10');marker.setAttribute('refX','8');marker.setAttribute('refY','3');marker.setAttribute('orient','auto');const tip=document.createElementNS(svg.namespaceURI,'path');tip.setAttribute('d','M0,0 L0,6 L9,3 z');tip.setAttribute('fill','#94a3b8');marker.append(tip);defs.append(marker);svg.append(defs);const pos={};nodes.forEach((n,i)=>pos[n.id]={x:30+i*180,y:105});
for(const e of graph.edges||[]){if(!pos[e.source]||!pos[e.target])continue;const line=document.createElementNS(svg.namespaceURI,'line');line.setAttribute('x1',pos[e.source].x+140);line.setAttribute('y1',pos[e.source].y+28);line.setAttribute('x2',pos[e.target].x);line.setAttribute('y2',pos[e.target].y+28);line.setAttribute('class','edge');svg.append(line)}
for(const n of nodes){const p=pos[n.id],g=document.createElementNS(svg.namespaceURI,'g'),rect=document.createElementNS(svg.namespaceURI,'rect'),text=document.createElementNS(svg.namespaceURI,'text');rect.setAttribute('x',p.x);rect.setAttribute('y',p.y);rect.setAttribute('width','140');rect.setAttribute('height','56');rect.setAttribute('rx','10');rect.setAttribute('class',`node ${n.kind}`);text.setAttribute('x',p.x+8);text.setAttribute('y',p.y+24);text.setAttribute('class','node-label');text.textContent=n.label.length>19?n.label.slice(0,18)+'…':n.label;g.append(rect,text);svg.append(g)}wrap.append(svg)}
api('/api/health').then(x=>{$('health').textContent=`${x.status} · ${x.service}`}).catch(()=>{$('health').textContent='Backend unavailable'});
loadProjects().catch(e=>setError(e.message));
</script></body></html>"""


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
