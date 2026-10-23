from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1)
    description: str = ""


class ProjectRead(BaseModel):
    id: str
    name: str
    description: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SourceFileCreate(BaseModel):
    filename: str
    content: str


class SourceFileRead(BaseModel):
    id: str
    project_id: str
    filename: str
    internal_name: str
    content: str
    created_at: datetime

    class Config:
        from_attributes = True


class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    category: str
    config: Dict[str, Any] = Field(default_factory=dict)


class PolicyRead(BaseModel):
    id: str
    project_id: str
    name: str
    description: str
    category: str
    config: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True


class AnalysisRunRead(BaseModel):
    id: str
    project_id: str
    status: str
    summary: str
    findings_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class FindingRead(BaseModel):
    id: str
    analysis_id: str
    title: str
    severity: str
    status: str
    policy_name: str
    data_category: str
    source: str
    destination: str
    intermediate_path: List[str]
    file_path: str
    line_numbers: List[int]
    explanation: str
    remediation: str
    limitations: str
    graph_payload: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True


class AnalyzeRequest(BaseModel):
    source_code: str
    file_name: str = "main.py"
    policies: Optional[List[str]] = None
    approved_destinations: Optional[List[str]] = None


class GraphNode(BaseModel):
    id: str
    label: str
    kind: str
    file: str
    line: int


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str


class GraphResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class AnalysisReport(BaseModel):
    project_id: str
    analysis_id: str
    status: str
    findings: List[FindingRead]
    graph: GraphResponse
