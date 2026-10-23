from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

SENSITIVE_KEYS = {
    "password": "password",
    "api_key": "api_key",
    "key": "api_key",
    "token": "api_key",
    "email": "email",
    "user_email": "email",
}

REQUEST_SINKS = {"requests.get", "requests.post", "requests.put", "requests.delete", "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "urllib.request.urlopen"}
FILE_WRITE_SINKS = {"write", "writelines"}
LOGGING_CALLS = {"logger.info", "logging.info", "logger.warning", "logging.warning"}


@dataclass
class TraceValue:
    category: str
    source: str
    path: List[str]
    lines: List[int] = field(default_factory=list)
    file: str = ""


def unique_preserve_order(items: List[Any]) -> List[Any]:
    seen = set()
    result: List[Any] = []
    for item in items:
        key = repr(item)
        if key in seen:
            continue
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


def safe_literal(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for value in node.values:
            literal = safe_literal(value)
            if literal is not None:
                parts.append(literal)
        return "".join(parts)
    if isinstance(node, ast.FormattedValue):
        return "{}"
    return None


def evaluate_expr(node: ast.AST, env: Dict[str, TraceValue], file_name: str) -> Optional[TraceValue]:
    if isinstance(node, ast.Name):
        trace = env.get(node.id)
        if trace is None:
            return None
        return TraceValue(trace.category, trace.source, list(trace.path), list(trace.lines), trace.file)
    if isinstance(node, ast.Attribute):
        base = evaluate_expr(node.value, env, file_name)
        if base is None:
            return None
        attribute_name = f"{base.source}.{node.attr}"
        return TraceValue(base.category, attribute_name, unique_preserve_order(base.path + [attribute_name]), list(base.lines), file_name)
    if isinstance(node, ast.Call):
        call_name = get_call_name(node)
        if ".get" in call_name and node.args:
            root_name = call_name.lower().split('.')[0]
            supported_roots = {"request", "req", "form", "payload", "params", "context"}
            if root_name not in supported_roots and 'request' not in call_name.lower():
                return None
            key = safe_literal(node.args[0])
            if key and find_sensitive_key(key):
                category = find_sensitive_key(key)
                source_label = f'{call_name}("{key}")'
                return TraceValue(category, source_label, [source_label], [node.lineno], file_name)
        return None
    if isinstance(node, ast.Subscript):
        return evaluate_expr(node.value, env, file_name)
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            literal_key = safe_literal(key) if key is not None else None
            if literal_key and find_sensitive_key(literal_key):
                traced = evaluate_expr(value, env, file_name)
                if traced is not None:
                    return traced
                return TraceValue(find_sensitive_key(literal_key), literal_key, [literal_key], [node.lineno], file_name)
    if isinstance(node, ast.BinOp):
        left = evaluate_expr(node.left, env, file_name)
        right = evaluate_expr(node.right, env, file_name)
        if left and right:
            combined = unique_preserve_order(left.path + right.path)
            return TraceValue(left.category, left.source, combined, unique_preserve_order(left.lines + right.lines), file_name)
        return left or right
    return None


def find_sensitive_reference_in_node(node: ast.AST, env: Dict[str, TraceValue]) -> Optional[TraceValue]:
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.Attribute):
        return evaluate_expr(node, env, "")
    if isinstance(node, ast.Call):
        return evaluate_expr(node, env, "")
    if isinstance(node, ast.Dict):
        return evaluate_expr(node, env, "")
    return None


def assign_name_to_env(target: ast.AST, value_trace: Optional[TraceValue], env: Dict[str, TraceValue], file_name: str, line_no: int):
    if isinstance(target, ast.Name):
        category = find_sensitive_key(target.id) or (value_trace.category if value_trace else "unknown")
        if value_trace:
            path = list(value_trace.path)
            if target.id not in path:
                path.append(target.id)
            env[target.id] = TraceValue(
                category=category,
                source=value_trace.source if value_trace.source else target.id,
                path=path,
                lines=unique_preserve_order([*value_trace.lines, line_no]),
                file=file_name,
            )
        else:
            env[target.id] = TraceValue(category, target.id, [target.id], [line_no], file_name)


def build_graph_path(path_items: List[str], file_name: str, lines: List[int]) -> Dict[str, Any]:
    nodes = []
    edges = []
    for index, item in enumerate(path_items):
        node_id = f"n{index}"
        nodes.append({
            "id": node_id,
            "label": item,
            "kind": "source" if index == 0 else "sink" if index == len(path_items) - 1 else "assignment",
            "file": file_name,
            "line": lines[index] if index < len(lines) else 0,
        })
        if index > 0:
            edges.append({"id": f"e{index-1}-{index}", "source": f"n{index-1}", "target": node_id})
    return {"nodes": nodes, "edges": edges}


def get_request_destination(call: ast.Call) -> str:
    if not call.args:
        for keyword in call.keywords:
            if keyword.arg == "url":
                if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    return keyword.value.value
        return "unknown"
    target = call.args[0]
    if isinstance(target, ast.Constant) and isinstance(target.value, str):
        return target.value
    if isinstance(target, ast.Name):
        return target.id
    return "unknown"


def is_unapproved_destination(destination: str, approved: Iterable[str]) -> bool:
    parsed = urlparse(destination if "://" in destination else f"https://{destination}")
    host = parsed.netloc or parsed.path
    clean_host = host.lower().replace("https://", "").replace("http://", "")
    if not clean_host:
        return False
    approved_hosts = {entry.lower().replace("https://", "").replace("http://", "") for entry in approved}
    return clean_host not in approved_hosts


def evaluate_call(call: ast.Call, env: Dict[str, TraceValue], file_name: str, approved_destinations: Iterable[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    call_name = get_call_name(call)

    if call_name in LOGGING_CALLS:
        for arg in call.args:
            trace = find_sensitive_reference_in_node(arg, env)
            if trace is None:
                continue
            if trace.category == "password":
                path_items = [*trace.path, call_name]
                findings.append({
                    "title": "Password value logged",
                    "severity": "high",
                    "status": "open",
                    "policy_name": "no-password-logging",
                    "data_category": "password",
                    "source": trace.source,
                    "destination": call_name,
                    "intermediate_path": path_items,
                    "file_path": file_name,
                    "line_numbers": unique_preserve_order([*trace.lines, call.lineno]),
                    "explanation": "A sensitive password value flows into a logging sink without a redaction policy.",
                    "remediation": "Remove the password from log arguments or mask it before logging.",
                    "limitations": "This conservative analysis supports direct variable and alias propagation only.",
                    "graph_payload": build_graph_path(path_items, file_name, unique_preserve_order([*trace.lines, call.lineno])),
                })
    if call_name in FILE_WRITE_SINKS:
        for arg in call.args:
            trace = find_sensitive_reference_in_node(arg, env)
            if trace is not None:
                path_items = [*trace.path, call_name]
                findings.append({
                    "title": "Sensitive data written to file",
                    "severity": "medium",
                    "status": "open",
                    "policy_name": "sensitive-email-logs",
                    "data_category": trace.category,
                    "source": trace.source,
                    "destination": call_name,
                    "intermediate_path": path_items,
                    "file_path": file_name,
                    "line_numbers": unique_preserve_order([*trace.lines, call.lineno]),
                    "explanation": "Sensitive data is written to a sink without explicit approval.",
                    "remediation": "Review the write target and ensure the value is sanitized or encrypted.",
                    "limitations": "Only direct writes and simple alias propagation are tracked.",
                    "graph_payload": build_graph_path(path_items, file_name, unique_preserve_order([*trace.lines, call.lineno])),
                })
    if call_name in REQUEST_SINKS:
        destination = get_request_destination(call)
        sensitive_values: List[TraceValue] = []
        for node in [*call.args, *[kw.value for kw in call.keywords]]:
            trace = find_sensitive_reference_in_node(node, env)
            if trace is not None:
                sensitive_values.append(trace)
        for trace in sensitive_values:
            if trace.category == "api_key" and is_unapproved_destination(destination, approved_destinations):
                path_items = [*trace.path, destination]
                findings.append({
                    "title": "API key sent to unapproved destination",
                    "severity": "high",
                    "status": "open",
                    "policy_name": "approved-api-destination",
                    "data_category": "api_key",
                    "source": trace.source,
                    "destination": destination,
                    "intermediate_path": path_items,
                    "file_path": file_name,
                    "line_numbers": unique_preserve_order([*trace.lines, call.lineno]),
                    "explanation": "The API key value is sent to a destination that is not in the approved allowlist.",
                    "remediation": "Use an approved endpoint or add the destination to the policy allowlist.",
                    "limitations": "The analyzer operates on static syntax trees and cannot resolve dynamic URLs.",
                    "graph_payload": build_graph_path(path_items, file_name, unique_preserve_order([*trace.lines, call.lineno])),
                })
    return findings


def analyze_python_source(source_code: str, file_name: str = "main.py", approved_destinations: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    approved_destinations = list(approved_destinations or [])
    try:
        tree = ast.parse(source_code)
    except SyntaxError as exc:
        return {
            "ok": False,
            "error": {
                "title": "Syntax error",
                "message": f"Invalid Python syntax at line {exc.lineno}: {exc.msg}",
                "line": exc.lineno,
            },
            "findings": [],
            "graph": {"nodes": [], "edges": []},
        }

    env: Dict[str, TraceValue] = {}
    findings: List[Dict[str, Any]] = []

    def visit_statements(statements: List[ast.stmt]):
        for stmt in statements:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    assign_name_to_env(target, evaluate_expr(stmt.value, env, file_name), env, file_name, stmt.lineno)
            elif isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name):
                    assign_name_to_env(stmt.target, evaluate_expr(stmt.value, env, file_name), env, file_name, stmt.lineno)
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                findings.extend(evaluate_call(stmt.value, env, file_name, approved_destinations))
            elif isinstance(stmt, (ast.If, ast.With, ast.Try, ast.For, ast.While)):
                if hasattr(stmt, "body"):
                    visit_statements(list(stmt.body))
                if hasattr(stmt, "orelse"):
                    visit_statements(list(stmt.orelse))
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit_statements(list(stmt.body))

    visit_statements(tree.body)

    graph_nodes: List[Dict[str, Any]] = []
    graph_edges: List[Dict[str, Any]] = []
    for finding in findings:
        path_nodes = finding["intermediate_path"]
        for index, item in enumerate(path_nodes):
            graph_nodes.append({
                "id": f"{finding['title']}-{index}",
                "label": item,
                "kind": "source" if index == 0 else "sink" if index == len(path_nodes) - 1 else "assignment",
                "file": file_name,
                "line": finding["line_numbers"][index] if index < len(finding["line_numbers"]) else 0,
            })
            if index > 0:
                graph_edges.append({
                    "id": f"{finding['title']}-edge-{index-1}",
                    "source": f"{finding['title']}-{index-1}",
                    "target": f"{finding['title']}-{index}",
                })

    return {"ok": True, "findings": findings, "graph": {"nodes": graph_nodes, "edges": graph_edges}, "error": None}
