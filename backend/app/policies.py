from __future__ import annotations

from typing import Any, Dict, List, Optional

DEFAULT_POLICIES: List[Dict[str, Any]] = [
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


def get_default_policy_names() -> List[str]:
    return [policy["name"] for policy in DEFAULT_POLICIES]


def get_policy_by_name(name: str) -> Optional[Dict[str, Any]]:
    for policy in DEFAULT_POLICIES:
        if policy["name"] == name:
            return policy
    return None


def policy_payload(name: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    base = get_policy_by_name(name) or {"name": name, "description": "Custom policy", "category": "unknown", "config": {}}
    return {
        "name": base["name"],
        "description": base["description"],
        "category": base["category"],
        "config": {**base.get("config", {}), **(config or {})},
    }
