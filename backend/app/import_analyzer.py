from __future__ import annotations

from typing import Any

SENSITIVE_ACTIONS = {
    "iam:*",
    "iam:CreateUser",
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:PassRole",
    "iam:DeleteRole",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "kms:Decrypt",
    "secretsmanager:GetSecretValue",
}
WILDCARD_ACTIONS = {"*", "s3:*", "ec2:*", "dynamodb:*", "iam:*", "lambda:*", "kms:*"}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _find_policy_document(data: Any) -> tuple[str, Any]:
    if isinstance(data, dict):
        if "Statement" in data:
            return "aws", data
        for key in ("PolicyDocument", "policyDocument", "Document", "document"):
            if key in data:
                return _find_policy_document(data[key])
        if "PolicyVersion" in data:
            return _find_policy_document(data["PolicyVersion"])
        if "bindings" in data:
            return "gcp", data
        if "value" in data and isinstance(data["value"], list):
            return "azure", data
        if "roleAssignments" in data:
            return "azure", data
        if "permissions" in data:
            return "normalized", data
    if isinstance(data, list):
        if data and all(isinstance(x, dict) and ("roleDefinitionId" in x or "properties" in x) for x in data):
            return "azure", data
    return "generic", data


def _extract_aws(data: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    statements = _as_list(data.get("Statement"))
    permissions: list[dict[str, Any]] = []
    for st in statements:
        if not isinstance(st, dict) or st.get("Effect", "Allow") != "Allow":
            continue
        resources = _as_list(st.get("Resource", "*")) or ["*"]
        actions = _as_list(st.get("Action"))
        for action in actions:
            for resource in resources:
                permissions.append({"action": str(action), "resource": str(resource), "effect": "Allow"})
    return permissions, ["AWS IAM policy document"]


def _extract_normalized(data: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    raw = data.get("permissions", [])
    permissions: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, str):
            permissions.append({"action": item, "resource": "*", "effect": "Allow"})
        elif isinstance(item, dict) and item.get("action"):
            permissions.append({
                "action": str(item["action"]),
                "resource": str(item.get("resource", "*")),
                "effect": str(item.get("effect", "Allow")),
            })
    evidence = {"usage": data.get("usage", {}), "dependencies": data.get("dependencies", [])}
    return permissions, ["AegisIAM normalized policy"], evidence


def _extract_azure(data: Any) -> tuple[list[dict[str, Any]], list[str]]:
    items = data if isinstance(data, list) else data.get("value", data.get("roleAssignments", []))
    permissions: list[dict[str, Any]] = []
    for item in _as_list(items):
        if not isinstance(item, dict):
            continue
        props = item.get("properties", item)
        role_id = props.get("roleDefinitionId")
        scope = props.get("scope", "*")
        if role_id:
            permissions.append({"action": f"role:{role_id}", "resource": scope, "effect": "Allow", "kind": "azure-rbac"})
        # Also accept exports that inline role-definition permissions.
        for action in _as_list(props.get("permissions") or item.get("permissions")):
            if isinstance(action, str):
                permissions.append({"action": action, "resource": scope, "effect": "Allow"})
            elif isinstance(action, dict):
                for a in _as_list(action.get("actions")):
                    permissions.append({"action": str(a), "resource": scope, "effect": "Allow"})
    return permissions, ["Azure RBAC role assignment export"]


def _extract_gcp(data: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    permissions: list[dict[str, Any]] = []
    for binding in _as_list(data.get("bindings")):
        if not isinstance(binding, dict):
            continue
        role = str(binding.get("role", "unknown"))
        members = _as_list(binding.get("members"))
        permissions.append({"action": f"role:{role}", "resource": "*", "effect": "Allow", "kind": "gcp-role", "members": members})
    return permissions, ["Google Cloud IAM policy binding export"]


def analyze_import(data: Any, filename: str) -> dict[str, Any]:
    provider, source = _find_policy_document(data)
    evidence: dict[str, Any] = {"usage": {}, "dependencies": []}
    if provider == "aws":
        permissions, sources = _extract_aws(source)
    elif provider == "azure":
        permissions, sources = _extract_azure(source)
    elif provider == "gcp":
        permissions, sources = _extract_gcp(source)
    elif provider == "normalized":
        permissions, sources, evidence = _extract_normalized(source)
    else:
        permissions = []
        sources = ["Generic JSON import"]
        if isinstance(source, dict):
            # Accept a simple {actions:[...]} export as a useful fallback.
            for action in _as_list(source.get("actions")):
                permissions.append({"action": str(action), "resource": "*", "effect": "Allow"})

    if not permissions:
        raise ValueError("No IAM/RBAC permissions were found. Upload an AWS policy document, Azure role assignment export, GCP IAM policy, or AegisIAM normalized JSON.")

    usage = evidence.get("usage", {}) or {}
    deps = evidence.get("dependencies", []) or []
    decisions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for p in permissions:
        action = p["action"]
        resource = p.get("resource", "*")
        key = (action, resource)
        duplicate = key in seen
        seen.add(key)
        sensitive = action in SENSITIVE_ACTIONS or action in WILDCARD_ACTIONS or action.endswith(":*") or action == "*"
        usage_item = usage.get(action, {}) if isinstance(usage, dict) else {}
        calls = usage_item.get("calls") if isinstance(usage_item, dict) else None
        unused = calls == 0

        if duplicate:
            decision, reason = "REMOVE", "Duplicate permission entry; safe to de-duplicate."
        elif unused:
            decision, reason = "REMOVE", "Explicit usage evidence shows zero calls."
        elif sensitive:
            decision, reason = "INVESTIGATE", "High-privilege action requires resource and usage evidence before removal."
        elif calls is None:
            decision, reason = "INVESTIGATE", "IAM configuration was imported, but usage/audit evidence was not supplied."
        else:
            decision, reason = "KEEP", "Permission has observed usage in the supplied evidence."

        decisions.append({
            "permission": action,
            "resource": resource,
            "decision": decision,
            "reason": reason,
            "sensitive": sensitive,
            "calls": calls,
            "evidence": "usage + IAM policy" if calls is not None else "IAM policy only",
        })

    removed = [d["permission"] for d in decisions if d["decision"] == "REMOVE"]
    sensitive_count = sum(1 for d in decisions if d["sensitive"])
    investigate_count = sum(1 for d in decisions if d["decision"] == "INVESTIGATE")
    score = max(0, min(100, 100 - 8 * sensitive_count - 3 * investigate_count + 5 * len(removed)))
    role = source.get("role", source.get("name", filename.rsplit(".", 1)[0])) if isinstance(source, dict) else filename
    final_policy = [d["permission"] for d in decisions if d["decision"] != "REMOVE"]

    return {
        "run_id": f"import-{filename}-{len(permissions)}",
        "status": "ANALYSIS_COMPLETE",
        "mode": "IMPORTED_IAM",
        "source_file": filename,
        "provider": provider.upper(),
        "scenario": {
            "id": "imported-iam",
            "name": f"Imported IAM · {role}",
            "role": str(role),
            "permissions": [p["action"] for p in permissions],
            "dependencies": deps,
            "services": [],
        },
        "iam_findings": [{"permission": p["action"], "resource": p.get("resource", "*"), "sensitive": p["action"] in SENSITIVE_ACTIONS or p["action"] == "*", "source": sources[0]} for p in permissions],
        "usage_findings": [{"permission": d["permission"], "calls": d["calls"], "unused": d["calls"] == 0, "evidence_available": d["calls"] is not None} for d in decisions],
        "decisions": decisions,
        "proposed_policy": final_policy,
        "simulation": {"status": "NOT_RUN", "services": [], "note": "Imported policy analysis is configuration/evidence analysis only. No production cloud changes are performed."},
        "red_team_findings": [
            {"permission": d["permission"], "severity": "HIGH", "finding": "Sensitive or wildcard privilege requires deeper review."}
            for d in decisions if d["sensitive"] and d["decision"] != "REMOVE"
        ],
        "verification": {
            "status": "ANALYSIS_ONLY",
            "security_score": score,
            "functionality_score": None,
            "removed": removed,
            "red_team_clean": False if sensitive_count else True,
            "services_healthy": None,
            "evidence_coverage": "PARTIAL" if investigate_count else "GOOD",
            "note": "Functionality cannot be proven from IAM JSON alone; add audit/dependency evidence or use a seeded synthetic scenario for simulation/recovery.",
        },
        "import_summary": {
            "permission_count": len(permissions),
            "removed_candidates": len(removed),
            "high_risk_permissions": sensitive_count,
            "investigate_permissions": investigate_count,
            "evidence_sources": sources,
            "dependencies_supplied": len(deps),
        },
    }
