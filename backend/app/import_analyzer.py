from __future__ import annotations

from typing import Any
from .simulator import SyntheticCloud

SENSITIVE_ACTIONS = {
    "iam:*", "iam:CreateUser", "iam:CreateRole", "iam:AttachRolePolicy",
    "iam:PutRolePolicy", "iam:PassRole", "iam:DeleteRole",
    "iam:UpdateAssumeRolePolicy", "sts:AssumeRole", "kms:Decrypt",
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
        # Evidence-enriched exports commonly wrap the actual IAM document.
        for key in ("PolicyDocument", "policyDocument", "Document", "document", "policy"):
            if key in data and isinstance(data[key], (dict, list)):
                provider, source = _find_policy_document(data[key])
                if provider != "generic":
                    return provider, source
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


def _extract_aws(data: dict[str, Any]) -> list[dict[str, Any]]:
    permissions: list[dict[str, Any]] = []
    for st in _as_list(data.get("Statement")):
        if not isinstance(st, dict) or st.get("Effect", "Allow") != "Allow":
            continue
        resources = _as_list(st.get("Resource", "*")) or ["*"]
        for action in _as_list(st.get("Action")):
            for resource in resources:
                permissions.append({"action": str(action), "resource": str(resource), "effect": "Allow"})
    return permissions


def _extract_normalized(data: dict[str, Any]) -> list[dict[str, Any]]:
    permissions: list[dict[str, Any]] = []
    for item in _as_list(data.get("permissions", [])):
        if isinstance(item, str):
            permissions.append({"action": item, "resource": "*", "effect": "Allow"})
        elif isinstance(item, dict) and item.get("action"):
            permissions.append({
                "action": str(item["action"]),
                "resource": str(item.get("resource", "*")),
                "effect": str(item.get("effect", "Allow")),
            })
    return permissions


def _extract_azure(data: Any) -> list[dict[str, Any]]:
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
        for action in _as_list(props.get("permissions") or item.get("permissions")):
            if isinstance(action, str):
                permissions.append({"action": action, "resource": scope, "effect": "Allow"})
            elif isinstance(action, dict):
                for a in _as_list(action.get("actions")):
                    permissions.append({"action": str(a), "resource": scope, "effect": "Allow"})
    return permissions


def _extract_gcp(data: dict[str, Any]) -> list[dict[str, Any]]:
    permissions: list[dict[str, Any]] = []
    for binding in _as_list(data.get("bindings")):
        if not isinstance(binding, dict):
            continue
        role = str(binding.get("role", "unknown"))
        permissions.append({
            "action": f"role:{role}", "resource": "*", "effect": "Allow",
            "kind": "gcp-role", "members": _as_list(binding.get("members")),
        })
    return permissions


def _evidence_from_root(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {"usage": {}, "dependencies": [], "services": [], "failure_injection": None}
    usage = data.get("usage") or data.get("audit") or data.get("auditLogs") or {}
    dependencies = data.get("dependencies") or data.get("dependencyGraph") or []
    services = data.get("services") or data.get("serviceDependencies") or []
    failure = data.get("failure_injection") or data.get("failureInjection")
    return {"usage": usage, "dependencies": dependencies, "services": services, "failure_injection": failure}


def _usage_calls(usage: Any, action: str) -> int | None:
    if not isinstance(usage, dict):
        return None
    item = usage.get(action)
    if isinstance(item, dict):
        calls = item.get("calls", item.get("count"))
    else:
        calls = item
    if calls is None:
        return None
    try:
        return int(calls)
    except (TypeError, ValueError):
        return None


def _dependency_permissions(dependencies: list[Any]) -> set[str]:
    required: set[str] = set()
    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        for key in ("permission", "action", "requires", "required_permission"):
            value = dep.get(key)
            for item in _as_list(value):
                if isinstance(item, str) and (":" in item or item == "*"):
                    required.add(item)
    return required


def _service_permissions(services: list[Any]) -> set[str]:
    required: set[str] = set()
    for service in services:
        if not isinstance(service, dict):
            continue
        for item in _as_list(service.get("required")):
            if isinstance(item, str):
                required.add(item)
    return required


def _build_services(services: list[Any], dependencies: list[Any]) -> list[dict[str, Any]]:
    if services:
        return [s for s in services if isinstance(s, dict) and s.get("name")]
    # If only dependency edges were supplied, create lightweight non-critical checks.
    grouped: dict[str, list[str]] = {}
    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        src = dep.get("from") or dep.get("service")
        action = dep.get("permission") or dep.get("action") or dep.get("to")
        if src and action and isinstance(action, str) and ":" in action:
            grouped.setdefault(str(src), []).append(action)
    return [{"id": name.lower().replace(" ", "-"), "name": name, "required": list(dict.fromkeys(reqs)), "critical": False} for name, reqs in grouped.items()]


def analyze_import(data: Any, filename: str) -> dict[str, Any]:
    provider, source = _find_policy_document(data)
    root_evidence = _evidence_from_root(data)

    if provider == "aws":
        permissions = _extract_aws(source)
        sources = ["AWS IAM policy document"]
    elif provider == "azure":
        permissions = _extract_azure(source)
        sources = ["Azure RBAC role assignment export"]
    elif provider == "gcp":
        permissions = _extract_gcp(source)
        sources = ["Google Cloud IAM policy binding export"]
    elif provider == "normalized":
        permissions = _extract_normalized(source)
        sources = ["AegisIAM normalized policy"]
        root_evidence = {**root_evidence, **_evidence_from_root(source)}
    else:
        permissions = []
        sources = ["Generic JSON import"]
        if isinstance(source, dict):
            for action in _as_list(source.get("actions")):
                permissions.append({"action": str(action), "resource": "*", "effect": "Allow"})

    if not permissions:
        raise ValueError("No IAM/RBAC permissions were found. Upload an AWS policy document, Azure role assignment export, GCP IAM policy, or AegisIAM evidence bundle.")

    usage = root_evidence["usage"] or {}
    dependencies = root_evidence["dependencies"] or []
    services = _build_services(root_evidence["services"] or [], dependencies)
    dependency_required = _dependency_permissions(dependencies) | _service_permissions(services)

    decisions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for p in permissions:
        action, resource = p["action"], p.get("resource", "*")
        key = (action, resource)
        duplicate = key in seen
        seen.add(key)
        sensitive = action in SENSITIVE_ACTIONS or action in WILDCARD_ACTIONS or action.endswith(":*") or action == "*"
        calls = _usage_calls(usage, action)
        dependency = action in dependency_required

        if duplicate:
            decision, reason = "REMOVE", "Duplicate permission entry; safe to de-duplicate."
        elif dependency:
            decision, reason = "KEEP", "Required by supplied service/dependency evidence; functionality dependency overrides low or absent usage."
        elif calls == 0:
            decision, reason = "REMOVE", "Explicit audit evidence shows zero calls and no supplied service dependency requires it."
        elif sensitive and calls is None:
            decision, reason = "INVESTIGATE", "High-privilege action requires usage/resource evidence before removal."
        elif calls is None:
            decision, reason = "INVESTIGATE", "IAM configuration was imported, but usage/audit evidence was not supplied."
        else:
            decision, reason = "KEEP", "Permission has observed usage in the supplied audit evidence."

        decisions.append({
            "permission": action, "resource": resource, "decision": decision, "reason": reason,
            "sensitive": sensitive, "calls": calls, "dependency": dependency,
            "evidence": "IAM + audit + dependency" if calls is not None and dependency else ("IAM + audit" if calls is not None else "IAM policy only"),
        })

    original_policy = list(dict.fromkeys(p["action"] for p in permissions))
    proposed = [d["permission"] for d in decisions if d["decision"] != "REMOVE"]
    removed = [d["permission"] for d in decisions if d["decision"] == "REMOVE"]
    simulation: dict[str, Any] = {"status": "NOT_RUN", "services": [], "note": "Simulation requires service/dependency telemetry in the import bundle."}
    events: list[dict[str, Any]] = [
        {"agent": "IAM Import Parser", "role": "Detect provider and normalize IAM/RBAC JSON", "message": f"Parsed {len(permissions)} permission entries.", "duration_ms": 0},
        {"agent": "IAM Forensics", "role": "Classify privilege sensitivity and scope", "message": f"Found {sum(1 for d in decisions if d['sensitive'])} high-risk permission(s).", "duration_ms": 0},
        {"agent": "Usage Intelligence", "role": "Correlate audit evidence with configured access", "message": f"Audit evidence covers {sum(1 for d in decisions if d['calls'] is not None)} permission(s).", "duration_ms": 0},
        {"agent": "Dependency Intelligence", "role": "Map permissions to service requirements", "message": f"Loaded {len(dependencies)} dependency edge(s) and {len(services)} service check(s).", "duration_ms": 0},
        {"agent": "Policy Strategist", "role": "Generate evidence-backed least-privilege recommendations", "message": f"Generated {len(removed)} removal candidate(s).", "duration_ms": 0},
    ]

    if services:
        scenario = {
            "id": "imported-evidence", "name": f"Imported IAM · {filename}",
            "role": str((data.get("roleName") if isinstance(data, dict) else None) or (source.get("role") if isinstance(source, dict) else None) or filename.rsplit(".", 1)[0]),
            "permissions": original_policy, "services": services, "dependencies": dependencies,
        }
        cloud = SyntheticCloud(scenario)
        cloud.set_policy(proposed)
        simulation = cloud.simulate()
        events.append({"agent": "Policy Simulator", "role": "Execute proposed policy against synthetic service checks", "message": f"Initial simulation: {simulation['status']}.", "duration_ms": 0})

        if simulation["status"] == "FAIL":
            missing = sorted({p for result in simulation["services"] if result["status"] == "FAIL" for p in result["missing_permissions"]})
            proposed = list(dict.fromkeys(proposed + missing))
            events.extend([
                {"agent": "Root Cause Agent", "role": "Diagnose failed service and missing permissions", "message": f"Detected {len(missing)} missing permission(s) required by failed service(s).", "duration_ms": 0},
                {"agent": "Replanner", "role": "Restore only permissions proven necessary for functionality", "message": f"Restored {len(missing)} dependency permission(s) and re-simulated.", "duration_ms": 0},
            ])
            cloud.set_policy(proposed)
            simulation = cloud.simulate()
            removed = [p for p in original_policy if p not in proposed]
            events.append({"agent": "Policy Simulator", "role": "Re-run after autonomous recovery", "message": f"Recovery simulation: {simulation['status']}.", "duration_ms": 0})

    # Adversarial check: sensitive permissions with explicit zero usage can be removed;
    # sensitive permissions with unknown usage stay under investigation.
    red_team = [
        {"permission": d["permission"], "severity": "HIGH", "finding": "Sensitive privilege remains in the final candidate policy; review scope before deployment."}
        for d in decisions if d["sensitive"] and d["decision"] != "REMOVE" and d["calls"] is None and not d["dependency"]
    ]
    events.append({"agent": "Red-Team Agent", "role": "Probe final policy for privilege-escalation risk", "message": f"Found {len(red_team)} unresolved sensitive finding(s).", "duration_ms": 0})

    functionality_score = None
    services_healthy = None
    if services:
        critical = [s for s in simulation.get("services", []) if any(x.get("id") == s.get("id") and s.get("critical", False) for x in services)]
        services_healthy = all(x["status"] == "PASS" for x in critical) if critical else all(x["status"] == "PASS" for x in simulation.get("services", []))
        functionality_score = round(100 * sum(x["status"] == "PASS" for x in simulation.get("services", [])) / max(1, len(simulation.get("services", []))))

    evidence_complete = bool(usage) and bool(services or dependencies)
    sensitive_count = sum(1 for d in decisions if d["sensitive"] and d["decision"] != "REMOVE")
    investigate_count = sum(1 for d in decisions if d["decision"] == "INVESTIGATE")
    security_score = max(0, min(100, 100 - 8 * sensitive_count - 3 * investigate_count + 5 * len(removed)))
    final_status = "VERIFIED" if evidence_complete and not red_team and (services_healthy is True or not services) else "ANALYSIS_ONLY"
    if services and services_healthy is False:
        final_status = "REVIEW_REQUIRED"

    events.append({"agent": "Final Verifier", "role": "Verify security, functionality and evidence coverage", "message": f"Final decision: {final_status}.", "duration_ms": 0})
    role = (data.get("roleName") if isinstance(data, dict) else None) or (source.get("role") if isinstance(source, dict) else None) or filename.rsplit(".", 1)[0]
    final_policy = list(dict.fromkeys(proposed))

    return {
        "run_id": f"import-{filename}-{len(permissions)}",
        "status": "ANALYSIS_COMPLETE" if final_status == "ANALYSIS_ONLY" else final_status,
        "mode": "IMPORTED_IAM",
        "source_file": filename,
        "provider": provider.upper(),
        "scenario": {"id": "imported-iam", "name": f"Imported IAM · {role}", "role": str(role), "permissions": original_policy, "dependencies": dependencies, "services": services},
        "iam_findings": [{"permission": p["action"], "resource": p.get("resource", "*"), "sensitive": p["action"] in SENSITIVE_ACTIONS or p["action"] == "*", "source": sources[0]} for p in permissions],
        "usage_findings": [{"permission": d["permission"], "calls": d["calls"], "unused": d["calls"] == 0, "evidence_available": d["calls"] is not None} for d in decisions],
        "decisions": decisions,
        "proposed_policy": final_policy,
        "simulation": simulation,
        "events": events,
        "red_team_findings": red_team,
        "replans": [{"reason": "Service failure after least-privilege proposal", "restored": [p for p in final_policy if p not in original_policy or p not in removed]}] if services and any(e["agent"] == "Replanner" for e in events) else [],
        "verification": {
            "status": final_status, "security_score": security_score, "functionality_score": functionality_score,
            "removed": removed, "red_team_clean": not red_team, "services_healthy": services_healthy,
            "evidence_coverage": "GOOD" if evidence_complete else "PARTIAL",
            "note": "Evidence-enriched imports can be simulated in the local sandbox. IAM-only exports remain analysis-only because usage and dependencies cannot be inferred safely.",
        },
        "import_summary": {
            "permission_count": len(permissions), "removed_candidates": len(removed),
            "high_risk_permissions": sum(1 for d in decisions if d["sensitive"]),
            "investigate_permissions": investigate_count, "evidence_sources": sources,
            "dependencies_supplied": len(dependencies), "services_supplied": len(services),
            "audit_entries_supplied": sum(1 for d in decisions if d["calls"] is not None),
        },
    }
