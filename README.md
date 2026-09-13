# AegisIAM

## Autonomous Multi-Agent Least-Privilege Security Orchestrator

> Don't just remove permissions. Prove they can be removed.

A fully local synthetic-cloud security lab for Tech Zephyr 4.0 Problem 10. AegisIAM uses specialized agents to investigate IAM permissions, correlate audit evidence, map service dependencies, estimate blast radius, generate a least-privilege policy, simulate rollout, recover from service failure, run red-team checks, and verify the final policy.

### Run locally

Backend:
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Frontend:
```bash
cd frontend
npm install
npm run dev
```

No AWS account, credentials, paid cloud service, or real production action is required.

### Import a real IAM/RBAC JSON export

The dashboard now has two modes:

1. **Synthetic scenario** — runs the full autonomous simulation, including failure recovery and red-team verification.
2. **Import IAM JSON** — accepts a JSON export from a cloud IAM/RBAC system and produces a conservative configuration analysis without touching the real cloud.

Supported import shapes:
- AWS IAM policy documents (`Statement` / `Action` / `Resource`), including common `PolicyDocument` and `PolicyVersion.Document` wrappers.
- Azure RBAC role-assignment exports (`value` / `roleDefinitionId` / `scope`), plus exports that inline role-definition actions.
- Google Cloud IAM policy bindings (`bindings` / `role` / `members`).
- AegisIAM normalized JSON with `permissions`, and optional `usage` and `dependencies` evidence.

**Important:** an IAM policy export describes configured authorization, not actual usage. If usage or dependency evidence is absent, AegisIAM marks the permission as `INVESTIGATE` instead of pretending it is unused. Functionality is also marked N/A in import mode because an IAM JSON file alone cannot prove that an application will continue to work.

For AWS/Azure/GCP production integrations, provider-specific adapters can later collect audit logs and service/resource metadata. The hackathon prototype deliberately keeps analysis and simulation local and does not make production IAM changes.

### Agent pipeline

Supervisor → IAM Forensics → Usage Intelligence → Dependency Intelligence → Policy Strategist → Blast Radius → Simulator → Root Cause → Replanner → Red Team → Verifier

The seeded PaymentRole scenario intentionally contains a bad candidate change: removing `dynamodb:PutItem` breaks Payment Service. Agents observe the failure, inspect dependencies, replan, restore the required permission, and verify the final policy.

No GitHub Actions workflows are included; the project is committed directly to `main`.
