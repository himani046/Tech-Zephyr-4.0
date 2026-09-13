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

### Agent pipeline

Supervisor → IAM Forensics → Usage Intelligence → Dependency Intelligence → Policy Strategist → Blast Radius → Simulator → Root Cause → Replanner → Red Team → Verifier

The seeded PaymentRole scenario intentionally contains a bad candidate change: removing `dynamodb:PutItem` breaks Payment Service. Agents observe the failure, inspect dependencies, replan, restore the required permission, and verify the final policy.

No GitHub Actions workflows are included; the project is committed directly to `main`.
