from __future__ import annotations
from typing import Any

class Agent:
    name = "Agent"
    role = ""
    def act(self, state: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

class IAMForensicsAgent(Agent):
    name="IAM Forensics"; role="Analyze the current IAM surface"
    def act(self,s):
        perms=s["scenario"]["permissions"]
        sensitive={"iam:CreateUser","iam:PassRole","iam:CreateRole","iam:AttachRolePolicy"}
        findings=[]
        for p in perms:
            findings.append({"permission":p,"sensitive":p in sensitive,"source":"IAM policy"})
        return {"iam_findings":findings,"message":f"Inspected {len(perms)} permissions."}

class UsageIntelligenceAgent(Agent):
    name="Usage Intelligence"; role="Correlate permissions with audit evidence"
    def act(self,s):
        usage=s["scenario"]["usage"]; findings=[]
        for p,v in usage.items():
            unused=v["calls"]==0
            findings.append({"permission":p,"calls":v["calls"],"last_used":v["last_used"],"unused":unused})
        return {"usage_findings":findings,"message":f"Correlated {len(findings)} permission histories."}

class DependencyAgent(Agent):
    name="Dependency Intelligence"; role="Map permissions to service dependencies"
    def act(self,s):
        deps=s["scenario"].get("dependencies",[])
        required=set()
        for service in s["scenario"]["services"]: required.update(service["required"])
        return {"dependencies":deps,"required_permissions":sorted(required),"message":f"Mapped {len(deps)} dependency edges and {len(required)} service requirements."}

class PolicyStrategistAgent(Agent):
    name="Policy Strategist"; role="Propose evidence-backed least privilege"
    def act(self,s):
        perms=s["scenario"]["permissions"]; usage={x["permission"]:x for x in s["usage_findings"]}; required=set(s["required_permissions"])
        decisions=[]
        for p in perms:
            if p in required: d="KEEP"; reason="Required by a service dependency"
            elif usage[p]["unused"]: d="REMOVE"; reason="Unused in audit evidence"
            else: d="INVESTIGATE"; reason="Usage/dependency evidence is inconclusive"
            decisions.append({"permission":p,"decision":d,"reason":reason})
        # Deliberate adversarial candidate creates a meaningful failure/replan in the demo.
        inj=s["scenario"].get("failure_injection")
        if inj and inj["permission"] in perms:
            for x in decisions:
                if x["permission"]==inj["permission"]: x["decision"]="REMOVE"; x["reason"]="Intentional demo challenge: candidate removal to test recovery"
        proposed=[x["permission"] for x in decisions if x["decision"]!="REMOVE"]
        return {"decisions":decisions,"proposed_policy":proposed,"message":"Generated candidate Policy V1 from evidence."}

class BlastRadiusAgent(Agent):
    name="Blast Radius"; role="Estimate impact before rollout"
    def act(self,s):
        required=set(s["required_permissions"]); out=[]
        for x in s["decisions"]:
            p=x["permission"]; impact="LOW"
            if x["decision"]=="REMOVE" and p in required: impact="HIGH"
            elif x["decision"]=="REMOVE": impact="LOW"
            out.append({"permission":p,"impact":impact,"affected_services":[sv["name"] for sv in s["scenario"]["services"] if p in sv["required"]]})
        return {"blast_radius":out,"message":"Calculated impact for every proposed change."}

class SimulationAgent(Agent):
    name="Policy Simulator"; role="Execute policy in synthetic cloud"
    def act(self,s):
        result=s["cloud"].simulate()
        return {"simulation":result,"message":f"Simulation {result['status']} across {len(result['services'])} services."}

class RootCauseAgent(Agent):
    name="Root Cause"; role="Diagnose failed service behavior"
    def act(self,s):
        sim=s["simulation"]; failures=[x for x in sim["services"] if x["status"]=="FAIL"]
        missing=sorted({p for f in failures for p in f["missing_permissions"]})
        return {"root_cause":{"failed_services":failures,"missing_permissions":missing,"confidence":0.99},"message":f"Diagnosed {len(failures)} failed service(s)."}

class ReplannerAgent(Agent):
    name="Replanner"; role="Adapt policy using simulation feedback"
    def act(self,s):
        policy=list(s["proposed_policy"])
        for p in s.get("root_cause",{}).get("missing_permissions",[]):
            if p not in policy: policy.append(p)
        return {"proposed_policy":policy,"replan_reason":s.get("root_cause"),"message":"Replanned Policy V2 using observed failure evidence."}

class RedTeamAgent(Agent):
    name="Red Team"; role="Challenge the final policy for privilege risks"
    def act(self,s):
        policy=set(s["proposed_policy"]); findings=[]
        for p in s["scenario"].get("red_team",[]):
            if p in policy: findings.append({"permission":p,"severity":"HIGH","finding":"Sensitive privilege remains exposed"})
        return {"red_team_findings":findings,"message":f"Adversarial review found {len(findings)} issue(s)."}

class VerifierAgent(Agent):
    name="Verifier"; role="Verify security, functionality and evidence"
    def act(self,s):
        policy=set(s["proposed_policy"]); original=set(s["scenario"]["permissions"]); sim=s["simulation"]
        removed=sorted(original-policy); critical_ok=sim["status"]=="PASS"; red_ok=len(s.get("red_team_findings",[]))==0
        security=max(0, min(100, 65 + 5*len(removed) + (10 if red_ok else 0)))
        return {"verification":{"status":"VERIFIED" if critical_ok and red_ok else "REPLAN_REQUIRED","security_score":security,"functionality_score":100 if critical_ok else 0,"removed":removed,"red_team_clean":red_ok,"services_healthy":critical_ok},"message":"Final verification completed."}
