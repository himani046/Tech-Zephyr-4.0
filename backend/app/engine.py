from __future__ import annotations
from typing import Any
import json, uuid, time
from .agents import IAMForensicsAgent, UsageIntelligenceAgent, DependencyAgent, PolicyStrategistAgent, BlastRadiusAgent, SimulationAgent, RootCauseAgent, ReplannerAgent, RedTeamAgent, VerifierAgent
from .simulator import SyntheticCloud

class AegisEngine:
    def __init__(self, scenarios): self.scenarios={x["id"]:x for x in scenarios}; self.runs={}
    def run(self, scenario_id:str):
        scenario=self.scenarios[scenario_id]; run_id=str(uuid.uuid4())
        cloud=SyntheticCloud(scenario); state={"run_id":run_id,"scenario":scenario,"cloud":cloud,"status":"RUNNING","iteration":0,"events":[],"decisions":[],"replans":[]}
        agents=[IAMForensicsAgent(),UsageIntelligenceAgent(),DependencyAgent(),PolicyStrategistAgent(),BlastRadiusAgent(),SimulationAgent()]
        self._execute(state,agents)
        if state["simulation"]["status"]=="FAIL":
            self._execute(state,[RootCauseAgent(),ReplannerAgent()]); state["iteration"]+=1
            cloud.set_policy(state["proposed_policy"]); self._execute(state,[SimulationAgent()])
        self._execute(state,[RedTeamAgent()])
        if state.get("red_team_findings"):
            # Deterministic remediation for seeded sensitive permissions.
            bad={x["permission"] for x in state["red_team_findings"]}; state["proposed_policy"]=[p for p in state["proposed_policy"] if p not in bad]
            state["replans"].append({"reason":"Red-team finding","removed":sorted(bad)})
            cloud.set_policy(state["proposed_policy"]); self._execute(state,[SimulationAgent()]); self._execute(state,[RedTeamAgent()])
        self._execute(state,[VerifierAgent()]); state["status"]=state["verification"]["status"]
        state["cloud"]=None
        self.runs[run_id]=state
        return self.public_state(state)
    def _execute(self,state,agents):
        for agent in agents:
            started=time.time(); result=agent.act(state); state.update(result)
            event={"agent":agent.name,"role":agent.role,"message":result.get("message", ""),"timestamp":time.time(),"duration_ms":round((time.time()-started)*1000,2),"status":"completed"}
            state["events"].append(event)
    def public_state(self,s):
        out={k:v for k,v in s.items() if k not in {"cloud"}}
        return out
