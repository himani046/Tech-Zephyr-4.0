from __future__ import annotations
from typing import Any
import networkx as nx

class SyntheticCloud:
    def __init__(self, scenario: dict[str, Any]):
        self.scenario = scenario
        self.current_policy = list(scenario["permissions"])
        self.history: list[dict[str, Any]] = []

    def set_policy(self, permissions: list[str]):
        self.current_policy = list(dict.fromkeys(permissions))

    def simulate(self) -> dict[str, Any]:
        results = []
        for service in self.scenario["services"]:
            missing = [p for p in service["required"] if p not in self.current_policy]
            results.append({"service": service["name"], "id": service["id"], "status": "FAIL" if missing else "PASS", "missing_permissions": missing})
        passed = all(x["status"] == "PASS" for x in results if self._critical(x["id"]))
        result = {"status": "PASS" if passed else "FAIL", "services": results}
        self.history.append(result)
        return result

    def _critical(self, service_id: str) -> bool:
        for s in self.scenario["services"]:
            if s["id"] == service_id:
                return s.get("critical", False)
        return False


def build_graph(scenario: dict[str, Any]) -> nx.DiGraph:
    g = nx.DiGraph()
    for dep in scenario.get("dependencies", []):
        g.add_edge(dep["from"], dep["to"], label=dep.get("label", "depends"))
    return g
