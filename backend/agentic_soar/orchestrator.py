"""
Agentic Orchestrator Pipeline
==============================
Coordinates the complete end-to-end workflow:
Packet Input → Deep Packet Inspection (DPI) → ML Threat Detection Layer
→ Multi-Agent System (Traffic, Intel, Behavior, Investigation ReAct, Risk, Response)
→ FortiSOAR Playbook Execution
"""

from typing import Dict, Any
from .ml_detector import detector
from .agents import (
    TrafficAnalysisAgent,
    ThreatIntelAgent,
    BehaviorAnalysisAgent,
    InvestigationAgent,
    RiskAssessmentAgent,
    ResponseAgent
)

class AgenticOrchestrator:
    def __init__(self):
        self.detector = detector

    def process_packet(self, packet_data: dict, dpi_verdict: dict) -> dict:
        """
        Executes the 6-layer Fortinet-inspired workflow.
        """
        # 1. ML Detection Layer
        ml_result = self.detector.predict_flow(packet_data)

        # 2. Agent 1 — Traffic Analysis Agent
        traffic_res = TrafficAnalysisAgent.run(packet_data, ml_result)

        # 3. Agent 2 — Threat Intelligence Agent
        intel_res = ThreatIntelAgent.run(packet_data, ml_result)

        # 4. Agent 3 — Behavior Analysis Agent
        behavior_res = BehaviorAnalysisAgent.run(packet_data)

        # 5. Agent 4 — Investigation Agent (ReAct Loop)
        investigation_res = InvestigationAgent.run(
            packet_data, ml_result, traffic_res, intel_res, behavior_res
        )

        # 6. Agent 5 — Risk Assessment Agent
        risk_res = RiskAssessmentAgent.run(ml_result, intel_res, behavior_res)

        # 7. Agent 6 — Response Agent (FortiSOAR Simulator)
        response_res = ResponseAgent.run(packet_data, risk_res, intel_res)

        # Build full agentic telemetry object
        return {
            "ml_detection": ml_result,
            "agents": {
                "traffic_agent": traffic_res,
                "threat_intel_agent": intel_res,
                "behavior_agent": behavior_res,
                "investigation_agent": investigation_res,
                "risk_agent": risk_res,
                "response_agent": response_res
            },
            "summary": {
                "prediction": ml_result["prediction"],
                "attack_category": ml_result["attack_category"],
                "risk_level": risk_res["risk_level"],
                "risk_score": risk_res["risk_score"],
                "playbook_id": response_res["playbook_id"],
                "mitre_technique": intel_res["mitre_info"]["technique_id"] + " - " + intel_res["mitre_info"]["technique_name"],
                "response_status": response_res["simulation_status"]
            }
        }

# Global Orchestrator instance
orchestrator = AgenticOrchestrator()
