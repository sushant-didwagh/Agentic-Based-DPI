"""
Multi-Agent System & ReAct Autonomous Loop
===========================================
6 Specialized Security Agents inspired by Fortinet (FortiNDR + FortiAI / FortiSOAR):

1. Traffic Analysis Agent     → Analyzes packet features, flow duration, volume
2. Threat Intelligence Agent   → Queries IOC database, IP/Domain reputation, MITRE ATT&CK
3. Behavior Analysis Agent    → Compares flow against endpoint historical baseline
4. Investigation Agent        → ReAct Loop (Observe → Reason → Act → Observe → Reason)
5. Risk Assessment Agent       → Calculates final weighted risk level (LOW/MEDIUM/HIGH/CRITICAL)
6. Response Agent (FortiSOAR)  → Executes playbooks & simulates firewall/endpoint isolation
"""

from typing import Dict, Any, List
import json
from .threat_intel import ThreatIntelligence
from .behavior_profiler import BehaviorProfiler
from .rag_memory import RAGKnowledgeBase, incident_memory

# ─────────────────────────────────────────────────────────────
# Agent 1: Traffic Analysis Agent
# ─────────────────────────────────────────────────────────────
class TrafficAnalysisAgent:
    @staticmethod
    def run(packet_data: dict, ml_result: dict) -> dict:
        src_ip   = packet_data.get("source_ip", "0.0.0.0")
        dst_ip   = packet_data.get("destination_ip", "0.0.0.0")
        src_port = packet_data.get("source_port", 0)
        dst_port = packet_data.get("destination_port", 0)
        proto    = packet_data.get("protocol", "TCP")
        payload  = packet_data.get("payload", "")

        findings = []
        if dst_port in [80, 443, 53]:
            findings.append(f"Standard protocol service port {dst_port} ({proto})")
        else:
            findings.append(f"Non-standard communication port {dst_port} ({proto})")

        if len(payload) > 1000:
            findings.append(f"Large payload body detected ({len(payload)} bytes)")
        elif ml_result.get("payload_entropy", 0) > 6.0:
            findings.append(f"High payload entropy ({ml_result.get('payload_entropy')} bits/byte) indicating encryption or obfuscation")

        observation = (
            f"Endpoint {src_ip}:{src_port} connected to {dst_ip}:{dst_port} via {proto}. "
            f"Traffic payload size: {len(payload)} bytes. " + " ".join(findings)
        )

        return {
            "agent_name": "Traffic Analysis Agent",
            "status": "COMPLETED",
            "observation": observation,
            "findings": findings
        }

# ─────────────────────────────────────────────────────────────
# Agent 2: Threat Intelligence Agent
# ─────────────────────────────────────────────────────────────
class ThreatIntelAgent:
    @staticmethod
    def run(packet_data: dict, ml_result: dict) -> dict:
        dst_ip = packet_data.get("destination_ip", "")
        sni    = packet_data.get("sni", "")
        cat    = ml_result.get("attack_category", "Clean Traffic")

        ip_info   = ThreatIntelligence.query_ip(dst_ip)
        domain_info = ThreatIntelligence.query_domain(sni)
        mitre_info  = ThreatIntelligence.get_mitre_info(cat)

        threat_findings = []
        is_malicious = False

        if ip_info:
            is_malicious = True
            threat_findings.append(f"Destination IP {dst_ip} flagged as {ip_info['reputation']} ({ip_info['threat_type']}) by Threat Intel")
        if domain_info:
            is_malicious = True
            threat_findings.append(f"Domain '{sni}' flagged as {domain_info['reputation']} ({domain_info['category']})")

        if not threat_findings:
            threat_findings.append("No active IOC matches found in local reputation feed.")

        observation = (
            f"MITRE ATT&CK Mapping: {mitre_info['technique_id']} ({mitre_info['technique_name']}) - {mitre_info['tactic']}. "
            + " ".join(threat_findings)
        )

        return {
            "agent_name": "Threat Intelligence Agent",
            "status": "COMPLETED",
            "observation": observation,
            "is_ioc_matched": is_malicious,
            "ip_ioc": ip_info,
            "domain_ioc": domain_info,
            "mitre_info": mitre_info
        }

# ─────────────────────────────────────────────────────────────
# Agent 3: Behavior Analysis Agent
# ─────────────────────────────────────────────────────────────
class BehaviorAnalysisAgent:
    @staticmethod
    def run(packet_data: dict) -> dict:
        src_ip    = packet_data.get("source_ip", "")
        dst_ip    = packet_data.get("destination_ip", "")
        dst_port  = packet_data.get("destination_port", 80)
        sni       = packet_data.get("sni", "")
        conn_rate = float(packet_data.get("conn_rate", 5.0))
        bytes_sent= int(packet_data.get("bytes_sent", len(packet_data.get("payload", ""))))

        profile = BehaviorProfiler.profile_connection(src_ip, dst_ip, dst_port, sni, conn_rate, bytes_sent)

        # Check endpoint memory history
        past_incidents = incident_memory.get_endpoint_history(src_ip)
        history_note = f"Host has {len(past_incidents)} previous flagged security incidents." if past_incidents else "Host has no previous security incidents."

        observation = (
            f"Device Role: {profile['device_role']}. Anomaly Score: {profile['anomaly_score']}. "
            f"Behavioral Indicators: {'; '.join(profile['anomalies'])}. {history_note}"
        )

        return {
            "agent_name": "Behavior Analysis Agent",
            "status": "COMPLETED",
            "observation": observation,
            "anomaly_score": profile["anomaly_score"],
            "has_anomaly": profile["has_anomaly"],
            "anomalies": profile["anomalies"],
            "history_count": len(past_incidents)
        }

# ─────────────────────────────────────────────────────────────
# Agent 4: Investigation Agent (ReAct Loop)
# ─────────────────────────────────────────────────────────────
class InvestigationAgent:
    @staticmethod
    def run(packet_data: dict, ml_result: dict, traffic_res: dict, intel_res: dict, behavior_res: dict) -> dict:
        react_steps = []

        # Step 1: Initial Observation
        react_steps.append({
            "step": 1,
            "phase": "OBSERVE",
            "thought": "Network event received. ML Classifier predicted " + ml_result["prediction"] + " (" + ml_result["attack_category"] + ") with " + str(int(ml_result["confidence_score"] * 100)) + "% confidence.",
            "action": "Initiate Agentic Multi-Tool Investigation Workflow",
            "result": "Telemetry dispatched to specialized agents."
        })

        # Step 2: Evaluate Traffic Analysis
        react_steps.append({
            "step": 2,
            "phase": "REASON",
            "thought": "Inspecting network payload metrics and port characteristics.",
            "action": "Query Traffic Analysis Agent",
            "result": traffic_res["observation"]
        })

        # Step 3: Evaluate Threat Intelligence & RAG Knowledge
        rag_docs = RAGKnowledgeBase.query(ml_result["attack_category"] + " " + packet_data.get("payload", ""))
        rag_summary = rag_docs[0]["content"] if rag_docs else "No specific KB policy found."

        react_steps.append({
            "step": 3,
            "phase": "ACT",
            "thought": "Cross-referencing IOC database and querying Security RAG Knowledge Base.",
            "action": "Execute Threat Intel Lookup & Knowledge Base Retrieval",
            "result": f"Threat Intel: {intel_res['observation']} | RAG Policy Match: {rag_summary}"
        })

        # Step 4: Evaluate Behavioral Anomaly
        react_steps.append({
            "step": 4,
            "phase": "REASON",
            "thought": "Comparing current flow against host historical baseline and past incident memory.",
            "action": "Query Behavior Analysis Agent",
            "result": behavior_res["observation"]
        })

        # Step 5: Final Reasoning & Hypothesis Synthesis
        if ml_result["is_attack"] or intel_res["is_ioc_matched"] or behavior_res["has_anomaly"]:
            hypothesis = (
                f"CORRELATED THREAT HYPOTHESIS: High confidence indication of {ml_result['attack_category']} "
                f"targeting destination {packet_data.get('destination_ip')}. MITRE Technique: {intel_res['mitre_info']['technique_id']}. "
                f"Action required: Escalate to Risk Assessment and trigger FortiSOAR playbook."
            )
        else:
            hypothesis = "CORRELATED THREAT HYPOTHESIS: Clean network traffic. No threat indicators or baseline anomalies detected."

        react_steps.append({
            "step": 5,
            "phase": "OBSERVE & DECIDE",
            "thought": hypothesis,
            "action": "Formulate Final Investigation Conclusion",
            "result": hypothesis
        })

        return {
            "agent_name": "Investigation Agent (ReAct Loop)",
            "status": "COMPLETED",
            "hypothesis": hypothesis,
            "react_steps": react_steps,
            "rag_docs": rag_docs
        }

# ─────────────────────────────────────────────────────────────
# Agent 5: Risk Assessment Agent
# ─────────────────────────────────────────────────────────────
class RiskAssessmentAgent:
    @staticmethod
    def run(ml_result: dict, intel_res: dict, behavior_res: dict) -> dict:
        # Weighted Risk Formula:
        # Risk = (ML_Confidence * 0.40) + (IOC_Score * 0.35) + (Anomaly_Score * 0.25)
        ml_score  = ml_result["confidence_score"] if ml_result["is_attack"] else 0.05
        ioc_score = 0.95 if intel_res["is_ioc_matched"] else 0.0
        anom_score= behavior_res["anomaly_score"]

        composite_score = (ml_score * 0.40) + (ioc_score * 0.35) + (anom_score * 0.25)
        composite_score = round(min(1.0, max(0.0, composite_score)), 2)

        if composite_score >= 0.75:
            risk_level = "CRITICAL"
        elif composite_score >= 0.50:
            risk_level = "HIGH"
        elif composite_score >= 0.25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        justification = (
            f"Calculated Weighted Risk Index: {composite_score*100:.0f}%. "
            f"Factors: ML Threat Score ({ml_score*100:.0f}%), Threat Intel IOC Match ({ioc_score*100:.0f}%), "
            f"Behavior Anomaly Score ({anom_score*100:.0f}%)."
        )

        return {
            "agent_name": "Risk Assessment Agent",
            "status": "COMPLETED",
            "risk_level": risk_level,
            "risk_score": composite_score,
            "justification": justification
        }

# ─────────────────────────────────────────────────────────────
# Agent 6: Response Agent (FortiSOAR Playbook Simulator)
# ─────────────────────────────────────────────────────────────
class ResponseAgent:
    @staticmethod
    def run(packet_data: dict, risk_res: dict, intel_res: dict) -> dict:
        risk_level = risk_res["risk_level"]
        dst_ip     = packet_data.get("destination_ip", "0.0.0.0")
        src_ip     = packet_data.get("source_ip", "0.0.0.0")
        mitre_pb   = intel_res["mitre_info"].get("fortinet_playbook", "SOAR-PB-DEFAULT")

        actions = []
        if risk_level in ["HIGH", "CRITICAL"]:
            actions.append(f"BLOCK DESTINATION IP ({dst_ip}) via FortiGate Firewall Rule")
            actions.append(f"ISOLATE ENDPOINT HOST ({src_ip}) via FortiEDR / SOAR Fabric")
            actions.append(f"CREATE HIGH-PRIORITY SOC INCIDENT TICKET ({mitre_pb})")
            actions.append("SEND IMMEDIATE PAGER/SLACK ALERT TO SOC SEC-OPS TEAM")
            action_status = "ACTION SIMULATED SUCCESSFULLY — FIREWALL & ISOLATION RULES GENERATED"
        elif risk_level == "MEDIUM":
            actions.append(f"RATE-LIMIT TRAFFIC TO {dst_ip}")
            actions.append("FLAG HOST FOR HEIGHTENED DPI LOGGING")
            actions.append("CREATE MEDIUM-PRIORITY ANALYST INVESTIGATION TASK")
            action_status = "ACTION SIMULATED SUCCESSFULLY — TRAFFIC RATE-LIMITED"
        else:
            actions.append("CONTINUE MONITORED PASS-THROUGH TRAFFIC")
            actions.append("LOG SESSION TO TELEMETRY ARCHIVE")
            action_status = "ACTION COMPLETED — PASSTHROUGH LOGGED"

        # Record to memory
        incident_memory.add_incident({
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "risk_level": risk_level,
            "actions_taken": actions
        })

        return {
            "agent_name": "Response Agent (FortiSOAR)",
            "status": "COMPLETED",
            "playbook_id": mitre_pb,
            "recommended_actions": actions,
            "simulation_status": action_status
        }
