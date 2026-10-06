"""
RAG Knowledge Base & Incident Memory Module
===========================================
- Security RAG Knowledge Base: Retrievable security policies, MITRE ATT&CK docs,
  FortiSOAR playbook guidelines.
- Incident Memory: Stores past security alerts, investigation findings, and actions taken
  for endpoint cross-correlation.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

# RAG Security Knowledge Corpus
KNOWLEDGE_BASE = [
    {
        "id": "KB-C2-001",
        "title": "Command and Control (C2) Detection Policy",
        "content": "C2 traffic typically exhibits periodic beaconing, TLS SNI spoofing, non-standard ports (e.g., 31337, 4444), or encrypted HTTP POST requests to unrated domains. Action: Immediately isolate endpoint and block destination IP."
    },
    {
        "id": "KB-EXFIL-002",
        "title": "Data Exfiltration Detection & Prevention",
        "content": "Data exfiltration involves large outbound byte transfers over HTTP/FTP/DNS tunnels. If data transfer rate exceeds 1MB/sec to an unverified external host, block connection and revoke network session tokens."
    },
    {
        "id": "KB-RECON-003",
        "title": "Port Scanning & Network Reconnaissance",
        "content": "Reconnaissance involves rapid sequential TCP SYN probes or UDP port sweeps across subnets. Action: Enable rate-limiting, flag host for heightened SOC monitoring."
    },
    {
        "id": "KB-SQLI-004",
        "title": "Web Application Exploitation (SQLi / RCE)",
        "content": "Exploit payloads contain keywords like UNION SELECT, OR 1=1, /bin/sh, or script tags in HTTP URIs or headers. Action: Block request at WAF layer and log source IP."
    },
    {
        "id": "KB-PLAYBOOK-005",
        "title": "FortiSOAR Playbook Execution Guidelines",
        "content": "High and Critical risk incidents require automated firewall rule creation (BLOCK DESTINATION) and immediate endpoint network isolation (SOAR-PB-ISOLATE)."
    }
]

class RAGKnowledgeBase:
    @staticmethod
    def query(query_text: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """Simple keyword / TF-IDF style similarity search over security knowledge corpus."""
        words = set(query_text.lower().split())
        scored = []
        for doc in KNOWLEDGE_BASE:
            doc_words = set(doc["content"].lower().split())
            overlap = len(words.intersection(doc_words))
            scored.append((overlap, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored[:top_k]]

class IncidentMemory:
    def __init__(self):
        self.history: List[Dict[str, Any]] = []

    def add_incident(self, incident: Dict[str, Any]):
        incident["timestamp"] = datetime.now().isoformat()
        self.history.insert(0, incident)
        if len(self.history) > 100:
            self.history.pop()

    def get_endpoint_history(self, src_ip: str) -> List[Dict[str, Any]]:
        return [i for i in self.history if i.get("source_ip") == src_ip]

# Global Memory Instance
incident_memory = IncidentMemory()
