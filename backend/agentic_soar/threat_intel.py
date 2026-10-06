"""
Local Threat Intelligence & IOC Database Module
================================================
Provides offline threat reputation database & MITRE ATT&CK framework mapping.
No external API calls required for offline academic evaluation.
"""

from typing import Dict, Any, Optional

# Local IOC IP Reputation Database
KNOWN_IP_IOCS: Dict[str, Dict[str, Any]] = {
    "198.51.100.5": {
        "reputation": "MALICIOUS",
        "threat_type": "Command & Control (C2)",
        "threat_actor": "APT-29 (Cozy Bear)",
        "risk_score": 95,
        "country": "RU",
        "asn": "AS49872 (Suspicious Hosting)"
    },
    "185.220.101.5": {
        "reputation": "MALICIOUS",
        "threat_type": "Tor Exit Node / C2 Proxy",
        "threat_actor": "Unknown Botnet",
        "risk_score": 90,
        "country": "DE",
        "asn": "AS205100"
    },
    "192.168.1.50": {
        "reputation": "SUSPICIOUS",
        "threat_type": "Compromised Internal Host",
        "threat_actor": "Insider Threat / Infected Workstation",
        "risk_score": 85,
        "country": "LOCAL",
        "asn": "LAN Subnet"
    },
    "172.16.5.99": {
        "reputation": "SUSPICIOUS",
        "threat_type": "Port Scanner / Recon Hub",
        "threat_actor": "Internal Probe",
        "risk_score": 75,
        "country": "LOCAL",
        "asn": "LAN Subnet"
    }
}

# Local Domain / SNI IOC Database
KNOWN_DOMAIN_IOCS: Dict[str, Dict[str, Any]] = {
    "bad-domain.xyz": {
        "reputation": "MALICIOUS",
        "category": "C2 Domain",
        "first_seen": "2026-08-15",
        "risk_score": 98
    },
    "malicious-test.example": {
        "reputation": "MALICIOUS",
        "category": "Phishing / Malware Distribution",
        "first_seen": "2026-09-01",
        "risk_score": 92
    },
    "c2-server.net": {
        "reputation": "MALICIOUS",
        "category": "Command & Control Beacon",
        "first_seen": "2026-07-20",
        "risk_score": 99
    }
}

# MITRE ATT&CK Mapping
MITRE_ATTACK_MAPPING: Dict[str, Dict[str, Any]] = {
    "Command & Control (C2)": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries communicate using application layer protocols (HTTP/HTTPS) to blend in with normal network traffic.",
        "fortinet_playbook": "SOAR-PB-C2-ISOLATE"
    },
    "Data Exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries steal sensitive internal data by transferring it over an established C2 channel.",
        "fortinet_playbook": "SOAR-PB-EXFIL-BLOCK"
    },
    "Reconnaissance / Port Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries attempt to get a listing of services running on remote hosts to locate vulnerable endpoints.",
        "fortinet_playbook": "SOAR-PB-RECON-MONITOR"
    },
    "DoS / DDoS Attack": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries perform network DoS attacks to degrade or disrupt service availability.",
        "fortinet_playbook": "SOAR-PB-DDOS-RATE-LIMIT"
    },
    "Exploit / SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries attempt to exploit software vulnerabilities in web servers via malicious payload parameters.",
        "fortinet_playbook": "SOAR-PB-WAF-BLOCK"
    },
    "Malware Backchannel": {
        "technique_id": "T1571",
        "technique_name": "Non-Standard Port Communication",
        "tactic": "Command and Control",
        "description": "Adversaries send malicious commands over non-standard network ports to bypass standard firewall rules.",
        "fortinet_playbook": "SOAR-PB-ISOLATE-PORT"
    }
}

class ThreatIntelligence:
    @staticmethod
    def query_ip(ip: str) -> Optional[Dict[str, Any]]:
        return KNOWN_IP_IOCS.get(ip)

    @staticmethod
    def query_domain(domain: str) -> Optional[Dict[str, Any]]:
        if not domain:
            return None
        domain_lower = domain.lower()
        for k, v in KNOWN_DOMAIN_IOCS.items():
            if k in domain_lower:
                return v
        return None

    @staticmethod
    def get_mitre_info(attack_category: str) -> Dict[str, Any]:
        return MITRE_ATTACK_MAPPING.get(attack_category, {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "description": "Suspicious execution pattern detected in network payload stream.",
            "fortinet_playbook": "SOAR-PB-GENERIC-ALERT"
        })
