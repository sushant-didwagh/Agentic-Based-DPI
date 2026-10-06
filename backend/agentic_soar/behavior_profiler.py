"""
Behavior Profiler & Anomaly Detection Engine (FortiNDR Profile)
===============================================================
Maintains baseline behavior profiles for internal endpoints:
- Normal destination subnets & domains
- Baseline throughput / byte rates
- Typical connection frequencies & active hours

Calculates Anomaly Score (0.0 to 1.0) and generates behavioral anomaly logs.
"""

from typing import Dict, Any, List

# Predefined baseline profiles for internal LAN IP addresses
ENDPOINT_BASELINES: Dict[str, Dict[str, Any]] = {
    "192.168.1.10": {
        "hostname": "Workstation-Finance-01",
        "role": "Corporate EndUser",
        "allowed_ports": [80, 443, 53],
        "trusted_domains": ["example.com", "microsoft.com", "google.com"],
        "max_conn_per_min": 20,
        "max_bytes_per_sec": 50000
    },
    "192.168.1.25": {
        "hostname": "Workstation-Dev-04",
        "role": "Software Developer",
        "allowed_ports": [80, 443, 22, 53, 8080],
        "trusted_domains": ["github.com", "example.com", "npmjs.org"],
        "max_conn_per_min": 50,
        "max_bytes_per_sec": 200000
    },
    "10.0.0.20": {
        "hostname": "Internal-AppServer-01",
        "role": "Production Application Web Server",
        "allowed_ports": [80, 443],
        "trusted_domains": ["internal-db.local"],
        "max_conn_per_min": 500,
        "max_bytes_per_sec": 10000000
    }
}

class BehaviorProfiler:
    @staticmethod
    def profile_connection(src_ip: str, dst_ip: str, dst_port: int, sni: str, conn_rate: float, bytes_sent: int) -> Dict[str, Any]:
        baseline = ENDPOINT_BASELINES.get(src_ip)
        anomalies: List[str] = []
        anomaly_score = 0.0

        if not baseline:
            # Unknown endpoint
            anomalies.append(f"Unprofiled internal device IP '{src_ip}'")
            anomaly_score += 0.25
        else:
            # Check Port
            if dst_port not in baseline["allowed_ports"]:
                anomalies.append(f"Unusual destination port {dst_port} for role '{baseline['role']}'")
                anomaly_score += 0.35

            # Check SNI
            if sni and not any(td in sni.lower() for td in baseline["trusted_domains"]):
                anomalies.append(f"Communication with unapproved domain '{sni}' outside 30-day baseline")
                anomaly_score += 0.30

            # Check Connection Rate
            if conn_rate > baseline["max_conn_per_min"]:
                anomalies.append(f"Connection rate {conn_rate}/min exceeds max baseline ({baseline['max_conn_per_min']}/min)")
                anomaly_score += 0.25

            # Check Bytes
            if bytes_sent > baseline["max_bytes_per_sec"]:
                anomalies.append(f"Data transfer ({bytes_sent} bytes) exceeds normal threshold")
                anomaly_score += 0.30

        # High port check (e.g. 31337, 4444)
        if dst_port in [31337, 4444, 6667, 8443] or (dst_port > 30000 and dst_port not in [3389, 8080]):
            if dst_port in [31337, 4444]:
                anomalies.append(f"Non-standard high-risk port {dst_port} detected")
                anomaly_score += 0.40

        anomaly_score = min(1.0, round(anomaly_score, 2))
        has_anomaly = anomaly_score > 0.30

        return {
            "has_anomaly": has_anomaly,
            "anomaly_score": anomaly_score,
            "anomalies": anomalies if anomalies else ["Traffic aligns with baseline behavioral profile."],
            "device_role": baseline["role"] if baseline else "Unknown LAN Endpoint"
        }
