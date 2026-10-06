"""
ML Threat Detection Layer (RandomForest / XGBoost Classifier)
============================================================
Trained on UNSW-NB15 / CIC-IDS2017 inspired network flow telemetry:
- Flow Duration
- Source / Destination Ports
- Byte Counts & Packet Counts
- Connection Frequency & Rate
- Protocol Encoding (TCP/UDP/ICMP)
- Payload Entropy & Signature Flags

Classifies traffic as NORMAL or ATTACK with specific categories:
- Command & Control (C2)
- Data Exfiltration
- Reconnaissance / Port Scan
- DoS / DDoS
- Exploits / SQL Injection
- Malware Backchannel
"""

import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml_model.joblib")

ATTACK_CATEGORIES = [
    "Clean Traffic",
    "Command & Control (C2)",
    "Data Exfiltration",
    "Reconnaissance / Port Scan",
    "DoS / DDoS Attack",
    "Exploit / SQL Injection",
    "Malware Backchannel"
]

class MLThreatDetector:
    def __init__(self):
        self.model = None
        self.feature_names = [
            "src_port", "dst_port", "protocol_code", "duration",
            "bytes_sent", "bytes_recv", "pkt_count", "conn_rate",
            "payload_len", "payload_entropy", "sni_suspicious"
        ]
        self._initialize_model()

    def _generate_synthetic_training_data(self, samples=2000):
        np.random.seed(42)
        data = []

        for _ in range(samples):
            # Pick a class
            is_attack = np.random.rand() > 0.45
            if not is_attack:
                category = 0 # Clean
                src_port = np.random.randint(1024, 65535)
                dst_port = np.random.choice([80, 443, 53, 22, 8080])
                protocol_code = np.random.choice([1, 2]) # TCP/UDP
                duration = np.random.exponential(5.0) + 0.1
                bytes_sent = np.random.randint(100, 15000)
                bytes_recv = np.random.randint(500, 50000)
                pkt_count = np.random.randint(5, 100)
                conn_rate = np.random.uniform(0.1, 5.0)
                payload_len = np.random.randint(20, 1000)
                payload_entropy = np.random.uniform(2.5, 4.5)
                sni_suspicious = 0
            else:
                category = np.random.choice([1, 2, 3, 4, 5, 6])
                if category == 1: # C2 Communication
                    src_port = np.random.randint(1024, 65535)
                    dst_port = np.random.choice([443, 8443, 31337, 4444])
                    protocol_code = 1 # TCP
                    duration = np.random.uniform(10.0, 300.0)
                    bytes_sent = np.random.randint(5000, 50000)
                    bytes_recv = np.random.randint(2000, 20000)
                    pkt_count = np.random.randint(50, 500)
                    conn_rate = np.random.uniform(10.0, 50.0)
                    payload_len = np.random.randint(200, 2000)
                    payload_entropy = np.random.uniform(5.5, 7.8)
                    sni_suspicious = 1
                elif category == 2: # Data Exfiltration
                    src_port = np.random.randint(1024, 65535)
                    dst_port = np.random.choice([443, 21, 8080])
                    protocol_code = 1
                    duration = np.random.uniform(60.0, 600.0)
                    bytes_sent = np.random.randint(100000, 5000000)
                    bytes_recv = np.random.randint(1000, 10000)
                    pkt_count = np.random.randint(500, 5000)
                    conn_rate = np.random.uniform(1.0, 20.0)
                    payload_len = np.random.randint(1000, 8000)
                    payload_entropy = np.random.uniform(6.0, 7.9)
                    sni_suspicious = np.random.choice([0, 1])
                elif category == 3: # Reconnaissance
                    src_port = np.random.randint(1024, 65535)
                    dst_port = np.random.randint(1, 10000)
                    protocol_code = 1
                    duration = np.random.uniform(0.01, 1.0)
                    bytes_sent = np.random.randint(40, 200)
                    bytes_recv = np.random.randint(0, 100)
                    pkt_count = np.random.randint(1, 5)
                    conn_rate = np.random.uniform(50.0, 200.0)
                    payload_len = np.random.randint(0, 100)
                    payload_entropy = np.random.uniform(1.0, 3.0)
                    sni_suspicious = 0
                elif category == 4: # DoS / DDoS
                    src_port = np.random.randint(1024, 65535)
                    dst_port = 80
                    protocol_code = 1
                    duration = np.random.uniform(0.1, 5.0)
                    bytes_sent = np.random.randint(500, 2000)
                    bytes_recv = np.random.randint(0, 200)
                    pkt_count = np.random.randint(100, 1000)
                    conn_rate = np.random.uniform(100.0, 500.0)
                    payload_len = np.random.randint(500, 1500)
                    payload_entropy = np.random.uniform(3.0, 5.0)
                    sni_suspicious = 0
                elif category == 5: # Exploit / SQLi
                    src_port = np.random.randint(1024, 65535)
                    dst_port = 80
                    protocol_code = 1
                    duration = np.random.uniform(0.2, 3.0)
                    bytes_sent = np.random.randint(500, 3000)
                    bytes_recv = np.random.randint(200, 1000)
                    pkt_count = np.random.randint(5, 20)
                    conn_rate = np.random.uniform(1.0, 10.0)
                    payload_len = np.random.randint(200, 1500)
                    payload_entropy = np.random.uniform(4.5, 6.5)
                    sni_suspicious = 0
                else: # Malware Backchannel
                    src_port = 31337
                    dst_port = 31337
                    protocol_code = 2 # UDP
                    duration = np.random.uniform(5.0, 50.0)
                    bytes_sent = np.random.randint(1000, 20000)
                    bytes_recv = np.random.randint(1000, 20000)
                    pkt_count = np.random.randint(20, 200)
                    conn_rate = np.random.uniform(5.0, 30.0)
                    payload_len = np.random.randint(300, 1200)
                    payload_entropy = np.random.uniform(5.0, 7.5)
                    sni_suspicious = 1

            data.append([
                src_port, dst_port, protocol_code, duration,
                bytes_sent, bytes_recv, pkt_count, conn_rate,
                payload_len, payload_entropy, sni_suspicious, category
            ])

        cols = self.feature_names + ["category"]
        df = pd.DataFrame(data, columns=cols)
        return df

    def _initialize_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                return
            except Exception:
                pass

        # Train new model
        df = self._generate_synthetic_training_data()
        X = df[self.feature_names]
        y = df["category"]

        clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
        clf.fit(X, y)
        self.model = clf

        try:
            joblib.dump(self.model, MODEL_PATH)
        except Exception:
            pass

    def _calculate_entropy(self, payload: str) -> float:
        if not payload:
            return 0.0
        prob = [float(payload.count(c)) / len(payload) for c in set(payload)]
        return -sum([p * np.log2(p) for p in prob])

    def predict_flow(self, packet_data: dict) -> dict:
        """
        Takes raw packet / flow telemetry and runs Random Forest ML classification.
        Returns:
            - is_attack (bool)
            - prediction ("ATTACK" or "NORMAL")
            - attack_category (str)
            - confidence_score (float 0..1)
            - top_features (dict)
        """
        protocol_str = str(packet_data.get("protocol", "TCP")).upper()
        proto_code = 1 if protocol_str == "TCP" else (2 if protocol_str == "UDP" else 3)

        payload = packet_data.get("payload", "")
        payload_entropy = self._calculate_entropy(payload)
        payload_len = len(payload)

        sni = packet_data.get("sni", "").lower()
        sni_suspicious = 1 if any(s in sni for s in ["bad", "malicious", "c2", "xyz", "evil", "trojan"]) else 0

        # Features array
        features = np.array([[
            packet_data.get("source_port", 54321),
            packet_data.get("destination_port", 80),
            proto_code,
            float(packet_data.get("duration", 2.5)),
            int(packet_data.get("bytes_sent", len(payload) + 100)),
            int(packet_data.get("bytes_recv", 500)),
            int(packet_data.get("packet_count", 15)),
            float(packet_data.get("conn_rate", 5.0)),
            payload_len,
            payload_entropy,
            sni_suspicious
        ]])

        probs = self.model.predict_proba(features)[0]
        pred_cat_idx = int(np.argmax(probs))
        confidence = float(probs[pred_cat_idx])

        # If malicious payload or blocked SNI keyword, ensure high confidence attack trigger
        if "MALICIOUS" in payload.upper() or "C2" in payload.upper() or sni_suspicious == 1:
            if pred_cat_idx == 0:
                pred_cat_idx = 1 # Force C2 category if strong signature present
                confidence = max(confidence, 0.93)

        category_name = ATTACK_CATEGORIES[pred_cat_idx]
        is_attack = pred_cat_idx != 0

        # Feature importances breakdown
        importances = self.model.feature_importances_
        feature_importance_dict = {
            name: round(float(imp), 4)
            for name, imp in zip(self.feature_names, importances)
        }

        return {
            "is_attack": is_attack,
            "prediction": "ATTACK" if is_attack else "NORMAL",
            "attack_category": category_name,
            "confidence_score": round(confidence, 4),
            "payload_entropy": round(payload_entropy, 2),
            "feature_importance": feature_importance_dict
        }

# Global detector instance
detector = MLThreatDetector()
