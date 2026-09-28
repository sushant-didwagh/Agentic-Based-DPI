"""
DPI Engine - Python Implementation
===================================
A faithful Python mirror of the C++ DPI engine in src/dpi_mt.cpp.

This module implements the same inspection pipeline:
  Packet Input → FiveTuple → Flow Lookup → SNI Inspection
  → Payload Inspection → Rule Evaluation → Verdict

All detection logic mirrors the C++ sniToAppType(), Rules::isBlocked(),
and the FastPath::classifyFlow() functions exactly.
"""

import time
import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, List, Tuple
from datetime import datetime
import threading


# =============================================================================
# AppType — mirrors DPI::AppType enum in include/types.h
# =============================================================================
class AppType(Enum):
    UNKNOWN    = 0
    HTTP       = 1
    HTTPS      = 2
    DNS        = 3
    TLS        = 4
    QUIC       = 5
    GOOGLE     = 6
    FACEBOOK   = 7
    YOUTUBE    = 8
    TWITTER    = 9
    INSTAGRAM  = 10
    NETFLIX    = 11
    AMAZON     = 12
    MICROSOFT  = 13
    APPLE      = 14
    WHATSAPP   = 15
    TELEGRAM   = 16
    TIKTOK     = 17
    SPOTIFY    = 18
    ZOOM       = 19
    DISCORD    = 20
    GITHUB     = 21
    CLOUDFLARE = 22


def app_type_to_string(app: AppType) -> str:
    """Mirrors DPI::appTypeToString() in src/types.cpp"""
    return {
        AppType.UNKNOWN:    "Unknown",
        AppType.HTTP:       "HTTP",
        AppType.HTTPS:      "HTTPS",
        AppType.DNS:        "DNS",
        AppType.TLS:        "TLS",
        AppType.QUIC:       "QUIC",
        AppType.GOOGLE:     "Google",
        AppType.FACEBOOK:   "Facebook",
        AppType.YOUTUBE:    "YouTube",
        AppType.TWITTER:    "Twitter/X",
        AppType.INSTAGRAM:  "Instagram",
        AppType.NETFLIX:    "Netflix",
        AppType.AMAZON:     "Amazon",
        AppType.MICROSOFT:  "Microsoft",
        AppType.APPLE:      "Apple",
        AppType.WHATSAPP:   "WhatsApp",
        AppType.TELEGRAM:   "Telegram",
        AppType.TIKTOK:     "TikTok",
        AppType.SPOTIFY:    "Spotify",
        AppType.ZOOM:       "Zoom",
        AppType.DISCORD:    "Discord",
        AppType.GITHUB:     "GitHub",
        AppType.CLOUDFLARE: "Cloudflare",
    }.get(app, "Unknown")


def sni_to_app_type(sni: str) -> AppType:
    """
    Mirrors DPI::sniToAppType() in src/types.cpp
    Maps domain strings to AppType using case-insensitive substring matching.
    """
    if not sni:
        return AppType.UNKNOWN

    lower = sni.lower()

    # YouTube (check before Google since YouTube is Google-owned)
    if any(p in lower for p in ["youtube", "ytimg", "youtu.be", "yt3.ggpht"]):
        return AppType.YOUTUBE

    # Google
    if any(p in lower for p in ["google", "gstatic", "googleapis", "ggpht", "gvt1"]):
        return AppType.GOOGLE

    # Facebook/Meta
    if any(p in lower for p in ["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"]):
        return AppType.FACEBOOK

    # Instagram
    if any(p in lower for p in ["instagram", "cdninstagram"]):
        return AppType.INSTAGRAM

    # WhatsApp
    if any(p in lower for p in ["whatsapp", "wa.me"]):
        return AppType.WHATSAPP

    # Twitter/X
    if any(p in lower for p in ["twitter", "twimg", "x.com", "t.co"]):
        return AppType.TWITTER

    # Netflix
    if any(p in lower for p in ["netflix", "nflxvideo", "nflximg"]):
        return AppType.NETFLIX

    # Amazon/AWS
    if any(p in lower for p in ["amazon", "amazonaws", "cloudfront", "aws"]):
        return AppType.AMAZON

    # Microsoft
    if any(p in lower for p in ["microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"]):
        return AppType.MICROSOFT

    # Apple
    if any(p in lower for p in ["apple", "icloud", "mzstatic", "itunes"]):
        return AppType.APPLE

    # Telegram
    if any(p in lower for p in ["telegram", "t.me"]):
        return AppType.TELEGRAM

    # TikTok
    if any(p in lower for p in ["tiktok", "tiktokcdn", "musical.ly", "bytedance"]):
        return AppType.TIKTOK

    # Spotify
    if any(p in lower for p in ["spotify", "scdn.co"]):
        return AppType.SPOTIFY

    # Zoom
    if "zoom" in lower:
        return AppType.ZOOM

    # Discord
    if any(p in lower for p in ["discord", "discordapp"]):
        return AppType.DISCORD

    # GitHub
    if any(p in lower for p in ["github", "githubusercontent"]):
        return AppType.GITHUB

    # Cloudflare
    if any(p in lower for p in ["cloudflare", "cf-"]):
        return AppType.CLOUDFLARE

    # Port-based fallback: if SNI is present but unrecognized → HTTPS
    return AppType.HTTPS


# =============================================================================
# FiveTuple — mirrors DPI::FiveTuple in include/types.h
# =============================================================================
@dataclass(frozen=True)
class FiveTuple:
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    protocol: str  # "TCP" or "UDP"

    def to_string(self) -> str:
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}/{self.protocol}"

    def hash_key(self) -> int:
        """
        Mirrors DPI::FiveTupleHash from include/types.h.
        Uses the same golden-ratio-based combining approach.
        """
        h = 0
        GOLDEN = 0x9e3779b9
        for val in [hash(self.src_ip), hash(self.dst_ip),
                    self.src_port, self.dst_port, hash(self.protocol)]:
            h ^= (val + GOLDEN + (h << 6) + (h >> 2)) & 0xFFFFFFFFFFFFFFFF
        return h


# =============================================================================
# FlowEntry — mirrors the FlowEntry struct in src/dpi_mt.cpp
# =============================================================================
@dataclass
class FlowEntry:
    tuple:            FiveTuple
    app_type:         AppType = AppType.UNKNOWN
    sni:              str = ""
    packets:          int = 0
    bytes_seen:       int = 0
    blocked:          bool = False
    classified:       bool = False
    block_reason_code: Optional[str] = None
    block_reason:     Optional[str] = None


# =============================================================================
# Verdict — machine-readable DPI decision (Phase 3 contract)
# =============================================================================
@dataclass
class DPIVerdict:
    action:      str          # "ALLOW" or "BLOCK"
    reason_code: str          # machine-readable code
    reason:      str          # human-readable message
    details:     dict = field(default_factory=dict)
    inspection_time_ms: float = 0.0


# =============================================================================
# Payload Signatures — safe simulation signatures
# These mirror what would be configured as DPI signatures in a real engine.
# =============================================================================
MALICIOUS_PAYLOAD_SIGNATURES: Dict[str, str] = {
    "MALICIOUS_TEST_SIGNATURE":  "Malicious test signature detected in payload",
    "SIMULATED_VIRUS_SIGNATURE": "Simulated virus signature detected in payload",
    "EICAR_TEST_SIGNATURE":      "EICAR-style test signature detected",
    "EXPLOIT_TEST_PAYLOAD":      "Exploit test pattern detected in payload",
    "SHELLCODE_TEST_PATTERN":    "Shellcode test pattern detected",
    "OR '1'='1'":                "SQL injection attack signature detected (OR 1=1)",
    "SELECT * FROM":             "SQL injection attack signature detected (SELECT query)",
    "<script>":                  "Cross-Site Scripting (XSS) payload detected",
}

SUSPICIOUS_PAYLOAD_SIGNATURES: Dict[str, str] = {
    "SUSPICIOUS_PAYLOAD_TEST":   "Suspicious payload pattern detected",
    "ANOMALY_TEST_PATTERN":      "Traffic anomaly pattern detected",
    "SQL_INJECT_TEST":           "SQL injection test pattern detected",
    "/bin/sh":                   "Suspicious shell command pattern detected",
    "cmd.exe":                   "Suspicious Windows command execution pattern",
}

# =============================================================================
# Default Security Rules
# These mirror the rules that can be configured via CLI in the C++ engine.
# =============================================================================
DEFAULT_BLOCKED_SNIS: List[str] = [
    "malicious-test.example",
    "blocked.example",
    "malware.test",
    "phishing.test",
    "blocked-domain.test",
    "malware-cdn.example",
]

DEFAULT_BLOCKED_IPS: List[str] = [
    "10.0.0.1",       # Example blocked server IP
    "192.168.1.50",   # Example blocked client IP
]

DEFAULT_BLOCKED_APPS: List[AppType] = [
    # Empty by default — can be configured
]

DEFAULT_BLOCKED_PORTS: List[int] = [
    # Empty by default — can be configured
]


# =============================================================================
# DPI Inspection Engine
# Mirrors the FastPath::classifyFlow() + Rules::isBlocked() logic from C++
# =============================================================================
class DPIInspectionEngine:
    """
    The core DPI inspection engine.

    Implements the same pipeline as the C++ FastPath thread:
      1. Flow lookup / creation (5-tuple based)
      2. Application classification (SNI → AppType)
      3. Security rule evaluation (IP / Port / App / Domain / Payload)
      4. Verdict generation with reason codes

    Thread-safe: uses a lock for flow table access.
    """

    def __init__(self):
        # Flow table — mirrors the per-FP flows_ map in C++
        self._flows: Dict[FiveTuple, FlowEntry] = {}
        self._lock = threading.Lock()

        # Security rules — mirrors the Rules class in dpi_mt.cpp
        self.blocked_ips:     List[str] = list(DEFAULT_BLOCKED_IPS)
        self.blocked_apps:    List[AppType] = list(DEFAULT_BLOCKED_APPS)
        self.blocked_domains: List[str] = list(DEFAULT_BLOCKED_SNIS)
        self.blocked_ports:   List[int] = list(DEFAULT_BLOCKED_PORTS)

        # Statistics
        self.total_inspected: int = 0
        self.total_allowed:   int = 0
        self.total_blocked:   int = 0
        self._stats_lock = threading.Lock()

    def inspect(
        self,
        source_ip:   str,
        source_port: int,
        dest_ip:     str,
        dest_port:   int,
        protocol:    str,
        sni:         str = "",
        payload:     str = "",
    ) -> DPIVerdict:
        """
        Main inspection method. Receives a normalized packet description
        and returns a DPIVerdict.

        This mirrors the FastPath::run() processing loop in src/dpi_mt.cpp,
        including flow lookup, classification, and rule evaluation.
        """
        start_time = time.perf_counter()

        # Build inspection log for the verdict details
        inspection_steps: List[str] = []

        # ── Step 1: Validate inputs ──────────────────────────────────────────
        validation_error = self._validate_inputs(source_ip, source_port, dest_ip, dest_port, protocol)
        if validation_error:
            elapsed = (time.perf_counter() - start_time) * 1000
            return DPIVerdict(
                action="ERROR",
                reason_code="VALIDATION_ERROR",
                reason=validation_error,
                details={"field": "input"},
                inspection_time_ms=round(elapsed, 2),
            )

        inspection_steps.append("Input validation: PASS")

        # ── Step 2: Build 5-tuple and look up / create flow ─────────────────
        # Mirrors: FlowEntry& flow = flows_[pkt.tuple] in FastPath::run()
        tuple_ = FiveTuple(
            src_ip=source_ip,
            dst_ip=dest_ip,
            src_port=source_port,
            dst_port=dest_port,
            protocol=protocol.upper(),
        )

        with self._lock:
            if tuple_ not in self._flows:
                self._flows[tuple_] = FlowEntry(tuple=tuple_)
            flow = self._flows[tuple_]
            flow.packets += 1
            flow.bytes_seen += len(payload)

        inspection_steps.append(f"Flow identified: {tuple_.to_string()}")

        # ── Step 3: SNI / Application classification ─────────────────────────
        # Mirrors: FastPath::classifyFlow() in src/dpi_mt.cpp
        effective_sni = sni.strip().lower() if sni else ""

        if not flow.classified:
            if effective_sni:
                flow.sni = effective_sni
                flow.app_type = sni_to_app_type(effective_sni)
                flow.classified = True
                inspection_steps.append(f"SNI extracted: {effective_sni}")
                inspection_steps.append(f"Application classified: {app_type_to_string(flow.app_type)}")
            elif dest_port == 443:
                flow.app_type = AppType.HTTPS
                inspection_steps.append("Port-based classification: HTTPS (port 443)")
            elif dest_port == 80:
                flow.app_type = AppType.HTTP
                inspection_steps.append("Port-based classification: HTTP (port 80)")
            elif dest_port == 53 or source_port == 53:
                flow.app_type = AppType.DNS
                flow.classified = True
                inspection_steps.append("Port-based classification: DNS (port 53)")
        else:
            inspection_steps.append(f"Flow already classified: {app_type_to_string(flow.app_type)}")

        # ── Step 4: Security rule evaluation ────────────────────────────────
        # Mirrors: Rules::isBlocked() in src/dpi_mt.cpp
        # Order: IP → Port → App → Domain → Payload signatures

        # 4a. Source IP check
        if source_ip in self.blocked_ips:
            verdict = self._make_block_verdict(
                reason_code="BLOCKED_IP",
                reason=f"Source IP {source_ip} is in the blocked IP list",
                flow=flow,
                steps=inspection_steps,
                step_msg=f"IP check: BLOCKED ({source_ip})",
                start_time=start_time,
            )
            self._record_block(flow, "BLOCKED_IP", verdict.reason)
            return verdict

        inspection_steps.append(f"IP check: PASS ({source_ip} not blocked)")

        # 4b. Destination port check
        if dest_port in self.blocked_ports:
            verdict = self._make_block_verdict(
                reason_code="BLOCKED_PORT",
                reason=f"Destination port {dest_port} is blocked",
                flow=flow,
                steps=inspection_steps,
                step_msg=f"Port check: BLOCKED (port {dest_port})",
                start_time=start_time,
            )
            self._record_block(flow, "BLOCKED_PORT", verdict.reason)
            return verdict

        inspection_steps.append(f"Port check: PASS (port {dest_port} not blocked)")

        # 4c. Application type check
        if flow.app_type in self.blocked_apps:
            app_name = app_type_to_string(flow.app_type)
            verdict = self._make_block_verdict(
                reason_code="BLOCKED_APP",
                reason=f"Application '{app_name}' is in the blocked application list",
                flow=flow,
                steps=inspection_steps,
                step_msg=f"App check: BLOCKED ({app_name})",
                start_time=start_time,
            )
            self._record_block(flow, "BLOCKED_APP", verdict.reason)
            return verdict

        inspection_steps.append(f"App check: PASS ({app_type_to_string(flow.app_type)} not blocked)")

        # 4d. Domain/SNI check — mirrors substring matching in C++ isBlocked()
        if effective_sni:
            inspection_steps.append(f"SNI inspection: checking '{effective_sni}'")
            for blocked_domain in self.blocked_domains:
                if blocked_domain.lower() in effective_sni:
                    verdict = self._make_block_verdict(
                        reason_code="BLOCKED_SNI",
                        reason=f"SNI '{effective_sni}' matches blocked domain pattern '{blocked_domain}'",
                        flow=flow,
                        steps=inspection_steps,
                        step_msg=f"SNI check: BLOCKED (matched '{blocked_domain}')",
                        start_time=start_time,
                    )
                    self._record_block(flow, "BLOCKED_SNI", verdict.reason)
                    return verdict
            inspection_steps.append("SNI check: PASS (no blocked domain matched)")

        # 4e. Payload signature inspection (extends C++ engine for demo)
        if payload:
            inspection_steps.append(f"Payload inspection: scanning {len(payload)} bytes")

            # Check malicious signatures
            for sig, description in MALICIOUS_PAYLOAD_SIGNATURES.items():
                if sig in payload:
                    verdict = self._make_block_verdict(
                        reason_code="MALICIOUS_SIGNATURE",
                        reason=description,
                        flow=flow,
                        steps=inspection_steps,
                        step_msg=f"Payload check: BLOCKED (malicious signature '{sig}')",
                        start_time=start_time,
                        extra={"matched_signature": sig, "field": "payload"},
                    )
                    self._record_block(flow, "MALICIOUS_SIGNATURE", verdict.reason)
                    return verdict

            # Check suspicious signatures
            for sig, description in SUSPICIOUS_PAYLOAD_SIGNATURES.items():
                if sig in payload:
                    verdict = self._make_block_verdict(
                        reason_code="SUSPICIOUS_PAYLOAD",
                        reason=description,
                        flow=flow,
                        steps=inspection_steps,
                        step_msg=f"Payload check: BLOCKED (suspicious pattern '{sig}')",
                        start_time=start_time,
                        extra={"matched_signature": sig, "field": "payload"},
                    )
                    self._record_block(flow, "SUSPICIOUS_PAYLOAD", verdict.reason)
                    return verdict

            inspection_steps.append("Payload check: PASS (no malicious signature detected)")
        else:
            inspection_steps.append("Payload check: PASS (no payload to inspect)")

        # ── Step 5: All checks passed → ALLOW ───────────────────────────────
        elapsed = (time.perf_counter() - start_time) * 1000
        inspection_steps.append("Verdict: ALLOW")

        with self._stats_lock:
            self.total_inspected += 1
            self.total_allowed += 1

        return DPIVerdict(
            action="ALLOW",
            reason_code="CLEAN_TRAFFIC",
            reason="Packet passed all DPI inspection checks",
            details={
                "flow":             tuple_.to_string(),
                "sni":              flow.sni or "(none)",
                "app_type":         app_type_to_string(flow.app_type),
                "payload_bytes":    len(payload),
                "inspection_steps": inspection_steps,
            },
            inspection_time_ms=round(elapsed, 2),
        )

    # ── Private helpers ──────────────────────────────────────────────────────

    def _validate_inputs(
        self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str
    ) -> Optional[str]:
        """Basic input validation — mirrors protocol/range checks."""
        ip_pattern = re.compile(
            r"^(\d{1,3}\.){3}\d{1,3}$"
        )
        if not ip_pattern.match(src_ip):
            return f"Invalid source IP format: '{src_ip}'"
        if not ip_pattern.match(dst_ip):
            return f"Invalid destination IP format: '{dst_ip}'"

        for part in src_ip.split(".") + dst_ip.split("."):
            if int(part) > 255:
                return f"IP address out of range"

        if not (0 <= src_port <= 65535):
            return f"Source port {src_port} out of range (0-65535)"
        if not (0 <= dst_port <= 65535):
            return f"Destination port {dst_port} out of range (0-65535)"
        if protocol.upper() not in ("TCP", "UDP", "ICMP"):
            return f"Unsupported protocol '{protocol}' (supported: TCP, UDP, ICMP)"

        return None

    def _make_block_verdict(
        self,
        reason_code: str,
        reason: str,
        flow: FlowEntry,
        steps: List[str],
        step_msg: str,
        start_time: float,
        extra: Optional[dict] = None,
    ) -> DPIVerdict:
        steps.append(step_msg)
        steps.append("Verdict: BLOCK")
        elapsed = (time.perf_counter() - start_time) * 1000

        details = {
            "flow":             flow.tuple.to_string(),
            "sni":              flow.sni or "(none)",
            "app_type":         app_type_to_string(flow.app_type),
            "inspection_steps": steps,
        }
        if extra:
            details.update(extra)

        return DPIVerdict(
            action="BLOCK",
            reason_code=reason_code,
            reason=reason,
            details=details,
            inspection_time_ms=round(elapsed, 2),
        )

    def _record_block(self, flow: FlowEntry, code: str, reason: str):
        with self._lock:
            flow.blocked = True
            flow.block_reason_code = code
            flow.block_reason = reason
        with self._stats_lock:
            self.total_inspected += 1
            self.total_blocked += 1

    def get_stats(self) -> dict:
        with self._stats_lock:
            return {
                "total_inspected": self.total_inspected,
                "total_allowed":   self.total_allowed,
                "total_blocked":   self.total_blocked,
                "active_flows":    len(self._flows),
                "block_rate_pct":  round(
                    (self.total_blocked / self.total_inspected * 100)
                    if self.total_inspected > 0 else 0.0, 1
                ),
            }

    def get_active_flows(self) -> List[dict]:
        with self._lock:
            return [
                {
                    "flow":     f.tuple.to_string(),
                    "app":      app_type_to_string(f.app_type),
                    "sni":      f.sni,
                    "packets":  f.packets,
                    "blocked":  f.blocked,
                }
                for f in self._flows.values()
            ]


# =============================================================================
# Singleton engine instance (shared across requests)
# =============================================================================
engine = DPIInspectionEngine()
