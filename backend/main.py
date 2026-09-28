"""
DPI Security Gateway — FastAPI Backend
=======================================
POST /send-packet    → Run DPI inspection, return verdict
GET  /history        → Return inspection history log
GET  /stats          → Return DPI engine statistics
GET  /flows          → Return active flow table
GET  /health         → Health check
DELETE /history      → Clear inspection history
"""

import sys
import os
import time
import json
import subprocess
from datetime import datetime
from typing import Optional, List
from collections import deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

# Add parent directory so we can import dpi_engine from this file's location
sys.path.insert(0, os.path.dirname(__file__))
from dpi_engine import engine, DPIVerdict

# =============================================================================
# FastAPI Application
# =============================================================================
app = FastAPI(
    title="DPI Security Gateway",
    description="""
Deep Packet Inspection Based Network Security Gateway

This API exposes the DPI inspection engine for simulated real-time
packet analysis. The engine implements the same logic as the C++ engine
in src/dpi_mt.cpp, including:

- 5-tuple flow identification
- SNI (Server Name Indication) extraction and inspection
- Payload signature scanning
- IP/Domain/App/Port based blocking rules
- Machine-readable verdict with reason codes
    """,
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS — allow all origins for local development demo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Request / Response Models
# =============================================================================
class PacketRequest(BaseModel):
    """
    Simulated packet representation sent from the frontend.
    Mirrors the fields needed by the C++ FiveTuple + payload inspection.
    """
    source_ip:      str = Field(..., example="192.168.1.10",  description="Source IP address")
    source_port:    int = Field(..., example=50000,            description="Source port (0-65535)")
    destination_ip: str = Field(..., example="10.0.0.20",     description="Destination IP address")
    destination_port: int = Field(..., example=443,            description="Destination port (0-65535)")
    protocol:       str = Field("TCP", example="TCP",          description="Protocol: TCP, UDP, or ICMP")
    sni:            str = Field("",    example="example.com",  description="Server Name Indication (domain)")
    payload:        str = Field("",    example="normal request", description="Packet payload content")

    @field_validator("payload")
    @classmethod
    def limit_payload_size(cls, v: str) -> str:
        if len(v) > 4096:
            raise ValueError("Payload exceeds maximum size of 4096 bytes")
        return v

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        valid = {"TCP", "UDP", "ICMP"}
        if v.upper() not in valid:
            raise ValueError(f"Protocol must be one of: {', '.join(valid)}")
        return v.upper()


class InspectionRecord(BaseModel):
    """A single inspection history entry."""
    id:              int
    timestamp:       str
    source_ip:       str
    source_port:     int
    destination_ip:  str
    destination_port: int
    protocol:        str
    sni:             str
    app_type:        str = "Generic"
    payload_preview: str
    action:          str
    reason_code:     str
    reason:          str
    inspection_time_ms: float


# =============================================================================
# In-memory inspection history (simple list, up to 500 entries)
# =============================================================================
MAX_HISTORY = 500
inspection_history: deque = deque(maxlen=MAX_HISTORY)
history_id_counter: int = 0
history_lock = __import__("threading").Lock()


def record_inspection(req: PacketRequest, verdict: DPIVerdict) -> None:
    global history_id_counter
    with history_lock:
        history_id_counter += 1
        app_type = verdict.details.get("app_type", "Generic") if isinstance(verdict.details, dict) else "Generic"
        inspection_history.appendleft(InspectionRecord(
            id=history_id_counter,
            timestamp=datetime.now().strftime("%H:%M:%S"),
            source_ip=req.source_ip,
            source_port=req.source_port,
            destination_ip=req.destination_ip,
            destination_port=req.destination_port,
            protocol=req.protocol,
            sni=req.sni or "(none)",
            app_type=app_type,
            payload_preview=(req.payload[:32] + "…") if len(req.payload) > 32 else req.payload,
            action=verdict.action,
            reason_code=verdict.reason_code,
            reason=verdict.reason,
            inspection_time_ms=verdict.inspection_time_ms,
        ))


# =============================================================================
# API Routes
# =============================================================================

@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint. Verifies the DPI engine is running."""
    return {
        "status": "active",
        "engine": "DPI Security Gateway v2.0",
        "engine_status": "OPERATIONAL",
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/send-packet", tags=["DPI Inspection"])
async def send_packet(req: PacketRequest):
    """
    Submit a simulated packet for DPI inspection.

    The packet is processed through the full DPI pipeline:
    1. Input validation
    2. 5-tuple flow identification
    3. Application classification (SNI → AppType)
    4. IP/Port/App/Domain rule evaluation
    5. Payload signature scanning
    6. Verdict generation

    Returns a machine-readable verdict with reason codes.
    """
    # Log incoming packet
    print(f"[INFO] Packet received: {req.source_ip}:{req.source_port} -> "
          f"{req.destination_ip}:{req.destination_port}/{req.protocol}")
    if req.sni:
        print(f"[INFO] SNI: {req.sni}")
    if req.payload:
        preview = req.payload[:40] + ("..." if len(req.payload) > 40 else "")
        print(f"[INFO] Payload ({len(req.payload)} bytes): {preview}")

    # Run DPI inspection
    verdict = engine.inspect(
        source_ip=req.source_ip,
        source_port=req.source_port,
        dest_ip=req.destination_ip,
        dest_port=req.destination_port,
        protocol=req.protocol,
        sni=req.sni,
        payload=req.payload,
    )

    # Log verdict
    level = "[WARN]" if verdict.action == "BLOCK" else "[INFO]"
    print(f"{level} Verdict: {verdict.action} | {verdict.reason_code} | {verdict.reason}")

    # Record in history
    record_inspection(req, verdict)

    # Build response
    response = {
        "status":              verdict.action.lower() if verdict.action in ("ALLOW", "BLOCK") else "error",
        "decision":            verdict.action,
        "reason_code":         verdict.reason_code,
        "reason":              verdict.reason,
        "details":             verdict.details,
        "inspection_time_ms":  verdict.inspection_time_ms,
        "timestamp":           datetime.now().isoformat(),
        "engine":              "DPI-Gateway-v2.0",
    }

    return JSONResponse(content=response, status_code=200)


@app.get("/history", tags=["DPI Inspection"])
async def get_history(limit: int = 50):
    """
    Return the inspection history log (most recent first).

    Args:
        limit: Maximum number of records to return (default 50, max 500)
    """
    if limit > MAX_HISTORY:
        limit = MAX_HISTORY
    with history_lock:
        records = list(inspection_history)[:limit]
    return {
        "count": len(records),
        "records": [r.model_dump() for r in records],
    }


@app.delete("/history", tags=["DPI Inspection"])
async def clear_history():
    """Clear all inspection history."""
    with history_lock:
        inspection_history.clear()
    return {"status": "cleared", "message": "Inspection history cleared"}


@app.get("/stats", tags=["DPI Inspection"])
async def get_stats():
    """Return DPI engine statistics: totals, block rate, active flows."""
    stats = engine.get_stats()
    return {
        "engine_stats": stats,
        "history_count": len(inspection_history),
        "engine_status": "OPERATIONAL",
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/flows", tags=["DPI Inspection"])
async def get_flows():
    """Return the active flow table (all tracked 5-tuple connections)."""
    flows = engine.get_active_flows()
    return {
        "count": len(flows),
        "flows": flows,
    }


@app.get("/rules", tags=["Configuration"])
async def get_rules():
    """Return currently active security rules."""
    return {
        "blocked_ips":     engine.blocked_ips,
        "blocked_apps":    [str(a) for a in engine.blocked_apps],
        "blocked_domains": engine.blocked_domains,
        "blocked_ports":   engine.blocked_ports,
    }


# =============================================================================
# Serve the frontend from /
# =============================================================================
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")


# =============================================================================
# Run directly with: python main.py
# =============================================================================
if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 60)
    print("  DPI SECURITY GATEWAY — Starting")
    print("=" * 60)
    print("  API:      http://localhost:8000")
    print("  Dashboard: http://localhost:8000")
    print("  API Docs: http://localhost:8000/api/docs")
    print("=" * 60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
