# DPI Security Gateway
## Deep Packet Inspection Based Network Security Gateway

A complete, demonstrable DPI Security Gateway with a C++ engine, Python FastAPI backend, and premium web dashboard.

---

## Quick Start

**1. Start the backend (runs everything):**
```bat
start.bat
```
Or directly:
```bat
python backend\main.py
```

**2. Open the dashboard:**
```
http://localhost:8000
```

**3. Run tests:**
```bat
python -X utf8 backend\test_dpi.py
```

---

## Project Structure

```
DPI_Project/
├── src/                        ← Original C++ DPI Engine (preserved)
│   ├── dpi_mt.cpp              ← Multi-threaded engine (Reader→LB→FP→Output)
│   ├── main_working.cpp        ← Single-threaded engine
│   ├── sni_extractor.cpp       ← TLS ClientHello / HTTP Host parser
│   ├── types.cpp               ← AppType / sniToAppType mapping
│   └── ...
├── include/                    ← C++ headers
├── backend/
│   ├── dpi_engine.py           ← Python DPI Engine (mirrors C++ logic)
│   ├── main.py                 ← FastAPI backend server
│   ├── test_dpi.py             ← Test suite (10 tests)
│   └── live_test.py            ← Live API tests
├── frontend/
│   ├── index.html              ← Security Dashboard
│   ├── style.css               ← Dark cybersecurity theme
│   └── app.js                  ← Frontend logic
├── test_dpi.pcap               ← Sample PCAP file
├── generate_test_pcap.py       ← PCAP generator
└── start.bat                   ← Windows launcher
```

---

## DPI Pipeline

```
Frontend (Browser)
      │
      │ POST /send-packet (JSON)
      ▼
FastAPI Backend (main.py)
      │
      │ validate → normalize
      ▼
Python DPI Engine (dpi_engine.py)
      │
      ├── 1. Input Validation
      ├── 2. FiveTuple (5-tuple) flow identification
      ├── 3. SNI / Application classification
      ├── 4. IP block check
      ├── 5. Port block check
      ├── 6. App block check
      ├── 7. Domain / SNI block check
      └── 8. Payload signature scan
      │
      ├── ALLOW → { action: "ALLOW", reason_code: "CLEAN_TRAFFIC" }
      └── BLOCK → { action: "BLOCK", reason_code: "MALICIOUS_SIGNATURE" | ... }
      │
      ▼
FastAPI Response (JSON verdict)
      │
      ▼
Dashboard shows result
```

---

## Test Scenarios

| Scenario | Input | Expected |
|----------|-------|----------|
| Normal Traffic | SNI: example.com, payload: normal | **ALLOW** |
| Malicious Payload | payload: MALICIOUS_TEST_SIGNATURE | **BLOCK** / MALICIOUS_SIGNATURE |
| Blocked Domain | SNI: malicious-test.example | **BLOCK** / BLOCKED_SNI |
| Blocked Source IP | src: 192.168.1.50 | **BLOCK** / BLOCKED_IP |
| Suspicious Pattern | payload: SUSPICIOUS_PAYLOAD_TEST | **BLOCK** / SUSPICIOUS_PAYLOAD |
| Invalid IP | src: not.an.ip! | **ERROR** / VALIDATION_ERROR |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/send-packet` | Submit packet for DPI inspection |
| GET | `/history` | Inspection history log |
| GET | `/stats` | Engine statistics |
| GET | `/flows` | Active flow table |
| GET | `/rules` | Active security rules |
| GET | `/health` | Engine health check |
| GET | `/api/docs` | Auto-generated API documentation |

---

## Verdict JSON Contract

```json
{
  "status": "blocked",
  "decision": "BLOCK",
  "reason_code": "MALICIOUS_SIGNATURE",
  "reason": "Malicious test signature detected in payload",
  "details": {
    "flow": "192.168.1.10:54321 -> 10.0.0.20:443/TCP",
    "sni": "example.com",
    "app_type": "HTTPS",
    "matched_signature": "MALICIOUS_TEST_SIGNATURE",
    "inspection_steps": [...]
  },
  "inspection_time_ms": 0.12
}
```

---

## C++ Engine (Original — Preserved)

The original C++ engine (`src/dpi_mt.cpp`) implements:
- **Multithreaded architecture**: Reader → 2 LB threads → 4 FP threads → Output writer
- **Real TLS ClientHello parsing**: Byte-by-byte SNI extraction
- **5-tuple flow tracking**: Hash-based consistent flow affinity
- **Zero external dependencies**: Pure C++17 STL

Build (requires GCC 7+ or MSVC 2017+):
```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine.exe \
    src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp \
    src/sni_extractor.cpp src/types.cpp
```

Run PCAP mode:
```bash
dpi_engine.exe test_dpi.pcap output.pcap --block-app YouTube --block-domain facebook
```
