# -*- coding: utf-8 -*-
"""
DPI Security Gateway - Test Suite
===================================
Tests all 8 required scenarios:
  1. Normal packet              → ALLOW
  2. Malicious payload          → BLOCK / MALICIOUS_SIGNATURE
  3. Blocked SNI                → BLOCK / BLOCKED_SNI
  4. Blocked source IP          → BLOCK / BLOCKED_IP
  5. Suspicious payload         → BLOCK / SUSPICIOUS_PAYLOAD
  6. Invalid input              → ERROR / VALIDATION_ERROR
  7. Unsupported protocol       → ERROR / VALIDATION_ERROR
  8. Multiple sequential req.   → engine remains stable

Run with:  python backend/test_dpi.py
"""

import sys
import os
import io
# Fix Windows console encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from dpi_engine import DPIInspectionEngine, AppType

# ─────────────────────────────────────────────────────────────
# Test Runner
# ─────────────────────────────────────────────────────────────
PASS = "[PASS]"
FAIL = "[FAIL]"

results = []

def run_test(name, fn):
    try:
        fn()
        print(f"  {PASS}  {name}")
        results.append(True)
    except AssertionError as e:
        print(f"  {FAIL}  {name}: {e}")
        results.append(False)
    except Exception as e:
        print(f"  {FAIL}  {name}: Unexpected error — {e}")
        results.append(False)


# ─────────────────────────────────────────────────────────────
# Test Cases
# ─────────────────────────────────────────────────────────────
engine = DPIInspectionEngine()

def test_normal_traffic():
    v = engine.inspect(
        source_ip="192.168.1.10", source_port=54321,
        dest_ip="10.0.0.20",      dest_port=443,
        protocol="TCP",           sni="example.com",
        payload="normal request",
    )
    assert v.action == "ALLOW",       f"Expected ALLOW, got {v.action}"
    assert v.reason_code == "CLEAN_TRAFFIC", f"Expected CLEAN_TRAFFIC, got {v.reason_code}"


def test_malicious_payload():
    v = engine.inspect(
        source_ip="192.168.1.10", source_port=54322,
        dest_ip="10.0.0.20",      dest_port=443,
        protocol="TCP",           sni="example.com",
        payload="MALICIOUS_TEST_SIGNATURE",
    )
    assert v.action == "BLOCK",                  f"Expected BLOCK, got {v.action}"
    assert v.reason_code == "MALICIOUS_SIGNATURE", f"Expected MALICIOUS_SIGNATURE, got {v.reason_code}"


def test_blocked_sni():
    v = engine.inspect(
        source_ip="192.168.1.10", source_port=54323,
        dest_ip="10.0.0.20",      dest_port=443,
        protocol="TCP",           sni="malicious-test.example",
        payload="GET / HTTP/1.1",
    )
    assert v.action == "BLOCK",           f"Expected BLOCK, got {v.action}"
    assert v.reason_code == "BLOCKED_SNI", f"Expected BLOCKED_SNI, got {v.reason_code}"


def test_blocked_ip():
    v = engine.inspect(
        source_ip="192.168.1.50", source_port=54324,
        dest_ip="10.0.0.20",      dest_port=443,
        protocol="TCP",           sni="example.com",
        payload="normal request",
    )
    assert v.action == "BLOCK",           f"Expected BLOCK, got {v.action}"
    assert v.reason_code == "BLOCKED_IP",  f"Expected BLOCKED_IP, got {v.reason_code}"


def test_suspicious_payload():
    v = engine.inspect(
        source_ip="192.168.1.10", source_port=54325,
        dest_ip="10.0.0.20",      dest_port=443,
        protocol="TCP",           sni="example.com",
        payload="SUSPICIOUS_PAYLOAD_TEST",
    )
    assert v.action == "BLOCK",                  f"Expected BLOCK, got {v.action}"
    assert v.reason_code == "SUSPICIOUS_PAYLOAD", f"Expected SUSPICIOUS_PAYLOAD, got {v.reason_code}"


def test_invalid_ip():
    v = engine.inspect(
        source_ip="not.an.ip!", source_port=54326,
        dest_ip="10.0.0.20",    dest_port=443,
        protocol="TCP",
    )
    assert v.action == "ERROR",               f"Expected ERROR, got {v.action}"
    assert v.reason_code == "VALIDATION_ERROR", f"Expected VALIDATION_ERROR, got {v.reason_code}"


def test_unsupported_protocol():
    v = engine.inspect(
        source_ip="192.168.1.10", source_port=54327,
        dest_ip="10.0.0.20",      dest_port=443,
        protocol="FTP",
    )
    assert v.action == "ERROR",               f"Expected ERROR, got {v.action}"
    assert v.reason_code == "VALIDATION_ERROR", f"Expected VALIDATION_ERROR, got {v.reason_code}"


def test_sequential_stability():
    """Send 20 sequential packets — engine must remain stable and stats accurate."""
    eng = DPIInspectionEngine()
    for i in range(10):
        v = eng.inspect(
            source_ip="10.1.0.1", source_port=40000 + i,
            dest_ip="8.8.8.8",    dest_port=443,
            protocol="TCP",       sni="google.com",
            payload="clean traffic",
        )
        assert v.action == "ALLOW", f"Packet {i} should be ALLOW"

    for i in range(10):
        v = eng.inspect(
            source_ip="10.1.0.1", source_port=50000 + i,
            dest_ip="8.8.8.8",    dest_port=443,
            protocol="TCP",       sni="example.com",
            payload="MALICIOUS_TEST_SIGNATURE",
        )
        assert v.action == "BLOCK", f"Packet {i} should be BLOCK"

    stats = eng.get_stats()
    assert stats["total_inspected"] == 20, f"Expected 20 inspected, got {stats['total_inspected']}"
    assert stats["total_allowed"]   == 10, f"Expected 10 allowed,   got {stats['total_allowed']}"
    assert stats["total_blocked"]   == 10, f"Expected 10 blocked,   got {stats['total_blocked']}"


def test_sni_app_classification():
    """Verify sniToAppType() mirrors the C++ implementation."""
    from dpi_engine import sni_to_app_type
    assert sni_to_app_type("www.youtube.com")  == AppType.YOUTUBE
    assert sni_to_app_type("www.facebook.com") == AppType.FACEBOOK
    assert sni_to_app_type("github.com")        == AppType.GITHUB
    assert sni_to_app_type("unknown.xyz")       == AppType.HTTPS
    assert sni_to_app_type("")                  == AppType.UNKNOWN


def test_pcap_binary_exists():
    """Verify original C++ DPI engine source files are preserved."""
    import os
    root = os.path.join(os.path.dirname(__file__), "..")
    required = [
        "src/dpi_mt.cpp",
        "src/main_working.cpp",
        "src/sni_extractor.cpp",
        "src/types.cpp",
        "include/types.h",
        "include/sni_extractor.h",
    ]
    for f in required:
        path = os.path.join(root, f)
        assert os.path.exists(path), f"C++ source missing: {f}"


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "=" * 56)
    print("  DPI Security Gateway — Test Suite")
    print("=" * 56)

    run_test("Test 1  - Normal traffic -> ALLOW",             test_normal_traffic)
    run_test("Test 2  - Malicious payload -> BLOCK",          test_malicious_payload)
    run_test("Test 3  - Blocked SNI -> BLOCK",                test_blocked_sni)
    run_test("Test 4  - Blocked source IP -> BLOCK",          test_blocked_ip)
    run_test("Test 5  - Suspicious payload -> BLOCK",         test_suspicious_payload)
    run_test("Test 6  - Invalid IP -> VALIDATION_ERROR",      test_invalid_ip)
    run_test("Test 7  - Unsupported protocol -> ERROR",       test_unsupported_protocol)
    run_test("Test 8  - Sequential stability (20 packets)",   test_sequential_stability)
    run_test("Test 9  - SNI app classification accuracy",     test_sni_app_classification)
    run_test("Test 10 - C++ source files preserved",          test_pcap_binary_exists)

    passed = sum(results)
    total  = len(results)
    print("\n" + "=" * 56)
    status = "ALL PASS" if passed == total else f"{total - passed} FAILED"
    print(f"  Result: {passed}/{total} tests passed - {status}")
    print("=" * 56 + "\n")
    sys.exit(0 if passed == total else 1)
