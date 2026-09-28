import urllib.request, json

base = "http://localhost:8000"

def post(data):
    req = urllib.request.Request(
        base + "/send-packet",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

print("=== LIVE API TESTS ===")

r = post({"source_ip":"192.168.1.10","source_port":54321,"destination_ip":"10.0.0.20","destination_port":443,"protocol":"TCP","sni":"example.com","payload":"normal request"})
print("Test 1 Normal Traffic:    " + r["decision"] + " (" + r["reason_code"] + ")")
assert r["decision"] == "ALLOW"

r = post({"source_ip":"192.168.1.10","source_port":54322,"destination_ip":"10.0.0.20","destination_port":443,"protocol":"TCP","sni":"example.com","payload":"MALICIOUS_TEST_SIGNATURE"})
print("Test 2 Malicious Payload: " + r["decision"] + " (" + r["reason_code"] + ")")
assert r["decision"] == "BLOCK" and r["reason_code"] == "MALICIOUS_SIGNATURE"

r = post({"source_ip":"192.168.1.10","source_port":54323,"destination_ip":"10.0.0.20","destination_port":443,"protocol":"TCP","sni":"malicious-test.example","payload":""})
print("Test 3 Blocked SNI:       " + r["decision"] + " (" + r["reason_code"] + ")")
assert r["decision"] == "BLOCK" and r["reason_code"] == "BLOCKED_SNI"

r = post({"source_ip":"192.168.1.50","source_port":54324,"destination_ip":"10.0.0.20","destination_port":443,"protocol":"TCP","sni":"example.com","payload":""})
print("Test 4 Blocked IP:        " + r["decision"] + " (" + r["reason_code"] + ")")
assert r["decision"] == "BLOCK" and r["reason_code"] == "BLOCKED_IP"

r = json.loads(urllib.request.urlopen(base + "/stats").read())
s = r["engine_stats"]
print("Stats: total=" + str(s["total_inspected"]) + " allowed=" + str(s["total_allowed"]) + " blocked=" + str(s["total_blocked"]))
assert s["total_inspected"] == 4

print("=== ALL LIVE API TESTS PASSED ===")
