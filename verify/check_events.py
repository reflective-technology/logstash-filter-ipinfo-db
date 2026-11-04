"""Check the json_lines events printed by the verification pipeline.

Usage: python3 -I check_events.py <logstash output file>
Log lines are mixed into the same output; only lines that parse as JSON events are used.
"""
import json
import sys

FAIL_TAG = "_ipinfo_db_lookup_failure"

events = {}
with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if "message" in event:
            events[event["message"]] = event

ok = True


def check(name, cond, detail=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))
    ok = ok and cond


for ip in ["8.8.8.8", "2001:4860:4860::8888"]:
    e = events.get(ip, {})
    info = e.get("ipinfo-db") or {}
    check(f"{ip}: enriched", bool(info), e)
    check(f"{ip}: country is US", info.get("country") == "US", info)
    check(f"{ip}: has asn", str(info.get("asn", "")).startswith("AS"), info)
    check(f"{ip}: not tagged", FAIL_TAG not in e.get("tags", []), e.get("tags"))

check("10.0.0.1 (private): event present", "10.0.0.1" in events)
e = events.get("10.0.0.1", {})
check("10.0.0.1 (private): not enriched", "ipinfo-db" not in e, e)
check("10.0.0.1 (private): not tagged", FAIL_TAG not in e.get("tags", []), e.get("tags"))

e = events.get("not-an-ip", {})
check("not-an-ip: tagged", FAIL_TAG in e.get("tags", []), e.get("tags"))

print("--- sample enriched event (check the field names against the README) ---")
print(json.dumps(events.get("8.8.8.8", {}).get("ipinfo-db"), indent=2))
sys.exit(0 if ok else 1)
