"""Read-only live checks; external feed samples are NOT local incident evidence."""
import json
from urllib.request import Request, urlopen


def post(path, payload):
    request = Request("http://127.0.0.1:8088" + path, data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=180) as response:
        return json.load(response)


def describe(indicator, origin):
    response = post("/api/findings/intel", {"kind": "aggregate", "indicator": indicator})
    print("INDICATOR", origin, indicator, "ok", response.get("ok"), "partial", response.get("partial"), flush=True)
    for row in (response.get("data") or {}).get("results", []):
        if row["provider"] not in {"otx", "greynoise", "virustotal", "cyfirma"}:
            continue
        details = row.get("detail") or {}
        summary = {"provider": row["provider"], "error": row.get("error"), "malicious": row.get("is_malicious"),
                   "risk": row.get("risk_level"), "pulse_count": details.get("pulse_count"),
                   "classification": details.get("classification"), "skipped": details.get("skipped"),
                   "stats": details.get("analysis_stats"), "scanned": details.get("scanned"),
                   "match_count": details.get("match_count", len(details.get("matches", []))),
                   "malware_families": row.get("malware_families"), "tags": row.get("tags"),
                   "campaigns": [p.get("name") for p in row.get("pulses", [])]}
        print(json.dumps(summary), flush=True)


data = post("/api/analysis/coverage", {"range": "24h"})
print("COVERAGE", json.dumps({key: data.get(key) for key in ["ok", "generated_at", "total_events", "events_with_observable", "other_rule_events", "rule_count_error_bound"]}), flush=True)
print("RULES", len(data["rules"]), "CANDIDATES", len(data["observables"]), flush=True)
ip = next(row["indicator"] for row in data["observables"] if row["kind"] == "ip" and row["public"] and ":" not in row["indicator"])
evidence = post("/api/findings/evidence", {"kind": "ip", "value": ip, "range": "24h"})
print("LOCAL EVIDENCE", ip, evidence["total"], "events", flush=True)
describe(ip, "Wazuh indexed source")
feed = post("/api/findings/intel", {"kind": "feed"})
print("CYFIRMA FEED", feed.get("ok"), "summary", json.dumps((feed.get("data") or {}).get("summary")), flush=True)
sample = next((row["iocs"][0] for row in (feed.get("data") or {}).get("items", []) if row.get("iocs")), None)
if sample:
    describe(sample, "External feed validation only; local match NOT established")
