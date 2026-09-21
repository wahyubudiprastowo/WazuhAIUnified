"""Telemetry readiness contract backed by stored Wazuh rollups."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


MIN_FIELD_COVERAGE = 0.8

SOURCES = (
    ("fortigate", "FortiGate firewall", ("source_ip", "destination_ip", "destination_port", "action", "firewall_policy", "application", "direction"), ("bruteforce", "scan", "dos", "exploit_attempt")),
    ("fortiweb", "FortiWeb WAF", ("source_ip", "destination_ip", "destination_port", "url", "action", "host", "firewall_policy"), ("web_attack.sqli", "web_attack.xss", "exploit_attempt")),
    ("waf_web", "WAF / web access", ("source_ip", "url", "action", "host"), ("web_attack.sqli", "web_attack.xss", "exploit_attempt")),
    ("windows_sysmon", "Windows / Sysmon", ("host", "identity", "process", "parent_process", "hash", "destination_ip"), ("malware", "bruteforce", "exploit_attempt")),
    ("linux_auditd", "Linux / auditd", ("host", "identity", "exe", "command", "uid", "source_ip"), ("bruteforce", "malware", "exploit_attempt")),
    ("container_runtime", "Container / Docker", ("host", "container", "image", "action"), ("malware", "exploit_attempt")),
    ("m365_audit", "Microsoft 365 / Entra audit", ("workload", "operation", "identity", "source_ip", "object", "session"), ("phishing", "bruteforce")),
    ("defender_xdr", "Microsoft Defender XDR", ("alert_or_incident", "severity", "entities", "status", "first_seen", "last_update"), ("malware", "phishing", "exploit_attempt")),
    ("ids_ndr", "IDS / NDR", ("source_ip", "destination_ip", "destination_port", "protocol", "action"), ("scan", "dos", "mitm_suspected", "beaconing", "sniffing", "exploit_attempt")),
)


def _count(rows: list[dict[str, Any]], terms: tuple[str, ...]) -> int:
    return sum(int(row.get("count") or 0) for row in rows
               if any(term in str(row.get("value") or row.get("name") or "").lower() for term in terms))


def _timestamp(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError):
        return None


def _latest(rows: list[dict[str, Any]], terms: tuple[str, ...]) -> str | None:
    matches = [row.get("last_seen") for row in rows
               if any(term in str(row.get("value") or row.get("name") or "").lower() for term in terms)]
    dated = [(epoch, value) for value in matches if (epoch := _timestamp(value)) is not None]
    return str(max(dated)[1]) if dated else None


SOURCE_TERMS = {
    "fortigate": ("fortigate",),
    "fortiweb": ("fortiweb",),
    "waf_web": ("modsecurity", "waf", "nginx", "apache", "iis"),
    "windows_sysmon": ("sysmon",),
    "linux_auditd": ("auditd", "linux_audit"),
    "container_runtime": ("docker", "containerd", "kubernetes", "k8s"),
    "ids_ndr": ("suricata", "snort", "zeek"),
}


def summary(dimensions: dict[str, Any] | None, cloud_total: int = 0,
            defender: dict[str, Any] | None = None, *,
            materialization_complete: bool | None = None,
            now: float | None = None, stale_after_seconds: int = 86400) -> dict[str, Any]:
    """Return source readiness from local aggregates; never issues an Indexer query."""
    dimensions = dimensions or {}
    decoders = dimensions.get("decoder") if isinstance(dimensions.get("decoder"), list) else []
    observed_sources = dimensions.get("telemetry_source") if isinstance(dimensions.get("telemetry_source"), list) else []
    observed_fields = dimensions.get("telemetry_field") if isinstance(dimensions.get("telemetry_field"), list) else []
    source_rows = {str(row.get("value")): row for row in observed_sources}
    known = {key: int(row.get("count") or 0) for key, row in source_rows.items()}
    field_counts = {str(row.get("value")): int(row.get("count") or 0) for row in observed_fields}
    defender = defender or {}
    now = datetime.now(timezone.utc).timestamp() if now is None else float(now)
    stale_after_seconds = max(300, int(stale_after_seconds))
    rows = []
    for key, label, required, families in SOURCES:
        count = known.get(key, 0)
        latest = (source_rows.get(key) or {}).get("last_seen")
        if not count:
            if key == "m365_audit":
                count = int(cloud_total or 0)
            elif key == "defender_xdr":
                count = int(defender.get("observations") or 0)
            else:
                terms = SOURCE_TERMS.get(key, ())
                count = _count(decoders, terms) if terms else 0
                latest = latest or (_latest(decoders, terms) if terms else None)
        if key == "defender_xdr":
            observed_counts = defender.get("field_counts") if isinstance(defender.get("field_counts"), dict) else {}
            denominator = max(0, int(defender.get("field_sample_size") or 0))
            field_count = {field: max(0, int(observed_counts.get(field) or 0)) for field in required}
            latest = defender.get("last_observed_at") or latest
        else:
            denominator = max(0, count)
            field_count = {field: max(0, field_counts.get(key + "|" + field, 0)) for field in required}
        available = [field for field in required if field_count[field] > 0]
        missing = [field for field in required if field not in available]
        coverage = {field: (field_count[field] / denominator if denominator else 0.0)
                    for field in required}
        undercovered = [field for field in available if coverage[field] < MIN_FIELD_COVERAGE]
        latest_epoch = _timestamp(latest)
        age = max(0, int(now - latest_epoch)) if latest_epoch is not None else None
        connector_status = str(defender.get("status") or "").lower() if key == "defender_xdr" else ""
        connector_degraded = connector_status in {"error", "invalid_configuration", "not_configured"}
        if not count:
            status = "not_observed"
            reason = ("Collector is configured but has not stored telemetry." if key == "defender_xdr" and defender.get("configured")
                      else "No decoded telemetry was observed in the selected window.")
        elif connector_degraded:
            status, reason = "degraded", f"Collector health is {connector_status}."
        elif age is not None and age > stale_after_seconds:
            status, reason = "stale", f"Latest stored telemetry is {age} seconds old."
        elif missing or undercovered:
            status = "observed_incomplete"
            reasons = []
            if missing:
                reasons.append("missing fields: " + ", ".join(missing))
            if undercovered:
                reasons.append(f"below {MIN_FIELD_COVERAGE:.0%} coverage: " + ", ".join(undercovered))
            reason = "Required detection fields are incomplete (" + "; ".join(reasons) + ")."
        elif latest_epoch is None:
            status, reason = "degraded", "Events exist, but source freshness cannot be established."
        elif materialization_complete is False:
            status, reason = "degraded", "The selected rollup still has materialization gaps."
        else:
            status, reason = "ready", "Required fields and freshness evidence are available."
        field_profile = ("all contract fields meet coverage threshold" if not missing and not undercovered
                         else "; ".join(part for part in (
                             "missing: " + ", ".join(missing) if missing else "",
                             "undercovered: " + ", ".join(undercovered) if undercovered else "") if part))
        rows.append({
            "key": key, "label": label, "observed_events": count, "status": status,
            "required_fields": list(required), "detection_families": list(families),
            "available_fields": available, "missing_fields": missing,
            "undercovered_fields": undercovered,
            "field_coverage": {field: round(value, 4) for field, value in coverage.items()},
            "minimum_field_coverage": MIN_FIELD_COVERAGE, "field_profile": field_profile,
            "last_seen": latest, "age_seconds": age, "status_reason": reason,
        })
    status_counts = {status: sum(1 for row in rows if row["status"] == status)
                     for status in ("ready", "observed_incomplete", "degraded", "stale", "not_observed")}
    return {
        "source": "durable detection rollups and local connector ledgers",
        "summary": {"observed_sources": sum(1 for row in rows if row["observed_events"] > 0),
                    "expected_sources": len(rows), **{f"{key}_sources": value for key, value in status_counts.items()}},
        "sources": rows,
        "note": "Ready requires decoded telemetry, every contract field, current freshness and healthy materialization. Event volume alone never means ready.",
    }
