"""Telemetry readiness contract backed by stored Wazuh rollups."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


MIN_FIELD_COVERAGE = 0.8

SOURCES = (
    ("fortigate", "FortiGate firewall", ("source_ip", "destination_ip", "destination_port", "action", "firewall_policy", "application", "direction"), ("bruteforce", "scan", "dos", "exploit_attempt")),
    ("sangfor_firewall", "Sangfor firewall", ("source_ip", "destination_ip", "destination_port", "action", "firewall_policy", "application", "direction"), ("bruteforce", "scan", "dos", "exploit_attempt")),
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
    "sangfor_firewall": ("sangfor",),
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


def inventory_evidence(
    dimensions: dict[str, Any] | None,
    contract: dict[str, Any] | None,
    *,
    indexed_events: int | None = None,
    bounded_samples: dict[str, int] | None = None,
    unmatched_decoder_events: int | None = None,
    trace_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Expose the measured G01 inventory without inventing unavailable fields.

    Rollups retain counts and ``last_seen`` values, not raw event provenance or
    parser versions.  The response therefore labels those dimensions as
    unavailable instead of treating a missing value as complete coverage.
    """
    dimensions = dimensions or {}
    contract = contract or {}

    def rows(name: str) -> list[dict[str, Any]]:
        value = dimensions.get(name)
        return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []

    source_matrix = []
    for source in contract.get("sources") or []:
        source_matrix.append({
            "source": source.get("key"),
            "label": source.get("label"),
            "status": source.get("status"),
            "observed_events": source.get("observed_events"),
            "last_seen": source.get("last_seen"),
            "age_seconds": source.get("age_seconds"),
            "available_fields": source.get("available_fields") or [],
            "missing_fields": source.get("missing_fields") or [],
            "undercovered_fields": source.get("undercovered_fields") or [],
            "field_coverage": source.get("field_coverage") or {},
            "status_reason": source.get("status_reason"),
        })

    subtype_dimensions = {}
    for name in ("forti_type", "forti_subtype", "forti_profile", "detection_family"):
        subtype_dimensions[name] = [
            {
                "value": row.get("value"),
                "count": int(row.get("count") or 0),
                "last_seen": row.get("last_seen"),
                "max_level": int(row.get("max_level") or 0),
            }
            for row in rows(name)
            if row.get("value") not in (None, "")
        ]

    index_to_ui_trace = []
    for record in trace_records or []:
        if not isinstance(record, dict) or not record.get("event_id"):
            continue
        index_to_ui_trace.append({
            "event_id": str(record.get("event_id"))[:160],
            "index": str(record.get("index") or "")[:160] or None,
            "event_time": record.get("timestamp"),
            "rule_id": record.get("rule_id"),
            "decoder": record.get("decoder"),
            "agent": record.get("agent"),
            "source_ip": record.get("source_ip"),
            "destination_ip": record.get("destination_ip"),
            "trace_scope": "Wazuh Indexer bounded sample -> dashboard payload",
        })

    return {
        "status": "measured",
        "scope": "selected alert window and durable rollup dimensions",
        "indexed_events": indexed_events,
        "source_matrix": source_matrix,
        "subtype_dimensions": subtype_dimensions,
        "bounded_samples": dict(bounded_samples or {}),
        "index_to_ui_trace": {
            "status": "measured" if index_to_ui_trace else "not_observed",
            "records": index_to_ui_trace[:20],
            "sample_limit": 20,
            "scope": "L1 records with rule.level >= 7 from the selected window",
            "not_proven": ["upstream syslog/archive ingress", "decoder processing before Indexer"],
        },
        "timestamp": {
            "status": "rollup_last_seen_only",
            "event_time_available": False,
            "reason": "The current rollup stores last_seen per dimension; an individual event timestamp is available only in bounded live samples.",
        },
        "parser_version": {
            "status": "not_observed",
            "value": None,
            "reason": "Parser/decoder version is not persisted in the current Wazuh alert projection or detection rollup.",
        },
        "received_vs_indexed": {
            "status": "unavailable",
            "received": None,
            "indexed": indexed_events,
            "reason": "The current contract has no durable upstream received counter for this window.",
        },
        "late_events": {
            "status": "unavailable",
            "count": None,
            "reason": "Event ingest time and late-arrival classification are not persisted in the current projection.",
        },
        "unmatched_decoder": {
            "status": "measured" if unmatched_decoder_events is not None else "unavailable",
            "count": unmatched_decoder_events,
            "basis": "decoder.name absent in the bounded alert aggregation" if unmatched_decoder_events is not None else None,
        },
        "limitations": [
            "Source status is window-scoped and does not prove historical absence.",
            "Subtype counts are rollup dimensions, not a raw-event trace or attack confirmation.",
            "Parser version, upstream received count, and late-event count require an additive ingestion contract.",
        ],
    }
