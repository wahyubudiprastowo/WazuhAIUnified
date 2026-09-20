"""Bounded CMDB/CPE normalization and vulnerability exposure graph helpers.

The graph is derived from local Wazuh vulnerability state plus the local CMDB.
It deliberately performs no provider or Wazuh network calls.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


CPE_PARTS = {"a": "application", "o": "operating_system", "h": "hardware"}
PATCH_STATES = {"patched", "pending", "vulnerable", "not_applicable", "unknown"}
CRITICALITY_WEIGHT = {"critical": 20, "high": 14, "medium": 8, "low": 3}
SEVERITY_WEIGHT = {"critical": 40, "high": 28, "medium": 16, "low": 7}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def _text(value: Any, limit: int = 500) -> str | None:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    result = str(value).strip()
    return result[:limit] if result else None


def _split_cpe(value: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def parse_cpe(value: Any) -> dict[str, Any]:
    raw = _text(value, 1024)
    if not raw:
        return {"value": None, "status": "missing", "valid": False, "reason": "CPE is not supplied"}
    fields = _split_cpe(raw)
    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]:
        return {"value": raw, "status": "invalid", "valid": False,
                "reason": "Expected a 13-field CPE 2.3 formatted string"}
    part, vendor, product, version = fields[2:6]
    if part not in CPE_PARTS or vendor in {"", "*", "-"} or product in {"", "*", "-"}:
        return {"value": raw, "status": "invalid", "valid": False,
                "reason": "CPE part, vendor and product must identify a component"}
    return {
        "value": raw, "status": "valid", "valid": True, "reason": None,
        "part": part, "part_label": CPE_PARTS[part], "vendor": vendor,
        "product": product, "version": None if version in {"", "*", "-"} else version,
    }


def _list(value: Any, limit: int = 50) -> list[str]:
    values = [value] if isinstance(value, str) else value if isinstance(value, list) else []
    result: list[str] = []
    for item in values[:limit]:
        text = _text(item, 256)
        if text and text not in result:
            result.append(text)
    return result


def normalize_component(component: Any, inherited: dict[str, Any] | None = None) -> dict[str, Any] | None:
    if not isinstance(component, dict):
        return None
    inherited = inherited or {}
    cpe = parse_cpe(component.get("cpe"))
    vendor = _text(component.get("vendor")) or cpe.get("vendor") or inherited.get("vendor")
    product = (_text(component.get("product")) or _text(component.get("name")) or
               cpe.get("product") or inherited.get("application"))
    version = _text(component.get("version")) or cpe.get("version") or inherited.get("version")
    if not any((vendor, product, version, cpe.get("value"))):
        return None
    patch_state = str(component.get("patch_state") or inherited.get("patch_state") or "unknown").lower()
    if patch_state not in PATCH_STATES:
        patch_state = "unknown"
    return {
        "name": _text(component.get("name")) or product or "unnamed component",
        "vendor": vendor, "product": product, "version": version,
        "cpe": cpe.get("value"), "cpe_status": cpe["status"], "cpe_reason": cpe.get("reason"),
        "cpe_part": cpe.get("part_label"), "patch_state": patch_state,
        "source": _text(component.get("source")) or inherited.get("source") or "CMDB",
        "last_verified": _text(component.get("last_verified")) or inherited.get("last_verified"),
    }


def normalize_cmdb_asset(asset: Any) -> dict[str, Any] | None:
    if not isinstance(asset, dict):
        return None
    scalar_fields = (
        "id", "agent_id", "name", "host", "hostname", "fqdn", "ip", "address",
        "owner", "criticality", "environment", "network_zone", "vendor", "version",
        "purpose", "application", "source", "last_verified", "patch_state",
    )
    normalized = {field: value for field in scalar_fields if (value := _text(asset.get(field))) is not None}
    if isinstance(asset.get("internet_exposed"), bool):
        normalized["internet_exposed"] = asset["internet_exposed"]
    for field in ("aliases", "ips", "addresses", "tags"):
        values = _list(asset.get(field))
        if values:
            normalized[field] = values
    root_cpe = parse_cpe(asset.get("cpe"))
    normalized.update(cpe=root_cpe.get("value"), cpe_status=root_cpe["status"],
                      cpe_reason=root_cpe.get("reason"))
    if normalized.get("criticality"):
        normalized["criticality"] = normalized["criticality"].lower()
    if normalized.get("patch_state") not in PATCH_STATES:
        normalized["patch_state"] = "unknown"
    inherited = {key: normalized.get(key) for key in
                 ("vendor", "version", "application", "source", "last_verified", "patch_state")}
    components = [row for row in
                  (normalize_component(item, inherited) for item in (asset.get("components") or [])[:100]) if row]
    if not components and any(normalized.get(key) for key in ("vendor", "version", "application", "cpe")):
        component = normalize_component({
            "name": normalized.get("application") or normalized.get("name"),
            "vendor": normalized.get("vendor"), "version": normalized.get("version"),
            "cpe": normalized.get("cpe"), "patch_state": normalized.get("patch_state"),
        }, inherited)
        if component:
            components.append(component)
    normalized["components"] = components
    normalized["component_count"] = len(components)
    return normalized


def asset_identifiers(asset: dict[str, Any]) -> set[str]:
    values: list[Any] = [asset.get(field) for field in
                         ("id", "agent_id", "name", "host", "hostname", "fqdn", "ip", "address")]
    for field in ("aliases", "ips", "addresses"):
        values.extend(asset.get(field) or [])
    return {str(value).strip().lower().rstrip(".")[:256] for value in values if str(value or "").strip()}


def _first(mapping: dict[str, Any], paths: tuple[tuple[str, ...], ...]) -> Any:
    for path in paths:
        value: Any = mapping
        for key in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _bool_signal(item: dict[str, Any], names: tuple[str, ...]) -> bool | None:
    for name in names:
        value = _first(item, tuple(tuple(part.split(".")) for part in (name,)))
        if value is None:
            continue
        if isinstance(value, bool):
            return value
        if str(value).lower() in {"true", "yes", "1", "listed", "known", "active"}:
            return True
        if str(value).lower() in {"false", "no", "0", "not_listed", "none"}:
            return False
    return None


def _cached_intelligence_signals(item: dict[str, Any]) -> tuple[Any, bool | None, bool | None]:
    intelligence = item.get("intelligence") if isinstance(item.get("intelligence"), dict) else {}
    cve_data = ((intelligence.get("cve") or {}).get("data") or {}) if isinstance(intelligence.get("cve"), dict) else {}
    components = cve_data.get("components") if isinstance(cve_data.get("components"), dict) else {}
    epss = components.get("epss_probability")
    kev = components.get("in_kev") if isinstance(components.get("in_kev"), bool) else None
    poc_value = components.get("poc_confidence")
    poc = None
    if isinstance(poc_value, bool):
        poc = poc_value
    elif str(poc_value or "").lower() in {"high", "confirmed", "available", "true"}:
        poc = True
    elif str(poc_value or "").lower() in {"none", "not_found", "false"}:
        poc = False
    return epss, kev, poc


def build_exposure_graph(items: list[dict[str, Any]], cmdb_assets: list[dict[str, Any]], max_paths: int = 100) -> dict[str, Any]:
    max_paths = min(max(int(max_paths), 1), 100)
    cmdb_index: dict[str, dict[str, Any]] = {}
    for asset in cmdb_assets:
        for identifier in asset_identifiers(asset):
            cmdb_index.setdefault(identifier, asset)
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    paths: list[dict[str, Any]] = []
    unique_cves: set[str] = set()
    unique_assets: set[str] = set()

    def node(node_id: str, kind: str, label: str, **extra: Any) -> None:
        nodes.setdefault(node_id, {"id": node_id, "type": kind, "label": label, **extra})

    def edge(source: str, target: str, relation: str, **extra: Any) -> None:
        edges.setdefault((source, target, relation), {"source": source, "target": target,
                                                        "relationship": relation, **extra})

    for raw in items[:max_paths]:
        if not isinstance(raw, dict):
            continue
        vuln = raw.get("vulnerability") if isinstance(raw.get("vulnerability"), dict) else {}
        agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
        package = raw.get("package") if isinstance(raw.get("package"), dict) else {}
        cve = str(vuln.get("id") or raw.get("cve") or raw.get("id") or "").upper()
        if not CVE_RE.match(cve):
            continue
        identifiers = asset_identifiers(agent)
        cmdb = next((cmdb_index[value] for value in identifiers if value in cmdb_index), None)
        asset_label = str(agent.get("name") or agent.get("id") or (cmdb or {}).get("name") or "unknown asset")
        asset_key = str(agent.get("id") or asset_label).lower()
        package_name = str(package.get("name") or raw.get("package_name") or "unknown component")
        package_version = _text(package.get("version") or raw.get("package_version"))
        matched_component = None
        for component in (cmdb or {}).get("components", []):
            names = {str(component.get(key) or "").lower() for key in ("name", "product")}
            if package_name.lower() in names:
                matched_component = component
                break
        item_cpe = _first(raw, (("package", "cpe"), ("vulnerability", "cpe"), ("cpe",)))
        cpe = parse_cpe(item_cpe or (matched_component or {}).get("cpe") or (cmdb or {}).get("cpe"))
        patch_state = str(_first(raw, (("package", "patch_state"), ("vulnerability", "status"), ("patch_state",)))
                          or (matched_component or {}).get("patch_state") or (cmdb or {}).get("patch_state") or "unknown").lower()
        if patch_state not in PATCH_STATES:
            patch_state = "unknown"
        severity = str(vuln.get("severity") or raw.get("severity") or "unknown").lower()
        cached_epss, cached_kev, cached_poc = _cached_intelligence_signals(raw)
        epss = _first(raw, (("epss",), ("vulnerability", "epss"), ("intelligence", "epss_probability")))
        epss = cached_epss if epss is None else epss
        kev = _bool_signal(raw, ("kev", "in_kev", "vulnerability.kev", "intelligence.in_kev"))
        kev = cached_kev if kev is None else kev
        poc = _bool_signal(raw, ("poc", "has_poc", "exploit_available", "intelligence.poc"))
        poc = cached_poc if poc is None else poc
        exploited = _bool_signal(raw, ("observed_exploitation", "actively_exploited", "exploitation_observed"))
        internet = (cmdb or {}).get("internet_exposed") if cmdb else None
        criticality = str((cmdb or {}).get("criticality") or "unknown").lower()
        score = SEVERITY_WEIGHT.get(severity, 4) + CRITICALITY_WEIGHT.get(criticality, 0)
        score += 12 if internet is True else 0
        score += 18 if kev is True else 0
        score += 10 if poc is True else 0
        score += 24 if exploited is True else 0
        score -= 30 if patch_state in {"patched", "not_applicable"} else 0
        score = max(0, min(100, score))
        priority = "critical" if score >= 70 else "high" if score >= 50 else "medium" if score >= 25 else "low"
        exposure_state = "observed_exploitation" if exploited is True else (
            "patched" if patch_state == "patched" else "inventory_confirmed")
        asset_id = f"asset:{asset_key}"
        component_id = f"component:{asset_key}:{package_name.lower()}:{(package_version or 'unknown').lower()}"
        cve_id = f"cve:{cve}"
        node(asset_id, "asset", asset_label, owner=(cmdb or {}).get("owner"), criticality=criticality,
             internet_exposed=internet)
        node(component_id, "component", package_name, version=package_version, cpe=cpe.get("value"),
             cpe_status=cpe["status"], patch_state=patch_state)
        node(cve_id, "cve", cve, severity=severity, epss=epss, kev=kev, poc=poc)
        edge(asset_id, component_id, "runs", provenance="Wazuh inventory")
        edge(component_id, cve_id, "affected_by", provenance="Wazuh vulnerability state")
        case_id = _text(raw.get("case_id") or raw.get("incident_id"))
        if case_id:
            case_node = f"case:{case_id.lower()}"
            node(case_node, "case", case_id)
            edge(cve_id, case_node, "tracked_by", provenance="case link")
        paths.append({
            "asset": asset_label, "agent_id": agent.get("id"), "owner": (cmdb or {}).get("owner"),
            "criticality": criticality, "environment": (cmdb or {}).get("environment"),
            "network_zone": (cmdb or {}).get("network_zone"), "internet_exposed": internet,
            "component": package_name, "version": package_version, "cpe": cpe.get("value"),
            "cpe_status": cpe["status"], "cpe_reason": cpe.get("reason"), "cve": cve,
            "severity": severity, "epss": epss, "kev": kev, "poc": poc,
            "observed_exploitation": exploited, "patch_state": patch_state, "case_id": case_id,
            "exposure_state": exposure_state, "priority": priority, "risk_score": score,
            "provenance": ["Wazuh vulnerability state", "local CMDB"] if cmdb else ["Wazuh vulnerability state"],
        })
        unique_cves.add(cve)
        unique_assets.add(asset_key)
    paths.sort(key=lambda row: (-row["risk_score"], row["cve"], row["asset"]))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "current Wazuh vulnerability state; no external provider calls",
        "bounded": len(items) > max_paths, "source_records": len(items), "path_limit": max_paths,
        "summary": {
            "paths": len(paths), "assets": len(unique_assets), "cves": len(unique_cves),
            "critical_paths": sum(row["priority"] == "critical" for row in paths),
            "internet_exposed": sum(row["internet_exposed"] is True for row in paths),
            "patch_unknown": sum(row["patch_state"] == "unknown" for row in paths),
            "valid_cpe": sum(row["cpe_status"] == "valid" for row in paths),
            "case_linked": sum(bool(row["case_id"]) for row in paths),
        },
        "coverage": {
            "wazuh_inventory": bool(paths),
            "cpe": sum(row["cpe_status"] == "valid" for row in paths),
            "epss": sum(row["epss"] is not None for row in paths),
            "kev": sum(row["kev"] is not None for row in paths),
            "poc": sum(row["poc"] is not None for row in paths),
            "internet_exposure": sum(row["internet_exposed"] is not None for row in paths),
            "patch_state": sum(row["patch_state"] != "unknown" for row in paths),
            "case": sum(bool(row["case_id"]) for row in paths),
            "denominator": len(paths),
        },
        "nodes": list(nodes.values()), "edges": list(edges.values()), "paths": paths,
        "limitations": [
            "EPSS, KEV and PoC appear only when already stored with the inventory record; drill-down enrichment remains on demand and cached.",
            "A CPE match is product identity evidence, not proof of exploitation.",
            "Unlinked cases and unknown patch state are shown as evidence gaps, not negative findings.",
        ],
    }
