#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
CrowdSec CTI - single + bulk IP reputation
"""
from __future__ import annotations
import json, logging, time, os, asyncio
from typing import Any
import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, field_validator
from mcp_server import mcp, CROWDSEC_API_KEY_ENV, CROWDSEC_CACHE_TTL, CROWDSEC_BASE_URL
from mcp_server.core.http_client import _api_call, _handle_api_error, _is_private_or_reserved, ValidPublicIp
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.threat_intel._cache import cache_get, cache_set, get_limiter

logger = logging.getLogger("blue_team_mcp.crowdsec")
_crowdsec_limiter = get_limiter("crowdsec", max_concurrent=3, min_interval=0.1)  # 10 req/sec


def _get_crowdsec_api_key() -> str:
    key = os.environ.get(CROWDSEC_API_KEY_ENV)
    if not key:
        raise RuntimeError(f"{CROWDSEC_API_KEY_ENV} not set. Get a free key at https://www.crowdsec.net/en/user/profile")
    return key


async def _crowdsec_request(path: str) -> dict[str, Any]:
    cached = cache_get("crowdsec", path)
    if cached is not None:
        return cached
    async with _crowdsec_limiter:
        headers = {"x-api-key": _get_crowdsec_api_key(), "accept": "application/json",
                   "User-Agent": "blue-team-mcp/1.0.0 (TangerangKota-CSIRT)"}
        url = f"{CROWDSEC_BASE_URL}{path}"
        resp = await _api_call("get", url, headers=headers)
        data = resp.json()
    cache_set("crowdsec", path, data, CROWDSEC_CACHE_TTL)
    return data


def _labels_from(items: Any) -> list[str]:
    labels: list[str] = []
    if isinstance(items, dict):
        for key in ("classifications", "items", "behaviors", "values", "false_positives"):
            if isinstance(items.get(key), list):
                items = items.get(key)
                break
        else:
            return labels
    if not isinstance(items, list):
        return labels
    for item in items:
        if isinstance(item, str):
            label = item
        elif isinstance(item, dict):
            label = (
                item.get("label")
                or item.get("name")
                or item.get("value")
                or item.get("classification")
                or item.get("technique")
                or item.get("id")
            )
        else:
            label = str(item)
        if label and label not in labels:
            labels.append(str(label))
    return labels


def _crowdsec_reason(raw: dict[str, Any]) -> str:
    reputation = str(raw.get("reputation") or "unknown")
    behaviors = _labels_from(raw.get("behaviors"))
    classifications = _labels_from(raw.get("classifications"))
    cves = raw.get("cves") if isinstance(raw.get("cves"), list) else []
    parts: list[str] = []
    if reputation.lower() != "unknown":
        parts.append(f"CrowdSec reputation is {reputation}.")
    if classifications:
        parts.append("Classified as " + ", ".join(classifications[:4]) + ".")
    if behaviors:
        parts.append("Observed behavior includes " + ", ".join(behaviors[:5]) + ".")
    if cves:
        cve_labels = [str(item.get("id") or item.get("cve") or item) if isinstance(item, dict) else str(item) for item in cves]
        parts.append("Linked CVE context: " + ", ".join(cve_labels[:5]) + ".")
    if raw.get("background_noise") and str(raw.get("background_noise")).lower() != "none":
        parts.append(f"Background noise: {raw.get('background_noise')}.")
    if raw.get("confidence") is not None and str(raw.get("confidence")).lower() != "none":
        parts.append(f"Confidence: {raw.get('confidence')}.")
    return " ".join(parts) or "CrowdSec returned no adverse context for this public IP."


def _compact_crowdsec_json(ip: str, raw: dict[str, Any]) -> dict[str, Any]:
    fields = [
        "reputation",
        "confidence",
        "scores",
        "background_noise",
        "background_noise_score",
        "ip_range",
        "ip_range_score",
        "ip_range_24",
        "ip_range_24_reputation",
        "ip_range_24_score",
        "as_name",
        "as_num",
        "location",
        "reverse_dns",
        "history",
        "classifications",
        "attack_details",
        "target_countries",
        "mitre_techniques",
        "references",
        "behaviors",
        "cves",
    ]
    result: dict[str, Any] = {"ip": ip, "why": _crowdsec_reason(raw)}
    for field in fields:
        if field in raw:
            result[field] = raw.get(field)
    result.setdefault("reputation", raw.get("reputation", "unknown"))
    result.setdefault("behaviors", raw.get("behaviors", []))
    result.setdefault("cves", raw.get("cves", []))
    result["raw_fields"] = sorted(raw.keys())
    return result


def _format_crowdsec_markdown(ip: str, raw: dict) -> str:
    lines = [f"# CrowdSec Reputation - {ip}", ""]
    lines.append(f"- **Reputation**: {raw.get('reputation', 'unknown')}")
    if raw.get("confidence") is not None: lines.append(f"- **Confidence**: {raw['confidence']}")
    if raw.get("background_noise"): lines.append(f"- **Background noise**: {raw['background_noise']}")
    if raw.get("ip_range"): lines.append(f"- **IP range**: {raw['ip_range']}")
    if raw.get("as_name"): lines.append(f"- **ASN**: {raw['as_name']}")
    if raw.get("location"):
        loc = raw.get("location") or {}
        lines.append(f"- **Location**: {loc.get('city','?')}, {loc.get('country','?')}")
    lines.append("")
    lines.append("## Why")
    lines.append(_crowdsec_reason(raw))
    for b in raw.get("behaviors") or []:
        lines.append(f"- **{b.get('name','?')}**{' - ' + b.get('label','') if b.get('label') else ''}")
    for m in raw.get("mitre_techniques") or []:
        lines.append(f"- MITRE: {m.get('name','?')} ({m.get('label','')})")
    for cve in raw.get("cves") or []:
        label = cve.get("id") or cve.get("cve") if isinstance(cve, dict) else cve
        lines.append(f"- CVE: {label}")
    return "\n".join(lines)


class CrowdsecIpReputationInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: ValidPublicIp = Field(..., min_length=3, max_length=45)
    response_format: str = Field(default="markdown")


@mcp.tool(name="crowdsec_ip_reputation", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def crowdsec_ip_reputation(params: CrowdsecIpReputationInput) -> str:
    _audit_log("crowdsec_ip_reputation", {"ip": params.ip})
    try:
        raw = await _crowdsec_request(f"/v2/smoke/{params.ip}")
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        return _handle_api_error(e, context="crowdsec_ip_reputation")
    if params.response_format == "json":
        return json.dumps(_compact_crowdsec_json(str(params.ip), raw), indent=2)
    return _truncate_if_needed(_format_crowdsec_markdown(params.ip, raw))


class CrowdsecIpReputationBulkInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ips: list[str] = Field(..., min_length=1, max_length=25)
    response_format: str = Field(default="markdown")

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, v):
        import ipaddress
        for ip in v:
            try:
                addr = ipaddress.ip_address(ip.strip())
            except ValueError:
                raise ValueError(f"Invalid IP: {ip}")
            if addr.is_private:
                raise ValueError(f"'{ip.strip()}' is a private/reserved IP - bulk lookup accepts public IPs only.")
        return v


@mcp.tool(name="crowdsec_ip_reputation_bulk", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def crowdsec_ip_reputation_bulk(params: CrowdsecIpReputationBulkInput) -> str:
    import asyncio
    _audit_log("crowdsec_ip_reputation_bulk", {"count": len(params.ips)})

    async def _lookup_one(ip: str) -> dict:
        try:
            raw = await _crowdsec_request(f"/v2/smoke/{ip.strip()}")
            return _compact_crowdsec_json(ip.strip(), raw)
        except Exception as e:
            return {"ip": ip, "error": _handle_api_error(e, context=ip)}

    results = await asyncio.gather(*[_lookup_one(ip) for ip in params.ips])
    if params.response_format == "json":
        return json.dumps(results, indent=2)
    lines = ["# CrowdSec Bulk Reputation", ""]
    for r in results:
        if "error" in r:
            lines.append(f"- **{r['ip']}** - ⚠️ {r['error']}")
        else:
            lines.append(f"- **{r['ip']}** - `{r['reputation']}`")
    return _truncate_if_needed("\n".join(lines))
