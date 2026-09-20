#!/usr/bin/env python3
"""
Asset Resolver - resolve alert identity (agent id/name/ip/host) to inventory.
Falls back to live Wazuh Indexer when CMDB has no curated match.
Never invents owner/criticality/application.
"""
from __future__ import annotations
import json, os
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import mcp
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.core.redact import _redact_alert_data
from mcp_server.tools.asset_context import _load_cmdb
from mcp_server.wazuh.indexer import _wazuh_indexer_post

def _find_cmdb(agent_id, agent_name, ip, host):
    """Score CMDB entries against every supplied identity key. Best match wins."""
    cands = []
    def _norm(v):
        return (v or "").strip().lower()
    for a in _load_cmdb():
        s = 0
        if agent_id and _norm(a.get("agent_id")) == _norm(agent_id):
            s += 4
        if host and _norm(a.get("host")) == _norm(host):
            s += 4
        if agent_name and _norm(a.get("host")) == _norm(agent_name):
            s += 3
        if ip and _norm(a.get("ip")) == _norm(ip):
            s += 3
        for al in a.get("aliases") or []:
            if agent_name and _norm(al) == _norm(agent_name):
                s += 2
            if host and _norm(al) == _norm(host):
                s += 2
        if s:
            cands.append((s, a))
    if not cands:
        return None
    cands.sort(key=lambda x: x[0], reverse=True)
    return cands[0][1]


async def _indexer_identity(agent_id, agent_name, ip):
    """Derive observed identity from live indexer (read-only, bounded)."""
    must = []
    if agent_id:
        must.append({"match": {"agent.id": agent_id}})
    if agent_name:
        must.append({"match_phrase": {"agent.name": agent_name}})
    if ip:
        must.append({"match": {"agent.ip": ip}})
    if not must:
        return {}
    body = {
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
        "_source": ["agent.id", "agent.name", "agent.ip", "host.name",
                    "agent.os.name", "agent.os.version"],
    }
    raw = await _wazuh_indexer_post(body)
    if isinstance(raw, dict) and "error" in raw:
        return {"error": str(raw.get("error") or raw.get("detail") or "")}
    hits = (raw.get("hits", {}) or {}).get("hits", []) if isinstance(raw, dict) else []
    if not hits:
        return {}
    src = hits[0].get("_source", {}) or {}
    agent = src.get("agent", {}) or {}
    host_name = agent.get("name") or (src.get("host", {}) or {}).get("name") or agent_name
    auto = {
        "agent_id": agent.get("id") or agent_id,
        "host": host_name or agent_id,
        "ip": agent.get("ip") or ip,
        "os": agent.get("os", {}).get("name") if isinstance(agent.get("os"), dict) else None,
    }
    auto["aliases"] = [v for v in (auto["host"], auto["ip"], agent_id) if v]
    return auto


async def resolve_asset(agent_id="", agent_name="", ip="", host="", force_indexer=False):
    """Resolve identity to inventory asset. Never invents manual facts."""
    cmdb = None if force_indexer else _find_cmdb(agent_id, agent_name, ip, host)
    if cmdb:
        return {"found": True, "asset": _redact_alert_data(cmdb), "source": "cmdb",
                "auto_enriched": False}
    auto = await _indexer_identity(agent_id, agent_name, ip)
    if auto.get("error"):
        return {"found": False, "asset": {}, "source": "indexer_error", "error": auto["error"]}
    if not auto:
        return {"found": False, "asset": {}, "source": "none",
                "detail": "No CMDB match and no recent indexer event for the supplied identity."}
    return {"found": True, "asset": _redact_alert_data(auto), "source": "indexer",
            "auto_enriched": True}


class AssetResolveInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    agent_id: str = Field(default="", max_length=128, description="Wazuh agent id (e.g. '001').")
    agent_name: str = Field(default="", max_length=256, description="Wazuh agent/hostname observed on the alert.")
    ip: str = Field(default="", max_length=128, description="Agent IP observed on the alert.")
    host: str = Field(default="", max_length=256, description="Hostname/subdomain to look up.")
    force_indexer: bool = Field(default=False,
        description="Skip the CMDB lookup and force live indexer identity discovery.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@mcp.tool(
    name="blueteam_asset_resolve",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_asset_resolve(params: AssetResolveInput) -> str:
    """Resolve an alert identity (agent id/name/ip/host) to an inventory asset.

    Unifies `blueteam_asset_context`'s hostname-only lookup across agent.id,
    agent.name, agent.ip, hostname, and aliases. If the asset is not curated in
    the CMDB, falls back to the live Wazuh Indexer to derive observed identity
    (host/ip/os) - marked `source: indexer`. Owner/criticality/application are
    NEVER invented.

    **Worked Examples**
    1. ``blueteam_asset_resolve(agent_id="001")``
    2. ``blueteam_asset_resolve(ip="103.107.116.24", response_format="json")``
    """
    _audit_log("blueteam_asset_resolve", params.model_dump())
    result = await resolve_asset(agent_id=params.agent_id, agent_name=params.agent_name,
                                 ip=params.ip, host=params.host, force_indexer=params.force_indexer)
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))
    return _truncate_if_needed(_render(result))


def _render(result: dict) -> str:
    asset = result.get("asset", {}) or {}
    if not result.get("found"):
        cmdb = os.environ.get("BLUETEAM_CMDB_FILE", "not set")
        parts = ["# Asset Resolve - not found", "",
                 f"- **source**: `{result.get('source')}`"]
        if result.get("error"):
            parts.append(f"- **detail**: {result['error']}")
        if result.get("detail"):
            parts.append(f"- **detail**: {result['detail']}")
        parts.append(f"\n_CMDB: {cmdb}_")
        return "\n".join(parts)
    source = result.get("source")
    host = asset.get("host") or asset.get("agent_id") or "?"
    lines = [f"# Asset Resolve - `{host}`", "",
             f"- **source**: `{source}`",
             f"- **agent_id**: `{asset.get('agent_id', '-')}`",
             f"- **ip**: `{asset.get('ip', '-')}`",
             f"- **os**: `{asset.get('os', '-')}`"]
    aliases = asset.get("aliases") or []
    if aliases:
        lines.append(f"- **aliases**: {', '.join('`' + a + '`' for a in aliases)}")
    if source == "cmdb":
        lines += [f"- **owner**: {asset.get('owner', '-')}",
                  f"- **criticality**: {asset.get('criticality', '-')}",
                  f"- **application**: {asset.get('application', '-')}"]
    return "\n".join(lines)