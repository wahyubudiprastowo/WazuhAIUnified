#!/usr/bin/env python3
"""
CYFIRMA STIX 2.1 threat-intelligence tools.
"""
from __future__ import annotations

import json

from mcp_server import mcp
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.threat_intel.cyfirma import (
    CyfirmaFeedInput,
    CyfirmaIOCInput,
    cyfirma_feed,
    cyfirma_ioc_lookup as _cyfirma_ioc_lookup,
)


def _format_feed_markdown(data: dict) -> str:
    summary = data.get("summary") or {}
    lines = ["# CYFIRMA IOC Feed", ""]
    lines.append(f"- **Scope**: {data.get('scope', '?')}")
    lines.append(f"- **Indicators**: {summary.get('count', 0)}")
    labels = summary.get("labels") or {}
    if labels:
        lines.append("- **Top Labels**: " + ", ".join(f"`{k}` ({v})" for k, v in list(labels.items())[:8]))
    phases = summary.get("kill_chain_phases") or {}
    if phases:
        lines.append("- **Kill Chain**: " + ", ".join(f"`{k}` ({v})" for k, v in list(phases.items())[:8]))
    for item in (data.get("items") or [])[:10]:
        iocs = ", ".join(item.get("iocs") or []) or item.get("pattern") or item.get("id")
        labels_text = ", ".join(item.get("labels") or []) or "unlabeled"
        lines.append(f"- `{item.get('scope')}` {iocs} | {labels_text} | confidence {item.get('confidence', '-')}")
    if data.get("errors"):
        lines.append("")
        lines.append("## Errors")
        for scope, error in data["errors"].items():
            lines.append(f"- `{scope}`: {error}")
    return "\n".join(lines)


def _format_lookup_markdown(data: dict) -> str:
    lines = [f"# CYFIRMA IOC Lookup - `{data.get('indicator', '?')}`", ""]
    lines.append(f"- **Found**: {data.get('found')}")
    lines.append(f"- **Matches**: {data.get('match_count', 0)}")
    lines.append(f"- **Scanned**: {data.get('scanned', {})}")
    for item in (data.get("matches") or [])[:10]:
        iocs = ", ".join(item.get("iocs") or []) or item.get("pattern") or item.get("id")
        labels_text = ", ".join(item.get("labels") or []) or "unlabeled"
        phases = ", ".join(p.get("phase_name", "") for p in item.get("kill_chain_phases", []) if p.get("phase_name")) or "-"
        lines.append(f"- `{item.get('scope')}` {iocs} | {labels_text} | kill-chain {phases} | confidence {item.get('confidence', '-')}")
    if data.get("errors"):
        lines.append("")
        lines.append("## Errors")
        for scope, error in data["errors"].items():
            lines.append(f"- `{scope}`: {error}")
    return "\n".join(lines)


@mcp.tool(
    name="cyfirma_ioc_feed",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
)
async def cyfirma_ioc_feed(params: CyfirmaFeedInput) -> str:
    """Load CYFIRMA STIX 2.1 IOC feed from tailored, global, or both scopes."""
    _audit_log("cyfirma_ioc_feed", {"scope": params.scope, "limit": params.limit})
    data = await cyfirma_feed(params)
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(data, indent=2, default=str))
    return _truncate_if_needed(_format_feed_markdown(data))


@mcp.tool(
    name="cyfirma_ioc_lookup",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
)
async def cyfirma_ioc_lookup(params: CyfirmaIOCInput) -> str:
    """Search CYFIRMA tailored/global STIX feeds for an IOC."""
    _audit_log("cyfirma_ioc_lookup", {"indicator": params.indicator, "scope": params.scope})
    data = await _cyfirma_ioc_lookup(params)
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(data, indent=2, default=str))
    return _truncate_if_needed(_format_lookup_markdown(data))
