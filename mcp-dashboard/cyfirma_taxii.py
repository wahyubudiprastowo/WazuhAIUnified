"""Bounded CYFIRMA TAXII 2.1 indicator intake.

The collector is intentionally opt-in: a custom STIX endpoint is not assumed to
be a TAXII collection. It accepts only a CYFIRMA HTTPS collection URL, one
bounded objects page, and returns normalized indicator rows for the existing
durable CYFIRMA ledger.
"""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from typing import Any


MAX_RESPONSE_BYTES = 1_500_000


def _collection_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(str(value or ""))
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not (host == "cyfirma.com" or host.endswith(".cyfirma.com")):
        raise ValueError("CYFIRMA TAXII collection URL must be HTTPS on a cyfirma.com host")
    if "/collections/" not in parsed.path:
        raise ValueError("CYFIRMA TAXII URL must identify a TAXII collection")
    path = parsed.path.rstrip("/") + "/"
    return urllib.parse.urlunsplit(("https", parsed.netloc, path, "", ""))


def _ioc_values(pattern: str) -> tuple[list[str], list[str]]:
    values, types = [], []
    for object_type, value in re.findall(r"([a-z0-9-]+):value\s*=\s*'([^']+)'", pattern or "", re.I):
        normalized = str(value).strip()[:500]
        if not normalized or normalized in values:
            continue
        values.append(normalized)
        types.append({"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain",
                      "url": "url", "file": "hash"}.get(object_type.lower(), object_type.lower())[:64])
    return values[:50], list(dict.fromkeys(types))[:12]


def normalize_indicator(item: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(item, dict) or str(item.get("type") or "") != "indicator":
        return None
    identifier = str(item.get("id") or "").strip()
    if not identifier:
        return None
    iocs, ioc_types = _ioc_values(str(item.get("pattern") or ""))
    references = []
    for reference in item.get("external_references") or []:
        if not isinstance(reference, dict):
            continue
        value = str(reference.get("url") or reference.get("external_id") or reference.get("source_name") or "").strip()
        if value and value not in references:
            references.append(value[:500])
    labels = [str(value)[:120] for value in (item.get("labels") or []) if str(value).strip()][:30]
    return {
        "id": identifier[:300], "scope": "taxii", "type": "indicator",
        "name": str(item.get("name") or identifier)[:500],
        "description": str(item.get("description") or "")[:3000],
        "confidence": item.get("confidence") or 0, "created": item.get("created"),
        "modified": item.get("modified"), "valid_from": item.get("valid_from"),
        "valid_until": item.get("valid_until"), "labels": labels,
        "kill_chain_phases": item.get("kill_chain_phases") if isinstance(item.get("kill_chain_phases"), list) else [],
        "references": references[:10], "iocs": iocs, "ioc_types": ioc_types,
    }


def _cursor(value: Any) -> str:
    """Keep a TAXII continuation token opaque and bounded.

    The token is passed back only as the value of the TAXII ``next`` query
    parameter. It is never treated as a URL, avoiding a provider-controlled
    redirect or request target.
    """
    if value in (None, ""):
        return ""
    if not isinstance(value, str):
        raise ValueError("CYFIRMA TAXII continuation token must be text")
    value = value.strip()
    if not value or len(value) > 2048:
        raise ValueError("CYFIRMA TAXII continuation token is invalid")
    return value


def fetch(collection_url: str, bearer_token: str, limit: int = 50, timeout: int = 15,
          cursor: str = "") -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch one bounded TAXII objects page with an optional saved cursor."""
    if not bearer_token:
        raise ValueError("CYFIRMA TAXII bearer token is required")
    base = _collection_url(collection_url)
    query_values = {"limit": str(max(1, min(int(limit), 100)))}
    next_cursor = _cursor(cursor)
    if next_cursor:
        query_values["next"] = next_cursor
    query = urllib.parse.urlencode(query_values)
    request = urllib.request.Request(
        urllib.parse.urljoin(base, "objects/") + "?" + query,
        headers={"Accept": "application/taxii+json;version=2.1", "Authorization": "Bearer " + bearer_token,
                 "User-Agent": "Wazuh-MCP-SOC/1.0 taxii-ledger"},
    )
    with urllib.request.urlopen(request, timeout=max(3, min(int(timeout), 30))) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("CYFIRMA TAXII response exceeded response limit")
    payload = json.loads(raw.decode("utf-8", errors="replace"))
    objects = payload.get("objects") if isinstance(payload, dict) else []
    if not isinstance(objects, list):
        raise ValueError("CYFIRMA TAXII response did not contain an objects list")
    rows = [row for row in (normalize_indicator(item) for item in objects[:100]) if row]
    more = bool(payload.get("more"))
    response_cursor = _cursor(payload.get("next")) if payload.get("next") not in (None, "") else ""
    return rows, {"status": "ok", "reported": len(objects), "loaded": len(rows),
                  "more": more, "next_cursor": response_cursor,
                  "cursor_used": bool(next_cursor),
                  "pagination_complete": not more}
