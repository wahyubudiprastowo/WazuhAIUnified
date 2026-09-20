from __future__ import annotations

import json
import os
import re
import asyncio
import urllib.parse
import urllib.request
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from mcp_server.threat_intel._cache import cache_get, cache_set, get_limiter


CYFIRMA_BASE_URL = os.getenv("CYFIRMA_BASE_URL", "https://api.cyfirma.com").rstrip("/")
CYFIRMA_API_KEY = os.getenv("CYFIRMA_API_KEY", "")
CYFIRMA_TAILORED_IOC_PATH = os.getenv(
    "CYFIRMA_TAILORED_IOC_PATH",
    "/api/ex/v3/da/stix/2.1/indicators/tailored",
)
CYFIRMA_GLOBAL_IOC_PATH = os.getenv(
    "CYFIRMA_GLOBAL_IOC_PATH",
    "/api/ex/v3/da/stix/2.1/indicators/all",
)
CYFIRMA_IOC_PATH = os.getenv("CYFIRMA_IOC_PATH", CYFIRMA_TAILORED_IOC_PATH)
CYFIRMA_VERIFY_SSL = os.getenv("CYFIRMA_VERIFY_SSL", "true").lower() == "true"
CYFIRMA_CACHE_TTL = int(os.getenv("CYFIRMA_CACHE_TTL", "1800"))

_cyfirma_limiter = get_limiter("cyfirma", max_concurrent=2, min_interval=0.5)


class CyfirmaIOCInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    indicator: str = Field(..., min_length=1, max_length=512, description="IP, domain, URL, hash or other IOC")
    scope: Literal["tailored", "global", "both"] = Field(default="both")
    limit: int = Field(default=25, ge=1, le=200)
    response_format: Literal["json", "markdown"] = Field(default="json")


class CyfirmaFeedInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    scope: Literal["tailored", "global", "both"] = Field(default="tailored")
    limit: int = Field(default=50, ge=1, le=500)
    response_format: Literal["json", "markdown"] = Field(default="json")


def _cyfirma_configured() -> str:
    if not CYFIRMA_BASE_URL:
        return "CYFIRMA_BASE_URL is not configured"
    if not CYFIRMA_API_KEY:
        return "CYFIRMA_API_KEY is not configured"
    return ""


def _scope_paths(scope: str) -> list[tuple[str, str]]:
    if scope == "tailored":
        return [("tailored", CYFIRMA_TAILORED_IOC_PATH or CYFIRMA_IOC_PATH)]
    if scope == "global":
        return [("global", CYFIRMA_GLOBAL_IOC_PATH)]
    return [
        ("tailored", CYFIRMA_TAILORED_IOC_PATH or CYFIRMA_IOC_PATH),
        ("global", CYFIRMA_GLOBAL_IOC_PATH),
    ]


def _url_for_path(path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return f"{CYFIRMA_BASE_URL}{path if path.startswith('/') else '/' + path}"


async def _cyfirma_request(scope: str, path: str) -> dict[str, Any]:
    missing = _cyfirma_configured()
    if missing:
        return {"error": missing}
    cache_key = f"{scope}:{path}"
    cached = cache_get("cyfirma", cache_key)
    if cached is not None:
        return cached
    async with _cyfirma_limiter:
        url = _url_for_path(path)
        params = {}
        if "apiKey=" not in url:
            params["apiKey"] = CYFIRMA_API_KEY
        headers = {"Accept": "application/json", "User-Agent": "wazuh-mcp-cyfirma/1.0"}
        try:
            async with httpx.AsyncClient(timeout=45.0, verify=CYFIRMA_VERIFY_SSL) as client:
                resp = await client.get(url, headers=headers, params=params)
                resp.raise_for_status()
                try:
                    data = resp.json()
                except Exception:
                    data = {"raw": resp.text}
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
            data = await asyncio.to_thread(_cyfirma_urllib_get, url, params, headers)
    cache_set("cyfirma", cache_key, data, CYFIRMA_CACHE_TTL)
    return data


def _cyfirma_urllib_get(url: str, params: dict[str, str], headers: dict[str, str]) -> dict[str, Any]:
    if params:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=45) as response:
        body = response.read()
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return {"raw": body.decode("utf-8", errors="replace")}


def _objects_from_feed(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        if isinstance(data.get("objects"), list):
            return [item for item in data["objects"] if isinstance(item, dict)]
        for key in ("data", "results", "indicators", "items"):
            if isinstance(data.get(key), list):
                return [item for item in data[key] if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def _extract_iocs_from_pattern(pattern: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"=\s*'([^']+)'", pattern or ""):
        value = match.group(1).strip()
        if value and value not in values:
            values.append(value)
    return values


def _normalize_indicator(obj: dict[str, Any], scope: str) -> dict[str, Any]:
    pattern = str(obj.get("pattern") or "")
    external_refs = obj.get("external_references") if isinstance(obj.get("external_references"), list) else []
    kill_chain = obj.get("kill_chain_phases") if isinstance(obj.get("kill_chain_phases"), list) else []
    return {
        "id": obj.get("id"),
        "scope": scope,
        "type": obj.get("type"),
        "name": obj.get("name") or obj.get("title"),
        "description": obj.get("description"),
        "labels": obj.get("labels") if isinstance(obj.get("labels"), list) else [],
        "pattern": pattern,
        "iocs": _extract_iocs_from_pattern(pattern),
        "confidence": obj.get("confidence"),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
        "valid_from": obj.get("valid_from"),
        "valid_until": obj.get("valid_until"),
        "kill_chain_phases": [
            {"kill_chain_name": item.get("kill_chain_name"), "phase_name": item.get("phase_name")}
            for item in kill_chain
            if isinstance(item, dict)
        ],
        "references": [
            {
                "source_name": item.get("source_name"),
                "url": item.get("url"),
                "description": item.get("description"),
            }
            for item in external_refs
            if isinstance(item, dict)
        ][:5],
    }


def _matches_indicator(row: dict[str, Any], indicator: str) -> bool:
    needle = indicator.lower().strip()
    haystack = json.dumps(row, ensure_ascii=False, default=str).lower()
    return needle in haystack


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labels: dict[str, int] = {}
    phases: dict[str, int] = {}
    for row in rows:
        for label in row.get("labels") or []:
            labels[str(label)] = labels.get(str(label), 0) + 1
        for phase in row.get("kill_chain_phases") or []:
            name = phase.get("phase_name")
            if name:
                phases[str(name)] = phases.get(str(name), 0) + 1
    return {
        "count": len(rows),
        "labels": dict(sorted(labels.items(), key=lambda item: item[1], reverse=True)[:10]),
        "kill_chain_phases": dict(sorted(phases.items(), key=lambda item: item[1], reverse=True)[:10]),
    }


async def cyfirma_feed(params: CyfirmaFeedInput) -> dict[str, Any]:
    feeds: dict[str, Any] = {}
    all_rows: list[dict[str, Any]] = []
    visible_rows: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    for scope, path in _scope_paths(params.scope):
        try:
            data = await _cyfirma_request(scope, path)
            if isinstance(data, dict) and data.get("error"):
                errors[scope] = str(data["error"])
                continue
            normalized = [_normalize_indicator(obj, scope) for obj in _objects_from_feed(data)]
            feeds[scope] = {"count": len(normalized), "items": normalized[: params.limit]}
            all_rows.extend(normalized)
            visible_rows.extend(normalized[: params.limit])
        except Exception as exc:
            errors[scope] = f"{type(exc).__name__}: {exc}"
    return {
        "provider": "cyfirma",
        "scope": params.scope,
        "summary": _summary(all_rows),
        "feeds": feeds,
        "items": visible_rows[: params.limit],
        "errors": errors,
    }


async def cyfirma_ioc_lookup(params: CyfirmaIOCInput) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    scanned: dict[str, int] = {}
    for scope, path in _scope_paths(params.scope):
        try:
            data = await _cyfirma_request(scope, path)
            if isinstance(data, dict) and data.get("error"):
                errors[scope] = str(data["error"])
                continue
            rows = [_normalize_indicator(obj, scope) for obj in _objects_from_feed(data)]
            scanned[scope] = len(rows)
            matches.extend(row for row in rows if _matches_indicator(row, params.indicator))
        except Exception as exc:
            errors[scope] = f"{type(exc).__name__}: {exc}"
    matches = matches[: params.limit]
    return {
        "provider": "cyfirma",
        "indicator": params.indicator,
        "scope": params.scope,
        "found": bool(matches),
        "match_count": len(matches),
        "scanned": scanned,
        "summary": _summary(matches),
        "matches": matches,
        "errors": errors,
    }
