#!/usr/bin/env python3
"""
HLD alert worker for the Wazuh + MCP AI Security Platform.

This worker is intentionally additive and non-destructive by default:
- polls Wazuh Indexer for high-severity alerts
- calls MCP tools through the JSON-RPC /mcp endpoint
- writes local audit JSONL events
- optionally sends approval requests to webhook/Teams endpoints
- never executes Wazuh active response unless ENABLE_AUTOMATED_RESPONSE=true
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    indexer_url: str = os.getenv("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200").rstrip("/")
    indexer_user: str = os.getenv("WAZUH_INDEXER_USER", "admin")
    indexer_password: str = os.getenv("WAZUH_INDEXER_PASSWORD", os.getenv("WAZUH_INDEXER_PASS", "SecretPassword"))
    indexer_verify_ssl: bool = _env_bool("WAZUH_INDEXER_VERIFY_SSL", False)
    mcp_url: str = os.getenv("MCP_URL", "http://wazuh-main-server:3000").rstrip("/")
    mcp_api_key: str = os.getenv("MCP_API_KEY", "")
    min_alert_level: int = _env_int("MIN_ALERT_LEVEL", 10)
    poll_interval: int = _env_int("POLL_INTERVAL", 10)
    lookback_minutes: int = _env_int("LOOKBACK_MINUTES", 30)
    runtime_dir: Path = Path(os.getenv("WORKER_RUNTIME_DIR", "/data"))
    webhook_url: str = os.getenv("SOAR_WEBHOOK_URL", "").strip()
    teams_webhook_url: str = os.getenv("TEAMS_WEBHOOK_URL", "").strip()
    enable_automated_response: bool = _env_bool("ENABLE_AUTOMATED_RESPONSE", False)
    response_min_level: int = _env_int("RESPONSE_MIN_LEVEL", 12)
    response_agent_id: str = os.getenv("RESPONSE_AGENT_ID", "").strip()


SETTINGS = Settings()
SEEN_LIMIT = _env_int("SEEN_CACHE_LIMIT", 5000, minimum=100)
# Optional throttle (seconds) between indexer-weight correlation/aggregation runs.
# 0 = disabled (current behaviour: runs on every new alert). Only active when env set.
CORRELATION_MIN_INTERVAL = _env_int("CORRELATION_MIN_INTERVAL", 0, minimum=0)
_last_correlation_at = 0.0
_MCP_TOKEN: str | None = None
_MCP_TOKEN_EXPIRES_AT = 0.0


def _correlation_due() -> bool:
    """Return True when a correlation/aggregation run is allowed (throttled if configured)."""
    global _last_correlation_at
    if CORRELATION_MIN_INTERVAL <= 0:
        return True
    now = time.time()
    if now - _last_correlation_at < CORRELATION_MIN_INTERVAL:
        return False
    _last_correlation_at = now
    return True


def _json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)


def _load_seen(path: Path) -> set[str]:
    try:
        return set(json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return set()


def _save_seen(path: Path, seen: set[str]) -> None:
    values = list(seen)[-SEEN_LIMIT:]
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(values, indent=2), encoding="utf-8")
    temp.replace(path)


def _append_jsonl(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(_json_dumps(event) + "\n")


def _alert_source(alert: dict[str, Any]) -> dict[str, Any]:
    return alert.get("_source") or {}


def _alert_id(alert: dict[str, Any]) -> str:
    return str(alert.get("_id") or _json_dumps(_alert_source(alert))[:512])


def _extract_srcip(source: dict[str, Any]) -> str | None:
    data = source.get("data") or {}
    for key in ("srcip", "src_ip", "source.ip", "client_ip"):
        value = data.get(key) or source.get(key)
        if value:
            return str(value)
    return None


def _rule_level(source: dict[str, Any]) -> int:
    try:
        return int((source.get("rule") or {}).get("level") or 0)
    except (TypeError, ValueError):
        return 0


async def query_alerts(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    query = {
        "size": 50,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"rule.level": {"gte": SETTINGS.min_alert_level}}},
                    {"range": {"@timestamp": {"gte": f"now-{SETTINGS.lookback_minutes}m", "lte": "now"}}},
                ]
            }
        },
    }
    response = await client.post(
        f"{SETTINGS.indexer_url}/wazuh-alerts-*/_search",
        json=query,
        timeout=30,
    )
    response.raise_for_status()
    return response.json().get("hits", {}).get("hits", [])


async def call_mcp_tool(client: httpx.AsyncClient, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if SETTINGS.mcp_api_key:
        headers["Authorization"] = f"Bearer {await get_mcp_token(client)}"

    payload = {
        "jsonrpc": "2.0",
        "id": f"hld-worker-{int(time.time() * 1000)}",
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    response = await client.post(f"{SETTINGS.mcp_url}/mcp", json=payload, headers=headers, timeout=90)
    response.raise_for_status()
    return response.json()


async def get_mcp_token(client: httpx.AsyncClient) -> str:
    global _MCP_TOKEN, _MCP_TOKEN_EXPIRES_AT

    if _MCP_TOKEN and time.time() < _MCP_TOKEN_EXPIRES_AT:
        return _MCP_TOKEN

    response = await client.post(
        f"{SETTINGS.mcp_url}/auth/token",
        json={"api_key": SETTINGS.mcp_api_key},
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError("MCP auth token response did not include access_token")

    expires_in = int(data.get("expires_in") or 3600)
    _MCP_TOKEN = str(token)
    _MCP_TOKEN_EXPIRES_AT = time.time() + max(60, expires_in - 60)
    return _MCP_TOKEN


def _mcp_has_error(result: dict[str, Any]) -> bool:
    if "error" in result:
        return True
    content = (result.get("result") or {}).get("content") or []
    for item in content:
        text = str(item.get("text") or "").lower()
        if "unknown tool" in text or "not found" in text:
            return True
    return False


async def call_mcp_with_fallbacks(
    client: httpx.AsyncClient,
    attempts: list[tuple[str, dict[str, Any]]],
) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    for tool_name, arguments in attempts:
        try:
            result = await call_mcp_tool(client, tool_name, arguments)
            if not _mcp_has_error(result):
                result["_selected_tool"] = tool_name
                return result
            errors.append({"tool": tool_name, "result": result})
        except Exception as exc:
            errors.append({"tool": tool_name, "error": str(exc)})
    return {"error": "all MCP tool attempts failed", "attempts": errors}


async def notify_webhook(client: httpx.AsyncClient, url: str, payload: dict[str, Any]) -> None:
    if not url:
        return
    response = await client.post(url, json=payload, timeout=30)
    response.raise_for_status()


async def analyze_alert(alert: dict[str, Any]) -> dict[str, Any]:
    source = _alert_source(alert)
    srcip = _extract_srcip(source)
    level = _rule_level(source)
    result: dict[str, Any] = {
        "alert_id": _alert_id(alert),
        "timestamp": source.get("@timestamp"),
        "agent": source.get("agent"),
        "rule": source.get("rule"),
        "srcip": srcip,
        "level": level,
        "mcp": {},
        "response": {"requested": False, "executed": False},
    }

    async with httpx.AsyncClient(verify=False) as client:
        if srcip:
            result["mcp"]["threat_intelligence"] = await call_mcp_with_fallbacks(
                client,
                [
                    ("advanced_threat_intelligence", {"indicator": srcip, "provider": "all"}),
                    ("analyze_security_threat", {"indicator": srcip, "indicator_type": "ip"}),
                    ("check_ioc_reputation", {"indicator": srcip, "indicator_type": "ip"}),
                ],
            )

        if _correlation_due():
            result["mcp"]["correlation"] = await call_mcp_with_fallbacks(
                client,
                [
                    (
                        "advanced_three_sum_correlation",
                        {"lookback_minutes": max(SETTINGS.lookback_minutes, 60), "threshold_score": 35},
                    ),
                    (
                        "get_alerts_aggregated",
                        {"timestamp_start": f"now-{max(SETTINGS.lookback_minutes, 60)}m", "timestamp_end": "now"},
                    ),
                ],
            )
        elif CORRELATION_MIN_INTERVAL > 0:
            result["mcp"]["correlation"] = {"skipped": True, "reason": "throttled", "interval_seconds": CORRELATION_MIN_INTERVAL}

        approval_payload = {
            "type": "wazuh_hld_approval_request",
            "alert": result,
            "recommended_action": "review_and_approve_containment",
        }
        await notify_webhook(client, SETTINGS.webhook_url, approval_payload)
        await notify_webhook(client, SETTINGS.teams_webhook_url, approval_payload)
        result["response"]["requested"] = bool(SETTINGS.webhook_url or SETTINGS.teams_webhook_url)

        if (
            SETTINGS.enable_automated_response
            and srcip
            and level >= SETTINGS.response_min_level
            and SETTINGS.response_agent_id
        ):
            result["response"]["executed"] = True
            result["response"]["tool"] = "wazuh_block_ip"
            result["response"]["mcp_result"] = await call_mcp_tool(
                client,
                "wazuh_block_ip",
                {"ip_address": srcip, "agent_id": SETTINGS.response_agent_id, "duration": 3600},
            )

    return result


async def main() -> None:
    SETTINGS.runtime_dir.mkdir(parents=True, exist_ok=True)
    seen_path = SETTINGS.runtime_dir / "seen-alerts.json"
    audit_path = SETTINGS.runtime_dir / "worker-events.jsonl"
    seen = _load_seen(seen_path)

    print("Wazuh HLD AI Alert Worker started", flush=True)
    print(f"Indexer: {SETTINGS.indexer_url}", flush=True)
    print(f"MCP: {SETTINGS.mcp_url}/mcp", flush=True)
    print(f"Automated response enabled: {SETTINGS.enable_automated_response}", flush=True)

    indexer_auth = (SETTINGS.indexer_user, SETTINGS.indexer_password)
    async with httpx.AsyncClient(verify=SETTINGS.indexer_verify_ssl, auth=indexer_auth) as indexer_client:
        while True:
            try:
                for alert in await query_alerts(indexer_client):
                    aid = _alert_id(alert)
                    if aid in seen:
                        continue
                    seen.add(aid)
                    event = await analyze_alert(alert)
                    _append_jsonl(audit_path, event)
                    print(_json_dumps({"new_alert": aid, "srcip": event.get("srcip"), "level": event.get("level")}), flush=True)
                _save_seen(seen_path, seen)
            except Exception as exc:
                error = {"type": "worker_error", "error": str(exc), "ts": int(time.time())}
                _append_jsonl(audit_path, error)
                print(_json_dumps(error), flush=True)
            await asyncio.sleep(SETTINGS.poll_interval)


if __name__ == "__main__":
    asyncio.run(main())
