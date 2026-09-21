#!/usr/bin/env python3
from __future__ import annotations

import json
import base64
import hashlib
import ipaddress
import mimetypes
import os
import re
import shutil
import ssl
import sqlite3
import time
import threading
import hmac
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from soc_analysis import explain_rule, coverage as analysis_coverage, vulnerability_inventory
from cve_exposure import (
    asset_identifiers as _normalized_asset_identifiers,
    build_exposure_graph,
    normalize_cmdb_asset as _normalize_cmdb_record,
)
import soc_automation
import soc_pipeline
import soc_workflows


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
CONFIG_FILE = Path(os.environ.get("DASHBOARD_CONFIG_FILE", ROOT / "dashboard.env"))
HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
PORT = int(os.environ.get("DASHBOARD_PORT", "8088"))
DASHBOARD_ACCESS_TOKEN = os.environ.get("DASHBOARD_ACCESS_TOKEN", "")
DASHBOARD_ACCESS_USERNAME = os.environ.get("DASHBOARD_ACCESS_USERNAME", "soc").strip() or "soc"
_manual_tool_slots = threading.BoundedSemaphore(1)

GENSECAI_MCP_URL = os.environ.get("GENSECAI_MCP_URL", "http://wazuh-main-server:3000").rstrip("/")
GENSECAI_API_KEY = os.environ.get("GENSECAI_API_KEY", "")
INFOKOM_MCP_URL = os.environ.get("INFOKOM_MCP_URL", "http://wazuh-infokom-mcp:8000/mcp").rstrip("/")
INFOKOM_API_KEY = os.environ.get("INFOKOM_API_KEY", "")
AI_ANALYST_ENABLED = os.environ.get("AI_ANALYST_ENABLED", "false").lower() == "true"
AI_PROVIDER_BASE_URL = os.environ.get("AI_PROVIDER_BASE_URL", "").rstrip("/")
AI_MODEL = os.environ.get("AI_MODEL", "")
AI_AUTO_ANALYZE = os.environ.get("AI_AUTO_ANALYZE", "false").lower() == "true"
AI_API_KEY = os.environ.get("AI_API_KEY", "")
DOCKER_ANALYTICS_ENABLED = os.environ.get("DOCKER_ANALYTICS_ENABLED", "true").lower() == "true"
M365_ANALYTICS_ENABLED = os.environ.get("M365_ANALYTICS_ENABLED", "true").lower() == "true"
M365_TENANT_ID = os.environ.get("M365_TENANT_ID", "")
M365_CLIENT_ID = os.environ.get("M365_CLIENT_ID", "")
M365_CLIENT_SECRET = os.environ.get("M365_CLIENT_SECRET", "")
M365_CONTENT_TYPES = os.environ.get("M365_CONTENT_TYPES", "Audit.AzureActiveDirectory,Audit.Exchange,Audit.SharePoint,Audit.General,DLP.All")
CROWDSEC_WATCHLIST_IPS = os.environ.get("CROWDSEC_WATCHLIST_IPS", "")
DOCKER_DATA_ROOT = os.environ.get("DOCKER_DATA_ROOT", "/data/wazuh-storage/docker")
WAZUH_INDEXER_VOLUME = os.environ.get("WAZUH_INDEXER_VOLUME", "/data/wazuh-storage/docker/volumes/single-node_wazuh-indexer-data/_data")
WAZUH_LOGS_VOLUME = os.environ.get("WAZUH_LOGS_VOLUME", "/data/wazuh-storage/docker/volumes/single-node_wazuh_logs/_data")
WAZUH_DOCKER_NETWORK = os.environ.get("WAZUH_DOCKER_NETWORK", "single-node_default")
WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200").rstrip("/")
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "SecretPassword")
SETTINGS_WRITE_ENABLED = os.environ.get("SETTINGS_WRITE_ENABLED", "true").lower() == "true"

_gensecai_token = ""
_gensecai_token_expires_at = 0.0
_tools_cache: dict[str, Any] = {"expires_at": 0.0, "tools": [], "errors": {}}
_intel_test_cache: dict[str, Any] = {"expires_at": 0.0, "data": None}
_finding_cache: dict[str, Any] = {}
_finding_lock = threading.Lock()
_analysis_cache: dict[str, Any] = {}
_analysis_lock = threading.Lock()
_overview_cache_lock = threading.Lock()
_overview_db_init_lock = threading.Lock()
_overview_db_initialized = False
_overview_refreshing: set[str] = set()
_incident_cache_lock = threading.Lock()
_incident_cache: dict[str, dict[str, Any]] = {}
_incident_refreshing: set[str] = set()
_infokom_session_lock = threading.Lock()
_infokom_session: dict[str, Any] = {"expires": 0, "id": None}
INDEXER_MAX_CONCURRENT_QUERIES = max(1, min(8, int(os.environ.get("SOC_INDEXER_MAX_CONCURRENT_QUERIES", "2") or "2")))
INDEXER_ACQUIRE_TIMEOUT_SECONDS = max(1, min(30, int(os.environ.get("SOC_INDEXER_ACQUIRE_TIMEOUT_SECONDS", "5") or "5")))
_indexer_slots = threading.BoundedSemaphore(INDEXER_MAX_CONCURRENT_QUERIES)
_automation_values = {key: os.environ.get(key, default) for key, default in soc_automation.DEFAULTS.items()}
OVERVIEW_CACHE_DB = Path(os.environ.get("SOC_OVERVIEW_CACHE_DB", ROOT / "runtime" / "soc-overview-cache.db"))
AUTOMATION_DB = Path(os.environ.get("SOC_AUTOMATION_DB", ROOT / "runtime" / "soc-automation.db"))
OVERVIEW_CACHE_TTL_SECONDS = int(os.environ.get("SOC_OVERVIEW_CACHE_TTL_SECONDS", "120") or "120")
OVERVIEW_HISTORY_RETENTION_DAYS = max(1, int(os.environ.get("SOC_OVERVIEW_HISTORY_RETENTION_DAYS", "180") or "180"))
PREWARM_ENABLED = os.environ.get("SOC_PREWARM_ENABLED", "true").lower() == "true"
PREWARM_RANGES = [item.strip() for item in os.environ.get("SOC_PREWARM_RANGES", "24h,7d,30d").split(",") if item.strip()]
_source_cmdb = ROOT.parent / "infokom-analysis" / "resource" / "assets.json"
SOC_CMDB_FILE = Path(os.environ.get(
    "SOC_CMDB_FILE",
    os.environ.get("BLUETEAM_CMDB_FILE", str(_source_cmdb if _source_cmdb.exists() else ROOT / "cmdb" / "assets.json")),
))
CMDB_MAX_BYTES = 5 * 1024 * 1024
CMDB_MAX_ASSETS = 10_000
_cmdb_lock = threading.Lock()
_cmdb_cache: dict[str, Any] = {
    "path": None, "mtime_ns": None, "size": None, "assets": [], "loaded_at": None, "error": None,
}


@contextmanager
def _sqlite_db(path: Path):
    """Transactional SQLite connection that is always closed."""
    connection = sqlite3.connect(path, timeout=15)
    try:
        connection.execute("PRAGMA busy_timeout=15000")
        with connection:
            yield connection
    finally:
        connection.close()

CONFIG_SCHEMA: list[dict[str, Any]] = [
    {"key": "GENSECAI_MCP_URL", "label": "GenSecAI MCP URL", "group": "MCP Connections", "type": "url", "required": True, "restart": False},
    {"key": "GENSECAI_API_KEY", "label": "GenSecAI API Key", "group": "MCP Connections", "type": "secret", "required": True, "restart": False},
    {"key": "INFOKOM_MCP_URL", "label": "INFOKOM MCP URL", "group": "MCP Connections", "type": "url", "required": True, "restart": False},
    {"key": "INFOKOM_API_KEY", "label": "INFOKOM API Key", "group": "MCP Connections", "type": "secret", "required": True, "restart": False},
    {"key": "AI_ANALYST_ENABLED", "label": "AI Analyst", "group": "AI Analyst", "type": "boolean", "required": False, "restart": False},
    {"key": "AI_AUTO_ANALYZE", "label": "Auto Analyze", "group": "AI Analyst", "type": "boolean", "required": False, "restart": False},
    {"key": "AI_PROVIDER_BASE_URL", "label": "AI Provider URL", "group": "AI Analyst", "type": "url_optional", "required": False, "restart": False},
    {"key": "AI_MODEL", "label": "AI Model", "group": "AI Analyst", "type": "text", "required": False, "restart": False},
    {"key": "AI_API_KEY", "label": "AI API Key", "group": "AI Analyst", "type": "secret", "required": False, "restart": False},
    {"key": "DOCKER_ANALYTICS_ENABLED", "label": "Docker Analytics", "group": "SOC Sources", "type": "boolean", "required": False, "restart": False},
    {"key": "M365_ANALYTICS_ENABLED", "label": "Microsoft 365 Analytics", "group": "SOC Sources", "type": "boolean", "required": False, "restart": False},
    {"key": "M365_TENANT_ID", "label": "M365 Tenant ID", "group": "SOC Sources", "type": "text", "required": False, "restart": True},
    {"key": "M365_CLIENT_ID", "label": "M365 Client ID", "group": "SOC Sources", "type": "text", "required": False, "restart": True},
    {"key": "M365_CLIENT_SECRET", "label": "M365 Client Secret", "group": "SOC Sources", "type": "secret", "required": False, "restart": True},
    {"key": "M365_CONTENT_TYPES", "label": "M365 Content Types", "group": "SOC Sources", "type": "text", "required": False, "restart": True},
    {"key": "CROWDSEC_WATCHLIST_IPS", "label": "CrowdSec Watchlist IPs", "group": "SOC Sources", "type": "csv_ips", "required": False, "restart": False},
    {"key": "WAZUH_INDEXER_URL", "label": "Wazuh Indexer URL", "group": "Wazuh Indexer", "type": "url", "required": True, "restart": False},
    {"key": "WAZUH_INDEXER_USER", "label": "Wazuh Indexer User", "group": "Wazuh Indexer", "type": "text", "required": True, "restart": False},
    {"key": "WAZUH_INDEXER_PASSWORD", "label": "Wazuh Indexer Password", "group": "Wazuh Indexer", "type": "secret", "required": True, "restart": False},
    {"key": "DOCKER_DATA_ROOT", "label": "Docker Data Root", "group": "Storage", "type": "path", "required": False, "restart": True},
    {"key": "WAZUH_INDEXER_VOLUME", "label": "Indexer Volume", "group": "Storage", "type": "path", "required": False, "restart": True},
    {"key": "WAZUH_LOGS_VOLUME", "label": "Wazuh Logs Volume", "group": "Storage", "type": "path", "required": False, "restart": True},
    {"key": "SOC_OVERVIEW_CACHE_TTL_SECONDS", "label": "Dashboard cache TTL (seconds)", "group": "Runtime", "type": "integer", "required": False, "restart": False},
    {"key": "SOC_OVERVIEW_HISTORY_RETENTION_DAYS", "label": "Historical dashboard retention (days)", "group": "Runtime", "type": "integer", "required": False, "restart": False},
    {"key": "SOC_CMDB_FILE", "label": "Asset CMDB JSON file", "group": "Asset Intelligence", "type": "path", "required": False, "restart": True},
    {"key": "WAZUH_DOCKER_NETWORK", "label": "Docker Network", "group": "Runtime", "type": "text", "required": True, "restart": True},
]
CONFIG_SCHEMA.extend(soc_automation.SCHEMA)


def _bool_text(value: Any) -> str:
    return "true" if str(value).lower() in {"1", "true", "yes", "on", "enabled"} or value is True else "false"


def _public_ip_list(value: str, limit: int = 25) -> list[str]:
    ips: list[str] = []
    for item in [part.strip() for part in str(value or "").split(",") if part.strip()]:
        try:
            parsed_ip = ipaddress.ip_address(item)
        except ValueError:
            continue
        if parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_multicast or parsed_ip.is_reserved:
            continue
        if item not in ips:
            ips.append(item)
        if len(ips) >= limit:
            break
    return ips


ASSET_CONTEXT_FIELDS = ("owner", "criticality", "environment", "network_zone", "vendor", "version", "cpe")
ASSET_IDENTIFIER_FIELDS = ("id", "agent_id", "name", "host", "hostname", "fqdn", "ip", "address")


def _asset_identifier(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")[:256]


def _asset_identifiers(asset: dict[str, Any]) -> set[str]:
    return _normalized_asset_identifiers(asset)


def _normalize_cmdb_asset(asset: Any) -> dict[str, Any] | None:
    normalized = _normalize_cmdb_record(asset)
    if not normalized or not _asset_identifiers(normalized):
        return None
    return normalized


def _load_cmdb_assets() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read a bounded local CMDB and retain the last valid snapshot on parse errors."""
    path = Path(SOC_CMDB_FILE)
    path_key = str(path)
    try:
        stat = path.stat()
        if stat.st_size > CMDB_MAX_BYTES:
            raise ValueError(f"CMDB exceeds {CMDB_MAX_BYTES // (1024 * 1024)} MiB limit")
    except (OSError, ValueError) as exc:
        with _cmdb_lock:
            previous = list(_cmdb_cache["assets"]) if _cmdb_cache.get("path") == path_key else []
        return previous, {
            "configured": bool(path_key), "available": bool(previous), "file": path.name,
            "assets": len(previous), "cached": bool(previous), "error": str(exc)[:300],
        }
    with _cmdb_lock:
        if (_cmdb_cache.get("path") == path_key and _cmdb_cache.get("mtime_ns") == stat.st_mtime_ns
                and _cmdb_cache.get("size") == stat.st_size):
            assets = list(_cmdb_cache["assets"])
            return assets, {
                "configured": True, "available": True, "file": path.name, "assets": len(assets),
                "cached": True, "loaded_at": _cmdb_cache.get("loaded_at"), "error": _cmdb_cache.get("error"),
            }
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                raw = raw.get("assets")
            if not isinstance(raw, list):
                raise ValueError("CMDB root must be a JSON array or an object containing assets[]")
            assets = [row for row in (_normalize_cmdb_asset(item) for item in raw[:CMDB_MAX_ASSETS]) if row]
            loaded_at = datetime.now(timezone.utc).isoformat()
            _cmdb_cache.update({
                "path": path_key, "mtime_ns": stat.st_mtime_ns, "size": stat.st_size,
                "assets": assets, "loaded_at": loaded_at, "error": None,
            })
            return list(assets), {
                "configured": True, "available": True, "file": path.name, "assets": len(assets),
                "cached": False, "loaded_at": loaded_at, "error": None,
            }
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            previous = list(_cmdb_cache["assets"]) if _cmdb_cache.get("path") == path_key else []
            _cmdb_cache["error"] = str(exc)[:300]
            return previous, {
                "configured": True, "available": bool(previous), "file": path.name,
                "assets": len(previous), "cached": bool(previous), "error": str(exc)[:300],
            }


def _asset_context(agent_items: list[dict[str, Any]], limit: int = 200) -> dict[str, Any]:
    cmdb_assets, status = _load_cmdb_assets()
    cmdb_index: dict[str, dict[str, Any]] = {}
    for asset in cmdb_assets:
        for identifier in _asset_identifiers(asset):
            cmdb_index.setdefault(identifier, asset)

    rows: list[dict[str, Any]] = []
    matched_cmdb: set[int] = set()
    matched_agents = 0
    for agent in agent_items[:limit]:
        if not isinstance(agent, dict):
            continue
        labels = agent.get("labels") if isinstance(agent.get("labels"), dict) else {}
        identifiers = _asset_identifiers({
            "id": agent.get("id"), "name": agent.get("name"), "host": agent.get("hostname"),
            "ip": agent.get("ip"), "aliases": [labels.get("hostname"), labels.get("fqdn")],
        })
        cmdb = next((cmdb_index[value] for value in identifiers if value in cmdb_index), None)
        if cmdb:
            matched_cmdb.add(id(cmdb))
            matched_agents += 1
        row: dict[str, Any] = {
            "id": agent.get("id"), "name": agent.get("name") or (cmdb or {}).get("name"),
            "ip": agent.get("ip") or (cmdb or {}).get("ip"), "managed": True,
            "source": "Wazuh + CMDB" if cmdb else "Wazuh",
        }
        for field in ASSET_CONTEXT_FIELDS:
            row[field] = agent.get(field) or labels.get(field) or (cmdb or {}).get(field)
        row["purpose"] = (cmdb or {}).get("purpose")
        row["application"] = (cmdb or {}).get("application")
        row["internet_exposed"] = (cmdb or {}).get("internet_exposed")
        row["patch_state"] = (cmdb or {}).get("patch_state") or "unknown"
        row["last_verified"] = (cmdb or {}).get("last_verified")
        row["cpe_status"] = (cmdb or {}).get("cpe_status") or "missing"
        row["cpe_reason"] = (cmdb or {}).get("cpe_reason")
        row["components"] = (cmdb or {}).get("components") or []
        rows.append(row)

    for asset in cmdb_assets:
        if len(rows) >= limit or id(asset) in matched_cmdb:
            continue
        rows.append({
            "id": asset.get("id") or asset.get("agent_id"),
            "name": asset.get("name") or asset.get("host") or asset.get("hostname") or asset.get("ip"),
            "ip": asset.get("ip"), "managed": False, "source": "CMDB",
            "purpose": asset.get("purpose"),
            "application": asset.get("application"), "internet_exposed": asset.get("internet_exposed"),
            "patch_state": asset.get("patch_state") or "unknown", "last_verified": asset.get("last_verified"),
            "cpe_status": asset.get("cpe_status") or "missing", "cpe_reason": asset.get("cpe_reason"),
            "components": asset.get("components") or [],
            **{field: asset.get(field) for field in ASSET_CONTEXT_FIELDS},
        })

    coverage = {field: sum(1 for row in rows if row.get(field)) for field in ASSET_CONTEXT_FIELDS}
    coverage.update({
        "valid_cpe": sum(1 for row in rows if row.get("cpe_status") == "valid"),
        "invalid_cpe": sum(1 for row in rows if row.get("cpe_status") == "invalid"),
        "components": sum(1 for row in rows if row.get("components")),
        "patch_state": sum(1 for row in rows if row.get("patch_state") not in {None, "unknown"}),
        "last_verified": sum(1 for row in rows if row.get("last_verified")),
    })
    status.update({
        "matched_agents": matched_agents,
        "unmatched_agents": max(0, len(agent_items) - matched_agents),
        "unmanaged_assets": sum(1 for row in rows if not row.get("managed")),
        "displayed_assets": len(rows),
    })
    return {"rows": rows, "coverage": coverage, "status": status}


def _finding_asset_context(finding: dict[str, Any], limit: int = 12) -> list[dict[str, Any]]:
    """Attach local CMDB evidence to a finding without any network or Wazuh request."""
    assets, _ = _load_cmdb_assets()
    if not assets:
        return []
    index: dict[str, dict[str, Any]] = {}
    for asset in assets:
        for identifier in _asset_identifiers(asset):
            index.setdefault(identifier, asset)
    candidates: list[Any] = []
    for field in ("assets", "affected_assets"):
        values = finding.get(field) or []
        if not isinstance(values, list):
            values = [values]
        for value in values[:20]:
            if isinstance(value, dict):
                candidates.extend(value.get(key) for key in ("asset", "name", "id", "host", "ip"))
            else:
                candidates.append(value)
    raw = finding.get("raw") if isinstance(finding.get("raw"), dict) else {}
    agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
    candidates.extend((finding.get("subject"), agent.get("id"), agent.get("name"), agent.get("ip")))

    matches: list[dict[str, Any]] = []
    seen: set[int] = set()
    for candidate in candidates:
        asset = index.get(_asset_identifier(candidate))
        if not asset or id(asset) in seen:
            continue
        seen.add(id(asset))
        matches.append({
            "asset": asset.get("name") or asset.get("host") or asset.get("ip"),
            "host": asset.get("host") or asset.get("hostname"),
            "ip": asset.get("ip"),
            **{field: asset.get(field) for field in ASSET_CONTEXT_FIELDS},
            "purpose": asset.get("purpose"), "application": asset.get("application"),
            "internet_exposed": asset.get("internet_exposed"), "patch_state": asset.get("patch_state"),
            "last_verified": asset.get("last_verified"), "cpe_status": asset.get("cpe_status"),
            "cpe_reason": asset.get("cpe_reason"), "components": asset.get("components") or [],
            "evidence": "Matched from local CMDB",
        })
        if len(matches) >= limit:
            break
    return matches


def _enrich_finding_asset_context(finding: dict[str, Any]) -> dict[str, Any]:
    if "asset_context" not in finding:
        context = _finding_asset_context(finding)
        if context:
            finding["asset_context"] = context
    return finding


def _parse_env_file(path: Path = CONFIG_FILE) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        values[key] = value
    return values


def _runtime_config_values() -> dict[str, str]:
    return {
        **_automation_values,
        "DASHBOARD_HOST": HOST,
        "DASHBOARD_PORT": str(PORT),
        "DASHBOARD_HOST_PORT": os.environ.get("DASHBOARD_HOST_PORT", "8088"),
        "GENSECAI_MCP_URL": GENSECAI_MCP_URL,
        "GENSECAI_API_KEY": GENSECAI_API_KEY,
        "INFOKOM_MCP_URL": INFOKOM_MCP_URL,
        "INFOKOM_API_KEY": INFOKOM_API_KEY,
        "AI_ANALYST_ENABLED": _bool_text(AI_ANALYST_ENABLED),
        "AI_AUTO_ANALYZE": _bool_text(AI_AUTO_ANALYZE),
        "AI_PROVIDER_BASE_URL": AI_PROVIDER_BASE_URL,
        "AI_MODEL": AI_MODEL,
        "AI_API_KEY": AI_API_KEY,
        "DOCKER_ANALYTICS_ENABLED": _bool_text(DOCKER_ANALYTICS_ENABLED),
        "M365_ANALYTICS_ENABLED": _bool_text(M365_ANALYTICS_ENABLED),
        "M365_TENANT_ID": M365_TENANT_ID,
        "M365_CLIENT_ID": M365_CLIENT_ID,
        "M365_CLIENT_SECRET": M365_CLIENT_SECRET,
        "M365_CONTENT_TYPES": M365_CONTENT_TYPES,
        "CROWDSEC_WATCHLIST_IPS": CROWDSEC_WATCHLIST_IPS,
        "WAZUH_INDEXER_URL": WAZUH_INDEXER_URL,
        "WAZUH_INDEXER_USER": WAZUH_INDEXER_USER,
        "WAZUH_INDEXER_PASSWORD": WAZUH_INDEXER_PASSWORD,
        "DOCKER_DATA_ROOT": DOCKER_DATA_ROOT,
        "WAZUH_INDEXER_VOLUME": WAZUH_INDEXER_VOLUME,
        "WAZUH_LOGS_VOLUME": WAZUH_LOGS_VOLUME,
        "WAZUH_DOCKER_NETWORK": WAZUH_DOCKER_NETWORK,
        "SOC_OVERVIEW_CACHE_TTL_SECONDS": str(OVERVIEW_CACHE_TTL_SECONDS),
        "SOC_OVERVIEW_HISTORY_RETENTION_DAYS": str(OVERVIEW_HISTORY_RETENTION_DAYS),
        "SOC_CMDB_FILE": str(SOC_CMDB_FILE),
    }


def _public_config() -> dict[str, Any]:
    values = _runtime_config_values()
    fields = []
    for spec in CONFIG_SCHEMA:
        key = spec["key"]
        value = values.get(key, "")
        field = dict(spec)
        field["configured"] = bool(value)
        if key == 'AI_PROVIDER_BASE_URL':
            # Gateways may embed credentials in the URL path, not only userinfo.
            field['type'] = 'secret'
        field["value"] = "" if field["type"] == "secret" else value
        fields.append(field)
    return {
        "enabled": SETTINGS_WRITE_ENABLED,
        "config_file": str(CONFIG_FILE),
        "writable": os.access(CONFIG_FILE, os.W_OK) if CONFIG_FILE.exists() else os.access(CONFIG_FILE.parent, os.W_OK),
        "fields": fields,
    }


def _validate_config_update(update: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    errors: list[str] = []
    cleaned: dict[str, str] = {}
    schema_by_key = {item["key"]: item for item in CONFIG_SCHEMA}
    current = _runtime_config_values()
    for key, raw_value in update.items():
        if key not in schema_by_key:
            errors.append(f"{key}: unsupported setting")
            continue
        spec = schema_by_key[key]
        value = str(raw_value).strip() if raw_value is not None else ""
        if "\n" in value or "\r" in value:
            errors.append(f"{key}: line breaks are not allowed")
            continue
        if (spec["type"] == "secret" or key == 'AI_PROVIDER_BASE_URL') and value in {"", "********", "configured"}:
            continue
        if spec["type"] == "boolean":
            value = _bool_text(value)
        if spec["type"] == "integer" and value:
            try:
                parsed = int(value)
                if parsed < 0:
                    raise ValueError()
                value = str(parsed)
            except ValueError:
                errors.append(f"{key}: expected a non-negative integer")
        if spec.get("required") and not value:
            errors.append(f"{key}: required")
        if spec["type"] in {"url", "url_optional"} and value:
            if not re.match(r"^https?://[A-Za-z0-9_.:/?&=%+#@~-]+$", value):
                errors.append(f"{key}: must be http(s) URL")
        if spec["type"] == "path" and value and not value.startswith("/"):
            errors.append(f"{key}: must be absolute path")
        if spec["type"] == "csv_ips" and value:
            for ip in [item.strip() for item in value.split(",") if item.strip()]:
                try:
                    parsed_ip = ipaddress.ip_address(ip)
                except ValueError:
                    errors.append(f"{key}: invalid IP {ip}")
                    continue
                if parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_multicast or parsed_ip.is_reserved:
                    errors.append(f"{key}: {ip} must be a public IP")
        if key.endswith("_ENABLED") and value not in {"true", "false"}:
            errors.append(f"{key}: must be true or false")
        cleaned[key] = value
    desired_ai_enabled = cleaned.get("AI_ANALYST_ENABLED", current.get("AI_ANALYST_ENABLED", "false")) == "true"
    desired_provider = cleaned.get("AI_PROVIDER_BASE_URL", current.get("AI_PROVIDER_BASE_URL", ""))
    desired_model = cleaned.get("AI_MODEL", current.get("AI_MODEL", ""))
    if desired_ai_enabled and (not desired_provider or not desired_model):
        errors.append("AI_ANALYST_ENABLED: AI_PROVIDER_BASE_URL and AI_MODEL are required")
    errors.extend(soc_automation.validate({**current, **cleaned}))
    return cleaned, errors


def _serialize_env(values: dict[str, str]) -> str:
    order = [
        "DASHBOARD_HOST", "DASHBOARD_PORT", "DASHBOARD_HOST_PORT",
        "GENSECAI_MCP_URL", "GENSECAI_API_KEY",
        "INFOKOM_MCP_URL", "INFOKOM_API_KEY",
        "AI_ANALYST_ENABLED", "AI_AUTO_ANALYZE", "AI_PROVIDER_BASE_URL", "AI_MODEL", "AI_API_KEY",
        "DOCKER_ANALYTICS_ENABLED", "M365_ANALYTICS_ENABLED", "M365_TENANT_ID", "M365_CLIENT_ID",
        "M365_CLIENT_SECRET", "M365_CONTENT_TYPES", "CROWDSEC_WATCHLIST_IPS",
        "WAZUH_INDEXER_URL", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD",
        "DOCKER_DATA_ROOT", "WAZUH_INDEXER_VOLUME", "WAZUH_LOGS_VOLUME", "WAZUH_DOCKER_NETWORK",
        "SOC_OVERVIEW_CACHE_TTL_SECONDS", "SOC_OVERVIEW_HISTORY_RETENTION_DAYS",
        "SOC_CMDB_FILE",
    ]
    lines = []
    for key in dict.fromkeys(order + list(soc_automation.DEFAULTS) + list(values)):
        if key not in values:
            continue
        value = str(values.get(key, ""))
        if "\n" in value:
            value = value.replace("\n", " ")
        lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


def _apply_runtime_config(values: dict[str, str]) -> None:
    _automation_values.update({key: values[key] for key in soc_automation.DEFAULTS if key in values})
    global GENSECAI_MCP_URL, GENSECAI_API_KEY, INFOKOM_MCP_URL, INFOKOM_API_KEY
    global AI_ANALYST_ENABLED, AI_PROVIDER_BASE_URL, AI_MODEL, AI_AUTO_ANALYZE, AI_API_KEY
    global DOCKER_ANALYTICS_ENABLED, M365_ANALYTICS_ENABLED, M365_TENANT_ID, M365_CLIENT_ID
    global M365_CLIENT_SECRET, M365_CONTENT_TYPES, DOCKER_DATA_ROOT, WAZUH_INDEXER_VOLUME
    global WAZUH_LOGS_VOLUME, WAZUH_DOCKER_NETWORK, WAZUH_INDEXER_URL, WAZUH_INDEXER_USER
    global WAZUH_INDEXER_PASSWORD, CROWDSEC_WATCHLIST_IPS, _gensecai_token, _gensecai_token_expires_at
    global OVERVIEW_CACHE_TTL_SECONDS, OVERVIEW_HISTORY_RETENTION_DAYS, SOC_CMDB_FILE
    GENSECAI_MCP_URL = values.get("GENSECAI_MCP_URL", GENSECAI_MCP_URL).rstrip("/")
    GENSECAI_API_KEY = values.get("GENSECAI_API_KEY", GENSECAI_API_KEY)
    INFOKOM_MCP_URL = values.get("INFOKOM_MCP_URL", INFOKOM_MCP_URL).rstrip("/")
    INFOKOM_API_KEY = values.get("INFOKOM_API_KEY", INFOKOM_API_KEY)
    AI_ANALYST_ENABLED = values.get("AI_ANALYST_ENABLED", _bool_text(AI_ANALYST_ENABLED)).lower() == "true"
    AI_AUTO_ANALYZE = values.get("AI_AUTO_ANALYZE", _bool_text(AI_AUTO_ANALYZE)).lower() == "true"
    AI_PROVIDER_BASE_URL = values.get("AI_PROVIDER_BASE_URL", AI_PROVIDER_BASE_URL).rstrip("/")
    AI_MODEL = values.get("AI_MODEL", AI_MODEL)
    AI_API_KEY = values.get("AI_API_KEY", AI_API_KEY)
    DOCKER_ANALYTICS_ENABLED = values.get("DOCKER_ANALYTICS_ENABLED", _bool_text(DOCKER_ANALYTICS_ENABLED)).lower() == "true"
    M365_ANALYTICS_ENABLED = values.get("M365_ANALYTICS_ENABLED", _bool_text(M365_ANALYTICS_ENABLED)).lower() == "true"
    M365_TENANT_ID = values.get("M365_TENANT_ID", M365_TENANT_ID)
    M365_CLIENT_ID = values.get("M365_CLIENT_ID", M365_CLIENT_ID)
    M365_CLIENT_SECRET = values.get("M365_CLIENT_SECRET", M365_CLIENT_SECRET)
    M365_CONTENT_TYPES = values.get("M365_CONTENT_TYPES", M365_CONTENT_TYPES)
    CROWDSEC_WATCHLIST_IPS = values.get("CROWDSEC_WATCHLIST_IPS", CROWDSEC_WATCHLIST_IPS)
    WAZUH_INDEXER_URL = values.get("WAZUH_INDEXER_URL", WAZUH_INDEXER_URL).rstrip("/")
    WAZUH_INDEXER_USER = values.get("WAZUH_INDEXER_USER", WAZUH_INDEXER_USER)
    WAZUH_INDEXER_PASSWORD = values.get("WAZUH_INDEXER_PASSWORD", WAZUH_INDEXER_PASSWORD)
    DOCKER_DATA_ROOT = values.get("DOCKER_DATA_ROOT", DOCKER_DATA_ROOT)
    WAZUH_INDEXER_VOLUME = values.get("WAZUH_INDEXER_VOLUME", WAZUH_INDEXER_VOLUME)
    WAZUH_LOGS_VOLUME = values.get("WAZUH_LOGS_VOLUME", WAZUH_LOGS_VOLUME)
    WAZUH_DOCKER_NETWORK = values.get("WAZUH_DOCKER_NETWORK", WAZUH_DOCKER_NETWORK)
    SOC_CMDB_FILE = Path(values.get("SOC_CMDB_FILE", str(SOC_CMDB_FILE)))
    try:
        OVERVIEW_CACHE_TTL_SECONDS = max(0, int(values.get("SOC_OVERVIEW_CACHE_TTL_SECONDS", OVERVIEW_CACHE_TTL_SECONDS)))
    except (TypeError, ValueError):
        pass
    try:
        OVERVIEW_HISTORY_RETENTION_DAYS = max(1, int(values.get("SOC_OVERVIEW_HISTORY_RETENTION_DAYS", OVERVIEW_HISTORY_RETENTION_DAYS)))
    except (TypeError, ValueError):
        pass
    _gensecai_token = ""
    _gensecai_token_expires_at = 0.0
    _tools_cache.update({"expires_at": 0.0, "tools": [], "errors": {}})
    with _infokom_session_lock:
        _infokom_session.update(expires=0, id=None)


def _save_config(update: dict[str, Any]) -> dict[str, Any]:
    if not SETTINGS_WRITE_ENABLED:
        raise RuntimeError("Settings write is disabled")
    cleaned, errors = _validate_config_update(update)
    if errors:
        return {"ok": False, "errors": errors, "settings": _settings()}
    values = _runtime_config_values()
    values.update(_parse_env_file())
    values.update(cleaned)
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(_serialize_env(values), encoding="utf-8")
    _apply_runtime_config(values)
    restart_required = sorted({
        spec["key"]
        for spec in CONFIG_SCHEMA
        if spec.get("restart") and spec["key"] in cleaned
    })
    return {"ok": True, "restart_required": restart_required, "settings": _settings()}


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    try:
        segment = token.split(".")[1]
        segment += "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(segment.encode("utf-8")).decode("utf-8"))
    except Exception:
        return {}


def _m365_token() -> tuple[str | None, dict[str, Any]]:
    token_payload = _http_form(
        f"https://login.microsoftonline.com/{M365_TENANT_ID}/oauth2/v2.0/token",
        {
            "client_id": M365_CLIENT_ID,
            "client_secret": M365_CLIENT_SECRET,
            "scope": "https://manage.office.com/.default",
            "grant_type": "client_credentials",
        },
    )
    token = token_payload.get("access_token")
    claims = _decode_jwt_claims(token or "")
    return token, {
        "ok": bool(token),
        "audience": claims.get("aud"),
        "app_id": claims.get("appid") or claims.get("azp"),
        "roles": claims.get("roles", []) or [],
        "expires_in": token_payload.get("expires_in"),
    }


def _m365_test(hours: int = 24) -> dict[str, Any]:
    if not M365_TENANT_ID or not M365_CLIENT_ID or not M365_CLIENT_SECRET:
        return {"ok": False, "error": "M365 tenant/client/secret belum lengkap"}
    result: dict[str, Any] = {"ok": False, "token": {}, "subscriptions": {}, "content": {}}
    try:
        token, token_status = _m365_token()
        result["token"] = token_status
        if not token:
            result["error"] = "Microsoft token response tidak berisi access_token"
            return result
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        base = f"https://manage.office.com/api/v1.0/{M365_TENANT_ID}/activity/feed"
        try:
            subscriptions = _http_get_json(f"{base}/subscriptions/list", headers)
            result["subscriptions"] = {
                "ok": True,
                "count": len(subscriptions) if isinstance(subscriptions, list) else 0,
                "items": subscriptions if isinstance(subscriptions, list) else [],
            }
        except urllib.error.HTTPError as exc:
            result["subscriptions"] = {
                "ok": False,
                "status": exc.code,
                "reason": exc.reason,
                "body": exc.read().decode("utf-8", errors="replace")[:800],
            }
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=max(1, min(int(hours or 24), 168)))).strftime("%Y-%m-%dT%H:%M:%S")
        end = now.strftime("%Y-%m-%dT%H:%M:%S")
        for content_type in [item.strip() for item in M365_CONTENT_TYPES.split(",") if item.strip()]:
            try:
                url = (
                    f"{base}/subscriptions/content"
                    f"?contentType={urllib.parse.quote(content_type)}&startTime={start}&endTime={end}"
                )
                rows = _http_get_json(url, headers)
                result["content"][content_type] = {
                    "ok": True,
                    "count": len(rows) if isinstance(rows, list) else 0,
                    "sample_keys": sorted((rows[0] if rows else {}).keys()) if isinstance(rows, list) and rows else [],
                }
            except urllib.error.HTTPError as exc:
                result["content"][content_type] = {
                    "ok": False,
                    "status": exc.code,
                    "reason": exc.reason,
                    "body": exc.read().decode("utf-8", errors="replace")[:500],
                }
        result["ok"] = bool(result["token"].get("ok")) and bool(result["subscriptions"].get("ok"))
        return result
    except urllib.error.HTTPError as exc:
        result["token"] = {
            "ok": False,
            "status": exc.code,
            "reason": exc.reason,
            "body": exc.read().decode("utf-8", errors="replace")[:800],
        }
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


def _m365_start_subscriptions() -> dict[str, Any]:
    if not M365_TENANT_ID or not M365_CLIENT_ID or not M365_CLIENT_SECRET:
        return {"ok": False, "error": "M365 tenant/client/secret belum lengkap", "started": {}}
    result: dict[str, Any] = {"ok": False, "token": {}, "started": {}, "test": {}}
    try:
        token, token_status = _m365_token()
        result["token"] = token_status
        if not token:
            result["error"] = "Microsoft token response tidak berisi access_token"
            return result
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        base = f"https://manage.office.com/api/v1.0/{M365_TENANT_ID}/activity/feed"
        for content_type in [item.strip() for item in M365_CONTENT_TYPES.split(",") if item.strip()]:
            try:
                url = f"{base}/subscriptions/start?contentType={urllib.parse.quote(content_type)}"
                row = _http_post_json(url, {}, headers)
                result["started"][content_type] = {"ok": True, "response": row}
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")[:800]
                already_enabled = exc.code == 400 and "AF20024" in body
                result["started"][content_type] = {
                    "ok": already_enabled,
                    "already_enabled": already_enabled,
                    "status": exc.code,
                    "reason": exc.reason,
                    "body": body,
                }
        result["ok"] = all(row.get("ok") for row in result["started"].values()) if result["started"] else False
        result["test"] = _m365_test(24)
        return result
    except urllib.error.HTTPError as exc:
        result["token"] = {
            "ok": False,
            "status": exc.code,
            "reason": exc.reason,
            "body": exc.read().decode("utf-8", errors="replace")[:800],
        }
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


TOOL_PRESETS: dict[str, dict[str, Any]] = {
    "advanced_three_sum_correlation": {"lookback_minutes": 60, "threshold_score": 35},
    "get_top_security_threats": {"time_range": "24h", "limit": 10},
    "get_wazuh_alert_summary": {"time_range": "24h", "group_by": "rule.level"},
    "crowdsec_ip_reputation": {"ip": "8.8.8.8", "response_format": "json"},
    "crowdsec_ip_reputation_bulk": {"ips": ["8.8.8.8"], "response_format": "json"},
    "greynoise_ip_context": {"ip": "8.8.8.8", "response_format": "json"},
    "threatfox_ioc_search": {"search_term": "8.8.8.8", "exact_match": False, "response_format": "json"},
    "threatfox_ioc_search_bulk": {"search_terms": ["8.8.8.8"], "exact_match": False, "response_format": "json"},
    "otx_lookup": {"indicator": "8.8.8.8", "section": "general", "response_format": "json"},
    "otx_lookup_bulk": {"indicators": ["8.8.8.8"], "section": "general", "response_format": "json"},
    "cyfirma_ioc_feed": {"scope": "tailored", "limit": 25, "response_format": "json"},
    "cyfirma_ioc_lookup": {"indicator": "8.8.8.8", "scope": "both", "limit": 25, "response_format": "json"},
    "blueteam_lookup_domain_virustotal": {"domain": "example.com", "response_format": "json"},
    "blueteam_lookup_hash_virustotal": {"hash": "44d88612fea8a8f36de82e1278abb02f", "response_format": "json"},
    "blueteam_unified_threat_score": {"ip": "8.8.8.8", "response_format": "json"},
    "blueteam_threat_intel_aggregate": {"indicator": "8.8.8.8", "response_format": "json"},
    "urlhaus_lookup": {"url": "http://example.com/", "response_format": "json"},
    "urlhaus_hash_lookup": {"file_hash": "44d88612fea8a8f36de82e1278abb02f", "response_format": "json"},
    "blueteam_ai_bot_recon": {"since": "24h", "top_n": 10, "response_format": "json"},
    "blueteam_wazuh_geo_heatmap": {"since": "24h", "top_n": 30, "response_format": "json"},
    "blueteam_wazuh_syscheck": {"since": "24h", "top_n": 20, "response_format": "json"},
    "blueteam_failed_logins": {"bypass_redaction": False},
    "blueteam_read_auth_log": {"lines": 200, "grep": "failed|invalid|authentication|sudo|pam|sshd", "bypass_redaction": False},
    "blueteam_read_web_log": {
        "server": "nginx",
        "log_type": "access",
        "lines": 300,
        "grep": "DVWA|.env|wp-|php|select|union|cmd|shell|passwd",
        "bypass_redaction": False,
    },
    "wazuh_alert_timeline": {"since": "24h", "bucket": "auto", "response_format": "json"},
    "wazuh_alert_aggregate_analysis": {"since": "24h", "response_format": "json"},
    "three_sum_correlation": {"since": "24h", "threshold_score": 35, "response_format": "json"},
    "blueteam_cve_lookup": {"cve_id": "CVE-2024-6387", "response_format": "json"},
    "blueteam_cve_epss": {"cve_ids": ["CVE-2024-6387"], "response_format": "json"},
    "blueteam_cve_kev": {"cve_id": "CVE-2024-6387", "response_format": "json"},
    "blueteam_cve_poc": {"cve_id": "CVE-2024-6387", "response_format": "json"},
    "blueteam_cve_score": {"cve_id": "CVE-2024-6387", "response_format": "json"},
    "blueteam_cve_ssvc": {"cve_id": "CVE-2024-6387", "response_format": "json"},
    "blueteam_cve_advisory": {"cve_id": "CVE-2024-6387", "response_format": "json"},
    "blueteam_cve_attack_mapping": {"cve_id": "CVE-2024-6387", "response_format": "json"},
    "blueteam_dependency_scan": {"raw_text": "requests==2.28.0\nlog4j-core:2.14.1", "response_format": "json"},
}


def _json_response(handler: SimpleHTTPRequestHandler, status: int, payload: Any) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    if handler.command != 'HEAD':
        handler.wfile.write(body)


def _http_json(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> tuple[dict[str, str], Any]:
    data = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            raw = resp.read().decode("utf-8")
            parsed = _parse_mcp_body(raw)
            return dict(resp.headers.items()), parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{exc.code} {exc.reason}: {raw[:800]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc


def _http_form(url: str, payload: dict[str, Any]) -> Any:
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_get_json(url: str, headers: dict[str, str]) -> Any:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else None


def _http_post_json(url: str, payload: dict[str, Any] | None, headers: dict[str, str]) -> Any:
    data = json.dumps(payload or {}).encode("utf-8")
    req_headers = {"Content-Type": "application/json; charset=utf-8", **headers}
    req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else None


def _parse_mcp_body(raw: str) -> Any:
    data_lines = [line[6:] for line in raw.splitlines() if line.startswith("data: ")]
    if data_lines:
        return json.loads(data_lines[-1])
    return json.loads(raw)


def _indexer_search(payload: dict[str, Any], index: str = "wazuh-alerts-*") -> Any:
    if index not in {"wazuh-alerts-*", "wazuh-states-vulnerabilities-*"}:
        raise ValueError("Unsupported index")
    return _indexer_request(f'/{index}/_search', payload)


def _indexer_request(path, payload, method='POST'):
    if path not in {'/wazuh-alerts-*/_search', '/wazuh-states-vulnerabilities-*/_search', '/wazuh-alerts-*/_search?scroll=2m', '/_search/scroll'}:
        raise ValueError('Unsupported indexer operation')
    if not _indexer_slots.acquire(timeout=INDEXER_ACQUIRE_TIMEOUT_SECONDS):
        raise RuntimeError("Indexer query capacity is busy; retry from cache")
    try:
        req = urllib.request.Request(
            f"{WAZUH_INDEXER_URL}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Basic "
                + base64.b64encode(f"{WAZUH_INDEXER_USER}:{WAZUH_INDEXER_PASSWORD}".encode("utf-8")).decode("ascii"),
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=30, context=ssl._create_unverified_context()) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read(8192).decode("utf-8", errors="replace")
            try:
                detail = json.loads(raw).get("error", raw)
                if isinstance(detail, dict):
                    detail = detail.get("reason") or detail.get("root_cause") or detail.get("type")
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                detail = raw
            message = re.sub(r"\s+", " ", str(detail or exc.reason)).strip()[:600]
            raise RuntimeError(f"OpenSearch HTTP {exc.code}: {message}") from None
    finally:
        _indexer_slots.release()


def _mcp_url(base: str) -> str:
    return base if base.endswith("/mcp") else f"{base}/mcp"


def _gensecai_auth_header() -> dict[str, str]:
    global _gensecai_token, _gensecai_token_expires_at
    if _gensecai_token and time.time() < _gensecai_token_expires_at:
        return {"Authorization": f"Bearer {_gensecai_token}"}
    if not GENSECAI_API_KEY:
        raise RuntimeError("GENSECAI_API_KEY belum diset di dashboard.env")
    _, payload = _http_json(f"{GENSECAI_MCP_URL}/auth/token", {"api_key": GENSECAI_API_KEY})
    token = payload.get("access_token") or payload.get("token")
    if not token:
        raise RuntimeError("GenSecAI /auth/token tidak mengembalikan token")
    _gensecai_token = token
    _gensecai_token_expires_at = time.time() + int(payload.get("expires_in", 3600)) - 60
    return {"Authorization": f"Bearer {_gensecai_token}"}


def _gensecai_rpc(method: str, params: dict[str, Any], req_id: str) -> Any:
    headers = _gensecai_auth_header()
    _, payload = _http_json(
        _mcp_url(GENSECAI_MCP_URL),
        {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
        headers,
    )
    return payload


def _infokom_headers(session_id: str | None = None) -> dict[str, str]:
    if not INFOKOM_API_KEY:
        raise RuntimeError("INFOKOM_API_KEY belum diset di dashboard.env")
    headers = {
        "Authorization": f"Bearer {INFOKOM_API_KEY}",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-06-18",
    }
    if session_id:
        headers["mcp-session-id"] = session_id
    return headers


def _initialize_infokom(req_id: str) -> str | None:
    init_headers, _ = _http_json(
        INFOKOM_MCP_URL,
        {
            "jsonrpc": "2.0",
            "id": f"{req_id}-init",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "wazuh-mcp-dashboard", "version": "1.0"},
            },
        },
        _infokom_headers(),
    )
    session_id = init_headers.get("mcp-session-id") or init_headers.get("Mcp-Session-Id")
    if session_id:
        try:
            _http_json(
                INFOKOM_MCP_URL,
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                _infokom_headers(session_id),
            )
        except Exception:
            pass
    return session_id


def _infokom_rpc(method: str, params: dict[str, Any], req_id: str) -> Any:
    # Reuse the handshake across dashboard calls, including stateless MCP servers.
    with _infokom_session_lock:
        if _infokom_session["expires"] <= time.time():
            _infokom_session.update(id=_initialize_infokom(req_id), expires=time.time() + 600)
        session_id = _infokom_session["id"]
    try:
        _, payload = _http_json(
            INFOKOM_MCP_URL,
            {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
            _infokom_headers(session_id),
        )
    except Exception:
        with _infokom_session_lock:
            _infokom_session["expires"] = 0
        # Never retry an action whose outcome may be unknown.
        raise
    return payload


def _tools_for(source: str) -> list[dict[str, Any]]:
    if source == "gensecai":
        payload = _gensecai_rpc("tools/list", {}, "tools-gensecai")
    else:
        payload = _infokom_rpc("tools/list", {}, "tools-infokom")
    if "error" in payload:
        raise RuntimeError(json.dumps(payload["error"]))
    tools = payload.get("result", {}).get("tools", [])
    for tool in tools:
        tool["source"] = source
    return tools


def _schema_requires_params(tool: dict[str, Any]) -> bool:
    schema = tool.get("inputSchema") or {}
    return "params" in (schema.get("required") or []) or "params" in (schema.get("properties") or {})


def _schema_param_schema(tool: dict[str, Any]) -> dict[str, Any]:
    schema = tool.get("inputSchema") or {}
    properties = schema.get("properties", {})
    param_spec = properties.get("params", {})
    ref = param_spec.get("$ref")
    if ref and ref.startswith("#/$defs/"):
        return schema.get("$defs", {}).get(ref.removeprefix("#/$defs/"), {}) or {}
    return schema


def _schema_param_properties(tool: dict[str, Any]) -> dict[str, Any]:
    return _schema_param_schema(tool).get("properties", {}) or {}


def _schema_param_required(tool: dict[str, Any]) -> list[str]:
    return list(_schema_param_schema(tool).get("required", []) or [])


def _schema_type(spec: dict[str, Any]) -> str:
    if spec.get("type"):
        return str(spec["type"])
    for item in spec.get("anyOf", []) or []:
        if item.get("type") and item.get("type") != "null":
            return str(item["type"])
    return "value"


def _schema_enum(spec: dict[str, Any]) -> list[Any]:
    if spec.get("enum"):
        return list(spec["enum"])
    for item in spec.get("anyOf", []) or []:
        if item.get("enum"):
            return list(item["enum"])
    return []


def _example_for_field(key: str, spec: dict[str, Any]) -> Any:
    key_l = key.lower()
    enum = _schema_enum(spec)
    if enum:
        return enum[0]
    if "default" in spec and spec["default"] is not None:
        return spec["default"]
    field_type = _schema_type(spec)
    if field_type == "integer":
        return spec.get("minimum", 1)
    if field_type == "number":
        return spec.get("minimum", 1)
    if field_type == "boolean":
        return False
    if field_type == "array":
        if "cve" in key_l:
            return ["CVE-2024-6387"]
        if "indicator" in key_l:
            return ["8.8.8.8"]
        if key_l in {"ips", "srcips", "source_ips"}:
            return ["8.8.8.8"]
        if "url" in key_l:
            return ["http://example.com/"]
        return []
    if field_type == "object":
        return {}
    if key_l in {"ip", "srcip", "source_ip"}:
        return "8.8.8.8"
    if "cve" in key_l:
        return "CVE-2024-6387"
    if "email" in key_l:
        return "user@example.com"
    if "url" in key_l:
        return "https://example.com"
    if "hash" in key_l:
        return "44d88612fea8a8f36de82e1278abb02f"
    if "domain" in key_l:
        return "example.com"
    if key_l in {"since", "time_range", "window"}:
        return "24h"
    if "format" in key_l:
        return "json"
    if key_l == "verdict":
        return "suspicious"
    return ""


def _category_for_tool(name: str, description: str = "") -> tuple[str, str]:
    haystack = f"{name} {description}".lower()
    checks = [
        ("Vulnerability", "L2", ("cve", "vulnerab", "epss", "kev", "poc", "ssvc", "dependency", "sbom")),
        ("Threat Intel", "L2", ("ioc", "threatfox", "otx", "greynoise", "crowdsec", "virustotal", "urlhaus", "cyfirma", "reputation")),
        ("Hunting", "L3", ("hunt", "attack_graph", "stix", "campaign", "pivot", "semantic", "timeline", "heatmap", "baseline", "beacon")),
        ("Response", "L2", ("block", "isolate", "quarantine", "kill_process", "firewall", "host_deny", "active_response", "unban")),
        ("Log Collector", "L1", ("auth_log", "syslog", "web_log", "journalctl", "manager_logs", "log_collector")),
        ("Wazuh Alerts", "L1", ("alert", "security_events", "aggregate", "summary", "rule", "syscheck")),
        ("Assets", "L1", ("agent", "process", "ports", "connections", "who_is_logged", "last_logins")),
        ("Compliance", "L3", ("compliance", "iso27001", "sca", "pci", "gdpr", "hipaa", "nist", "cis")),
        ("Case Management", "L2", ("case_", "investigation", "investigated", "verdict", "playbook")),
    ]
    for category, lane, needles in checks:
        if any(needle in haystack for needle in needles):
            return category, lane
    return "Utility", "L2"


def _default_arguments(tool: dict[str, Any]) -> dict[str, Any]:
    name = str(tool.get("name", ""))
    preset = dict(TOOL_PRESETS.get(name, {}))
    required = set(_schema_param_required(tool))
    for key, spec in _schema_param_properties(tool).items():
        if key == "params" or key in preset:
            continue
        if key in required or ("default" in spec and spec["default"] is not None) or _schema_enum(spec):
            preset[key] = _example_for_field(key, spec)
    return preset


def _schema_fields(tool: dict[str, Any]) -> list[dict[str, Any]]:
    required = set(_schema_param_required(tool))
    fields = []
    for key, spec in _schema_param_properties(tool).items():
        if key == "params":
            continue
        fields.append({
            "name": key,
            "type": _schema_type(spec),
            "required": key in required,
            "default": spec.get("default"),
            "enum": _schema_enum(spec),
            "description": spec.get("description", ""),
        })
    return fields


def _enrich_tool(tool: dict[str, Any]) -> dict[str, Any]:
    name = str(tool.get("name", ""))
    description = str(tool.get("description", "") or "")
    category, lane = _category_for_tool(name, description)
    enriched = dict(tool)
    enriched["category"] = category
    enriched["lane"] = lane
    enriched["requires_params"] = _schema_requires_params(tool)
    enriched["default_arguments"] = _default_arguments(tool)
    enriched["required_fields"] = _schema_param_required(tool)
    enriched["schema_fields"] = _schema_fields(tool)
    enriched["workflow"] = soc_workflows.policy(tool)
    dashboard_tools = {
        "get_wazuh_alert_summary", "get_top_security_threats", "get_wazuh_agents",
        "advanced_three_sum_correlation", "get_wazuh_vulnerability_summary",
        "get_wazuh_critical_vulnerabilities", "get_wazuh_statistics",
        "blueteam_ai_bot_recon", "wazuh_alert_timeline", "blueteam_wazuh_geo_heatmap",
        "blueteam_wazuh_syscheck", "blueteam_failed_logins", "blueteam_read_web_log",
        "blueteam_case_list",
    }
    provider_terms = ("crowdsec", "greynoise", "threatfox", "otx", "virustotal", "urlhaus", "abuseipdb", "cyfirma", "nvd", "epss", "kev")
    enriched["operational_mode"] = "dashboard" if name in dashboard_tools else "menu_workflow"
    enriched["readiness"] = "catalog_ready"
    enriched["readiness_note"] = (
        "Discovered and used automatically by a cached dashboard workflow."
        if name in dashboard_tools else
        f"Mapped to {enriched['workflow']['menu']}; execution is not triggered during page load."
    )
    if any(term in name.lower() for term in provider_terms):
        enriched["dependency"] = "external_provider"
        enriched["readiness_note"] += " Provider quota and credentials are validated only when invoked."
    else:
        enriched["dependency"] = "wazuh" if tool.get("source") == "gensecai" else "local_or_wazuh"
    return enriched


def _tools_response() -> dict[str, Any]:
    catalog = _tool_catalog()
    tools = [_enrich_tool(tool) for tool in catalog["tools"]]
    categories: dict[str, int] = {}
    lanes: dict[str, int] = {}
    for tool in tools:
        categories[tool["category"]] = categories.get(tool["category"], 0) + 1
        lanes[tool["lane"]] = lanes.get(tool["lane"], 0) + 1
    summary = {
        "discovered": len(tools),
        "dashboard": sum(1 for tool in tools if tool["operational_mode"] == "dashboard"),
        "workflow": sum(1 for tool in tools if tool["operational_mode"] == "menu_workflow"),
        "on_demand": sum(1 for tool in tools if tool["operational_mode"] == "on_demand"),
        "gensecai": sum(1 for tool in tools if tool.get("source") == "gensecai"),
        "infokom": sum(1 for tool in tools if tool.get("source") == "infokom"),
        "catalog_errors": len(catalog["errors"]),
        "menu_mapped": sum(1 for tool in tools if tool["workflow"]["mapped"]),
        "guided_findings": sum(1 for tool in tools if "findings" in tool["workflow"].get("surfaces", [])),
        "cached_read": sum(1 for tool in tools if tool["workflow"]["mode"] == "cached_read"),
        "approval_required": sum(1 for tool in tools if tool["workflow"]["mode"] == "approval"),
    }
    return {"tools": tools, "errors": catalog["errors"], "categories": categories, "lanes": lanes, "summary": summary}


def _tool_by_name(source: str, name: str) -> dict[str, Any] | None:
    for tool in _tool_catalog()["tools"]:
        if tool.get("source") == source and tool.get("name") == name:
            return tool
    return None


def _resolve_tool_source(name: str) -> tuple[str | None, list[str]]:
    matches = [str(tool.get("source")) for tool in _tool_catalog()["tools"] if tool.get("name") == name]
    seen: list[str] = []
    for source in matches:
        if source and source not in seen:
            seen.append(source)
    if not seen:
        return None, []
    if len(seen) == 1:
        return seen[0], seen
    for preferred in ("infokom", "gensecai"):
        if preferred in seen:
            return preferred, seen
    return seen[0], seen


def _call_tool(source: str, name: str, arguments: dict[str, Any]) -> Any:
    tool = _tool_by_name(source, name)
    if source == "infokom" and tool and _schema_requires_params(tool) and "params" not in arguments:
        arguments = {"params": arguments}
    params = {"name": name, "arguments": arguments}
    if source == "gensecai":
        return _gensecai_rpc("tools/call", params, f"call-{int(time.time())}")
    return _infokom_rpc("tools/call", params, f"call-{int(time.time())}")


def _normalized_call(source: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    started = time.time()
    tool = _tool_by_name(source, name)
    enriched = _enrich_tool(tool) if tool else {}
    raw = _call_tool(source, name, arguments)
    text = _tool_text(raw)
    parsed = _extract_json(text)
    is_error = _tool_is_error(raw) or "error" in raw
    return {
        "source": source,
        "name": name,
        "category": enriched.get("category"),
        "lane": enriched.get("lane"),
        "ok": not is_error,
        "is_error": is_error,
        "duration_ms": int((time.time() - started) * 1000),
        "text": text,
        "json": parsed,
        "raw": raw,
    }


def _incident_cases_sync(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    result = _normalized_call("infokom", "blueteam_case_list", {"response_format": "json"})
    data = result.get("json")
    if not result.get("ok") or not isinstance(data, list):
        return {"ok": False, "cases": [], "error": result.get("text") or "Case store unavailable"}
    payload = payload or {}
    start_ts = end_ts = None
    if payload.get("range") or payload.get("start") or payload.get("end"):
        try:
            start, end = soc_pipeline.bounds(_history_payload(payload))
            start_ts, end_ts = datetime.fromisoformat(start).timestamp(), datetime.fromisoformat(end).timestamp()
        except (TypeError, ValueError):
            start_ts = end_ts = None
    filtered = []
    all_time = 0
    for case in data[:200]:
        if not isinstance(case, dict):
            continue
        raw_time = next((case.get(key) for key in ("created_at", "created", "opened_at", "updated_at", "updated") if case.get(key)), None)
        case_ts = None
        if raw_time is not None:
            try:
                if isinstance(raw_time, (int, float)):
                    case_ts = float(raw_time)
                else:
                    case_ts = datetime.fromisoformat(str(raw_time).replace("Z", "+00:00")).timestamp()
            except (TypeError, ValueError, OverflowError):
                case_ts = None
        row = dict(case)
        row["all_time"] = case_ts is None
        if row["all_time"]:
            all_time += 1
        if start_ts is not None and end_ts is not None and case_ts is not None and not (start_ts <= case_ts < end_ts):
            continue
        filtered.append(row)
    return {"ok": True, "cases": filtered[:100], "all_time_count": all_time,
            "window": {"start": start_ts, "end": end_ts} if start_ts is not None else {"scope": "all-time"},
            "duration_ms": result.get("duration_ms", 0)}


def _incident_cases(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Serve incident scope quickly; refresh the remote case store outside the request path."""
    if payload is None:
        return _incident_cases_sync()
    key = hashlib.sha256(json.dumps({k: payload.get(k) for k in ("range", "start", "end")},
                                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    now = time.time()
    with _incident_cache_lock:
        cached = _incident_cache.get(key)
        refreshing = key in _incident_refreshing
        if cached and now - cached["stored_at"] < 60:
            return {**cached["data"], "cache": {"status": "hit", "age_seconds": int(now - cached["stored_at"])}}
        should_start = not refreshing
        if should_start:
            _incident_refreshing.add(key)
    result: dict[str, Any] = {}
    completed = threading.Event()
    def refresh() -> None:
        try:
            result["data"] = _incident_cases_sync(payload)
            with _incident_cache_lock:
                _incident_cache[key] = {"data": result["data"], "stored_at": time.time()}
        except Exception as exc:
            result["data"] = {"ok": False, "cases": [], "error": str(exc)}
        finally:
            with _incident_cache_lock:
                _incident_refreshing.discard(key)
            completed.set()
    if should_start:
        threading.Thread(target=refresh, daemon=True).start()
    completed.wait(1.0)
    if result.get("data"):
        return {**result["data"], "cache": {"status": "miss", "age_seconds": 0}}
    with _incident_cache_lock:
        cached = _incident_cache.get(key)
    if cached:
        return {**cached["data"], "cache": {"status": "stale-refreshing", "age_seconds": int(now - cached["stored_at"]),
                                              "note": "Case store refresh continues in background."}}
    return {"ok": False, "cases": [], "status": "materializing", "error": "Persistent case detail is still loading; retry shortly."}


def _incident_create(payload: dict[str, Any]) -> dict[str, Any]:
    title = str(payload.get("title") or "SOC investigation").strip()
    notes = str(payload.get("notes") or "").strip()
    if not title or len(title) > 200 or len(notes) > 2000:
        raise ValueError("Invalid case title or notes")
    srcips = []
    for value in payload.get("srcips") or []:
        try:
            normalized = str(ipaddress.ip_address(str(value)))
        except ValueError:
            continue
        if normalized not in srcips:
            srcips.append(normalized)
    lifecycle_limits = {"owner": 120, "sla_due": 64, "status": 32, "containment": 1000, "closure_reason": 1000}
    lifecycle = {key: str(payload.get(key) or "").strip() for key in lifecycle_limits}
    lifecycle["status"] = lifecycle["status"] or "open"
    if any(len(lifecycle[key]) > limit for key, limit in lifecycle_limits.items()):
        raise ValueError("Invalid case lifecycle field")
    result = _normalized_call("infokom", "blueteam_case_create", {
        "title": title, "srcips": srcips[:50], "notes": notes, **lifecycle,
    })
    data = result.get("json")
    if not result.get("ok") or not isinstance(data, dict) or data.get("error"):
        return {"ok": False, "error": data.get("error") if isinstance(data, dict) else result.get("text")}
    return {"ok": True, "case": data, "duration_ms": result.get("duration_ms", 0)}


def _sync_finding_case(finding: dict[str, Any], disposition: str, note: str = "", ai_advisory: dict[str, Any] | None = None) -> dict[str, Any]:
    """Persist an analyst-approved IP finding without making feedback depend on MCP availability."""
    raw_ip = finding.get("ip") or (finding.get("indicator") if finding.get("category") == "ip" else None)
    try:
        srcip = str(ipaddress.ip_address(str(raw_ip)))
    except ValueError:
        return {"ok": False, "skipped": True, "reason": "A source IP is required for case verdict synchronization"}

    verdict_map = {
        "true_positive": "true_positive",
        "false_positive": "false_positive",
        "expected_activity": "clean",
        "escalated": "suspicious",
        "needs_review": "unknown",
    }
    verdict = verdict_map.get(str(disposition or "").lower())
    if not verdict:
        return {"ok": False, "skipped": True, "reason": "Unsupported analyst disposition"}

    title = f"Finding: {str(finding.get('title') or finding.get('id') or srcip).strip()}"[:200]
    cases_result = _incident_cases()
    if not cases_result.get("ok"):
        return {"ok": False, "error": cases_result.get("error") or "Case store unavailable"}
    case = next((item for item in cases_result.get("cases", []) if item.get("title") == title), None)
    if not case:
        created = _incident_create({
            "title": title,
            "srcips": [srcip],
            "notes": f"Created from Security Findings analyst disposition for {finding.get('id') or srcip}.",
        })
        if not created.get("ok"):
            return created
        case = created.get("case") or {}

    case_id = str(case.get("case_id") or "")
    if not case_id:
        return {"ok": False, "error": "Case store returned no case ID"}
    advisory = ai_advisory if isinstance(ai_advisory, dict) else {}
    verdict_data = advisory.get("verdict") if isinstance(advisory.get("verdict"), dict) else {}
    details = [str(note or "").strip()]
    if verdict_data:
        details.append(
            "AI advisory: " + ", ".join(str(value) for value in (
                verdict_data.get("status"), verdict_data.get("severity"), verdict_data.get("confidence")
            ) if value)
        )
    result = _normalized_call("infokom", "blueteam_mark_investigated", {
        "srcip": srcip,
        "verdict": verdict,
        "notes": "; ".join(value for value in details if value)[:1024],
        "case_id": case_id,
    })
    data = result.get("json")
    if not result.get("ok") or (isinstance(data, dict) and data.get("error")):
        return {"ok": False, "case_id": case_id,
                "error": data.get("error") if isinstance(data, dict) else result.get("text")}
    return {"ok": True, "case_id": case_id, "verdict": verdict, "srcip": srcip,
            "duration_ms": result.get("duration_ms", 0)}


def _tool_text(payload: Any) -> str:
    try:
        content = payload.get("result", {}).get("content", [])
        if content and isinstance(content[0], dict):
            return str(content[0].get("text", ""))
    except Exception:
        pass
    return ""


def _tool_is_error(payload: Any) -> bool:
    return bool(payload.get("result", {}).get("isError")) if isinstance(payload, dict) else True


def _extract_json(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"(\{.*\}|\[.*\])", text, flags=re.S)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


def _safe_call(source: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        payload = _call_tool(source, name, arguments)
        text = _tool_text(payload)
        return {
            "ok": not _tool_is_error(payload),
            "name": name,
            "source": source,
            "text": text,
            "data": _extract_json(text),
        }
    except Exception as exc:
        return {"ok": False, "name": name, "source": source, "error": str(exc)}


THREAT_INTEL_TESTS: list[dict[str, Any]] = [
    {
        "provider": "CrowdSec",
        "label": "IP reputation",
        "tool": "crowdsec_ip_reputation",
        "arguments": {"ip": "8.8.8.8", "response_format": "json"},
    },
    {
        "provider": "AlienVault OTX",
        "label": "IOC pulses",
        "tool": "otx_lookup",
        "arguments": {"indicator": "8.8.8.8", "section": "general", "response_format": "json"},
    },
    {
        "provider": "CYFIRMA",
        "label": "Tailored STIX IOC feed",
        "tool": "cyfirma_ioc_feed",
        "arguments": {"scope": "tailored", "limit": 20, "response_format": "json"},
    },
    {
        "provider": "VirusTotal",
        "label": "Domain reputation",
        "tool": "blueteam_lookup_domain_virustotal",
        "arguments": {"domain": "example.com", "response_format": "json"},
    },
    {
        "provider": "CVE Enrichment",
        "label": "EPSS probability",
        "tool": "blueteam_cve_epss",
        "arguments": {"cve_ids": ["CVE-2024-6387"], "response_format": "json"},
    },
    {
        "provider": "NVD/CVE",
        "label": "CVE record lookup",
        "tool": "blueteam_cve_lookup",
        "arguments": {"cve_id": "CVE-2024-6387", "response_format": "json"},
    },
    {
        "provider": "Unified Score",
        "label": "SOC threat score",
        "tool": "blueteam_unified_threat_score",
        "arguments": {"ip": "8.8.8.8", "response_format": "json"},
    },
    {
        "provider": "ThreatFox",
        "label": "Malware IOC",
        "tool": "threatfox_ioc_search",
        "arguments": {"search_term": "8.8.8.8", "exact_match": False, "response_format": "json"},
    },
    {
        "provider": "AbuseIPDB",
        "label": "IP abuse reputation",
        "tool": "blueteam_lookup_ip_abuseipdb",
        "arguments": {"ip": "8.8.8.8", "max_age_days": 90, "response_format": "json"},
    },
    {
        "provider": "URLHaus",
        "label": "Malicious URL",
        "tool": "urlhaus_lookup",
        "arguments": {"url": "http://example.com/", "response_format": "json"},
    },
]


def _shorten(value: Any, limit: int = 220) -> str:
    text = str(value if value is not None else "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:limit] + ("..." if len(text) > limit else "")


def _provider_summary(data: Any, text: str) -> str:
    if isinstance(data, dict):
        direct_keys = (
            "status", "verdict", "classification", "risk", "risk_level", "score", "threat_score",
            "reputation", "malicious", "suspicious", "harmless", "epss", "percentile",
            "known", "noise", "riot", "pulse_count", "indicator", "cve_id",
        )
        parts = []
        for key in direct_keys:
            if key in data and data[key] not in (None, "", [], {}):
                parts.append(f"{key}: {_shorten(data[key], 60)}")
            if len(parts) >= 4:
                break
        if parts:
            return " | ".join(parts)
        for key, value in data.items():
            if value in (None, "", [], {}):
                continue
            if isinstance(value, (str, int, float, bool)):
                parts.append(f"{key}: {_shorten(value, 60)}")
            elif isinstance(value, list):
                parts.append(f"{key}: {len(value)} rows")
            elif isinstance(value, dict):
                parts.append(f"{key}: {len(value)} fields")
            if len(parts) >= 4:
                break
        if parts:
            return " | ".join(parts)
    if isinstance(data, list):
        return f"{len(data)} result row(s)"
    return _shorten(text or "No structured data returned")


def _provider_test_status(result: dict[str, Any]) -> tuple[str, bool]:
    data = result.get("json")
    data = data if isinstance(data, dict) else {}
    message = str(result.get("text", ""))
    lower = message.lower() if not data else ""
    errorish = " ".join(
        str(data.get(key, "")) for key in ("error", "errors", "message", "status", "query_status")
        if data.get(key)
    ).lower()
    failure_text = lower + " " + errorish
    if re.search(r"\b429\b|rate limit|quota exceeded", failure_text):
        return "rate limited", False
    if any(term in failure_text for term in ("not set", "missing api", "invalid api", "not configured")):
        return "needs configuration", False
    if any(term in errorish for term in ("401", "403", "unauthorized", "forbidden")):
        return "needs configuration", False
    if not result.get("ok") or data.get("error") or data.get("errors") or re.search(r"(^|\]\s*)error\s*:", lower):
        return "error", False
    if "no threat intel sources available" in (lower + str(data.get("verdict", "")).lower()):
        return "insufficient data", False
    if not data and not message.strip():
        return "empty response", False
    if data.get("query_status") in ("no_result", "no_results") or data.get("pulse_count") == 0:
        return "connected; no match", True
    return "connected", True


def _threat_intel_test(force: bool = False) -> dict[str, Any]:
    if not force and _intel_test_cache["data"] and time.time() < float(_intel_test_cache["expires_at"]):
        return dict(_intel_test_cache["data"], cached=True)
    providers = []
    for item in THREAT_INTEL_TESTS:
        started = time.time()
        try:
            result = _normalized_call("infokom", item["tool"], dict(item["arguments"]))
            text = result.get("text", "")
            parsed = result.get("json")
            status, ok = _provider_test_status(result)
            providers.append({
                "provider": item["provider"],
                "label": item["label"],
                "source": "infokom",
                "tool": item["tool"],
                "ok": ok,
                "status": status,
                "purpose": "connection_test",
                "arguments": item["arguments"],
                "summary": _provider_summary(parsed, text),
                "duration_ms": result.get("duration_ms", int((time.time() - started) * 1000)),
                "data": parsed,
                "error": "" if ok else _shorten(text or result.get("raw", {}).get("error", "")),
            })
        except Exception as exc:
            providers.append({
                "provider": item["provider"],
                "label": item["label"],
                "source": "infokom",
                "tool": item["tool"],
                "ok": False,
                "status": "error",
                "summary": "Provider test failed",
                "duration_ms": int((time.time() - started) * 1000),
                "data": None,
                "error": _shorten(exc),
            })
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "indicator": "8.8.8.8 / example.com / CVE-2024-6387",
        "cached": False,
        "providers": providers,
        "summary": {
            "ready": sum(1 for row in providers if row.get("ok")),
            "attention": sum(1 for row in providers if not row.get("ok")),
            "total": len(providers),
        },
    }
    _intel_test_cache.update({"expires_at": time.time() + 300, "data": payload})
    return payload


def _platform_overview_status() -> dict[str, Any]:
    """Unified cross-platform status for gensecai, infokom and AI Analyst."""
    catalog = _tool_catalog()
    tools = catalog.get("tools", [])
    gensecai_tools = [t for t in tools if t.get("source") == "gensecai"]
    infokom_tools = [t for t in tools if t.get("source") == "infokom"]
    gensecai_ok = "gensecai" not in (catalog.get("errors") or {})
    infokom_ok = "infokom" not in (catalog.get("errors") or {})
    try:
        ai_jobs = automation.finding_analysis_jobs(5)
    except Exception:
        ai_jobs = {}
    v = _runtime_config_values()
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platforms": {
            "gensecai": {
                "ok": bool(gensecai_ok),
                "label": "GenSecAI",
                "tools": len(gensecai_tools),
                "error": (catalog.get("errors") or {}).get("gensecai"),
            },
            "infokom": {
                "ok": bool(infokom_ok),
                "label": "INFOKOM",
                "tools": len(infokom_tools),
                "error": (catalog.get("errors") or {}).get("infokom"),
            },
            "ai_analyst": {
                "ok": v.get("AI_ANALYST_ENABLED") == "true",
                "label": "AI Analyst",
                "enabled": v.get("AI_ANALYST_ENABLED") == "true",
                "model": v.get("AI_MODEL", ""),
                "contract_version": soc_automation.CONTRACT_VERSION,
                "counts": ai_jobs.get("counts", {}),
                "average_completed_seconds": ai_jobs.get("average_completed_seconds", 0),
                "recent_jobs": ai_jobs.get("recent", [])[:5],
            },
        },
        "total_tools": len(gensecai_tools) + len(infokom_tools),
    }


def _tool_catalog() -> dict[str, Any]:
    if time.time() < float(_tools_cache.get("expires_at", 0)):
        return {"tools": _tools_cache["tools"], "errors": _tools_cache["errors"]}
    tools: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    for source in ("gensecai", "infokom"):
        try:
            tools.extend(_tools_for(source))
        except Exception as exc:
            errors[source] = str(exc)
    _tools_cache.update({"expires_at": time.time() + 30, "tools": tools, "errors": errors})
    return {"tools": tools, "errors": errors}


def _severity_buckets(groups: dict[str, Any]) -> dict[str, int]:
    buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for level_raw, count_raw in groups.items():
        try:
            level = int(level_raw)
            count = int(count_raw)
        except Exception:
            continue
        if level >= 15:
            buckets["critical"] += count
        elif level >= 12:
            buckets["high"] += count
        elif level >= 7:
            buckets["medium"] += count
        else:
            buckets["low"] += count
    return buckets


def _hourly_series(stats_data: Any) -> list[dict[str, int]]:
    items = []
    if isinstance(stats_data, dict):
        items = stats_data.get("data", {}).get("affected_items", []) or stats_data.get("affected_items", [])
    series = []
    for item in items:
        try:
            total = sum(int(alert.get("times", 0)) for alert in item.get("alerts", []) or [])
            series.append({"hour": int(item.get("hour", 0)), "alerts": total})
        except Exception:
            continue
    return sorted(series, key=lambda row: row["hour"])


def _source_ip_leaderboard(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, dict[str, Any]] = {}
    for threat in threats:
        score = int(threat.get("threat_score", 0) or 0)
        for ip in threat.get("source_ips", []) or []:
            row = counts.setdefault(str(ip), {"ip": str(ip), "hits": 0, "max_score": 0, "rules": set()})
            row["hits"] += 1
            row["max_score"] = max(int(row["max_score"]), score)
            if threat.get("rule_id"):
                row["rules"].add(str(threat["rule_id"]))
    leaders = []
    for row in counts.values():
        leaders.append({
            "ip": row["ip"],
            "hits": row["hits"],
            "max_score": row["max_score"],
            "rules": sorted(row["rules"])[:5],
        })
    return sorted(leaders, key=lambda row: (row["max_score"], row["hits"]), reverse=True)[:20]


def _bucket_value(bucket: dict[str, Any], key: str, default: Any = 0) -> Any:
    return bucket.get(key, bucket.get("doc_count", default))


def _timeline_buckets(timeline_data: Any) -> list[dict[str, Any]]:
    if not isinstance(timeline_data, dict):
        return []
    buckets = timeline_data.get("buckets", [])
    rows = []
    for bucket in buckets[:160]:
        rows.append({
            "time": bucket.get("key") or bucket.get("time") or bucket.get("timestamp"),
            "count": int(bucket.get("doc_count", bucket.get("count", 0)) or 0),
        })
    return rows


def _fim_summary(fim_data: Any) -> dict[str, Any]:
    if not isinstance(fim_data, dict):
        return {"total": 0, "top_paths": [], "top_agents": []}
    aggregations = fim_data.get("aggregations", {})
    by_path = aggregations.get("by_path", {}).get("buckets", [])
    by_agent = aggregations.get("by_agent", {}).get("buckets", [])
    return {
        "total": int(fim_data.get("total", 0) or 0),
        "top_paths": [{"path": row.get("key"), "count": int(row.get("doc_count", 0) or 0)} for row in by_path[:8]],
        "top_agents": [{"agent": row.get("key"), "count": int(row.get("doc_count", 0) or 0)} for row in by_agent[:8]],
    }


def _geo_summary(geo_data: Any) -> dict[str, Any]:
    if not isinstance(geo_data, dict):
        return {"total": 0, "cities": []}
    cities = []
    for city in geo_data.get("cities", [])[:20]:
        cities.append({
            "city": city.get("city") or "Unknown",
            "alerts": int(city.get("alerts", 0) or 0),
            "unique_ips": int(city.get("unique_ips", 0) or 0),
            "lat": city.get("lat", 0),
            "lon": city.get("lon", 0),
        })
    return {"total": int(geo_data.get("total", 0) or 0), "cities": cities}


def _window_from_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {"range": payload}
    requested = _normalize_range(payload.get("range", "24h"))
    if payload.get("range") == "custom" and payload.get("start") and payload.get("end"):
        start, end = soc_pipeline.bounds(payload)
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        hours = max(1, int((end_dt - start_dt).total_seconds() / 3600))
        return {
            "requested": "custom",
            "label": f"{start} - {end}",
            "tool_range": f"{min(hours, 168)}h",
            "bounds": {"gte": start, "lt": end},
        }
    return {
        "requested": requested,
        "label": requested,
        "tool_range": requested,
        "bounds": {"gte": "now-" + requested},
    }


def _history_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {"range": payload}
    normalized = dict(payload)
    if normalized.get("start") and normalized.get("end"):
        return normalized
    window = _window_from_payload(normalized)
    requested = window.get("requested", "24h")
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    if requested.endswith("h"):
        start = now - timedelta(hours=int(requested[:-1]))
    else:
        start = now - timedelta(days=int(requested[:-1]))
    normalized["start"] = start.isoformat()
    normalized["end"] = now.isoformat()
    return normalized


def _overview_cache_ttl(window: dict[str, Any]) -> int:
    if window.get("requested") == "custom":
        return max(60, OVERVIEW_CACHE_TTL_SECONDS * 2)
    return {
        "24h": OVERVIEW_CACHE_TTL_SECONDS,
        "7d": max(300, OVERVIEW_CACHE_TTL_SECONDS * 3),
        "30d": max(600, OVERVIEW_CACHE_TTL_SECONDS * 5),
    }.get(str(window.get("requested")), OVERVIEW_CACHE_TTL_SECONDS)


def _overview_cache_key(window: dict[str, Any]) -> str:
    payload = json.dumps({
        "schema": 2,
        "requested": window.get("requested"),
        "bounds": window.get("bounds"),
        "tool_range": window.get("tool_range"),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _overview_cache_init() -> None:
    global _overview_db_initialized
    if _overview_db_initialized:
        return
    OVERVIEW_CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
    with _overview_db_init_lock:
        if _overview_db_initialized:
            return
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            db.execute("""
                CREATE TABLE IF NOT EXISTS overview_snapshots (
                    cache_key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    requested_range TEXT NOT NULL
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_overview_expires ON overview_snapshots(expires_at)")
            db.execute("""
                CREATE TABLE IF NOT EXISTS api_snapshots (
                    namespace TEXT NOT NULL,
                    cache_key TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY(namespace, cache_key)
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_api_snapshots_expires ON api_snapshots(expires_at)")
            db.execute("""
                CREATE TABLE IF NOT EXISTS provider_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    namespace TEXT NOT NULL,
                    cache_key TEXT NOT NULL,
                    indicator TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    bucket_hour INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    UNIQUE(namespace, cache_key, bucket_hour)
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_provider_history_time ON provider_history(observed_at)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_provider_history_indicator ON provider_history(indicator, observed_at)")
            db.execute("""
                CREATE TABLE IF NOT EXISTS provider_history_summary (
                    history_id INTEGER PRIMARY KEY,
                    observed_at REAL NOT NULL,
                    bucket_day TEXT NOT NULL,
                    indicator TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    malicious INTEGER NOT NULL DEFAULT 0,
                    provider_results INTEGER NOT NULL DEFAULT 0,
                    provider_matches INTEGER NOT NULL DEFAULT 0,
                    provider_errors INTEGER NOT NULL DEFAULT 0,
                    cyfirma_matches INTEGER NOT NULL DEFAULT 0,
                    cached_source INTEGER NOT NULL DEFAULT 0
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_provider_summary_time ON provider_history_summary(observed_at)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_provider_summary_day ON provider_history_summary(bucket_day,indicator)")
            db.execute("""
                CREATE TABLE IF NOT EXISTS provider_history_provider (
                    history_id INTEGER NOT NULL,
                    provider TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    usable INTEGER NOT NULL DEFAULT 0,
                    matched INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    quota_remaining TEXT,
                    reason_not_used TEXT,
                    PRIMARY KEY(history_id,provider)
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_provider_fact_time ON provider_history_provider(observed_at,provider)")
            db.execute("""
                CREATE TABLE IF NOT EXISTS provider_health (
                    provider TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    next_retry_at REAL,
                    last_success_at REAL,
                    last_failure_at REAL,
                    last_error TEXT,
                    updated_at REAL NOT NULL
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_provider_health_retry ON provider_health(next_retry_at)")
            db.execute("""
                CREATE TABLE IF NOT EXISTS cve_exposure_summary (
                    snapshot_key TEXT NOT NULL,
                    path_key TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    requested_range TEXT NOT NULL,
                    cve TEXT NOT NULL,
                    asset TEXT,
                    agent_id TEXT,
                    component TEXT,
                    version TEXT,
                    cpe TEXT,
                    cpe_status TEXT,
                    epss REAL,
                    kev INTEGER,
                    poc INTEGER,
                    internet_exposure INTEGER,
                    patch_state TEXT,
                    case_id TEXT,
                    risk_score REAL,
                    priority TEXT,
                    PRIMARY KEY(snapshot_key, path_key)
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_cve_exposure_snapshot ON cve_exposure_summary(snapshot_key)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_cve_exposure_time ON cve_exposure_summary(observed_at)")
            db.execute("""
                CREATE TABLE IF NOT EXISTS provider_history_cve (
                    history_id INTEGER NOT NULL,
                    cve TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    PRIMARY KEY(history_id,cve)
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_provider_cve_time ON provider_history_cve(observed_at,cve)")
        _overview_db_initialized = True


def _provider_health(provider: str) -> dict[str, Any]:
    provider = str(provider or "unknown").strip() or "unknown"
    try:
        _overview_cache_init()
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            row = db.execute(
                "SELECT state,consecutive_failures,next_retry_at,last_success_at,last_failure_at,last_error,updated_at "
                "FROM provider_health WHERE provider=?", (provider,)
            ).fetchone()
        if not row:
            return {"provider": provider, "state": "unknown", "consecutive_failures": 0, "retry_at": None}
        retry_at = float(row[2]) if row[2] else None
        state = str(row[0] or "unknown")
        if state == "backoff" and retry_at and retry_at <= time.time():
            state = "recovering"
        return {"provider": provider, "state": state, "consecutive_failures": int(row[1] or 0),
                "retry_at": datetime.fromtimestamp(retry_at, timezone.utc).isoformat() if retry_at else None,
                "last_success_at": datetime.fromtimestamp(float(row[3]), timezone.utc).isoformat() if row[3] else None,
                "last_failure_at": datetime.fromtimestamp(float(row[4]), timezone.utc).isoformat() if row[4] else None,
                "last_error": row[5], "updated_at": datetime.fromtimestamp(float(row[6]), timezone.utc).isoformat() if row[6] else None}
    except (sqlite3.Error, OSError, ValueError, TypeError):
        return {"provider": provider, "state": "unavailable", "consecutive_failures": 0, "retry_at": None}


def _provider_health_record(provider: str, ok: bool, error: Any = None) -> dict[str, Any]:
    provider = str(provider or "unknown").strip() or "unknown"
    now = time.time()
    try:
        _overview_cache_init()
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            row = db.execute("SELECT consecutive_failures FROM provider_health WHERE provider=?", (provider,)).fetchone()
            failures = int(row[0] or 0) if row else 0
            if ok:
                values = (provider, "healthy", 0, None, now, None, None, now)
            else:
                failures += 1
                base = max(30, _runtime_int("SOC_PROVIDER_ERROR_BACKOFF_SECONDS", 14400))
                retry_at = now + min(base * (2 ** min(failures - 1, 5)), 86400)
                values = (provider, "backoff", failures, retry_at, None, now, str(error or "provider error")[:400], now)
            db.execute("""REPLACE INTO provider_health
                (provider,state,consecutive_failures,next_retry_at,last_success_at,last_failure_at,last_error,updated_at)
                VALUES (?,?,?,?,?,?,?,?)""", values)
    except (sqlite3.Error, OSError):
        pass
    return _provider_health(provider)


def _provider_health_rows() -> dict[str, dict[str, Any]]:
    try:
        _overview_cache_init()
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            names = [row[0] for row in db.execute("SELECT provider FROM provider_health ORDER BY provider")]
        return {name: _provider_health(name) for name in names}
    except (sqlite3.Error, OSError):
        return {}


def _materialize_cve_exposure(graph: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    """Persist bounded CVE exposure paths so historical views never need a provider call."""
    request_key = json.dumps({key: request.get(key) for key in ("severity", "search", "sort", "limit", "historical", "start", "end")},
                             sort_keys=True, separators=(",", ":"))
    snapshot_key = hashlib.sha256(request_key.encode("utf-8")).hexdigest()
    observed_at = time.time()
    paths = graph.get("paths") if isinstance(graph.get("paths"), list) else []
    rows = []
    for index, path in enumerate(paths):
        if not isinstance(path, dict) or not path.get("cve"):
            continue
        identity = "|".join(str(path.get(key) or "") for key in ("cve", "asset", "agent_id", "component", "version"))
        path_key = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        def numeric(value):
            try:
                return float(value) if value is not None else None
            except (TypeError, ValueError):
                return None
        rows.append((snapshot_key, path_key, observed_at, str(request.get("range") or "current"),
                     str(path.get("cve")), path.get("asset"), path.get("agent_id"), path.get("component"),
                     path.get("version"), path.get("cpe"), path.get("cpe_status"), numeric(path.get("epss")),
                     None if path.get("kev") is None else int(bool(path.get("kev"))),
                     None if path.get("poc") is None else int(bool(path.get("poc"))),
                     None if path.get("internet_exposed") is None else int(bool(path.get("internet_exposed"))),
                     path.get("patch_state"), path.get("case_id"), numeric(path.get("risk_score")), path.get("priority")))
    try:
        _overview_cache_init()
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            db.execute("DELETE FROM cve_exposure_summary WHERE snapshot_key=?", (snapshot_key,))
            db.executemany("""INSERT OR REPLACE INTO cve_exposure_summary
                (snapshot_key,path_key,observed_at,requested_range,cve,asset,agent_id,component,version,cpe,cpe_status,epss,kev,poc,internet_exposure,patch_state,case_id,risk_score,priority)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
            db.execute("DELETE FROM cve_exposure_summary WHERE observed_at < ?",
                       (time.time() - OVERVIEW_HISTORY_RETENTION_DAYS * 86400,))
            counts = db.execute("""SELECT COUNT(*),COUNT(DISTINCT cve),
                SUM(CASE WHEN cpe_status='valid' THEN 1 ELSE 0 END),
                SUM(CASE WHEN epss IS NOT NULL THEN 1 ELSE 0 END),
                SUM(CASE WHEN kev IS NOT NULL THEN 1 ELSE 0 END),
                SUM(CASE WHEN poc IS NOT NULL THEN 1 ELSE 0 END),
                SUM(CASE WHEN internet_exposure IS NOT NULL THEN 1 ELSE 0 END),
                SUM(CASE WHEN patch_state IS NOT NULL AND patch_state!='unknown' THEN 1 ELSE 0 END),
                SUM(CASE WHEN case_id IS NOT NULL AND case_id!='' THEN 1 ELSE 0 END)
                FROM cve_exposure_summary WHERE snapshot_key=?""", (snapshot_key,)).fetchone()
        graph["materialized_summary"] = {
            "snapshot_key": snapshot_key, "source": "sqlite cve_exposure_summary", "paths": int(counts[0] or 0),
            "cves": int(counts[1] or 0), "cpe": int(counts[2] or 0), "epss": int(counts[3] or 0),
            "kev": int(counts[4] or 0), "poc": int(counts[5] or 0), "internet_exposure": int(counts[6] or 0),
            "patch_state": int(counts[7] or 0), "case": int(counts[8] or 0),
        }
    except (sqlite3.Error, OSError):
        graph["materialized_summary"] = {"source": "unavailable", "paths": len(rows), "error": "summary persistence unavailable"}
    return graph


def _api_cache_key(payload: Any) -> str:
    safe_payload = json.dumps(payload or {}, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(safe_payload.encode("utf-8")).hexdigest()


def _api_cache_read(namespace: str, payload: Any, ttl: int) -> dict[str, Any] | None:
    try:
        _overview_cache_init()
        key = _api_cache_key(payload)
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            row = db.execute(
                "SELECT payload, created_at, expires_at FROM api_snapshots WHERE namespace = ? AND cache_key = ?",
                (namespace, key),
            ).fetchone()
    except Exception:
        return None
    if not row or float(row[2]) <= time.time():
        return None
    try:
        data = json.loads(row[0])
    except Exception:
        return None
    data["cache"] = {"status": "hit", "namespace": namespace, "age_seconds": int(time.time() - float(row[1])), "ttl_seconds": ttl}
    return data


def _api_cache_write(namespace: str, payload: Any, data: dict[str, Any], ttl: int) -> dict[str, Any]:
    now_ts = time.time()
    cached = dict(data)
    cached["cache"] = {"status": "miss", "namespace": namespace, "age_seconds": 0, "ttl_seconds": ttl}
    try:
        _overview_cache_init()
        key = _api_cache_key(payload)
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            db.execute(
                "REPLACE INTO api_snapshots (namespace, cache_key, payload, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (namespace, key, json.dumps(cached, separators=(",", ":")), now_ts, now_ts + ttl),
            )
            db.execute("DELETE FROM api_snapshots WHERE expires_at < ?", (now_ts - 86400,))
    except Exception:
        return data
    return cached


def _provider_history_materialize(db: sqlite3.Connection, history_id: int, indicator: str,
                                  observed_at: float, stored: dict[str, Any]) -> None:
    """Normalize one provider snapshot once so range reads never scan JSON blobs."""
    payload = stored.get("data") if isinstance(stored, dict) and isinstance(stored.get("data"), dict) else {}
    results = payload.get("results") if isinstance(payload.get("results"), list) else []
    provider_rows: list[tuple[Any, ...]] = []
    usable_count = match_count = error_count = 0
    for result in results:
        if not isinstance(result, dict):
            continue
        detail = result.get("detail") if isinstance(result.get("detail"), dict) else {}
        error = result.get("error")
        skipped = bool(detail.get("skipped"))
        usable = not error and not skipped
        risk = str(result.get("risk_level") or "").lower()
        matched = bool(result.get("is_malicious") or risk in {
            "critical", "high", "malicious", "suspicious"
        })
        usable_count += int(usable)
        match_count += int(usable and matched)
        error_count += int(bool(error))
        reason = error or detail.get("reason") or detail.get("skip_reason")
        quota = next((detail.get(key) for key in (
            "quota_remaining", "remaining", "rate_limit_remaining", "x_ratelimit_remaining"
        ) if detail.get(key) is not None), None)
        provider_rows.append((history_id, str(result.get("provider") or "unknown")[:120], observed_at,
                              int(usable), int(usable and matched),
                              "error" if error else "skipped" if skipped else "matched" if matched else "available",
                              None if quota is None else str(quota)[:120],
                              str(reason)[:500] if reason else None))
    cyfirma = payload.get("cyfirma_matches") if isinstance(payload.get("cyfirma_matches"), list) else []
    encoded = json.dumps(payload, default=str)
    cves = sorted(set(value.upper() for value in re.findall(
        r"CVE-\d{4}-\d{4,}", encoded, flags=re.IGNORECASE)))
    risk = str(payload.get("aggregated_risk_level") or "unknown")[:64]
    malicious = int(bool(payload.get("consensus_malicious") or match_count or cyfirma))
    bucket_day = datetime.fromtimestamp(float(observed_at), timezone.utc).date().isoformat()
    db.execute("""INSERT OR REPLACE INTO provider_history_summary
        (history_id,observed_at,bucket_day,indicator,risk,malicious,provider_results,
         provider_matches,provider_errors,cyfirma_matches,cached_source)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (history_id, observed_at, bucket_day, indicator, risk, malicious, usable_count,
         match_count, error_count, len(cyfirma), int(bool(stored.get("cached") or stored.get("memory_reused")))))
    db.execute("DELETE FROM provider_history_provider WHERE history_id=?", (history_id,))
    db.execute("DELETE FROM provider_history_cve WHERE history_id=?", (history_id,))
    if provider_rows:
        db.executemany("""INSERT OR REPLACE INTO provider_history_provider
            (history_id,provider,observed_at,usable,matched,status,quota_remaining,reason_not_used)
            VALUES (?,?,?,?,?,?,?,?)""", provider_rows)
    if cves:
        db.executemany("INSERT OR REPLACE INTO provider_history_cve(history_id,cve,observed_at) VALUES (?,?,?)",
                       [(history_id, cve, observed_at) for cve in cves])


def _provider_history_materialize_pending(db: sqlite3.Connection, start_ts: float | None = None,
                                          end_ts: float | None = None, limit: int = 2500) -> int:
    where = ["s.history_id IS NULL"]
    params: list[Any] = []
    if start_ts is not None:
        where.append("h.observed_at>=?")
        params.append(start_ts)
    if end_ts is not None:
        where.append("h.observed_at<?")
        params.append(end_ts)
    rows = db.execute(f"""SELECT h.id,h.indicator,h.observed_at,h.payload
        FROM provider_history h LEFT JOIN provider_history_summary s ON s.history_id=h.id
        WHERE {' AND '.join(where)} ORDER BY h.observed_at DESC LIMIT ?""", [*params, max(1, int(limit))]).fetchall()
    for history_id, indicator, observed_at, raw in rows:
        try:
            stored = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            stored = {}
        _provider_history_materialize(db, int(history_id), str(indicator), float(observed_at), stored)
    return len(rows)


def _provider_history_write(namespace: str, request_payload: Any, data: dict[str, Any], observed_at: Any = None) -> None:
    if namespace != "finding_intel" or not isinstance(request_payload, dict) or request_payload.get("kind") != "aggregate":
        return
    indicator = str(request_payload.get("indicator") or "").strip()
    result_data = data.get("data") if isinstance(data, dict) else None
    if not indicator or not isinstance(result_data, dict):
        return
    now_ts = time.time()
    history_ts = now_ts
    if observed_at is not None:
        try:
            history_ts = float(observed_at)
        except (TypeError, ValueError):
            try:
                history_ts = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00")).timestamp()
            except (TypeError, ValueError):
                history_ts = now_ts
        if history_ts <= 0 or history_ts > now_ts + 86400:
            history_ts = now_ts
    bucket_hour = int(history_ts // 3600 * 3600)
    retention_days = _runtime_int("SOC_PROVIDER_HISTORY_RETENTION_DAYS", 180)
    try:
        _overview_cache_init()
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            cache_key = _api_cache_key(request_payload)
            db.execute(
                """INSERT OR REPLACE INTO provider_history
                   (id, namespace, cache_key, indicator, observed_at, bucket_hour, payload)
                   VALUES ((SELECT id FROM provider_history WHERE namespace=? AND cache_key=? AND bucket_hour=?),?,?,?,?,?,?)""",
                (namespace, cache_key, bucket_hour,
                 namespace, cache_key, indicator, history_ts, bucket_hour,
                 json.dumps(data, separators=(",", ":"), default=str)),
            )
            history_id = db.execute("""SELECT id FROM provider_history
                WHERE namespace=? AND cache_key=? AND bucket_hour=?""",
                (namespace, cache_key, bucket_hour)).fetchone()[0]
            _provider_history_materialize(db, int(history_id), indicator, history_ts, data)
            db.execute("DELETE FROM provider_history WHERE observed_at < ?", (now_ts - retention_days * 86400,))
            db.execute("DELETE FROM provider_history_summary WHERE history_id NOT IN (SELECT id FROM provider_history)")
            db.execute("DELETE FROM provider_history_provider WHERE history_id NOT IN (SELECT id FROM provider_history)")
            db.execute("DELETE FROM provider_history_cve WHERE history_id NOT IN (SELECT id FROM provider_history)")
    except Exception:
        pass


def _provider_history_payload(start: str, end: str, offset: int = 0, query: str = "") -> dict[str, Any]:
    if offset < 0 or offset > 100000:
        raise ValueError("Invalid history offset")
    start_ts = datetime.fromisoformat(start).timestamp()
    end_ts = datetime.fromisoformat(end).timestamp()
    if end_ts <= start_ts:
        raise ValueError("History end must be after start")
    query = str(query or "").strip()[:256]
    where = "observed_at>=? AND observed_at<?"
    params: list[Any] = [start_ts, end_ts]
    if query:
        where += " AND indicator LIKE ?"
        params.append(f"%{query}%")
    try:
        _overview_cache_init()
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            total = int(db.execute(f"SELECT COUNT(*) FROM provider_history WHERE {where}", params).fetchone()[0] or 0)
            rows = db.execute(
                f"SELECT id,indicator,observed_at,payload FROM provider_history WHERE {where} ORDER BY observed_at DESC LIMIT 20 OFFSET ?",
                [*params, offset],
            ).fetchall()
            migrated = _provider_history_materialize_pending(db, start_ts, end_ts)
            summary_where = "s.observed_at>=? AND s.observed_at<?"
            summary_params: list[Any] = [start_ts, end_ts]
            if query:
                summary_where += " AND s.indicator LIKE ?"
                summary_params.append(f"%{query}%")
            pending = int(db.execute(f"""SELECT COUNT(*) FROM provider_history h
                LEFT JOIN provider_history_summary s ON s.history_id=h.id
                WHERE h.observed_at>=? AND h.observed_at<? AND s.history_id IS NULL""",
                (start_ts, end_ts)).fetchone()[0] or 0)
            aggregate = db.execute(f"""SELECT COUNT(*),COUNT(DISTINCT s.indicator),
                COALESCE(SUM(s.provider_results),0),COALESCE(SUM(s.provider_matches),0),
                COALESCE(SUM(s.provider_errors),0),COALESCE(SUM(s.cyfirma_matches),0)
                FROM provider_history_summary s WHERE {summary_where}""", summary_params).fetchone()
            hours = (end_ts - start_ts) / 3600
            step = 3600 if hours <= 48 else 86400
            timeline_rows = db.execute(f"""SELECT
                CAST((s.observed_at-?)/? AS INTEGER)*?+? AS bucket,COUNT(*)
                FROM provider_history_summary s WHERE {summary_where}
                GROUP BY bucket ORDER BY bucket""",
                [start_ts, step, step, int(start_ts), *summary_params]).fetchall()
            provider_rows = db.execute(f"""SELECT p.provider,COUNT(*)
                FROM provider_history_provider p
                JOIN provider_history_summary s ON s.history_id=p.history_id
                WHERE {summary_where} AND p.usable=1
                GROUP BY p.provider ORDER BY COUNT(*) DESC,p.provider LIMIT 50""", summary_params).fetchall()
            cve_rows = db.execute(f"""SELECT DISTINCT c.cve
                FROM provider_history_cve c
                JOIN provider_history_summary s ON s.history_id=c.history_id
                WHERE {summary_where} ORDER BY c.cve LIMIT 30""", summary_params).fetchall()
            indicator_rows = db.execute(f"""SELECT s.indicator,MAX(s.observed_at)
                FROM provider_history_summary s WHERE {summary_where}
                GROUP BY s.indicator ORDER BY MAX(s.observed_at) DESC,s.indicator LIMIT 100""",
                summary_params).fetchall()
    except sqlite3.Error as exc:
        raise ValueError("Provider history database unavailable") from exc

    def summarize(row_id: int | None, indicator: str, observed_at: float, raw: str, include_payload: bool) -> dict[str, Any]:
        try:
            stored = json.loads(raw)
        except Exception:
            stored = {}
        payload = stored.get("data") if isinstance(stored.get("data"), dict) else {}
        providers = payload.get("results") if isinstance(payload.get("results"), list) else []
        usable = [row for row in providers if isinstance(row, dict) and not row.get("error") and
                  not (row.get("detail") if isinstance(row.get("detail"), dict) else {}).get("skipped")]
        matches = [row for row in usable if row.get("is_malicious") or str(row.get("risk_level") or "").lower() in {"critical", "high", "malicious", "suspicious"}]
        encoded = json.dumps(payload, default=str)
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", encoded, flags=re.IGNORECASE)))[:30]
        cyfirma = payload.get("cyfirma_matches") if isinstance(payload.get("cyfirma_matches"), list) else []
        item = {
            "id": row_id,
            "indicator": indicator,
            "observed_at": datetime.fromtimestamp(observed_at, timezone.utc).isoformat(),
            "risk": payload.get("aggregated_risk_level") or "unknown",
            "malicious": bool(payload.get("consensus_malicious") or matches or cyfirma),
            "providers": [str(row.get("provider") or "unknown") for row in usable],
            "provider_results": len(usable),
            "provider_matches": len(matches),
            "provider_errors": len([row for row in providers if isinstance(row, dict) and row.get("error")]),
            "cve_refs": cves,
            "cyfirma_matches": len(cyfirma),
            "cached_source": bool(stored.get("cached") or stored.get("memory_reused")),
        }
        if include_payload:
            item["result"] = stored
        return item

    intelligence = [summarize(row_id, indicator, observed_at, raw, True) for row_id, indicator, observed_at, raw in rows]
    return {
        "ok": True,
        "total": total,
        "intelligence": intelligence,
        "timeline": [{"key": int(bucket) * 1000, "doc_count": int(count)}
                     for bucket, count in timeline_rows],
        "indicator_catalog": [{"indicator": indicator,
                                "observed_at": datetime.fromtimestamp(float(observed_at), timezone.utc).isoformat()}
                               for indicator, observed_at in indicator_rows],
        "summary": {
            "snapshots": int(aggregate[0] or 0),
            "unique_indicators": int(aggregate[1] or 0),
            "provider_results": int(aggregate[2] or 0),
            "provider_matches": int(aggregate[3] or 0),
            "provider_errors": int(aggregate[4] or 0),
            "cyfirma_matches": int(aggregate[5] or 0),
            "cve_refs": [row[0] for row in cve_rows],
            "providers": [{"provider": provider, "count": int(count)} for provider, count in provider_rows],
            "materialization": {"source": "sqlite_normalized_summary", "complete": pending == 0,
                                "pending_legacy_snapshots": pending, "migrated_this_read": migrated},
            "retention_days": _runtime_int("SOC_PROVIDER_HISTORY_RETENTION_DAYS", 180),
        },
    }


def _latest_provider_history(indicator: str) -> dict[str, Any] | None:
    indicator = str(indicator or "").strip()
    if not indicator:
        return None
    try:
        _overview_cache_init()
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            row = db.execute(
                "SELECT observed_at,payload FROM provider_history WHERE indicator=? ORDER BY observed_at DESC LIMIT 1",
                (indicator,),
            ).fetchone()
        if not row:
            return None
        stored = json.loads(row[1])
        data = stored.get("data") if isinstance(stored, dict) and isinstance(stored.get("data"), dict) else {}
        return {
            "observed_at": datetime.fromtimestamp(float(row[0]), timezone.utc).isoformat(),
            "results": data.get("results") if isinstance(data.get("results"), list) else [],
            "cyfirma_matches": data.get("cyfirma_matches") if isinstance(data.get("cyfirma_matches"), list) else [],
        }
    except (sqlite3.Error, ValueError, TypeError, json.JSONDecodeError):
        return None


def _provider_freshness() -> dict[str, Any]:
    try:
        _overview_cache_init()
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            _provider_history_materialize_pending(db, limit=500)
            rows = db.execute(
                """SELECT provider,observed_at,status,quota_remaining,reason_not_used
                FROM (
                    SELECT provider,observed_at,status,quota_remaining,reason_not_used,
                           ROW_NUMBER() OVER (PARTITION BY provider ORDER BY observed_at DESC) AS sequence
                    FROM provider_history_provider
                ) WHERE sequence=1 ORDER BY provider"""
            ).fetchall()
        now_ts = time.time()
        providers = []
        for provider, observed_at, status, quota, reason in rows:
            if isinstance(quota, str) and quota.isdigit():
                quota = int(quota)
            providers.append({
                "provider": provider,
                "observed_at": datetime.fromtimestamp(float(observed_at), timezone.utc).isoformat(),
                "age_seconds": max(0, int(now_ts - float(observed_at))),
                "status": status,
                "quota_remaining": quota,
                "reason_not_used": reason,
                "source": "materialized provider history",
                "health": _provider_health(provider),
            })
        for provider, health in _provider_health_rows().items():
            if not any(row.get("provider") == provider for row in providers):
                providers.append({"provider": provider, "observed_at": None, "age_seconds": None,
                                  "status": "health_only", "quota_remaining": None,
                                  "reason_not_used": health.get("last_error"),
                                  "source": "provider circuit state", "health": health})
    except (sqlite3.Error, OSError, ValueError, TypeError):
        return {"providers": [], "status": "unavailable"}
    return {"providers": providers, "status": "available" if providers else "empty",
            "retention_days": _runtime_int("SOC_PROVIDER_HISTORY_RETENTION_DAYS", 180)}


def _runtime_int(key: str, default: int) -> int:
    try:
        return int(_runtime_config_values().get(key) or default)
    except Exception:
        return default


def _disk_usage(path: str) -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
    except Exception as exc:
        return {"path": path, "ok": False, "error": str(exc)}
    used = usage.total - usage.free
    return {
        "path": path,
        "ok": True,
        "total": usage.total,
        "used": used,
        "free": usage.free,
        "used_percent": round((used / usage.total) * 100, 1) if usage.total else 0,
    }


def _cache_stats() -> dict[str, Any]:
    stats = {"overview_snapshots": 0, "api_snapshots": 0, "provider_history": 0,
             "provider_history_materialized": 0, "db_bytes": 0}
    try:
        if OVERVIEW_CACHE_DB.exists():
            stats["db_bytes"] = OVERVIEW_CACHE_DB.stat().st_size
        _overview_cache_init()
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            stats["overview_snapshots"] = int(db.execute("SELECT COUNT(*) FROM overview_snapshots").fetchone()[0] or 0)
            stats["api_snapshots"] = int(db.execute("SELECT COUNT(*) FROM api_snapshots").fetchone()[0] or 0)
            stats["provider_history"] = int(db.execute("SELECT COUNT(*) FROM provider_history").fetchone()[0] or 0)
            stats["provider_history_materialized"] = int(db.execute(
                "SELECT COUNT(*) FROM provider_history_summary").fetchone()[0] or 0)
    except Exception as exc:
        stats["error"] = str(exc)
    return stats


def _automation_db_stats() -> dict[str, Any]:
    stats = {"reports": 0, "report_summaries": 0, "ai_runs": 0, "finding_ai": 0,
             "ioc_queue": 0, "scan_batches": 0, "rollup_windows": 0,
             "cyfirma_observations": 0, "cyfirma_feed_runs": 0, "db_bytes": 0}
    try:
        if AUTOMATION_DB.exists():
            stats["db_bytes"] = AUTOMATION_DB.stat().st_size
        with _sqlite_db(AUTOMATION_DB) as db:
            for table in ("reports", "report_summaries", "ai_runs", "finding_ai", "ioc_queue",
                          "scan_batches", "rollup_windows", "cyfirma_observations", "cyfirma_feed_runs"):
                try:
                    stats[table] = int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] or 0)
                except sqlite3.OperationalError:
                    pass
    except Exception as exc:
        stats["error"] = str(exc)
    return stats


def _overview_cache_read(cache_key: str) -> dict[str, Any] | None:
    try:
        _overview_cache_init()
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            row = db.execute(
                "SELECT payload, created_at, expires_at FROM overview_snapshots WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
    except Exception:
        return None
    if not row:
        return None
    try:
        data = json.loads(row[0])
    except Exception:
        return None
    return {"data": data, "created_at": float(row[1]), "expires_at": float(row[2])}


def _overview_cache_write(cache_key: str, window: dict[str, Any], data: dict[str, Any], ttl: int) -> None:
    now = time.time()
    payload = dict(data)
    payload["cache"] = {
        "status": "miss",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "ttl_seconds": ttl,
        "age_seconds": 0,
    }
    with _overview_cache_lock:
        _overview_cache_init()
        with _sqlite_db(OVERVIEW_CACHE_DB) as db:
            db.execute(
                "REPLACE INTO overview_snapshots (cache_key, payload, created_at, expires_at, requested_range) VALUES (?, ?, ?, ?, ?)",
                (cache_key, json.dumps(payload, separators=(",", ":")), now, now + ttl, str(window.get("requested", ""))),
            )
            db.execute("DELETE FROM overview_snapshots WHERE expires_at < ?", (now - OVERVIEW_HISTORY_RETENTION_DAYS * 86400,))


def _overview_refresh_worker(cache_key: str, window: dict[str, Any], payload: Any, ttl: int) -> None:
    try:
        try:
            data = _overview(payload)
            _overview_cache_write(cache_key, window, data, ttl)
        except Exception:
            pass
    finally:
        with _overview_cache_lock:
            _overview_refreshing.discard(cache_key)


def _overview_refresh_async(cache_key: str, window: dict[str, Any], payload: Any, ttl: int) -> None:
    with _overview_cache_lock:
        if cache_key in _overview_refreshing:
            return
        _overview_refreshing.add(cache_key)
    thread = threading.Thread(
        target=_overview_refresh_worker,
        args=(cache_key, window, payload, ttl),
        daemon=True,
    )
    thread.start()


def _materialized_overview(window: dict[str, Any], payload: Any) -> dict[str, Any]:
    """Return retained SOC summaries while an exact long-range snapshot builds."""
    history: dict[str, Any] = {}
    timeline_rows: list[dict[str, Any]] = []
    rollup: dict[str, Any] = {}
    try:
        normalized = _history_payload(payload)
        start = datetime.fromisoformat(str(normalized["start"]).replace("Z", "+00:00")).isoformat()
        end = datetime.fromisoformat(str(normalized["end"]).replace("Z", "+00:00")).isoformat()
        history = automation.history_summary(start, end)
        timeline_rows = automation.report_timeline(start, end)
        rollup = pipeline.rollup_summary(start, end)
    except Exception:
        history = {}
        rollup = {}
    totals = history.get("totals") or {}
    dimensions = rollup.get("dimensions") or {}
    rollup_rows = int((rollup.get("coverage") or {}).get("rows") or 0)
    source_rows = dimensions.get("source_ip") or history.get("top_source_ips") or []
    source_ips = [{"ip": row.get("value"), "hits": int(row.get("count") or 0),
                   "max_score": int(row.get("max_level") or 0) * 4, "rules": []}
                  for row in source_rows if row.get("value")]
    threats = []
    for row in dimensions.get("rule") or history.get("top_rules") or []:
        value = str(row.get("value") or "")
        rule_id, _, history_title = value.partition(" | ")
        title = row.get("label") or history_title
        level = int(row.get("max_level") or 0)
        threats.append({
            "rule_id": rule_id or "-", "description": title or value or "Stored rule aggregate",
            "level": level, "count": int(row.get("count") or 0), "groups": ["materialized_rollup"],
            "source_ips": [], "threat_score": min(100, level * 5),
        })
    cached_tools = list(_tools_cache.get("tools") or [])
    tool_caps = _tool_capabilities(cached_tools)
    indexed = (sum(int(row.get("doc_count") or 0) for row in rollup.get("timeline") or [])
               if rollup_rows else int(totals.get("indexed_events") or 0))
    critical = int(totals.get("critical_cves") or 0)
    rollup_complete = bool((rollup.get("coverage") or {}).get("complete"))
    rollup_coverage = (rollup.get("coverage") or {}).get("gaps") or {}
    rollup_coverage_percent = rollup_coverage.get("coverage_percent")
    timeline_source = rollup.get("timeline") if rollup_rows else timeline_rows
    destination_rows = dimensions.get("destination_ip") or history.get("top_destinations") or []
    asset_rows = dimensions.get("asset") or history.get("affected_assets") or []
    decoder_rows = dimensions.get("decoder") or []
    mitre_rows = dimensions.get("mitre") or []
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "requested_range": window.get("requested"),
        "window": {"label": window.get("label"), "range": window.get("requested"), "bounds": window.get("bounds")},
        "materialization": {
            "status": "rollup" if rollup_complete else "building", "exact": rollup_complete,
            "source": "durable 5-minute detection rollups" if rollup_rows else "retained report summaries",
            "coverage": rollup.get("coverage") or {}, "bucket_minutes": rollup.get("bucket_minutes", 5),
            "note": ("The selected range is fully served from durable rollups."
                     if rollup_complete else "An exact Indexer snapshot is building in the background; available rollups and summaries remain visible meanwhile."),
        },
        "historical_detail": {
            "status": "available" if rollup_complete else "materializing",
            "l1": {"status": "unavailable" if rollup_complete else "materializing",
                    "message": ("Individual historical L1 alerts are not retained in the rollup." if rollup_complete
                                 else "Historical L1 detail is materializing in the background.")},
            "l2": {"status": "unavailable" if rollup_complete else "materializing",
                    "message": ("Historical L2 replay is not available from the bounded rollup." if rollup_complete
                                 else "Historical L2 correlation is materializing in the background.")},
        },
        "tools": {
            "total": len(cached_tools), "gensecai": sum(1 for row in cached_tools if row.get("source") == "gensecai"),
            "infokom": sum(1 for row in cached_tools if row.get("source") == "infokom"), "capabilities": tool_caps,
        },
        "analysis_funnel": {"indexed_events": indexed, "pipeline_status": "materializing", "ai_strategy": "case_and_rollup"},
        "alerts": {"time_range": window.get("label"), "total_alerts": indexed, "sampled": 0, "truncated": False,
                   "groups": {}, "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0}, "hourly": []},
        "threats": threats, "source_ips": source_ips, "l1_queue": [],
        "timeline": {"ok": bool(timeline_source), "bucket_interval": "materialized", "total_alerts": indexed,
                     "buckets": _timeline_buckets({"buckets": timeline_source})},
        "cloud_m365": {"ok": True, "total": 0, "workloads": [], "operations": [], "client_ips": [], "events": []},
        "detection_layers": [],
        "operational_evidence": {
            "data_quality": {
                "indexed_events": indexed,
                "decoder_named_events": None,
                "decoder_unmatched_events": None,
                "decoder_coverage_percent": None,
                "sampled_network_events": 0,
                "sampled_identity_events": 0,
                "sampled_limit_per_surface": 0,
                "bounded": True,
                "partial": not rollup_complete,
                "rollup_coverage_percent": rollup_coverage_percent,
                "source": "Durable 5-minute detection rollups",
                "note": ("Rollup is complete; decoder coverage requires an exact alert-window aggregation."
                         if rollup_complete else "Historical rollup is partial; missing buckets are being backfilled in the background."),
            },
            "network": {"events": [], "observed": 0}, "identity": {"events": [], "observed": 0},
            "mitre": {"techniques": [{"technique": row.get("value"), "count": row.get("count")}
                                      for row in mitre_rows], "timeline": [], "observed": len(mitre_rows)},
            "decoders": {"items": [{"name": row.get("value"), "count": row.get("count"),
                                      "max_level": row.get("max_level"), "last_seen": row.get("last_seen"),
                                      "rule": row.get("label")} for row in decoder_rows],
                         "observed": len(decoder_rows), "named_events": None, "coverage_percent": None,
                         "unmatched_events": None,
                         "note": "Materialized decoder volume; failed decoder telemetry requires manager metrics."},
            "telemetry": {"indexer": {"health": "materializing", "scope": "Exact historical aggregation is building."}},
        },
        "provider_freshness": _provider_freshness(),
        "fim": {"total": 0, "top_paths": [], "top_agents": []}, "auth": {"ok": True, "events": 0},
        "web": {"ok": True, "events": 0},
        "attack_surface": {
            "sources": source_ips, "web_recon": [],
            "targets": [{"name": row.get("value"), "alerts": row.get("count"), "rules": []}
                        for row in asset_rows], "destinations": destination_rows, "cities": [],
        },
        "agents": {"total": 0, "counts": {}, "platforms": {}, "items": [], "context": [], "context_coverage": {}},
        "three_sum": {"ok": True, "categories": [], "candidate_count": 0},
        "ai_recon": {"ok": True, "ai_agent_sources": 0, "sources": []},
        "vulnerabilities": {"total": critical, "affected_agents": 0, "critical": critical, "high": 0,
                            "medium": 0, "low": 0, "by_severity": {}, "critical_items": [],
                            "evidence_coverage": {"wazuh_inventory": bool(critical)}},
        "soc_lanes": {"l1": {"open_alerts": indexed, "active_agents": 0, "queue": threats[:6]},
                      "l2": {"ai_recon_sources": 0, "critical_vulnerabilities": critical, "correlation_categories": []},
                      "l3": {"hunting_tools": tool_caps.get("l3_hunting", {}), "response_tools": tool_caps.get("response", {}),
                             "compliance_tools": tool_caps.get("compliance", {})}},
        "errors": {},
    }


def _historical_snapshot_placeholder(window: dict[str, Any]) -> dict[str, Any]:
    """Return a truthful, bounded response while the first long-range snapshot builds."""
    cached_tools = list(_tools_cache.get("tools") or [])
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "requested_range": window.get("requested"),
        "window": {"label": window.get("label"), "range": window.get("requested"), "bounds": window.get("bounds")},
        "materialization": {"status": "building", "exact": False, "source": "background historical materializer",
                             "coverage": {}, "note": "Historical detail is materializing asynchronously; no live Indexer query is held open."},
        "historical_detail": {
            "status": "materializing",
            "l1": {"status": "materializing", "message": "Historical L1 detail is materializing in the background."},
            "l2": {"status": "materializing", "message": "Historical L2 correlation is materializing in the background."},
        },
        "tools": {"total": len(cached_tools), "gensecai": sum(1 for row in cached_tools if row.get("source") == "gensecai"),
                  "infokom": sum(1 for row in cached_tools if row.get("source") == "infokom"),
                  "capabilities": _tool_capabilities(cached_tools)},
        "analysis_funnel": {"indexed_events": None, "pipeline_status": "materializing", "ai_strategy": "case_and_rollup"},
        "alerts": {"time_range": window.get("label"), "total_alerts": None, "sampled": 0, "truncated": False,
                   "groups": {}, "severity": {}, "hourly": []},
        "threats": [], "source_ips": [], "l1_queue": [],
        "timeline": {"ok": False, "bucket_interval": "pending", "total_alerts": None, "buckets": []},
        "cloud_m365": {"ok": False, "status": "materializing", "total": None, "workloads": [], "operations": [], "client_ips": [], "events": []},
        "detection_layers": [],
        "operational_evidence": {"data_quality": {"indexed_events": None, "partial": True, "source": "background historical materializer",
                                                   "note": "Exact decoder and telemetry detail is not available until materialization completes."},
                                 "network": {"events": [], "observed": 0}, "identity": {"events": [], "observed": 0},
                                 "mitre": {"techniques": [], "timeline": [], "observed": 0},
                                 "decoders": {"items": [], "observed": 0, "named_events": None, "coverage_percent": None, "unmatched_events": None},
                                 "telemetry": {"indexer": {"health": "materializing", "scope": "Background historical aggregation is running."}}},
        "provider_freshness": _provider_freshness(), "fim": {"total": 0, "top_paths": [], "top_agents": []},
        "auth": {"ok": False, "status": "materializing", "events": None}, "web": {"ok": False, "status": "materializing", "events": None},
        "attack_surface": {"sources": [], "web_recon": [], "targets": [], "destinations": [], "cities": []},
        "agents": {"total": None, "counts": {}, "platforms": {}, "items": [], "context": [], "context_coverage": {}},
        "three_sum": {"ok": False, "status": "materializing", "categories": [], "candidate_count": 0},
        "ai_recon": {"ok": False, "status": "materializing", "ai_agent_sources": 0, "sources": []},
        "vulnerabilities": {"total": None, "affected_agents": None, "critical": None, "high": None, "medium": None, "low": None,
                            "by_severity": {}, "critical_items": [], "evidence_coverage": {"wazuh_inventory": False}},
        "soc_lanes": {"l1": {"open_alerts": None, "active_agents": None, "queue": []},
                      "l2": {"ai_recon_sources": None, "critical_vulnerabilities": None, "correlation_categories": []},
                      "l3": {"hunting_tools": {}, "response_tools": {}, "compliance_tools": {}}},
        "errors": {},
    }


def _ensure_historical_detail(data: dict[str, Any], window: dict[str, Any]) -> dict[str, Any]:
    """Backfill explicit L1/L2 availability on snapshots created before the status contract."""
    if window.get("requested") not in {"7d", "30d", "custom"} or data.get("historical_detail"):
        return data
    exact = bool((data.get("materialization") or {}).get("exact"))
    status = "partial" if exact else "materializing"
    message = ("Historical detail is not replayed by the bounded overview snapshot."
               if exact else "Historical detail is materializing in the background.")
    data["historical_detail"] = {
        "status": status,
        "l1": {"status": "unavailable" if exact else "materializing", "message": message},
        "l2": {"status": "unavailable" if exact else "materializing", "message": message},
    }
    return data


def _overview_cached(payload: Any = "24h") -> dict[str, Any]:
    force_refresh = isinstance(payload, dict) and bool(payload.get("force"))
    window = _window_from_payload(payload)
    cache_key = _overview_cache_key(window)
    ttl = _overview_cache_ttl(window)
    cached = _overview_cache_read(cache_key)
    now = time.time()
    if cached and cached["expires_at"] > now and not force_refresh:
        data = dict(cached["data"])
        _ensure_historical_detail(data, window)
        data["cache"] = {
            **(data.get("cache") or {}),
            "status": "hit",
            "age_seconds": int(now - cached["created_at"]),
            "ttl_seconds": ttl,
        }
        return data
    if cached and not force_refresh:
        data = dict(cached["data"])
        _ensure_historical_detail(data, window)
        data["cache"] = {
            **(data.get("cache") or {}),
            "status": "stale-refreshing",
            "age_seconds": int(now - cached["created_at"]),
            "ttl_seconds": ttl,
        }
        _overview_refresh_async(cache_key, window, payload, ttl)
        return data
    if not cached and not force_refresh and window.get("requested") in {"7d", "30d", "custom"}:
        result: dict[str, Any] = {}
        completed = threading.Event()
        def materialize_fast() -> None:
            try:
                result["data"] = _materialized_overview(window, payload)
            finally:
                completed.set()
        threading.Thread(target=materialize_fast, daemon=True).start()
        completed.wait(0.05)
        data = result.get("data") or _historical_snapshot_placeholder(window)
        if data.get("materialization", {}).get("exact"):
            data["cache"] = {"status": "rollup", "age_seconds": 0, "ttl_seconds": ttl}
            return data
        _overview_refresh_async(cache_key, window, payload, ttl)
        data["cache"] = {"status": "building", "age_seconds": 0, "ttl_seconds": ttl}
        return data
    data = _overview(payload)
    try:
        _overview_cache_write(cache_key, window, data, ttl)
    except Exception as exc:
        data["cache"] = {"status": "bypass", "error": str(exc), "ttl_seconds": ttl}
        return data
    stored = _overview_cache_read(cache_key)
    return stored["data"] if stored else data


def _overview_prewarm_loop() -> None:
    if not PREWARM_ENABLED:
        return
    time.sleep(5)
    while True:
        for requested in PREWARM_RANGES:
            try:
                window = _window_from_payload({"range": requested})
                ttl = _overview_cache_ttl(window)
                cache_key = _overview_cache_key(window)
                cached = _overview_cache_read(cache_key)
                age = time.time() - cached["created_at"] if cached else ttl + 1
                if not cached or age >= max(30, ttl * 0.8):
                    _overview_refresh_async(cache_key, window, {"range": requested}, ttl)
                    # One materialization per cycle keeps long-range scans from
                    # competing with alert ingestion and interactive queries.
                    break
            except Exception:
                pass
        time.sleep(60)


def _start_overview_prewarm() -> None:
    threading.Thread(target=_overview_prewarm_loop, daemon=True).start()


def _histogram_interval(window: dict[str, Any]) -> str:
    if window.get("requested") == "custom":
        try:
            start = datetime.fromisoformat(window["bounds"]["gte"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(window["bounds"]["lt"].replace("Z", "+00:00"))
            hours = max(1, (end - start).total_seconds() / 3600)
            if hours <= 48:
                return "1h"
            if hours <= 24 * 14:
                return "6h"
        except Exception:
            pass
    return {"24h": "1h", "7d": "6h", "30d": "1d"}.get(window.get("tool_range"), "1h")


def _source_value(source: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value: Any = source
        for key in path.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        if value not in (None, "", []):
            return value
    return None


def _operational_evidence(data: dict[str, Any], elapsed_ms: int) -> dict[str, Any]:
    aggs = data.get("aggregations", {}) if isinstance(data, dict) else {}
    total_raw = ((data.get("hits") or {}).get("total") or {}) if isinstance(data, dict) else {}
    total_events = int(total_raw.get("value", 0) if isinstance(total_raw, dict) else total_raw or 0)

    def samples(name: str, mapper) -> list[dict[str, Any]]:
        hits = (((aggs.get(name) or {}).get("sample") or {}).get("hits") or {}).get("hits") or []
        return [mapper(hit.get("_source") or {}) for hit in hits]

    network = samples("network_events", lambda source: {
        "timestamp": source.get("@timestamp"),
        "source": _source_value(source, "data.srcip", "data.src_ip", "data.source.ip"),
        "destination": _source_value(source, "data.dstip", "data.dst_ip", "data.destination.ip"),
        "port": _source_value(source, "data.dstport", "data.dst_port", "data.destination.port", "data.service"),
        "application": _source_value(source, "data.app", "data.application", "data.appcat", "data.service"),
        "policy": _source_value(source, "data.policyid", "data.policy_id", "data.policyname", "data.rule_name"),
        "action": _source_value(source, "data.action", "data.event.action", "data.status"),
        "direction": _source_value(source, "data.direction", "data.flow_direction"),
        "decoder": _source_value(source, "decoder.name"),
        "agent": _source_value(source, "agent.name", "agent.id"),
    })
    identity = samples("identity_events", lambda source: {
        "timestamp": source.get("@timestamp"),
        "user": _source_value(source, "data.office365.UserId", "data.dstuser", "data.srcuser", "data.win.eventdata.targetUserName", "data.user"),
        "mailbox": _source_value(source, "data.office365.MailboxOwnerUPN", "data.office365.ObjectId"),
        "operation": _source_value(source, "data.office365.Operation", "data.win.system.eventID", "data.action"),
        "privilege": _source_value(source, "data.win.eventdata.privilegeList", "data.office365.ModifiedProperties"),
        "session": _source_value(source, "data.win.eventdata.targetLogonId", "data.office365.SessionId", "data.sessionid"),
        "authentication": _source_value(source, "data.win.eventdata.authenticationPackageName", "data.office365.AuthenticationType", "data.auth_method"),
        "source_ip": _source_value(source, "data.office365.ClientIP", "data.win.eventdata.ipAddress", "data.srcip"),
        "agent": _source_value(source, "agent.name", "agent.id"),
    })
    decoders = []
    for bucket in (aggs.get("decoders") or {}).get("buckets", []):
        latest = ((((bucket.get("sample") or {}).get("hits") or {}).get("hits") or [{}])[0].get("_source") or {})
        decoders.append({
            "name": str(bucket.get("key") or "unknown"), "count": int(bucket.get("doc_count") or 0),
            "max_level": int((bucket.get("max_level") or {}).get("value") or 0),
            "last_seen": latest.get("@timestamp"),
            "rule": _source_value(latest, "rule.description"),
        })
    mitre = [{"technique": str(row.get("key")), "count": int(row.get("doc_count") or 0)}
             for row in (aggs.get("mitre_techniques") or {}).get("buckets", [])]
    mitre_timeline = []
    for bucket in (aggs.get("mitre_timeline") or {}).get("buckets", []):
        techniques = [
            {"technique": str(row.get("key")), "count": int(row.get("doc_count") or 0)}
            for row in ((bucket.get("techniques") or {}).get("buckets") or [])
        ]
        if techniques:
            mitre_timeline.append({"timestamp": bucket.get("key_as_string"), "techniques": techniques})
    telemetry = {}
    for key in ("dropped_events", "agent_flooding", "manager_queue"):
        telemetry[key] = int((aggs.get(key) or {}).get("doc_count") or 0)
    shards = data.get("_shards") or {}
    telemetry["indexer"] = {
        "request_ms": elapsed_ms,
        "query_took_ms": int(data.get("took") or 0),
        "timed_out": bool(data.get("timed_out")),
        "shards_total": int(shards.get("total") or 0),
        "shards_successful": int(shards.get("successful") or 0),
        "shards_failed": int(shards.get("failed") or 0),
        "health": "degraded" if data.get("timed_out") or shards.get("failed") else "healthy",
        "scope": "Current bounded dashboard query; cluster-wide health endpoint is not queried.",
    }
    decoder_named = int((aggs.get("decoder_named_events") or {}).get("doc_count") or 0)
    decoder_unmatched = int((aggs.get("unmatched_decoder") or {}).get("doc_count") or 0)
    decoder_coverage = round(decoder_named / total_events * 100, 2) if total_events else None
    return {
        "data_quality": {
            "indexed_events": total_events,
            "decoder_named_events": decoder_named,
            "decoder_unmatched_events": decoder_unmatched,
            "decoder_coverage_percent": decoder_coverage,
            "sampled_network_events": len(network),
            "sampled_identity_events": len(identity),
            "sampled_limit_per_surface": 12,
            "bounded": True,
            "partial": bool(data.get("timed_out")) or bool(shards.get("failed")),
            "source": "Wazuh Indexer alert aggregation",
            "note": "Counts are exact for the selected alert window; detail tables are bounded samples.",
        },
        "network": {"events": network, "observed": len(network), "sample_limit": 12},
        "identity": {"events": identity, "observed": len(identity), "sample_limit": 12},
        "mitre": {"techniques": mitre, "timeline": mitre_timeline, "observed": len(mitre), "bucket_limit": 20},
        "decoders": {"items": decoders, "observed": len(decoders), "bucket_limit": 20,
                     "named_events": decoder_named, "coverage_percent": decoder_coverage,
                     "unmatched_events": decoder_unmatched,
                     "failed_events": None,
                     "note": "Decoder failures require Wazuh manager/archive metrics; unmatched counts only mean decoder.name was absent."},
        "telemetry": telemetry,
    }


def _local_alert_window(window: dict[str, Any]) -> dict[str, Any]:
    interval = _histogram_interval(window)
    payload = {
        "track_total_hits": True,
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"@timestamp": window["bounds"]}}]}},
        "aggs": {
            "severity": {"terms": {"field": "rule.level", "size": 32}},
            "timeline": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval}},
            "rules": {
                "terms": {"field": "rule.id", "size": 10},
                "aggs": {
                    "sample": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["rule", "agent", "data.srcip", "data.office365.ClientIP", "GeoLocation", "location"],
                        }
                    }
                },
            },
            "srcip": {"terms": {"field": "data.srcip", "size": 20}},
            "l1_alerts": {"filter": {"range": {"rule.level": {"gte": 7}}}, "aggs": {
                "sample": {"top_hits": {"size": 20, "sort": [{"@timestamp": {"order": "desc"}}],
                    "_source": ["@timestamp", "rule", "agent", "decoder", "data.srcip", "data.dstip",
                                "data.dstport", "data.office365.ClientIP", "data.office365.UserId"]}}
            }},
            "network_events": {"filter": {"bool": {"should": [
                {"exists": {"field": "data.dstip"}}, {"exists": {"field": "data.dst_ip"}},
                {"exists": {"field": "data.destination.ip"}}, {"exists": {"field": "data.dstport"}}
            ], "minimum_should_match": 1}}, "aggs": {"sample": {"top_hits": {"size": 12,
                "sort": [{"@timestamp": {"order": "desc"}}], "_source": ["@timestamp", "agent", "decoder", "data"]}}}},
            "identity_events": {"filter": {"bool": {"should": [
                {"exists": {"field": "data.office365.UserId"}}, {"exists": {"field": "data.dstuser"}},
                {"exists": {"field": "data.srcuser"}}, {"exists": {"field": "data.win.eventdata.targetUserName"}}
            ], "minimum_should_match": 1}}, "aggs": {"sample": {"top_hits": {"size": 12,
                "sort": [{"@timestamp": {"order": "desc"}}], "_source": ["@timestamp", "agent", "data"]}}}},
            "mitre_techniques": {"terms": {"field": "rule.mitre.id", "size": 20}},
            "mitre_timeline": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval}, "aggs": {
                "techniques": {"terms": {"field": "rule.mitre.id", "size": 8}}
            }},
            "decoders": {"terms": {"field": "decoder.name", "size": 20}, "aggs": {
                "max_level": {"max": {"field": "rule.level"}}, "sample": {"top_hits": {"size": 1,
                    "sort": [{"@timestamp": {"order": "desc"}}], "_source": ["@timestamp", "rule.description"]}}}},
            "decoder_named_events": {"filter": {"exists": {"field": "decoder.name"}}},
            "unmatched_decoder": {"filter": {"bool": {"must_not": [{"exists": {"field": "decoder.name"}}]}}},
            "dropped_events": {"filter": {"bool": {"should": [
                {"term": {"rule.groups": "event_dropped"}}, {"match_phrase": {"rule.description": "event dropped"}},
                {"match_phrase": {"rule.description": "events dropped"}}
            ], "minimum_should_match": 1}}},
            "agent_flooding": {"filter": {"bool": {"should": [
                {"term": {"rule.groups": "agent_flooding"}}, {"match_phrase": {"rule.description": "agent event queue"}}
            ], "minimum_should_match": 1}}},
            "manager_queue": {"filter": {"bool": {"should": [
                {"term": {"rule.groups": "wazuh_manager"}}, {"match_phrase": {"rule.description": "manager queue"}}
            ], "minimum_should_match": 1}}},
            "m365": {"filter": {"exists": {"field": "data.office365.Workload"}}, "aggs": {
                "workload": {"terms": {"field": "data.office365.Workload", "size": 10}},
                "operation": {"terms": {"field": "data.office365.Operation", "size": 10}},
                "client_ip": {"terms": {"field": "data.office365.ClientIP", "size": 10}},
                "subscription": {"terms": {"field": "data.office365.Subscription", "size": 10}},
                "sample": {"top_hits": {"size": 8, "sort": [{"@timestamp": {"order": "desc"}}],
                    "_source": ["@timestamp", "rule", "data.office365"]}},
            }},
        },
    }
    started = time.monotonic()
    try:
        data = _indexer_search(payload)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    elapsed_ms = int((time.monotonic() - started) * 1000)
    aggs = data.get("aggregations", {}) if isinstance(data, dict) else {}
    total_raw = ((data.get("hits") or {}).get("total") or {}) if isinstance(data, dict) else {}
    total = int(total_raw.get("value", 0) if isinstance(total_raw, dict) else total_raw or 0)
    severity = {str(row.get("key")): int(row.get("doc_count", 0) or 0) for row in aggs.get("severity", {}).get("buckets", [])}
    threats: list[dict[str, Any]] = []
    for row in aggs.get("rules", {}).get("buckets", []):
        hit_rows = (((row.get("sample") or {}).get("hits") or {}).get("hits") or [])
        src = hit_rows[0].get("_source", {}) if hit_rows else {}
        rule = src.get("rule") or {}
        data_fields = src.get("data") or {}
        source_ip = data_fields.get("srcip") or ((data_fields.get("office365") or {}).get("ClientIP"))
        threat = {
            "rule_id": str(row.get("key")),
            "description": rule.get("description") or "Wazuh rule match",
            "level": int(rule.get("level", 0) or 0),
            "count": int(row.get("doc_count", 0) or 0),
            "groups": rule.get("groups", []) or [],
            "source_ips": [source_ip] if source_ip else [],
            "agent": (src.get("agent") or {}).get("name"),
            "threat_score": min(100, int(rule.get("level", 0) or 0) * 4 + min(40, int(row.get("doc_count", 0) or 0) // 10)),
        }
        threat["analysis"] = explain_rule(threat)
        threats.append(threat)
    source_ips = [
        {"ip": str(row.get("key")), "hits": int(row.get("doc_count", 0) or 0), "max_score": 0, "rules": []}
        for row in aggs.get("srcip", {}).get("buckets", [])
    ]
    l1_queue = []
    l1_hits = ((((aggs.get("l1_alerts") or {}).get("sample") or {}).get("hits") or {}).get("hits") or [])
    for hit in l1_hits:
        source = hit.get("_source") or {}
        rule = source.get("rule") or {}
        fields = source.get("data") or {}
        office365 = fields.get("office365") if isinstance(fields.get("office365"), dict) else {}
        level = int(rule.get("level") or 0)
        l1_queue.append({
            "event_id": hit.get("_id"), "index": hit.get("_index"), "timestamp": source.get("@timestamp"),
            "rule_id": str(rule.get("id") or "-"), "title": rule.get("description") or "Wazuh alert",
            "level": level, "groups": rule.get("groups") or [],
            "source_ip": fields.get("srcip") or office365.get("ClientIP"),
            "destination_ip": fields.get("dstip"), "destination_port": fields.get("dstport"),
            "identity": office365.get("UserId"),
            "agent": (source.get("agent") or {}).get("name"),
            "decoder": (source.get("decoder") or {}).get("name"),
            "assignment": "unassigned", "status": "new",
            "sla_minutes": 15 if level >= 15 else 30 if level >= 12 else 120,
        })
    m365_agg = aggs.get("m365") or {}
    m365_events = []
    for hit in ((((m365_agg.get("sample") or {}).get("hits") or {}).get("hits") or [])):
        source = hit.get("_source") or {}
        office365 = ((source.get("data") or {}).get("office365") or {})
        rule = source.get("rule") or {}
        m365_events.append({
            "timestamp": source.get("@timestamp"), "description": rule.get("description"),
            "analysis": explain_rule(rule), "level": rule.get("level", 0),
            "workload": office365.get("Workload"), "operation": office365.get("Operation"),
            "user": office365.get("UserId"), "client_ip": office365.get("ClientIP"),
            "subscription": office365.get("Subscription"), "object": office365.get("ObjectId"),
        })
    cloud_m365 = {
        "ok": True, "total": int(m365_agg.get("doc_count") or 0),
        "workloads": (m365_agg.get("workload") or {}).get("buckets", []),
        "operations": (m365_agg.get("operation") or {}).get("buckets", []),
        "client_ips": (m365_agg.get("client_ip") or {}).get("buckets", []),
        "subscriptions": (m365_agg.get("subscription") or {}).get("buckets", []),
        "events": m365_events, "source": "shared overview aggregation",
    }
    return {
        "ok": True,
        "alert_data": {
            "time_range": window["label"],
            "total_alerts": total,
            "alerts_sampled": min(total, 1000),
            "truncated": total > 1000,
            "groups": severity,
        },
        "threats": threats,
        "source_ips": source_ips,
        "l1_queue": l1_queue,
        "cloud_m365": cloud_m365,
        "timeline": {
            "bucket_interval": interval,
            "total_alerts": total,
            "buckets": [
                {"key": row.get("key_as_string"), "doc_count": int(row.get("doc_count", 0) or 0)}
                for row in aggs.get("timeline", {}).get("buckets", [])[:160]
            ],
        },
        "operational_evidence": _operational_evidence(data, elapsed_ms),
    }


def _cloud_m365_summary(window: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "track_total_hits": True,
        "size": 8,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": window["bounds"]}},
                    {"exists": {"field": "data.office365.Workload"}},
                ]
            }
        },
        "aggs": {
            "workload": {"terms": {"field": "data.office365.Workload", "size": 10}},
            "operation": {"terms": {"field": "data.office365.Operation", "size": 10}},
            "client_ip": {"terms": {"field": "data.office365.ClientIP", "size": 10}},
            "subscription": {"terms": {"field": "data.office365.Subscription", "size": 10}},
        },
        "_source": [
            "@timestamp",
            "rule.description",
            "rule.level",
            "rule.groups",
            "location",
            "data.office365.Workload",
            "data.office365.Operation",
            "data.office365.UserId",
            "data.office365.ClientIP",
            "data.office365.Subscription",
            "data.office365.ObjectId",
        ],
    }
    try:
        data = _indexer_search(payload)
    except Exception as exc:
        return {"ok": False, "total": 0, "error": str(exc), "workloads": [], "operations": [], "client_ips": [], "events": []}
    aggs = data.get("aggregations", {}) if isinstance(data, dict) else {}
    hits = data.get("hits", {}) if isinstance(data, dict) else {}
    total = hits.get("total", {})
    events = []
    for hit in hits.get("hits", []) if isinstance(hits, dict) else []:
        source = hit.get("_source", {})
        o365 = ((source.get("data") or {}).get("office365") or {}) if isinstance(source, dict) else {}
        rule = source.get("rule") or {}
        events.append({
            "timestamp": source.get("@timestamp"),
            "description": rule.get("description"),
            "analysis": explain_rule(rule),
            "level": rule.get("level", 0),
            "workload": o365.get("Workload"),
            "operation": o365.get("Operation"),
            "user": o365.get("UserId"),
            "client_ip": o365.get("ClientIP"),
            "subscription": o365.get("Subscription"),
            "object": o365.get("ObjectId"),
        })
    return {
        "ok": True,
        "total": int(total.get("value", 0) if isinstance(total, dict) else total or 0),
        "workloads": aggs.get("workload", {}).get("buckets", []),
        "operations": aggs.get("operation", {}).get("buckets", []),
        "client_ips": aggs.get("client_ip", {}).get("buckets", []),
        "subscriptions": aggs.get("subscription", {}).get("buckets", []),
        "events": events,
    }


def _count_log_lines(text: str) -> int:
    if not text or text.lower().startswith("no "):
        return 0
    return len([line for line in text.splitlines() if line.strip() and not line.startswith("Error ")])


def _detection_layers(
    alert_data: dict[str, Any],
    threats: list[dict[str, Any]],
    source_ips: list[dict[str, Any]],
    fim: dict[str, Any],
    ai_data: dict[str, Any],
    auth_count: int,
    web_count: int,
    vuln_data: dict[str, Any],
    cloud_data: dict[str, Any],
) -> list[dict[str, Any]]:
    total_alerts = int(alert_data.get("total_alerts", 0) or 0)
    firewall_count = 0
    nids_count = 0
    docker_count = 0
    m365_count = 0
    for threat in threats:
        haystack = " ".join([
            str(threat.get("description", "")),
            " ".join(str(group) for group in threat.get("groups", []) or []),
        ]).lower()
        count = int(threat.get("count", 0) or 0)
        if any(word in haystack for word in ("fortigate", "firewall", "syslog")):
            firewall_count += count
        if any(word in haystack for word in ("icmp", "scan", "port", "nids", "suricata", "ids")):
            nids_count += count
        if any(word in haystack for word in ("docker", "container", "containerd", "kubernetes", "k8s")):
            docker_count += count
        if any(word in haystack for word in ("office365", "office 365", "microsoft 365", "o365", "azure", "entra", "graph")):
            m365_count += count
    web_recon = sum(int(row.get("alerts", 0) or 0) for row in ai_data.get("sources", [])[:10]) if isinstance(ai_data, dict) else 0
    layers = [
        {
            "key": "fim",
            "name": "FIM / Integrity",
            "count": int(fim.get("total", 0) or 0),
            "signal": "File and registry change monitoring",
            "tool": "blueteam_wazuh_syscheck",
            "status": "active" if fim.get("total") else "ready",
        },
        {
            "key": "auth",
            "name": "Authentication",
            "count": auth_count,
            "signal": "SSH, sudo, PAM, failed login traces",
            "tool": "blueteam_failed_logins",
            "status": "active" if auth_count else "ready",
        },
        {
            "key": "network",
            "name": "Network IDS / Firewall",
            "count": firewall_count + nids_count + len(source_ips),
            "signal": "Fortigate/syslog, ICMP, port scanning, source IP clusters",
            "tool": "blueteam_wazuh_alerts",
            "status": "active" if firewall_count or nids_count or source_ips else "ready",
        },
        {
            "key": "web",
            "name": "Web / DVWA Recon",
            "count": web_recon + web_count,
            "signal": "Sensitive path probes, web access logs, app-layer attacks",
            "tool": "blueteam_ai_bot_recon",
            "status": "active" if web_recon or web_count else "ready",
        },
        {
            "key": "container",
            "name": "Container / Docker",
            "count": docker_count,
            "signal": "Docker engine, container runtime, image and process telemetry",
            "tool": "wazuh_alert_aggregate_analysis",
            "status": "active" if docker_count else "ready",
        },
        {
            "key": "cloud",
            "name": "Cloud / Microsoft 365",
            "count": int(cloud_data.get("total", 0) or m365_count),
            "signal": "Office 365, Azure/Entra, Graph and SaaS audit activity",
            "tool": "wazuh_alert_aggregate_analysis",
            "status": "active" if cloud_data.get("total") or m365_count else "ready",
        },
        {
            "key": "vuln",
            "name": "Vulnerability Exposure",
            "count": int(vuln_data.get("total_vulnerabilities", 0) or 0),
            "signal": "CVE, EPSS, KEV, PoC, affected packages",
            "tool": "blueteam_cve_score",
            "status": "active" if vuln_data.get("total_vulnerabilities") else "ready",
        },
        {
            "key": "siem",
            "name": "SIEM Correlation",
            "count": total_alerts,
            "signal": "Rules, severity, MITRE tags, 3-Sum correlation",
            "tool": "advanced_three_sum_correlation",
            "status": "active" if total_alerts else "ready",
        },
    ]
    return layers


def _attack_surface(
    threats: list[dict[str, Any]],
    source_ips: list[dict[str, Any]],
    ai_data: dict[str, Any],
    geo: dict[str, Any],
) -> dict[str, Any]:
    targets: dict[str, dict[str, Any]] = {}
    for threat in threats:
        for agent in threat.get("affected_agents", []) or []:
            name = str(agent.get("name") or agent.get("id") or "unknown")
            row = targets.setdefault(name, {"name": name, "alerts": 0, "rules": set()})
            row["alerts"] += int(threat.get("count", 0) or 0)
            if threat.get("rule_id"):
                row["rules"].add(str(threat["rule_id"]))
    ai_sources = ai_data.get("sources", [])[:10] if isinstance(ai_data, dict) else []
    return {
        "sources": source_ips[:16],
        "web_recon": ai_sources,
        "targets": [
            {"name": row["name"], "alerts": row["alerts"], "rules": sorted(row["rules"])[:5]}
            for row in sorted(targets.values(), key=lambda item: item["alerts"], reverse=True)[:10]
        ],
        "cities": geo.get("cities", [])[:12],
    }


def _tool_capabilities(tools: list[dict[str, Any]]) -> dict[str, Any]:
    buckets = {
        "l1_triage": ("alert", "agent", "summary", "health", "search_security"),
        "l2_investigation": ("three_sum", "correlation", "threat_intelligence", "ioc", "ai_bot", "vulnerab", "cve"),
        "l3_hunting": ("attack_graph", "threat_hunt", "stix", "dependency", "semantic", "playbook", "report", "case"),
        "threat_intel": ("threatfox", "greynoise", "otx", "crowdsec", "ioc", "reputation", "abuse"),
        "hunt": ("hunt", "ioc", "attack", "stix", "sigma", "yara", "recon"),
        "vulnerability": ("vulnerab", "cve", "epss", "kev", "poc", "ssvc", "advisory"),
        "dependency": ("dependency", "package", "sbom", "library"),
        "response": ("active_response", "block", "isolate", "quarantine", "kill_process", "firewall", "host_deny"),
        "compliance": ("iso27001", "compliance", "sca", "pci", "gdpr", "hipaa"),
    }
    result: dict[str, Any] = {}
    for bucket, needles in buckets.items():
        matched = []
        for tool in tools:
            name = str(tool.get("name", "")).lower()
            if any(needle in name for needle in needles):
                matched.append({"name": tool.get("name"), "source": tool.get("source")})
        result[bucket] = {"count": len(matched), "tools": matched[:18]}
    return result


def _normalize_range(value: Any) -> str:
    value = str(value or "24h").lower()
    return value if value in {"24h", "7d", "30d"} else "24h"


def _overview(payload: Any = "24h") -> dict[str, Any]:
    window = _window_from_payload(payload)
    time_range = window["tool_range"]
    catalog = _tool_catalog()
    errors: dict[str, str] = dict(catalog["errors"])
    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    local_alerts = _local_alert_window(window)
    if not local_alerts.get("ok"):
        errors["local_index_aggregation"] = local_alerts.get("error", "unavailable")
    historical_window = window.get("requested") in {"7d", "30d", "custom"}

    if local_alerts.get("ok"):
        alert_summary = {"ok": True, "data": {"data": local_alerts.get("alert_data") or {}}}
        top_threats = {"ok": True, "data": {"data": {"threats": local_alerts.get("threats") or []}}}
        timeline = {"ok": True, "data": local_alerts.get("timeline") or {}}
    else:
        alert_summary = _safe_call("gensecai", "get_wazuh_alert_summary", {
            "time_range": time_range, "group_by": "rule.level",
        })
        top_threats = _safe_call("gensecai", "get_top_security_threats", {
            "limit": 10, "time_range": time_range,
        })
        timeline = _safe_call("infokom", "wazuh_alert_timeline", {
            "params": {"since": time_range, "bucket": "auto", "response_format": "json"}
        })
    agents = _safe_call("gensecai", "get_wazuh_agents", {"limit": 100})
    three_sum = ({"ok": True, "data": {"categories": {}, "historical_skip": True}}
                 if historical_window else _safe_call("gensecai", "advanced_three_sum_correlation", {
                     "lookback_minutes": 60, "threshold_score": 35,
                 }))
    ai_recon = ({"ok": True, "data": {"sources": [], "historical_skip": True}}
                if historical_window else _safe_call("infokom", "blueteam_ai_bot_recon", {
                    "since": time_range, "top_n": 10, "response_format": "json",
                }))
    vuln_summary = _safe_call("gensecai", "get_wazuh_vulnerability_summary", {})
    critical_vulns = _safe_call("gensecai", "get_wazuh_critical_vulnerabilities", {"limit": 10})
    statistics = ({"ok": True, "data": {}} if historical_window else _safe_call("gensecai", "get_wazuh_statistics", {}))
    geo_heatmap = ({"ok": True, "data": {"historical_skip": True}} if historical_window else
                   _safe_call("infokom", "blueteam_wazuh_geo_heatmap", {
                       "since": time_range, "top_n": 30, "response_format": "json",
                   }))
    fim_events = ({"ok": True, "data": {"historical_skip": True}} if historical_window else
                  _safe_call("infokom", "blueteam_wazuh_syscheck", {
                      "since": time_range, "top_n": 20, "response_format": "json",
                  }))
    auth_log = ({"ok": True, "text": ""} if historical_window else
                _safe_call("infokom", "blueteam_failed_logins", {"bypass_redaction": False}))
    web_log = ({"ok": True, "text": ""} if historical_window else
               _safe_call("infokom", "blueteam_read_web_log", {
                   "server": "nginx", "log_type": "access", "lines": 300,
                   "grep": "DVWA|.env|wp-|php|select|union|cmd|shell|passwd", "bypass_redaction": False,
               }))

    alert_data = (alert_summary.get("data") or {}).get("data", {})
    threat_data = (top_threats.get("data") or {}).get("data", {})
    agents_data = (agents.get("data") or {}).get("data", {})
    three_data = three_sum.get("data") or {}
    ai_data = ai_recon.get("data") or {}
    vuln_data = (vuln_summary.get("data") or {}).get("data", {})
    critical_vuln_data = (critical_vulns.get("data") or {}).get("data", {})
    stats_data = statistics.get("data") or {}
    timeline_data = timeline.get("data") or {}
    geo_data = geo_heatmap.get("data") or {}
    fim_data = fim_events.get("data") or {}
    auth_text = auth_log.get("text", "")
    web_text = web_log.get("text", "")

    for key, result in {
        "alert_summary": alert_summary,
        "top_threats": top_threats,
        "agents": agents,
        "three_sum": three_sum,
        "ai_recon": ai_recon,
        "vuln_summary": vuln_summary,
        "critical_vulns": critical_vulns,
        "statistics": statistics,
        "timeline": timeline,
        "geo_heatmap": geo_heatmap,
        "fim_events": fim_events,
        "auth_log": auth_log,
        "web_log": web_log,
    }.items():
        if not result["ok"]:
            errors[key] = result.get("error") or result.get("text", "")

    agent_items = agents_data.get("affected_items", []) if isinstance(agents_data, dict) else []
    agent_counts: dict[str, int] = {}
    platforms: dict[str, int] = {}
    for agent in agent_items:
        status = str(agent.get("status", "unknown"))
        agent_counts[status] = agent_counts.get(status, 0) + 1
        os_data = agent.get("os") or {}
        platform = str(os_data.get("platform") or os_data.get("name") or "unknown")
        platforms[platform] = platforms.get(platform, 0) + 1

    categories = three_data.get("categories", {}) if isinstance(three_data, dict) else {}
    three_categories = []
    for name, details in categories.items():
        if isinstance(details, dict):
            three_categories.append({
                "name": name,
                "ip_count": details.get("ip_count", 0),
                "entries": len(details.get("entries", []) or []),
            })
    three_candidate_count = sum(int(row.get("ip_count", 0) or row.get("entries", 0) or 0) for row in three_categories)

    tools = catalog["tools"]
    threats = threat_data.get("threats", [])[:10] if isinstance(threat_data, dict) else []
    for threat in threats:
        threat["analysis"] = explain_rule(threat)
    critical_items = critical_vuln_data.get("affected_items", []) if isinstance(critical_vuln_data, dict) else []
    source_ips = _source_ip_leaderboard(threats)
    fim = _fim_summary(fim_data)
    geo = _geo_summary(geo_data)
    auth_count = _count_log_lines(auth_text)
    web_count = _count_log_lines(web_text)
    cloud_m365 = local_alerts.get("cloud_m365") if local_alerts.get("ok") else _cloud_m365_summary(window)
    layers = _detection_layers(alert_data, threats, source_ips, fim, ai_data, auth_count, web_count, vuln_data, cloud_m365)
    if local_alerts.get("ok"):
        alert_data = local_alerts["alert_data"]
        threats = local_alerts["threats"] or threats
        source_ips = local_alerts["source_ips"] or source_ips
        layers = _detection_layers(alert_data, threats, source_ips, fim, ai_data, auth_count, web_count, vuln_data, cloud_m365)
    try:
        stream_status = pipeline.status()
    except Exception as exc:
        stream_status = {"enabled": False, "error": str(exc), "scan_status": "unavailable"}
    indexed_events = int(alert_data.get("total_alerts", 0) or 0)
    operational_evidence = local_alerts.get("operational_evidence") or {
        "network": {"events": [], "observed": 0}, "identity": {"events": [], "observed": 0},
        "mitre": {"techniques": [], "observed": 0}, "decoders": {"items": [], "observed": 0, "unmatched_events": 0},
        "telemetry": {"indexer": {"health": "unavailable", "scope": "Local aggregation was unavailable."}},
    }
    asset_context = _asset_context(agent_items)
    asset_context_rows = asset_context["rows"]
    asset_coverage = asset_context["coverage"]
    vuln_encoded = json.dumps(critical_items, default=str).lower()
    return {
        "generated_at": generated_at,
        "requested_range": window["requested"],
        "materialization": {
            "status": "exact", "exact": True,
            "source": "bounded Indexer aggregation with retained dashboard snapshot",
            "historical_retention_days": OVERVIEW_HISTORY_RETENTION_DAYS,
        },
        "historical_detail": {
            "status": "available" if not historical_window else "partial",
            "l1": {"status": "available" if not historical_window else "unavailable",
                    "message": ("Live L1 alert detail is available." if not historical_window else
                                 "Historical individual L1 alerts are not replayed by the bounded overview query.")},
            "l2": {"status": "available" if not historical_window else "unavailable",
                    "message": ("Live L2 correlation and AI recon are available." if not historical_window else
                                 "Historical L2 correlation and AI recon are not replayed by the bounded overview query.")},
        },
        "window": {
            "label": window["label"],
            "range": window["requested"],
            "bounds": window["bounds"],
        },
        "tools": {
            "total": len(tools),
            "gensecai": sum(1 for t in tools if t.get("source") == "gensecai"),
            "infokom": sum(1 for t in tools if t.get("source") == "infokom"),
            "capabilities": _tool_capabilities(tools),
        },
        "analysis_funnel": {
            "indexed_events": indexed_events,
            "rules_evaluated_events": indexed_events,
            "rule_engine": "Wazuh evaluates every indexed alert before dashboard aggregation.",
            "pipeline_checkpoint_events": int(stream_status.get("checkpoint_events_scanned", 0) or 0),
            "pipeline_replay_events": int(stream_status.get("live_replay_events_scanned", 0) or 0),
            "pipeline_status": stream_status.get("scan_status", "unavailable"),
            "pipeline_lag_seconds": stream_status.get("lag_seconds"),
            "queued_unique_indicators": int(stream_status.get("queued_indicators", 0) or 0),
            "ai_strategy": "case_and_rollup",
            "ai_note": "AI analyzes deduplicated findings, indicators, and time-window rollups instead of sending every raw event to the model.",
            "historical_scope_complete": bool(stream_status.get("historical_scope_complete", False)),
        },
        "alerts": {
            "time_range": alert_data.get("time_range", "24h"),
            "total_alerts": alert_data.get("total_alerts", 0),
            "sampled": alert_data.get("alerts_sampled", 0),
            "truncated": alert_data.get("truncated", False),
            "groups": alert_data.get("groups", {}),
            "severity": _severity_buckets(alert_data.get("groups", {}) or {}),
            "hourly": _hourly_series(stats_data),
        },
        "threats": threats,
        "source_ips": source_ips,
        "l1_queue": local_alerts.get("l1_queue") or [],
        "crowdsec_watchlist_ips": _public_ip_list(CROWDSEC_WATCHLIST_IPS),
        "timeline": {
            "ok": local_alerts.get("ok") or timeline["ok"],
            "bucket_interval": (local_alerts.get("timeline") or {}).get("bucket_interval") if local_alerts.get("ok") else (timeline_data.get("bucket_interval") if isinstance(timeline_data, dict) else None),
            "total_alerts": (local_alerts.get("timeline") or {}).get("total_alerts", 0) if local_alerts.get("ok") else (timeline_data.get("total_alerts", 0) if isinstance(timeline_data, dict) else 0),
            "buckets": _timeline_buckets((local_alerts.get("timeline") or {}) if local_alerts.get("ok") else timeline_data),
        },
        "geo_heatmap": {
            "ok": geo_heatmap["ok"],
            **geo,
        },
        "cloud_m365": cloud_m365,
        "detection_layers": layers,
        "operational_evidence": operational_evidence,
        "provider_freshness": _provider_freshness(),
        "fim": fim,
        "auth": {
            "ok": auth_log["ok"],
            "events": auth_count,
            "summary": auth_text[:500],
        },
        "web": {
            "ok": web_log["ok"],
            "events": web_count,
            "summary": web_text[:500],
        },
        "attack_surface": _attack_surface(threats, source_ips, ai_data, geo),
        "agents": {
            "total": len(agent_items),
            "counts": agent_counts,
            "platforms": platforms,
            "items": agent_items[:20],
            "context": asset_context_rows,
            "context_coverage": asset_coverage,
            "context_status": asset_context["status"],
            "context_source": "Wazuh agent fields/labels merged with the cached local CMDB; no Wazuh or provider lookup is performed per asset.",
        },
        "three_sum": {
            "ok": three_sum["ok"],
            "window": three_data.get("window", {}) if isinstance(three_data, dict) else {},
            "configuration": three_data.get("configuration", {}) if isinstance(three_data, dict) else {},
            "categories": three_categories,
            "candidate_count": three_candidate_count,
        },
        "ai_recon": {
            "ok": ai_recon["ok"],
            "ai_agent_sources": ai_data.get("ai_agent_sources", 0) if isinstance(ai_data, dict) else 0,
            "sources": ai_data.get("sources", [])[:10] if isinstance(ai_data, dict) else [],
            "window": ai_data.get("window", {}) if isinstance(ai_data, dict) else {},
        },
        "vulnerabilities": {
            "total": vuln_data.get("total_vulnerabilities", 0) if isinstance(vuln_data, dict) else 0,
            "affected_agents": vuln_data.get("affected_agents", 0) if isinstance(vuln_data, dict) else 0,
            "critical": vuln_data.get("critical", 0) if isinstance(vuln_data, dict) else 0,
            "high": vuln_data.get("high", 0) if isinstance(vuln_data, dict) else 0,
            "medium": vuln_data.get("medium", 0) if isinstance(vuln_data, dict) else 0,
            "low": vuln_data.get("low", 0) if isinstance(vuln_data, dict) else 0,
            "by_severity": vuln_data.get("by_severity", {}) if isinstance(vuln_data, dict) else {},
            "critical_items": critical_items[:10],
            "evidence_coverage": {
                "wazuh_inventory": bool(vuln_data or critical_items),
                "cpe": "cpe" in vuln_encoded,
                "epss": "epss" in vuln_encoded,
                "kev": "kev" in vuln_encoded,
                "poc": "poc" in vuln_encoded or "exploit" in vuln_encoded,
                "internet_exposure": "internet_exposure" in vuln_encoded or "public_ip" in vuln_encoded,
                "patch_state": "patch" in vuln_encoded or "status" in vuln_encoded,
                "note": "NVD/EPSS/KEV/PoC are loaded on CVE drill-down and cached; absence here means not present in the summary payload.",
            },
        },
        "soc_lanes": {
            "l1": {
                "open_alerts": alert_data.get("total_alerts", 0),
                "active_agents": agent_counts.get("active", 0),
                "queue": threats[:6],
            },
            "l2": {
                "ai_recon_sources": ai_data.get("ai_agent_sources", 0) if isinstance(ai_data, dict) else 0,
                "critical_vulnerabilities": vuln_data.get("critical", 0) if isinstance(vuln_data, dict) else 0,
                "correlation_categories": three_categories,
            },
            "l3": {
                "hunting_tools": _tool_capabilities(tools)["l3_hunting"],
                "response_tools": _tool_capabilities(tools)["response"],
                "compliance_tools": _tool_capabilities(tools)["compliance"],
            },
        },
        "errors": errors,
    }


def _finding_history(indicator: str) -> dict[str, Any]:
    try:
        return automation.indicator_memory(indicator)
    except Exception:
        return {"status": "unavailable", "findings": []}


def _merge_finding_history(kind: str, indicator: str, result: dict[str, Any]) -> dict[str, Any]:
    if kind != "aggregate" or not indicator:
        return result
    history = _finding_history(indicator)
    findings = history.get("findings") or []
    if not findings:
        return result
    merged = dict(result)
    data = dict(merged.get("data") or {})
    data["history"] = history
    data.setdefault("historical_cves", findings[0].get("cves") or [])
    data.setdefault("cyfirma_matches", findings[0].get("cyfirma_matches") or [])
    live_rows = data.get("results") if isinstance(data.get("results"), list) else []
    usable_live = any(not row.get("error") and not (
        row.get("detail") if isinstance(row.get("detail"), dict) else {}
    ).get("skipped") for row in live_rows if isinstance(row, dict))
    if not usable_live:
        historical_rows = []
        for provider in findings[0].get("providers") or []:
            row = dict(provider)
            detail = dict(row.get("detail") or {})
            detail["historical"] = True
            detail.setdefault("report_id", findings[0].get("report_id"))
            detail.setdefault("enriched_at", findings[0].get("enriched_at") or findings[0].get("generated_at"))
            row["detail"] = detail
            row.setdefault("summary", "Historical provider result reused from automation cache.")
            historical_rows.append(row)
        if historical_rows:
            data["results"] = historical_rows
            merged["ok"] = True
            merged["memory_reused"] = True
            merged.pop("error", None)
    merged["data"] = data
    return merged


def _finding_intel(kind: str, indicator: str = "", observed_at: Any = None) -> dict[str, Any]:
    """Bounded, cached read-only intelligence for the findings workspace."""
    if not isinstance(indicator, str) or len(indicator) > 512:
        raise ValueError("Invalid indicator")
    indicator = indicator.strip()
    requests = {
        "feed": ("cyfirma_ioc_feed", {"scope": "tailored", "limit": 20}),
        "feed_global": ("cyfirma_ioc_feed", {"scope": "global", "limit": 20}),
        "aggregate": ("blueteam_threat_intel_aggregate", {"indicator": indicator}),
        "cyfirma": ("cyfirma_ioc_lookup", {"indicator": indicator, "scope": "both", "limit": 25}),
        "threatfox": ("threatfox_ioc_search", {"search_term": indicator, "exact_match": True}),
        "urlhaus": ("urlhaus_lookup", {"url": indicator}),
        "urlhaus_hash": ("urlhaus_hash_lookup", {"file_hash": indicator}),
        "crowdsec": ("crowdsec_ip_reputation", {"ip": indicator}),
        "otx": ("otx_lookup", {"indicator": indicator, "section": "general"}),
        "greynoise": ("greynoise_ip_context", {"ip": indicator}),
        "cve": ("blueteam_cve_score", {"cve_id": indicator}),
        "nvd": ("blueteam_cve_lookup", {"cve_id": indicator}),
        "kev": ("blueteam_cve_kev", {"cve_id": indicator}),
        "poc": ("blueteam_cve_poc", {"cve_id": indicator}),
    }
    provider_for_kind = {
        "cyfirma": "CYFIRMA", "threatfox": "ThreatFox", "urlhaus": "URLHaus",
        "urlhaus_hash": "URLHaus", "crowdsec": "CrowdSec", "otx": "AlienVault OTX",
        "greynoise": "GreyNoise", "cve": "CVE enrichment", "nvd": "NVD",
        "kev": "CISA KEV", "poc": "PoC enrichment",
    }
    if kind not in requests or (kind not in {"feed", "feed_global"} and not indicator):
        raise ValueError("Unsupported enrichment request")
    if kind in {"feed", "feed_global"}:
        offset = int(indicator or 0)
        if offset < 0 or offset > 100000:
            raise ValueError("Invalid feed offset")
        requests[kind][1]["offset"] = offset
    if kind == "urlhaus":
        try:
            parsed_url = urllib.parse.urlparse(indicator)
        except Exception as exc:
            raise ValueError("Invalid URL") from exc
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise ValueError("URLHaus lookup needs a full http/https URL")
    if kind == "urlhaus_hash" and not re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{64}", indicator):
        raise ValueError("URLHaus hash lookup needs MD5 or SHA256")
    if kind in {"cve", "nvd", "kev", "poc"} and not re.fullmatch(r"CVE-\d{4}-\d{4,}", indicator):
        raise ValueError("Invalid CVE ID")
    if kind in {"crowdsec", "greynoise", "aggregate", "otx", "cyfirma", "threatfox"}:
        try:
            address = ipaddress.ip_address(indicator)
        except ValueError:
            if kind in {"crowdsec", "greynoise"}:
                raise ValueError("Invalid IP address")
            address = None
        if address is not None and not address.is_global:
            return {"ok": False, "error": "Private/reserved IP: external lookup skipped"}
    key = f"{kind}:{indicator}"
    cache_payload = {"kind": kind, "indicator": indicator}
    disk_cached = _api_cache_read("finding_intel", cache_payload, _runtime_int("SOC_PROVIDER_OK_CACHE_SECONDS", 21600))
    if disk_cached:
        provider = provider_for_kind.get(kind)
        health = _provider_health(provider) if provider else None
        retryable_error = bool(provider and not disk_cached.get("ok") and health and health.get("state") in {"recovering", "unknown"})
        if retryable_error:
            disk_cached = None
    if disk_cached:
        disk_cached["cached"] = True
        disk_cached = _merge_finding_history(kind, indicator, disk_cached)
        _provider_history_write("finding_intel", cache_payload, disk_cached, observed_at)
        return disk_cached
    # Share in-flight calls between browser tabs to avoid duplicate quota usage.
    with _finding_lock:
        if len(_finding_cache) >= 256:
            for old_key, value in list(_finding_cache.items()):
                if value.get("expires", 0) < time.time() and not value["lock"].locked():
                    del _finding_cache[old_key]
        if key not in _finding_cache and len(_finding_cache) >= 256:
            raise ValueError("Enrichment cache busy; retry later")
        slot = _finding_cache.setdefault(key, {"lock": threading.Lock(), "expires": 0})
    with slot["lock"]:
        if slot["expires"] > time.time():
            return dict(slot["result"], cached=True)
        name, arguments = requests[kind]
        provider = provider_for_kind.get(kind)
        if provider:
            health = _provider_health(provider)
            retry_at = health.get("retry_at")
            if health.get("state") == "backoff" and retry_at:
                result = {"ok": False, "name": name, "source": "infokom", "data": None,
                          "error": f"{provider} provider is in backoff; retry after {retry_at}",
                          "provider": provider, "health": health, "cached": False}
                result = _api_cache_write("finding_intel", cache_payload, result,
                                          _runtime_int("SOC_PROVIDER_ERROR_BACKOFF_SECONDS", 14400))
                _provider_history_write("finding_intel", cache_payload, result, observed_at)
                slot.update(result=result, expires=time.time() + 60)
                return result
        result = _safe_call("infokom", name, dict(arguments, response_format="json"))
        data = result.get("data")
        if kind == "aggregate" and isinstance(data, dict) and isinstance(data.get("results"), list):
            result["partial"] = bool(data.get("errors"))
            if result["partial"]:
                result["warnings"] = data["errors"]
            if not any(not row.get("error") and not (
                row.get("detail") if isinstance(row.get("detail"), dict) else {}
            ).get("skipped") for row in data["results"] if isinstance(row, dict)):
                if any(row.get("error") for row in data["results"] if isinstance(row, dict)) or data.get("errors"):
                    result["ok"] = False
                    result["error"] = "No provider returned usable context for this indicator"
                else:
                    result["no_match"] = True
        if isinstance(data, dict) and (data.get("error") or (data.get("errors") and not data.get("results")) or data.get("ok") is False):
            result["ok"] = False
            result["error"] = data.get("error") or data.get("errors") or "Provider returned an error"
        if data is None:
            result["ok"] = False
            result["error"] = result.get("error") or result.get("text") or "No structured response"
        if provider:
            result["provider"] = provider
            result["health"] = _provider_health_record(provider, bool(result.get("ok")), result.get("error"))
        elif kind == "aggregate" and isinstance(data, dict):
            for row in data.get("results") or []:
                if not isinstance(row, dict):
                    continue
                provider_name = str(row.get("provider") or "unknown")
                _provider_health_record(provider_name, not bool(row.get("error")), row.get("error"))
        result.update(generated_at=datetime.now(timezone.utc).isoformat(), cached=False)
        result = _merge_finding_history(kind, indicator, result)
        ttl = _runtime_int("SOC_PROVIDER_OK_CACHE_SECONDS", 21600) if result.get("ok") and not result.get("partial") else _runtime_int("SOC_PROVIDER_ERROR_BACKOFF_SECONDS", 14400)
        result = _api_cache_write("finding_intel", cache_payload, result, ttl)
        _provider_history_write("finding_intel", cache_payload, result, observed_at)
        slot.update(result=result, expires=time.time() + (600 if result.get("ok") else 60))
        return result


def _finding_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    kind = payload.get("kind")
    value = payload.get("value", "")
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError("Invalid evidence filter")
    fields = {
        "ip": ["data.srcip", "data.src_ip", "data.source.ip", "data.office365.ClientIP",
               "data.dstip", "data.dst_ip", "data.destination.ip"],
        "rule": ["rule.id"],
        "m365": ["data.office365.Operation"],
        "domain": ["data.dns.question.name"],
        "hash": ["syscheck.md5_after", "syscheck.sha1_after", "syscheck.sha256_after",
                 "data.win.eventdata.hashes", "data.virustotal.source.md5"],
        "city": ["GeoLocation.city_name"],
        "path": ["syscheck.path"],
        "url": ["data.url", "data.http.url", "data.request.url", "url.original"],
    }
    fields["ip"].append("data.win.eventdata.ipAddress")
    if kind not in fields:
        raise ValueError("Unsupported evidence filter")
    time_range = _normalize_range(payload.get("range", "24h"))
    event_bounds = {'gte': 'now-' + time_range}
    if payload.get('start') or payload.get('end'):
        start, end = soc_pipeline.bounds(payload)
        event_bounds = {'gte': start, 'lt': end}
    query = {
        "size": 25, "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": event_bounds}},
            {"bool": {"should": [{"term": {field: value}} for field in fields[kind]],
                      "minimum_should_match": 1}},
        ]}},
        "_source": ["@timestamp", "timestamp", "rule", "agent", "data", "syscheck", "GeoLocation", "decoder", "location"],
    }
    result = _indexer_search(query)
    hits = result.get("hits", {})
    total = hits.get("total", {})
    return {"ok": True, "total": total.get("value", 0) if isinstance(total, dict) else total,
            "relation": total.get("relation", "eq") if isinstance(total, dict) else "eq",
            "range": time_range, "fields_checked": fields[kind],
            "events": [{"id": h.get("_id"), **h.get("_source", {}),
                        "analysis": explain_rule(h.get("_source", {}).get("rule", {}))} for h in hits.get("hits", [])]}


def _settings() -> dict[str, Any]:
    catalog = _tool_catalog()
    try:
        pipeline_status = pipeline.status()
    except Exception as exc:
        pipeline_status = {"enabled": False, "error": str(exc)}
    return {
        "urls": {
            "gensecai": GENSECAI_MCP_URL,
            "infokom": INFOKOM_MCP_URL,
        },
        "auth": {
            "gensecai_key_set": bool(GENSECAI_API_KEY),
            "infokom_key_set": bool(INFOKOM_API_KEY),
        },
        "ai_agent": {
            "enabled": AI_ANALYST_ENABLED,
            "auto_analyze": AI_AUTO_ANALYZE,
            "provider_base_url": (urllib.parse.urlsplit(AI_PROVIDER_BASE_URL).hostname or 'configured') if AI_PROVIDER_BASE_URL else 'not configured',
            "model": AI_MODEL or "not configured",
            "mode": "llm" if AI_ANALYST_ENABLED and AI_PROVIDER_BASE_URL and AI_MODEL else "rules-only",
        },
        "config": _public_config(),
        "tools": {
            "total": len(catalog["tools"]),
            "gensecai": sum(1 for t in catalog["tools"] if t.get("source") == "gensecai"),
            "infokom": sum(1 for t in catalog["tools"] if t.get("source") == "infokom"),
            "dashboard": sum(1 for t in catalog["tools"] if _enrich_tool(t).get("operational_mode") == "dashboard"),
            "workflow": sum(1 for t in catalog["tools"] if _enrich_tool(t).get("operational_mode") == "menu_workflow"),
            "guided_findings": sum(1 for t in catalog["tools"] if "findings" in _enrich_tool(t)["workflow"].get("surfaces", [])),
            "on_demand": sum(1 for t in catalog["tools"] if _enrich_tool(t).get("operational_mode") == "on_demand"),
            "cached_read": sum(1 for t in catalog["tools"] if _enrich_tool(t)["workflow"]["mode"] == "cached_read"),
            "approval_required": sum(1 for t in catalog["tools"] if _enrich_tool(t)["workflow"]["mode"] == "approval"),
            "errors": catalog["errors"],
        },
        "storage": {
            "docker_data_root": DOCKER_DATA_ROOT,
            "wazuh_indexer_volume": WAZUH_INDEXER_VOLUME,
            "wazuh_logs_volume": WAZUH_LOGS_VOLUME,
            "root_disk": _disk_usage("/"),
            "data_disk": _disk_usage("/data/wazuh-storage"),
            "runtime_disk": _disk_usage(str(OVERVIEW_CACHE_DB.parent)),
            "docker_on_data_disk": str(DOCKER_DATA_ROOT).startswith("/data/wazuh-storage"),
            "overview_cache_db": str(OVERVIEW_CACHE_DB),
            "automation_db": str(AUTOMATION_DB),
            "cache": _cache_stats(),
            "automation": _automation_db_stats(),
            "overview_cache_ttl_seconds": OVERVIEW_CACHE_TTL_SECONDS,
            "prewarm_enabled": PREWARM_ENABLED,
            "prewarm_ranges": PREWARM_RANGES,
        },
        "pipeline": pipeline_status,
    }


class Handler(SimpleHTTPRequestHandler):
    server_version = "WazuhMCPDashboard/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def _authorized(self) -> bool:
        if not DASHBOARD_ACCESS_TOKEN:
            return True
        supplied = self.headers.get('Authorization', '')
        token = supplied.removeprefix('Bearer ') if supplied.startswith('Bearer ') else ''
        if supplied.startswith('Basic '):
            try:
                username, token = base64.b64decode(supplied[6:], validate=True).decode().split(':', 1)
                if not hmac.compare_digest(username.encode(), DASHBOARD_ACCESS_USERNAME.encode()):
                    token = ''
            except (ValueError, UnicodeError, IndexError):
                token = ''
        if hmac.compare_digest(token.encode(), DASHBOARD_ACCESS_TOKEN.encode()):
            return True
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="SOC Dashboard", charset="UTF-8"')
        self.send_header('Content-Length', '0')
        self.end_headers()
        return False

    def do_HEAD(self) -> None:
        # Never inherit SimpleHTTPRequestHandler's working-directory file access.
        self.do_GET()

    def do_GET(self) -> None:
        if not self._authorized():
            return
        request_path = urllib.parse.unquote(self.path.split("?", 1)[0])
        if request_path == "/":
            self._serve_file(STATIC / "index.html")
            return
        if request_path.startswith("/static/"):
            self._serve_file(STATIC / request_path.removeprefix("/static/"))
            return
        _json_response(self, 404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._authorized():
            return
        try:
            origin = self.headers.get('Origin')
            if origin and urllib.parse.urlsplit(origin).netloc != self.headers.get('Host'):
                _json_response(self, 403, {'error': 'Cross-origin request rejected'})
                return
            size = int(self.headers.get("Content-Length", "0"))
            if size < 0 or size > 1_048_576 or self.headers.get('Transfer-Encoding'):
                _json_response(self, 413, {'error': 'Request body exceeds limit'})
                return
            self.connection.settimeout(20)
            body = self.rfile.read(size)
            payload = json.loads(body or b"{}")
            if not isinstance(payload, dict):
                raise ValueError('Request must be a JSON object')
            if self.path == '/api/workflows/run':
                result = workflows.submit(payload.get('source'), payload.get('name'), payload.get('arguments', {}))
                _json_response(self, 202 if result['status'] in {'queued', 'running'} else 200, result)
                return
            if self.path == '/api/workflows/job':
                _json_response(self, 200, workflows.get(payload.get('id')))
                return
            if self.path == '/api/workflows/history':
                start = end = None
                if payload.get('start') or payload.get('end'):
                    start_iso, end_iso = soc_pipeline.bounds(payload)
                    start, end = datetime.fromisoformat(start_iso).timestamp(), datetime.fromisoformat(end_iso).timestamp()
                _json_response(self, 200, workflows.history(payload.get('menu'), start, end))
                return
            if self.path == '/api/workflows/evidence':
                window = _history_payload(payload)
                cached = _api_cache_read('workflow_evidence', window, 60)
                if cached is None:
                    cached = _api_cache_write('workflow_evidence', window,
                        pipeline.rollup_summary(window['start'], window['end']), 60)
                _json_response(self, 200, cached)
                return
            if self.path == '/api/intelligence/cyfirma':
                window = _history_payload(payload)
                start, end = soc_pipeline.bounds(window)
                try:
                    limit = min(max(int(payload.get('limit', 30)), 1), 100)
                except (TypeError, ValueError):
                    raise ValueError('Invalid intelligence result limit') from None
                cache_payload = {**window, 'limit': limit}
                cached = _api_cache_read('cyfirma_updates', cache_payload, 60)
                if cached is None:
                    cached = _api_cache_write('cyfirma_updates', cache_payload,
                        automation.cyfirma_updates(start, end, limit), 60)
                _json_response(self, 200, cached)
                return
            if self.path == '/api/history/events':
                history_payload = _history_payload(payload)
                cached = _api_cache_read("history_events", history_payload, 180)
                if cached:
                    _json_response(self, 200, cached)
                    return
                _json_response(self, 200, _api_cache_write("history_events", history_payload, soc_pipeline.history(_indexer_search, history_payload), 180))
                return
            if self.path == '/api/history/reports':
                start, end = soc_pipeline.bounds(_history_payload(payload))
                _json_response(self, 200, {'reports': automation.reports(start,end,int(payload.get('offset',0))),
                                           'timeline': automation.report_timeline(start, end) if int(payload.get('offset', 0)) == 0 else [],
                                           'summary': automation.history_summary(start, end) if int(payload.get('offset', 0)) == 0 else None})
                return
            if self.path == '/api/history/intelligence':
                start, end = soc_pipeline.bounds(_history_payload(payload))
                _json_response(self, 200, _provider_history_payload(
                    start, end, int(payload.get('offset', 0)), payload.get('query', '')))
                return
            if self.path == '/api/history/report':
                _json_response(self, 200, {'report': automation.report(payload.get('id'))})
                return
            if self.path == '/api/pipeline/status':
                _json_response(self, 200, pipeline.status())
                return
            if self.path == "/api/automation/status":
                _json_response(self, 200, automation.status(payload.get('known_revision')))
                return
            if self.path == "/api/automation/run":
                _json_response(self, 202, automation.trigger(payload))
                return
            if self.path == "/api/automation/ai-test":
                _json_response(self, 200, automation.test_ai())
                return
            if self.path == "/api/automation/ai-ping":
                _json_response(self, 200, soc_automation.test_model_connection(_runtime_config_values()))
                return
            if self.path == "/api/automation/smtp-test":
                result = soc_automation.smtp_test(_runtime_config_values())
                if result.get("error"):
                    result["error"] = automation.clean_error(result["error"])
                _json_response(self, 200, result)
                return
            if self.path == "/api/automation/send":
                report = automation.status().get("latest")
                if not report:
                    _json_response(self, 400, {"error": "No analysis report available"})
                    return
                _json_response(self, 200, automation.send(report, payload.get("channel")))
                return
            if self.path == "/api/tools":
                _json_response(self, 200, _tools_response())
                return
            if self.path == "/api/incidents/list":
                _json_response(self, 200, _incident_cases(payload))
                return
            if self.path == "/api/incidents/create":
                _json_response(self, 200, _incident_create(payload))
                return
            if self.path == "/api/analysis/coverage":
                window = _window_from_payload(payload)
                cache_payload = {"window": window}
                disk_cached = _api_cache_read("analysis_coverage", cache_payload, 180)
                if disk_cached:
                    _json_response(self, 200, disk_cached)
                    return
                cache_key = json.dumps(window, sort_keys=True)
                with _analysis_lock:
                    cached = _analysis_cache.get(cache_key)
                    if not cached or cached["expires"] < time.time():
                        cached = {"data": _api_cache_write("analysis_coverage", cache_payload, analysis_coverage(_indexer_search, window), 180), "expires": time.time() + 120}
                        _analysis_cache[cache_key] = cached
                _json_response(self, 200, cached["data"])
                return
            if self.path == "/api/findings/intel":
                _json_response(self, 200, _finding_intel(payload.get("kind"), payload.get("indicator", "")))
                return
            if self.path == "/api/findings/ai-analysis":
                finding = _enrich_finding_asset_context(dict(payload.get("finding") or {}))
                stored_intelligence = _latest_provider_history(finding.get("ip") or finding.get("indicator"))
                if stored_intelligence:
                    finding["stored_provider_history"] = stored_intelligence
                if payload.get("async"):
                    result = automation.queue_finding_analysis(finding, bool(payload.get("force")))
                    _json_response(self, 202 if result.get("status") in {"queued", "processing"} else 200, result)
                else:
                    _json_response(self, 200, automation.analyze_finding(finding, bool(payload.get("force"))))
                return
            if self.path == "/api/ai/contract":
                _json_response(self, 200, soc_automation.contract_definition(payload.get("scope")))
                return
            if self.path == "/api/findings/ai-status":
                _json_response(self, 200, automation.finding_analysis_job(payload.get("job_id")))
                return
            if self.path == "/api/findings/ai-jobs":
                _json_response(self, 200, automation.finding_analysis_jobs(payload.get("limit", 10)))
                return
            if self.path == "/api/findings/ai-retry":
                result = automation.retry_finding_analysis_job(payload.get("job_id"))
                _json_response(self, 202 if result.get("status") == "queued" else 400, result)
                return
            if self.path == "/api/findings/feedback":
                result = automation.save_finding_feedback(payload.get("finding_id"), payload.get("disposition"),
                    payload.get("note"), payload.get("finding"))
                if result.get("ok") and payload.get("sync_case"):
                    try:
                        result["case_sync"] = _sync_finding_case(
                            dict(payload.get("finding") or {}), payload.get("disposition"),
                            payload.get("note"), payload.get("ai_advisory"))
                    except Exception as exc:
                        result["case_sync"] = {"ok": False, "error": str(exc)}
                _json_response(self, 200 if result.get("ok") else 400, result)
                return
            if self.path == "/api/findings/feedback/history":
                _json_response(self, 200, automation.finding_feedback(payload.get("finding_id"), payload.get("limit", 10)))
                return
            if self.path == "/api/vulnerabilities/inventory":
                _json_response(self, 200, vulnerability_inventory(_indexer_search, payload))
                return
            if self.path == "/api/vulnerabilities/exposure":
                historical = payload.get("range") in {"7d", "30d", "custom"} or bool(payload.get("start") or payload.get("end"))
                request = {
                    "severity": payload.get("severity", "all"), "search": payload.get("search", ""),
                    "sort": payload.get("sort", "cve"), "limit": min(int(payload.get("limit", 100)), 100),
                    "include_summary": False, "range": payload.get("range", "24h"),
                }
                if historical:
                    start, end = soc_pipeline.bounds(_history_payload(payload))
                    request.update({"historical": True, "start": start, "end": end})
                cached = _api_cache_read("cve_exposure", request, 900)
                if cached:
                    if not cached.get("materialized_summary"):
                        cached = _materialize_cve_exposure(cached, request)
                    _json_response(self, 200, cached)
                    return
                if historical:
                    history = automation.cve_history(request["start"], request["end"], request["limit"])
                    inventory = {"ok": True, "items": history["items"],
                                 "total": history["observations"], "inventory_total": history["observations"]}
                else:
                    history = None
                    inventory = vulnerability_inventory(_indexer_search, request)
                cmdb_assets, cmdb_status = _load_cmdb_assets()
                items = inventory.get("items") or []
                cves = {
                    str((item.get("vulnerability") or {}).get("id") or item.get("cve") or "").upper()
                    for item in items if isinstance(item, dict)
                }
                cached_intelligence = automation.cached_cve_intelligence(cves)
                for item in items:
                    cve = str((item.get("vulnerability") or {}).get("id") or item.get("cve") or "").upper()
                    if cve in cached_intelligence:
                        item["intelligence"] = cached_intelligence[cve]["data"]
                        item["intelligence_expires_at"] = cached_intelligence[cve]["expires_at"]
                graph = build_exposure_graph(items, cmdb_assets, request["limit"])
                graph.update({
                    "inventory_total": inventory.get("inventory_total", inventory.get("total", 0)),
                    "inventory_ok": inventory.get("ok", False), "cmdb": cmdb_status,
                    "cached_cve_enrichment": len(cached_intelligence),
                    "history": history,
                })
                graph = _materialize_cve_exposure(graph, request)
                _json_response(self, 200, _api_cache_write("cve_exposure", request, graph, 900))
                return
            if self.path == "/api/findings/evidence":
                _json_response(self, 200, _finding_evidence(payload))
                return
            if self.path == "/api/overview":
                _json_response(self, 200, _overview_cached(payload))
                return
            if self.path == "/api/platform/status":
                _json_response(self, 200, _platform_overview_status())
                return
            if self.path == "/api/settings":
                _json_response(self, 200, _settings())
                return
            if self.path == "/api/settings/save":
                result = _save_config(payload.get("settings") or {})
                _json_response(self, 200 if result.get("ok") else 400, result)
                return
            if self.path == "/api/m365/test":
                _json_response(self, 200, _m365_test(int(payload.get("hours", 24) or 24)))
                return
            if self.path == "/api/m365/start-subscriptions":
                _json_response(self, 200, _m365_start_subscriptions())
                return
            if self.path == "/api/threat-intel/test":
                _json_response(self, 200, _threat_intel_test(bool(payload.get("force"))))
                return
            if self.path == "/api/call":
                source = payload.get("source")
                name = payload.get("name")
                arguments = payload.get("arguments") or {}
                if not isinstance(name, str):
                    _json_response(self, 400, {"error": "source/name invalid"})
                    return
                if source not in {"gensecai", "infokom"}:
                    resolved_source, candidates = _resolve_tool_source(name)
                    if not resolved_source:
                        _json_response(self, 400, {"error": "tool not found", "name": name})
                        return
                    source = resolved_source
                tool = _tool_by_name(source, name)
                if not tool:
                    raise ValueError('Tool not found')
                if soc_workflows.policy(tool)['mode'] == 'approval' and payload.get('confirmed') is not True:
                    _json_response(self, 403, {'error': 'Explicit operator confirmation required'})
                    return
                if not _manual_tool_slots.acquire(blocking=False):
                    raise soc_workflows.WorkflowBusy('Tool Console is busy; retry shortly')
                try:
                    result = _normalized_call(source, name, arguments)
                finally:
                    _manual_tool_slots.release()
                _json_response(self, 200, result)
                return
            _json_response(self, 404, {"error": "not found"})
        except soc_workflows.WorkflowBusy as exc:
            _json_response(self, 429, {'error': str(exc)})
        except (ValueError, TypeError) as exc:
            _json_response(self, 400, {'error': str(exc)})
        except Exception as exc:
            _json_response(self, 500, {"error": automation.clean_error(exc)})

    def _serve_file(self, path: Path) -> None:
        path = path.resolve()
        if not path.is_relative_to(STATIC.resolve()) or not path.exists() or not path.is_file():
            _json_response(self, 404, {"error": "not found"})
            return
        body = path.read_bytes()
        content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Bound request threads so a slow client cannot exhaust dashboard memory."""
    daemon_threads = True
    block_on_close = False
    request_queue_size = 64

    def __init__(self, server_address, handler, max_threads=32):
        self._request_slots = threading.BoundedSemaphore(max_threads)
        super().__init__(server_address, handler)

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b'HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n'
                    b'Content-Length: 0\r\nRetry-After: 2\r\n\r\n')
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


automation = soc_automation.Automation(_runtime_config_values,
    lambda window: analysis_coverage(_indexer_search, window), _finding_intel, _finding_evidence,
    lambda payload: vulnerability_inventory(_indexer_search, payload), _safe_call,
    AUTOMATION_DB, _provider_history_write)
pipeline = soc_pipeline.Pipeline(automation, _indexer_request)
automation.pipeline = pipeline


def _workflow_lookup(source, name):
    tool = _tool_by_name(source, name)
    return _enrich_tool(tool) if tool else None


def _workflow_redact(text):
    for key, value in _runtime_config_values().items():
        if value and any(part in key for part in ('KEY', 'PASSWORD', 'SECRET', 'WEBHOOK')):
            text = text.replace(str(value), '[redacted]')
    return text


def _workflow_call(source, name, arguments):
    # Yield to an interactive console request; never pile work on top of it.
    if not _manual_tool_slots.acquire(timeout=5):
        raise soc_workflows.WorkflowBusy('Interactive tool request in progress')
    try:
        return _normalized_call(source, name, arguments)
    finally:
        _manual_tool_slots.release()


workflows = soc_workflows.Workflows(
    Path(os.environ.get('SOC_WORKFLOW_DB', AUTOMATION_DB.parent / 'soc-workflows.db')),
    _workflow_lookup, _workflow_call, _workflow_redact)


if __name__ == "__main__":
    workflows.start()
    automation.start()
    pipeline.start()
    _start_overview_prewarm()
    if not DASHBOARD_ACCESS_TOKEN and HOST not in {'127.0.0.1', '::1', 'localhost'}:
        print('WARNING: DASHBOARD_ACCESS_TOKEN is empty while listening on a public interface')
    print(f"Dashboard listening on {HOST}:{PORT}")
    BoundedThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
