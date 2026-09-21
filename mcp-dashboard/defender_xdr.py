"""Low-rate Microsoft Defender XDR alert collector with a durable checkpoint."""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

import entity_resolver


DEFAULT_BASE_URL = "https://api.security.microsoft.com"
GRAPH_BASE_URL = "https://graph.microsoft.com"
PROVIDERS = {
    "defender": {"base": DEFAULT_BASE_URL, "scope": "https://api.security.microsoft.com/.default"},
    "graph": {"base": GRAPH_BASE_URL, "scope": "https://graph.microsoft.com/.default"},
}
COLLECTIONS = {
    # Incidents are the least-privileged useful XDR unit. They contain related
    # alerts and entities while requiring Incident.Read.All rather than the
    # legacy alerts endpoint's Alert.ReadWrite.All application permission.
    "incidents": {"path": "/api/incidents", "title": "incidentName", "timestamp": "lastUpdateTime"},
    "alerts": {"path": "/api/alerts", "title": "title", "timestamp": "lastUpdateTime"},
}


def _request_json(url: str, headers: dict[str, str], timeout: int = 15) -> dict[str, Any]:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=max(3, min(int(timeout), 30))) as response:
        payload = response.read(1_000_000)
    data = json.loads(payload.decode("utf-8", errors="replace"))
    return data if isinstance(data, dict) else {}


def _token(tenant_id: str, client_id: str, client_secret: str, scope: str, timeout: int = 15) -> str:
    body = urllib.parse.urlencode({"client_id": client_id, "client_secret": client_secret,
        "scope": scope, "grant_type": "client_credentials"}).encode()
    request = urllib.request.Request(f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(request, timeout=max(3, min(int(timeout), 30))) as response:
        data = json.loads(response.read(256_000).decode("utf-8", errors="replace"))
    token = str(data.get("access_token") or "")
    if not token:
        raise ValueError("Defender XDR token response did not include access_token")
    return token


def ensure_schema(db) -> None:
    db.execute('''CREATE TABLE IF NOT EXISTS defender_xdr_checkpoint (
        source TEXT PRIMARY KEY, checkpoint TEXT, updated_at REAL NOT NULL, status TEXT NOT NULL, detail TEXT)''')
    db.execute('''CREATE TABLE IF NOT EXISTS defender_xdr_observations (
        item_key TEXT PRIMARY KEY, observed_at REAL NOT NULL, collected_at REAL NOT NULL,
        alert_id TEXT, incident_id TEXT, severity TEXT, status TEXT, category TEXT, title TEXT,
        data TEXT NOT NULL)''')
    db.execute("CREATE INDEX IF NOT EXISTS defender_xdr_observed ON defender_xdr_observations(observed_at DESC)")
    db.execute('''CREATE TABLE IF NOT EXISTS defender_xdr_correlations (
        correlation_key TEXT PRIMARY KEY, item_key TEXT NOT NULL, correlated_at REAL NOT NULL,
        score INTEGER NOT NULL, data TEXT NOT NULL)''')
    db.execute("CREATE INDEX IF NOT EXISTS defender_xdr_correlation_item ON defender_xdr_correlations(item_key,correlated_at DESC)")
    entity_resolver.ensure_schema(db)


_FIRST_SEEN_KEYS = {"firstactivitydatetime", "starttime", "createddatetime", "alertcreationtime"}
_LAST_UPDATE_KEYS = {"lastupdatedatetime", "lastupdatetime", "lastactivitydatetime"}


def _incident_entities(record: dict[str, Any]) -> dict[str, set[str]]:
    extracted = entity_resolver.extract_entities(record)
    by_type: dict[str, set[str]] = {}
    for row in extracted:
        by_type.setdefault(row["type"], set()).add(row["value"])
    return {
        "ips": by_type.get("ip", set()),
        "identities": by_type.get("user", set()),
        "assets": set().union(by_type.get("hostname", set()), by_type.get("device", set())),
    }


def _contains_key(value: Any, keys: set[str], depth: int = 0) -> bool:
    if depth > 8:
        return False
    if isinstance(value, dict):
        for key, child in value.items():
            compact = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if compact in keys and child not in (None, "", []):
                return True
            if _contains_key(child, keys, depth + 1):
                return True
    elif isinstance(value, list):
        return any(_contains_key(child, keys, depth + 1) for child in value[:100])
    return False


def correlate(db, context: dict[str, Any], limit: int = 20) -> dict[str, Any]:
    """Correlate the local Defender ledger with bounded Wazuh evidence only.

    This intentionally does not query Microsoft or the Indexer. The caller supplies
    the samples from the overview aggregation, so page views cannot add load to
    either telemetry platform.
    """
    ensure_schema(db)
    limit = max(1, min(int(limit), 40))
    # The bounded overview is a compatibility/freshness input. Persist it first,
    # then correlate against the complete local graph accumulated by the worker.
    entity_resolver.ingest_prepared(db, entity_resolver.prepare_context(
        context if isinstance(context, dict) else {}))
    rows = db.execute("""SELECT item_key,observed_at,incident_id,alert_id,severity,status,category,title,data
        FROM defender_xdr_observations ORDER BY observed_at DESC LIMIT ?""", (limit * 5,)).fetchall()
    correlations = []
    now = time.time()
    seen_incidents: set[str] = set()
    for item_key, observed_at, incident_id, alert_id, severity, status, category, title, raw in rows:
        incident_key = str(incident_id or alert_id or item_key)
        if incident_key in seen_incidents:
            continue
        seen_incidents.add(incident_key)
        try:
            incident = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            incident = {}
        prepared = entity_resolver.prepare_evidence(
            "defender_xdr", str(item_key), observed_at, incident,
            title or "Defender XDR incident", severity or "unknown", 90,
        )
        if not prepared:
            continue
        entity_resolver.ingest_prepared(db, [prepared])
        match = entity_resolver.correlate_evidence(
            db, prepared, incident_key, title or "Defender XDR incident",
            severity or "unknown", status or "unknown",
        )
        if not match:
            continue
        result = {
            "incident_id": incident_key, "alert_id": alert_id,
            "title": title or "Defender XDR incident", "severity": severity or "unknown",
            "status": status or "unknown", "category": category or "", "observed_at": datetime.fromtimestamp(observed_at, timezone.utc).isoformat(),
            **match,
            "case_candidate": True,
            "case_note": "Create a persistent case only after analyst validation; no case was created automatically.",
            "evidence_source": "durable canonical entity graph built from local Defender, Wazuh, M365, and CMDB evidence",
        }
        correlation_key = hashlib.sha256((str(item_key) + "\x1f" + json.dumps(match["matches"], sort_keys=True)).encode()).hexdigest()
        db.execute("""INSERT INTO defender_xdr_correlations(correlation_key,item_key,correlated_at,score,data)
            VALUES (?,?,?,?,?) ON CONFLICT(correlation_key) DO UPDATE SET correlated_at=excluded.correlated_at,
            score=excluded.score,data=excluded.data""", (correlation_key, item_key, now, match["score"], json.dumps(result, separators=(",", ":"))))
        correlations.append(result)
    db.execute("DELETE FROM defender_xdr_correlations WHERE correlated_at<?", (now - 180 * 86400,))
    correlations.sort(key=lambda row: (-row["score"], row["title"]))
    return {"total": len(correlations), "items": correlations[:12],
            "source": "durable local canonical entity graph", "provider_calls": 0,
            "graph": entity_resolver.status(db)}


def _safe_base(value: str, provider: str) -> str:
    expected = PROVIDERS[provider]["base"]
    parsed = urllib.parse.urlsplit(value or expected)
    if parsed.scheme != "https" or parsed.netloc != urllib.parse.urlsplit(expected).netloc:
        raise ValueError(f"{provider} API base must be {expected}")
    return expected


def _observed(item: dict[str, Any]) -> str:
    for key in ("lastUpdateTime", "lastUpdateDateTime", "alertCreationTime", "createdDateTime"):
        value = item.get(key)
        if value:
            return str(value)
    return datetime.now(timezone.utc).isoformat()


def _observed_epoch(value: str, fallback: float) -> float:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError):
        return fallback


def collect(db, config: dict[str, str]) -> dict[str, Any]:
    """Collect a bounded alert page. Disabled/missing config never makes HTTP calls."""
    ensure_schema(db)
    if config.get("DEFENDER_XDR_ENABLED") != "true":
        return {"enabled": False, "status": "disabled", "observations": 0}
    tenant = str(config.get("DEFENDER_XDR_TENANT_ID") or "")
    client = str(config.get("DEFENDER_XDR_CLIENT_ID") or "")
    secret = str(config.get("DEFENDER_XDR_CLIENT_SECRET") or "")
    if not all((tenant, client, secret)):
        return {"enabled": True, "status": "not_configured", "observations": 0,
                "reason": "Defender XDR tenant/client/secret are required"}
    provider = str(config.get("DEFENDER_XDR_API_PROVIDER") or "defender").strip().lower()
    if provider not in PROVIDERS:
        return {"enabled": True, "status": "invalid_configuration", "observations": 0,
                "reason": "Defender XDR API provider must be defender or graph"}
    mode = str(config.get("DEFENDER_XDR_COLLECTION_MODE") or "incidents").strip().lower()
    collection = COLLECTIONS.get(mode)
    if collection is None:
        return {"enabled": True, "status": "invalid_configuration", "observations": 0,
                "reason": "Defender XDR collection mode must be incidents or alerts"}
    interval = max(300, min(int(config.get("DEFENDER_XDR_POLL_INTERVAL_SECONDS") or 900), 86400))
    source = f"{provider}:{mode}"
    row = db.execute("SELECT checkpoint,updated_at,status FROM defender_xdr_checkpoint WHERE source=?", (source,)).fetchone()
    # `checkpoint` is an ISO timestamp returned by Defender. Cooldown must use
    # the durable local update epoch, otherwise the second poll tries to cast
    # an ISO value to float and the collector never reaches its backoff path.
    if row and time.time() - float(row[1] or 0) < interval:
        count = int(db.execute("SELECT COUNT(*) FROM defender_xdr_observations").fetchone()[0] or 0)
        return {"enabled": True, "status": "cooldown", "provider": provider, "mode": mode, "observations": count}
    batch = max(1, min(int(config.get("DEFENDER_XDR_BATCH_SIZE") or 50), 100))
    try:
        if provider == "graph" and mode != "incidents":
            return {"enabled": True, "status": "invalid_configuration", "observations": 0,
                    "reason": "Microsoft Graph supports incidents mode only"}
        token = _token(tenant, client, secret, PROVIDERS[provider]["scope"])
        configured_base = str(config.get("DEFENDER_XDR_API_BASE_URL") or "")
        # Older deployments retain the Defender default in this field. A Graph
        # provider selection intentionally switches to the documented Graph base.
        if provider == "graph" and configured_base == DEFAULT_BASE_URL:
            configured_base = GRAPH_BASE_URL
        base = _safe_base(configured_base, provider)
        query = {"$top": str(batch)}
        # Incident-level metadata does not always contain the affected entity.
        # Graph supports expanding the related alerts in the same bounded request,
        # which supplies the IP/user/device clues needed for local correlation.
        if provider == "graph":
            query["$expand"] = "alerts"
        # This endpoint supports an OData time filter. If the collector has no
        # watermark yet, its first bounded pull stays deliberately small.
        if row and row[0]:
            query["$filter"] = ("lastUpdateDateTime" if provider == "graph" else collection["timestamp"]) + " ge " + str(row[0])
        path = "/v1.0/security/incidents" if provider == "graph" else collection["path"]
        url = base + path + "?" + urllib.parse.urlencode(query)
        payload = _request_json(url, {"Authorization": "Bearer " + token, "Accept": "application/json"})
        values = payload.get("value") if isinstance(payload.get("value"), list) else []
        rows = []
        now = time.time()
        for item in values[:batch]:
            if not isinstance(item, dict):
                continue
            alert_id = str(item.get("id") or item.get("alertId") or item.get("incidentId") or "")[:256]
            observed = _observed(item)
            key = hashlib.sha256((alert_id + "\x1f" + observed).encode()).hexdigest()
            severity = str(item.get("severity") or "")[:32]
            status = str(item.get("status") or "")[:64]
            category = str(item.get("determination") or item.get("classification") or item.get("category") or item.get("threatName") or "")[:256]
            title_key = "displayName" if provider == "graph" else collection["title"]
            title = str(item.get(title_key) or item.get("title") or item.get("alertName") or category)[:500]
            incident_id = str(item.get("incidentId") or (item.get("id") if mode == "incidents" else ""))[:256]
            rows.append((key, _observed_epoch(observed, now), now, alert_id, incident_id, severity,
                         status, category, title, json.dumps(item, separators=(",", ":"))))
        db.executemany("""INSERT INTO defender_xdr_observations
            (item_key,observed_at,collected_at,alert_id,incident_id,severity,status,category,title,data)
            VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(item_key) DO UPDATE SET
            collected_at=excluded.collected_at,severity=excluded.severity,status=excluded.status,
            category=excluded.category,title=excluded.title,data=excluded.data""", rows)
        db.execute("""INSERT INTO defender_xdr_checkpoint(source,checkpoint,updated_at,status,detail)
            VALUES (?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET checkpoint=excluded.checkpoint,
            updated_at=excluded.updated_at,status=excluded.status,detail=excluded.detail""",
            (source, _observed(values[0]) if values else None, now, "ok", json.dumps({"received": len(rows), "provider": provider, "mode": mode})))
        count = int(db.execute("SELECT COUNT(*) FROM defender_xdr_observations").fetchone()[0] or 0)
        return {"enabled": True, "status": "ok", "provider": provider, "mode": mode, "received": len(rows), "observations": count}
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError) as exc:
        message = str(exc)[:300]
        db.execute("""INSERT INTO defender_xdr_checkpoint(source,checkpoint,updated_at,status,detail)
            VALUES (?,NULL,?,?,?) ON CONFLICT(source) DO UPDATE SET updated_at=excluded.updated_at,
            status=excluded.status,detail=excluded.detail""", (source, time.time(), "error", message))
        count = int(db.execute("SELECT COUNT(*) FROM defender_xdr_observations").fetchone()[0] or 0)
        return {"enabled": True, "status": "error", "provider": provider, "mode": mode, "observations": count, "reason": message}


def status(db) -> dict[str, Any]:
    ensure_schema(db)
    count = int(db.execute("SELECT COUNT(*) FROM defender_xdr_observations").fetchone()[0] or 0)
    row = db.execute("SELECT updated_at,status,detail FROM defender_xdr_checkpoint ORDER BY updated_at DESC LIMIT 1").fetchone()
    recent_rows = db.execute("""SELECT observed_at,alert_id,incident_id,severity,status,category,title
        FROM defender_xdr_observations ORDER BY observed_at DESC LIMIT 40""").fetchall()
    recent, recent_keys = [], set()
    for item in recent_rows:
        key = str(item[2] or item[1] or "")
        if key in recent_keys:
            continue
        recent_keys.add(key)
        recent.append(item)
        if len(recent) >= 8:
            break
    profile_rows = db.execute("""SELECT observed_at,alert_id,incident_id,severity,status,data
        FROM defender_xdr_observations ORDER BY observed_at DESC LIMIT 100""").fetchall()
    field_counts = {field: 0 for field in (
        "alert_or_incident", "severity", "entities", "status", "first_seen", "last_update")}
    for observed_at, alert_id, incident_id, severity, item_status, raw in profile_rows:
        try:
            document = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            document = {}
        entities = _incident_entities(document)
        field_counts["alert_or_incident"] += int(bool(alert_id or incident_id))
        field_counts["severity"] += int(bool(severity))
        field_counts["status"] += int(bool(item_status))
        field_counts["entities"] += int(any(entities.values()))
        field_counts["first_seen"] += int(_contains_key(document, _FIRST_SEEN_KEYS))
        # observed_at is the source timestamp or local fallback timestamp; it
        # is not evidence that Microsoft supplied a last-update field.
        field_counts["last_update"] += int(_contains_key(document, _LAST_UPDATE_KEYS))
    available_fields = [field for field, value in field_counts.items() if value]
    latest_observed = profile_rows[0][0] if profile_rows else None
    return {"observations": count, "last_checked_at": datetime.fromtimestamp(row[0], timezone.utc).isoformat() if row else None,
            "status": row[1] if row else "not_started", "detail": row[2] if row else None,
            "last_observed_at": datetime.fromtimestamp(latest_observed, timezone.utc).isoformat() if latest_observed else None,
            "available_fields": available_fields, "field_counts": field_counts,
            "field_sample_size": len(profile_rows),
            "recent": [{"observed_at": datetime.fromtimestamp(item[0], timezone.utc).isoformat(),
                        "alert_id": item[1], "incident_id": item[2], "severity": item[3] or "unknown",
                        "status": item[4] or "unknown", "category": item[5] or "", "title": item[6] or "Defender XDR record",
                        "cluster_id": entity_resolver.cluster_id(str(item[2] or item[1] or ""))}
                       for item in recent], "entity_graph": entity_resolver.status(db)}


def history(db, start: str | None = None, end: str | None = None, limit: int = 30, offset: int = 0) -> dict[str, Any]:
    """Read already collected XDR records only; this never contacts Microsoft."""
    ensure_schema(db)
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    filters: list[str] = []
    params: list[Any] = []
    for boundary, operator in ((start, ">="), (end, "<")):
        if boundary:
            epoch = _observed_epoch(str(boundary), 0)
            filters.append(f"observed_at{operator}?")
            params.append(epoch)
    where = " WHERE " + " AND ".join(filters) if filters else ""
    total = int(db.execute("SELECT COUNT(*) FROM defender_xdr_observations" + where, params).fetchone()[0] or 0)
    rows = db.execute("""SELECT observed_at,collected_at,alert_id,incident_id,severity,status,category,title,data
        FROM defender_xdr_observations""" + where + " ORDER BY observed_at DESC LIMIT ? OFFSET ?", (*params, limit, offset)).fetchall()
    items = []
    severity_counts: dict[str, int] = {}
    for observed_at, collected_at, alert_id, incident_id, severity, item_status, category, title, raw in rows:
        level = str(severity or "unknown").lower()
        severity_counts[level] = severity_counts.get(level, 0) + 1
        try:
            data = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            data = {}
        items.append({
            "observed_at": datetime.fromtimestamp(observed_at, timezone.utc).isoformat(),
            "collected_at": datetime.fromtimestamp(collected_at, timezone.utc).isoformat(),
            "alert_id": alert_id, "incident_id": incident_id, "severity": severity or "unknown",
            "status": item_status or "unknown", "category": category or "", "title": title or "Defender XDR record",
            "data": data,
        })
    return {"source": "Microsoft Defender XDR local ledger", "total": total, "items": items,
            "summary": {"severity": severity_counts}, "provider_calls": 0,
            "storage": "soc-automation SQLite Defender ledger"}
