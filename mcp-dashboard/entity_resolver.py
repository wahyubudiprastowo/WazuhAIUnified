"""Durable canonical entity graph for local SOC correlation.

The resolver stores compact evidence metadata and entity relationships. It does
not retain raw Wazuh events and never contacts Wazuh or an intelligence provider.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Iterable


MAX_ENTITIES_PER_EVIDENCE = 48
MAX_RELATIONS_PER_EVIDENCE = 160
WEAK_CLUSTER_TYPES = {"cve", "cpe", "package", "domain", "hostname_alias"}
MATCH_WEIGHTS = {
    "hash": 90, "device": 85, "cloud_resource": 85, "user": 70,
    "hostname": 65, "url": 60, "ip": 45, "domain": 25,
    "hostname_alias": 20, "cve": 15, "cpe": 10, "package": 10,
}
CANDIDATE_LOOKBACK_HOURS = 24

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_HEX = re.compile(r"^[0-9a-f]+$", re.I)
_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$", re.I)
_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+._:/@-]{0,255}$", re.I)

_IP_KEYS = {"ip", "ipaddress", "sourceip", "destinationip", "srcip", "dstip",
            "remoteip", "localip", "clientip", "senderip"}
_HOST_KEYS = {"hostname", "host", "devicename", "devicednsname", "computername",
              "machinename", "fqdn", "targethostname"}
_USER_KEYS = {"user", "userid", "username", "userprincipalname", "upn", "accountupn",
              "accountname", "mailbox", "mailboxaddress", "primaryaddress", "email"}
_DEVICE_KEYS = {"deviceid", "mdedeviceid", "azureaddeviceid", "agentid", "machineid",
                "hostid", "endpointid"}
_DOMAIN_KEYS = {"domain", "domainname", "dnsdomain", "targetdomainname"}
_URL_KEYS = {"url", "uri", "requesturl", "fullurl"}
_HASH_KEYS = {"hash", "hashes", "filehash", "sha1", "sha256", "md5"}
_CVE_KEYS = {"cve", "cveid", "vulnerability", "vulnerabilityid"}
_CPE_KEYS = {"cpe", "cpe23uri", "cpename"}
_CLOUD_KEYS = {"azureresourceid", "cloudresourceid", "amazonresourceid",
               "googlecloudresourceid", "resourcearn", "arn"}


def ensure_schema(db) -> None:
    db.execute('''CREATE TABLE IF NOT EXISTS entity_nodes (
        entity_id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, canonical_value TEXT NOT NULL,
        display_value TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
        observation_count INTEGER NOT NULL DEFAULT 0,
        UNIQUE(entity_type,canonical_value))''')
    db.execute("CREATE INDEX IF NOT EXISTS entity_nodes_type_value ON entity_nodes(entity_type,canonical_value)")
    db.execute('''CREATE TABLE IF NOT EXISTS entity_evidence (
        evidence_id TEXT PRIMARY KEY, source TEXT NOT NULL, source_record_id TEXT NOT NULL,
        observed_at REAL NOT NULL, last_seen REAL NOT NULL, title TEXT, severity TEXT,
        confidence INTEGER NOT NULL, payload_hash TEXT NOT NULL,
        occurrence_count INTEGER NOT NULL DEFAULT 1, data TEXT NOT NULL)''')
    db.execute("CREATE INDEX IF NOT EXISTS entity_evidence_source_time ON entity_evidence(source,observed_at DESC)")
    db.execute('''CREATE TABLE IF NOT EXISTS entity_observations (
        evidence_id TEXT NOT NULL, entity_id TEXT NOT NULL, role TEXT NOT NULL,
        field_path TEXT NOT NULL, confidence INTEGER NOT NULL, observed_at REAL NOT NULL,
        source TEXT NOT NULL, PRIMARY KEY(evidence_id,entity_id,role,field_path),
        FOREIGN KEY(evidence_id) REFERENCES entity_evidence(evidence_id),
        FOREIGN KEY(entity_id) REFERENCES entity_nodes(entity_id))''')
    db.execute("CREATE INDEX IF NOT EXISTS entity_observations_entity ON entity_observations(entity_id,observed_at DESC)")
    db.execute('''CREATE TABLE IF NOT EXISTS entity_relations (
        relation_id TEXT PRIMARY KEY, source_entity_id TEXT NOT NULL, target_entity_id TEXT NOT NULL,
        relation_type TEXT NOT NULL, evidence_id TEXT NOT NULL, observed_at REAL NOT NULL,
        source TEXT NOT NULL, confidence INTEGER NOT NULL,
        FOREIGN KEY(evidence_id) REFERENCES entity_evidence(evidence_id))''')
    db.execute("CREATE INDEX IF NOT EXISTS entity_relations_evidence ON entity_relations(evidence_id,observed_at DESC)")
    db.execute("CREATE INDEX IF NOT EXISTS entity_relations_nodes ON entity_relations(source_entity_id,target_entity_id)")
    db.execute('''CREATE TABLE IF NOT EXISTS entity_clusters (
        cluster_id TEXT PRIMARY KEY, cluster_key TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
        severity TEXT, status TEXT, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
        confidence INTEGER NOT NULL, updated_at REAL NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS entity_cluster_members (
        cluster_id TEXT NOT NULL, evidence_id TEXT NOT NULL, source_record_id TEXT NOT NULL,
        source TEXT NOT NULL, confidence INTEGER NOT NULL, first_seen REAL NOT NULL,
        last_seen REAL NOT NULL, PRIMARY KEY(cluster_id,evidence_id),
        FOREIGN KEY(cluster_id) REFERENCES entity_clusters(cluster_id),
        FOREIGN KEY(evidence_id) REFERENCES entity_evidence(evidence_id))''')
    db.execute("CREATE INDEX IF NOT EXISTS entity_cluster_members_evidence ON entity_cluster_members(evidence_id)")
    db.execute('''CREATE TABLE IF NOT EXISTS entity_graph_batches (
        batch_key TEXT PRIMARY KEY, candidate_count INTEGER NOT NULL,
        stored_count INTEGER NOT NULL, dropped_count INTEGER NOT NULL,
        committed_at REAL NOT NULL)''')
    db.execute("CREATE INDEX IF NOT EXISTS entity_graph_batches_time ON entity_graph_batches(committed_at DESC)")
    batch_columns = {row[1] for row in db.execute("PRAGMA table_info(entity_graph_batches)")}
    for name in ("queued_count", "coalesced_count"):
        if name not in batch_columns:
            db.execute(f"ALTER TABLE entity_graph_batches ADD COLUMN {name} INTEGER NOT NULL DEFAULT 0")
    db.execute('''CREATE TABLE IF NOT EXISTS entity_graph_queue (
        evidence_id TEXT PRIMARY KEY, batch_key TEXT NOT NULL, payload TEXT NOT NULL,
        queued_at REAL NOT NULL)''')
    db.execute("CREATE INDEX IF NOT EXISTS entity_graph_queue_time ON entity_graph_queue(queued_at,evidence_id)")
    db.execute('''CREATE TABLE IF NOT EXISTS correlation_candidates (
        candidate_id TEXT PRIMARY KEY, candidate_key TEXT NOT NULL UNIQUE,
        primary_entity_type TEXT NOT NULL, primary_entity_value TEXT NOT NULL,
        first_seen REAL NOT NULL, last_seen REAL NOT NULL, evidence_count INTEGER NOT NULL,
        source_count INTEGER NOT NULL, confidence INTEGER NOT NULL,
        classification TEXT NOT NULL DEFAULT 'candidate', updated_at REAL NOT NULL)''')
    db.execute("CREATE INDEX IF NOT EXISTS correlation_candidates_time ON correlation_candidates(last_seen DESC)")
    db.execute('''CREATE TABLE IF NOT EXISTS correlation_candidate_state (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_run REAL NOT NULL,
        observations_considered INTEGER NOT NULL, candidates INTEGER NOT NULL,
        truncated INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
        error TEXT)''')
    db.execute('''CREATE TABLE IF NOT EXISTS correlation_candidate_evidence (
        candidate_id TEXT NOT NULL, evidence_id TEXT NOT NULL, source TEXT NOT NULL,
        source_record_id TEXT NOT NULL, observed_at REAL NOT NULL, confidence INTEGER NOT NULL,
        PRIMARY KEY(candidate_id,evidence_id),
        FOREIGN KEY(candidate_id) REFERENCES correlation_candidates(candidate_id),
        FOREIGN KEY(evidence_id) REFERENCES entity_evidence(evidence_id))''')
    db.execute("CREATE INDEX IF NOT EXISTS correlation_candidate_evidence_ref ON correlation_candidate_evidence(evidence_id)")


def _compact(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _epoch(value: Any, fallback: float | None = None) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError):
        return time.time() if fallback is None else float(fallback)


def _domain(value: Any) -> str | None:
    text = str(value or "").strip().lower().rstrip(".")
    if not text or len(text) > 253 or not _HOST.fullmatch(text):
        return None
    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def canonicalize(entity_type: str, value: Any) -> str | None:
    """Return a conservative canonical value, or None for malformed input."""
    kind = str(entity_type or "").strip().lower()
    text = str(value or "").strip()
    if not text or len(text) > 2048:
        return None
    if kind == "ip":
        try:
            parsed = ipaddress.ip_address(text.strip("[]"))
            if getattr(parsed, "ipv4_mapped", None):
                parsed = parsed.ipv4_mapped
            return str(parsed)
        except ValueError:
            return None
    if kind in {"hostname", "domain", "hostname_alias"}:
        return _domain(text)
    if kind == "user":
        normalized = text.lower().rstrip(".")
        return normalized if 1 < len(normalized) <= 320 and not any(c.isspace() for c in normalized) else None
    if kind == "device":
        normalized = text.lower().strip("{}")
        return normalized if 1 < len(normalized) <= 256 and not any(c.isspace() for c in normalized) else None
    if kind == "url":
        candidate = text if "://" in text else "https://" + text
        try:
            parsed = urllib.parse.urlsplit(candidate)
        except ValueError:
            return None
        host = _domain(parsed.hostname)
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            return None
        port = parsed.port
        netloc = host + (f":{port}" if port and port not in {80, 443} else "")
        path = urllib.parse.quote(urllib.parse.unquote(parsed.path or "/"), safe="/%:@-._~!$&'()*+,;=")
        # Query strings frequently contain tokens. Keep equality without storing the clear value.
        query = ("?q=" + hashlib.sha256(parsed.query.encode()).hexdigest()[:16]) if parsed.query else ""
        return f"{parsed.scheme.lower()}://{netloc}{path}{query}"
    if kind == "hash":
        normalized = text.lower()
        if "=" in normalized:
            prefix, normalized = normalized.split("=", 1)
            prefix = prefix.strip()
        else:
            prefix = ""
        normalized = normalized.strip()
        if not _HEX.fullmatch(normalized) or len(normalized) not in {32, 40, 64}:
            return None
        algorithm = {32: "md5", 40: "sha1", 64: "sha256"}[len(normalized)]
        if prefix and prefix not in {algorithm, "hash"}:
            return None
        return f"{algorithm}:{normalized}"
    if kind == "cve":
        match = _CVE.fullmatch(text)
        return match.group(0).upper() if match else None
    if kind == "cpe":
        normalized = text.lower()
        return normalized if normalized.startswith(("cpe:2.3:", "cpe:/")) and len(normalized) <= 1024 else None
    if kind == "package":
        normalized = text.lower().strip()
        return normalized if _PACKAGE.fullmatch(normalized) else None
    if kind == "cloud_resource":
        normalized = text.strip()
        if normalized.lower().startswith("/subscriptions/"):
            return normalized.lower().rstrip("/")
        if normalized.lower().startswith("arn:") and normalized.count(":") >= 5:
            return normalized.rstrip("/")
        if normalized.lower().startswith(("//compute.googleapis.com/", "projects/")):
            return normalized.rstrip("/")
        return None
    return None


def _add(result: dict[tuple[str, str, str], dict[str, Any]], kind: str, value: Any,
         role: str, field_path: str, confidence: int = 90) -> None:
    canonical = canonicalize(kind, value)
    if not canonical:
        return
    key = (kind, canonical, role or "observed")
    current = result.get(key)
    row = {"type": kind, "value": canonical, "display": str(value)[:500],
           "role": (role or "observed")[:80], "field_path": field_path[:300],
           "confidence": max(1, min(int(confidence), 100))}
    if not current or row["confidence"] > current["confidence"]:
        result[key] = row
    if kind == "hostname" and "." in canonical:
        _add(result, "hostname_alias", canonical.split(".", 1)[0], "short_name", field_path, 60)
        _add(result, "domain", canonical.split(".", 1)[1], "dns_domain", field_path, 75)
    if kind == "url":
        try:
            _add(result, "domain", urllib.parse.urlsplit(canonical).hostname, "url_host", field_path, 85)
        except ValueError:
            pass


def extract_entities(document: Any) -> list[dict[str, Any]]:
    """Extract bounded canonical entities from Defender, Wazuh, CMDB, or STIX-shaped JSON."""
    result: dict[tuple[str, str, str], dict[str, Any]] = {}

    def walk(value: Any, path: str = "", parent_type: str = "", depth: int = 0) -> None:
        if depth > 10 or len(result) >= MAX_ENTITIES_PER_EVIDENCE:
            return
        if isinstance(value, dict):
            evidence_type = str(value.get("@odata.type") or parent_type or "").lower()
            roles = value.get("roles") or value.get("detailedRoles") or []
            role = str(roles[0]) if isinstance(roles, list) and roles else "observed"
            path_tail = _compact(path.rsplit(".", 1)[-1].split("[", 1)[0]) if path else ""
            if path_tail == "agent":
                _add(result, "device", value.get("id"), "managed_agent", path + ".id", 95)
                _add(result, "hostname", value.get("name"), "managed_asset", path + ".name", 95)
                _add(result, "ip", value.get("ip"), "managed_asset", path + ".ip", 90)
            elif path_tail == "host":
                _add(result, "device", value.get("id"), "host_id", path + ".id", 90)
                _add(result, "hostname", value.get("name") or value.get("hostname"), "host", path + ".name", 90)
            package_name = next((value.get(k) for k in ("packageName", "softwareName", "productName") if value.get(k)), None)
            package_version = next((value.get(k) for k in ("packageVersion", "softwareVersion", "productVersion", "version") if value.get(k)), None)
            if not package_name and path_tail in {"package", "packages", "component", "components"}:
                package_name = value.get("name") or value.get("product")
                if package_name and value.get("vendor"):
                    package_name = str(value["vendor"]) + ":" + str(package_name)
            if package_name:
                package = str(package_name) + ("@" + str(package_version) if package_version else "")
                _add(result, "package", package, "affected_package", path or "package", 85)
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                compact = _compact(key)
                if not isinstance(child, (dict, list)):
                    if compact in _IP_KEYS:
                        ip_role = ("source" if compact.startswith(("src", "source", "remote", "sender", "client"))
                                   else "destination" if compact.startswith(("dst", "destination", "local")) else role)
                        _add(result, "ip", child, ip_role, child_path)
                    elif compact in _HOST_KEYS:
                        _add(result, "hostname", child, role, child_path)
                    elif compact in _USER_KEYS:
                        _add(result, "user", child, "mailbox" if "mail" in compact else role, child_path)
                    elif compact in _DEVICE_KEYS:
                        _add(result, "device", child, role, child_path)
                    elif compact in _DOMAIN_KEYS:
                        _add(result, "domain", child, role, child_path)
                    elif compact in _URL_KEYS and compact != "incidentweburl":
                        _add(result, "url", child, role, child_path)
                    elif compact in _HASH_KEYS:
                        for item in re.split(r"[,;\s]+", str(child)):
                            _add(result, "hash", item, role, child_path)
                    elif compact in _CVE_KEYS:
                        for item in _CVE.findall(str(child)):
                            _add(result, "cve", item, "vulnerability", child_path)
                    elif compact in _CPE_KEYS:
                        _add(result, "cpe", child, "platform", child_path)
                    elif compact in _CLOUD_KEYS or (compact == "resourceid" and any(
                            token in evidence_type for token in ("azureresource", "amazonresource", "googlecloudresource"))):
                        _add(result, "cloud_resource", child, role, child_path)
                    if compact in {"title", "name", "description"}:
                        for item in _CVE.findall(str(child))[:8]:
                            _add(result, "cve", item, "referenced", child_path, 75)
                walk(child, child_path, evidence_type, depth + 1)
        elif isinstance(value, list):
            for index, child in enumerate(value[:100]):
                walk(child, f"{path}[{index}]", parent_type, depth + 1)

    walk(document)
    return list(result.values())[:MAX_ENTITIES_PER_EVIDENCE]


def _digest(*parts: Any) -> str:
    return hashlib.sha256("\x1f".join(str(part) for part in parts).encode()).hexdigest()


def _attack_mappings(document: Any) -> list[dict[str, str]]:
    """Extract only explicit ATT&CK technique IDs from structured fields."""
    mappings: dict[str, dict[str, str]] = {}
    stack = [document]
    keys = {"mitretechniques", "attacktechniques", "techniqueids", "mitretechniqueid"}
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                compact = _compact(key)
                if compact in keys:
                    candidates = item if isinstance(item, list) else [item]
                    for candidate in candidates[:12]:
                        details = candidate if isinstance(candidate, dict) else {"id": candidate}
                        technique_id = str(details.get("techniqueId") or details.get("technique_id") or details.get("id") or "").strip().upper()
                        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id):
                            continue
                        mappings[technique_id] = {
                            "id": technique_id,
                            "name": str(details.get("techniqueName") or details.get("name") or "")[:160],
                            "tactic": str(details.get("tactic") or details.get("tacticName") or "")[:100],
                            "mapping_source": "source_event_field",
                        }
                if isinstance(item, (dict, list)):
                    stack.append(item)
        elif isinstance(value, list):
            stack.extend(value[:100])
    return [mappings[key] for key in sorted(mappings)[:12]]


def prepare_evidence(source: str, source_record_id: str, observed_at: Any, document: Any,
                     title: str = "", severity: str = "", confidence: int = 80,
                     occurrence_count: int = 1, evidence_key: str | None = None) -> dict[str, Any] | None:
    entities = extract_entities(document)
    if not entities:
        return None
    source = str(source or "unknown")[:80]
    source_record_id = str(source_record_id or _digest(json.dumps(document, sort_keys=True, default=str)))[:500]
    observed = _epoch(observed_at)
    payload_hash = _digest(json.dumps(document, sort_keys=True, default=str, ensure_ascii=True))
    evidence_id = "ev-" + _digest(source, evidence_key or source_record_id)
    attack_mappings = _attack_mappings(document)
    return {
        "evidence_id": evidence_id, "source": source, "source_record_id": source_record_id,
        "observed_at": observed, "last_seen": observed, "title": str(title or "")[:500],
        "severity": str(severity or "unknown")[:40], "confidence": max(1, min(int(confidence), 100)),
        "payload_hash": payload_hash, "occurrence_count": max(1, int(occurrence_count)),
        "entities": entities,
        "data": {"attack_techniques": attack_mappings} if attack_mappings else {},
    }


def prepare_wazuh_evidence(event: dict[str, Any], record_id: str, index: str = "") -> dict[str, Any] | None:
    """Prepare only correlation-worthy event metadata already read by the rollup stream."""
    rule = event.get("rule") if isinstance(event.get("rule"), dict) else {}
    level = int(rule.get("level") or 0)
    prepared = prepare_evidence("wazuh", f"{index}:{record_id}", event.get("@timestamp"), event,
                                rule.get("description") or "Wazuh alert", str(level), min(95, 55 + level * 3))
    if not prepared:
        return None
    strong_types = {row["type"] for row in prepared["entities"] if row["type"] not in WEAK_CLUSTER_TYPES}
    if level < 7 and len(strong_types) < 2:
        return None
    bucket = datetime.fromtimestamp(prepared["observed_at"], timezone.utc).replace(
        minute=(datetime.fromtimestamp(prepared["observed_at"], timezone.utc).minute // 5) * 5,
        second=0, microsecond=0).isoformat()
    signature = ",".join(sorted(f'{row["type"]}:{row["value"]}' for row in prepared["entities"]))
    prepared["evidence_id"] = "ev-" + _digest("wazuh", bucket, rule.get("id") or "", signature)
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
    raw_techniques = mitre.get("id") or []
    if isinstance(raw_techniques, str):
        raw_techniques = [raw_techniques]
    techniques = []
    for technique in raw_techniques[:12] if isinstance(raw_techniques, list) else []:
        technique_id = str(technique).strip().upper()
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id):
            tactics = mitre.get("tactic") or []
            names = mitre.get("technique") or []
            techniques.append({
                "id": technique_id,
                "tactic": str(tactics[0] if isinstance(tactics, list) and tactics else tactics or "")[:100],
                "name": str(names[0] if isinstance(names, list) and names else names or "")[:160],
                "mapping_source": "wazuh_rule.mitre",
            })
    prepared["data"] = {
        "rule_id": str(rule.get("id") or "")[:80], "bucket": bucket,
        "representative_record_id": str(record_id)[:300],
        "decoder": str((event.get("decoder") or {}).get("name") or "")[:120]
        if isinstance(event.get("decoder"), dict) else "",
        "attack_techniques": techniques or prepared.get("data", {}).get("attack_techniques", []),
    }
    return prepared


def entity_timeline(db, entities: Iterable[dict[str, Any]], start: float, end: float,
                    limit: int = 100) -> dict[str, Any]:
    """Return timestamped evidence related to canonical case entities.

    This reads only the local evidence graph. It intentionally returns an
    evidence sequence, not inferred edges or an attack path.
    """
    ensure_schema(db)
    aliases = {"source_ip": "ip", "srcip": "ip", "ip_address": "ip",
               "host": "hostname", "fqdn": "hostname", "asset": "device",
               "asset_id": "device", "agent_id": "device", "endpoint": "device",
               "upn": "user", "mailbox": "user", "identity": "user"}
    selected: list[tuple[str, str]] = []
    for entity in list(entities or [])[:50]:
        if not isinstance(entity, dict):
            continue
        kind = str(entity.get("entity_type") or entity.get("type") or "").lower().strip()
        value = entity.get("entity_value") or entity.get("value")
        kind = aliases.get(kind, kind)
        if kind not in {"ip", "hostname", "user", "device", "domain", "url", "hash", "cve", "cpe", "package", "cloud_resource"}:
            continue
        canonical = canonicalize(kind, value)
        if canonical and (kind, canonical) not in selected:
            selected.append((kind, canonical))
    if not selected:
        return {"status": "no_entities", "events": [], "entities": [], "source": "local entity graph"}
    start, end = float(start), float(end)
    if start >= end or end - start > 186 * 86400:
        raise ValueError("Timeline range must be positive and no longer than 186 days")
    match_sql = " OR ".join("(n.entity_type=? AND n.canonical_value=?)" for _ in selected)
    match_params = [part for pair in selected for part in pair]
    event_rows = db.execute(f'''SELECT e.evidence_id,e.source,e.source_record_id,e.observed_at,
            e.last_seen,e.title,e.severity,e.confidence,e.occurrence_count,e.data
        FROM entity_evidence e WHERE e.observed_at>=? AND e.observed_at<? AND EXISTS (
            SELECT 1 FROM entity_observations o JOIN entity_nodes n ON n.entity_id=o.entity_id
            WHERE o.evidence_id=e.evidence_id AND ({match_sql}))
        ORDER BY e.observed_at,e.evidence_id LIMIT ?''',
        [start, end, *match_params, max(1, min(int(limit), 200))]).fetchall()
    observations_by_evidence: dict[str, list[tuple[Any, ...]]] = {}
    evidence_ids = [row[0] for row in event_rows]
    if evidence_ids:
        placeholders = ",".join("?" for _ in evidence_ids)
        for item in db.execute(f'''SELECT o.evidence_id,n.entity_type,n.canonical_value,o.role,
                o.field_path,o.confidence FROM entity_observations o
            JOIN entity_nodes n ON n.entity_id=o.entity_id
            WHERE o.evidence_id IN ({placeholders})
            ORDER BY o.evidence_id,n.entity_type,n.canonical_value''', evidence_ids).fetchall():
            bucket = observations_by_evidence.setdefault(item[0], [])
            if len(bucket) < 48:
                bucket.append(item[1:])
    events = []
    related_entities: set[tuple[str, str]] = set()
    for row in event_rows:
        evidence_id = row[0]
        observations = observations_by_evidence.get(evidence_id, [])
        event_entities = [{"type": item[0], "value": item[1], "role": item[2],
                           "field_path": item[3], "confidence": item[4]} for item in observations]
        matched_entities = [{"type": kind, "value": value} for kind, value in selected
                           if (kind, value) in {(item[0], item[1]) for item in observations}]
        related_entities.update((item[0], item[1]) for item in observations)
        try:
            metadata = json.loads(row[9]) if row[9] else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            metadata = {}
        techniques = metadata.get("attack_techniques", []) if isinstance(metadata, dict) else []
        events.append({
            "evidence_id": evidence_id, "timestamp": datetime.fromtimestamp(row[3], timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(row[4], timezone.utc).isoformat(),
            "source": row[1], "source_record_id": row[2], "title": row[5] or "Evidence event",
            "severity": row[6] or "unknown", "confidence": row[7], "occurrence_count": row[8],
            "rule_id": metadata.get("rule_id") if isinstance(metadata, dict) else None,
            "decoder": metadata.get("decoder") if isinstance(metadata, dict) else None,
            "attack_techniques": techniques if isinstance(techniques, list) else [],
            "attack_mapping_status": "mapped" if techniques else "not_mapped_in_source_evidence",
            "matched_entities": matched_entities, "entities": event_entities,
        })
    return {"status": "available" if events else "no_events", "events": events,
            "entities": [{"type": kind, "value": value} for kind, value in sorted(related_entities)],
            "range": {"start": datetime.fromtimestamp(start, timezone.utc).isoformat(),
                      "end": datetime.fromtimestamp(end, timezone.utc).isoformat()},
            "returned": len(events), "limit": max(1, min(int(limit), 200)),
            "truncated": len(event_rows) >= max(1, min(int(limit), 200)),
            "source": "local durable entity graph",
            "interpretation": "Chronological evidence sequence; co-observation does not establish causality or attack path."}


def prepare_context(context: dict[str, Any]) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = []
    for group, source, limit in (("network", "wazuh_overview_network", 24),
                                 ("identity", "wazuh_overview_identity", 24),
                                 ("m365", "m365", 24), ("assets", "cmdb", 200)):
        for row in (context.get(group) or [])[:limit]:
            if not isinstance(row, dict):
                continue
            document = dict(row)
            if group == "network":
                document.update({
                    "sourceIp": row.get("source") or row.get("source_ip"),
                    "destinationIp": row.get("destination") or row.get("destination_ip"),
                    "deviceDnsName": row.get("agent") or row.get("asset") or row.get("device") or row.get("hostname"),
                })
            elif group in {"identity", "m365"}:
                document.update({
                    "ipAddress": row.get("source_ip") or row.get("client_ip") or row.get("ip"),
                    "userPrincipalName": row.get("user") or row.get("identity") or row.get("account"),
                    "primaryAddress": row.get("mailbox"),
                    "deviceDnsName": row.get("agent") or row.get("device") or row.get("hostname"),
                })
            elif group == "assets":
                document.update({
                    "deviceId": row.get("id") or row.get("agent_id"),
                    "deviceDnsName": row.get("name") or row.get("hostname") or row.get("host"),
                    "ipAddress": row.get("ip"),
                })
            identity = _digest(group, json.dumps(row, sort_keys=True, default=str, ensure_ascii=True))
            item = prepare_evidence(source, identity, row.get("timestamp") or row.get("last_verified"), document,
                                    row.get("operation") or row.get("name") or group,
                                    row.get("severity") or "context", 75 if source != "cmdb" else 85)
            if item:
                prepared.append(item)
    return prepared


def _entity_id(kind: str, canonical: str) -> str:
    return "ent-" + _digest(kind, canonical)


def _relation_type(left: dict[str, Any], right: dict[str, Any]) -> str:
    types = {left["type"], right["type"]}
    roles = {left["role"].lower(), right["role"].lower()}
    if types == {"cve", "package"}:
        return "affects"
    if "user" in types and types & {"device", "hostname", "cloud_resource"}:
        return "authenticated_to"
    if "hash" in types and types & {"device", "hostname"}:
        return "observed_on"
    if {"source", "destination"} <= roles or {"attacker", "compromised"} <= roles:
        return "communicates_with"
    return "co_observed"


def ingest_prepared(db, records: Iterable[dict[str, Any] | None]) -> dict[str, int]:
    """Idempotently persist prepared evidence in the caller's transaction."""
    ensure_schema(db)
    counts = {"evidence": 0, "entities": 0, "relations": 0}
    now = time.time()
    for record in records:
        if not record or not record.get("entities"):
            continue
        evidence_id = record["evidence_id"]
        metadata = record.get("data") if isinstance(record.get("data"), dict) else {}
        db.execute('''INSERT INTO entity_evidence
            (evidence_id,source,source_record_id,observed_at,last_seen,title,severity,confidence,
             payload_hash,occurrence_count,data) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(evidence_id) DO UPDATE SET
            last_seen=MAX(entity_evidence.last_seen,excluded.last_seen),title=excluded.title,
            severity=excluded.severity,confidence=MAX(entity_evidence.confidence,excluded.confidence),
            occurrence_count=MAX(entity_evidence.occurrence_count,excluded.occurrence_count),data=excluded.data''',
            (evidence_id, record["source"], record["source_record_id"], record["observed_at"],
             record.get("last_seen", record["observed_at"]), record.get("title"), record.get("severity"),
             record["confidence"], record["payload_hash"], record.get("occurrence_count", 1),
             json.dumps(metadata, separators=(",", ":"))))
        counts["evidence"] += 1
        nodes: list[tuple[str, dict[str, Any]]] = []
        for entity in record["entities"][:MAX_ENTITIES_PER_EVIDENCE]:
            entity_id = _entity_id(entity["type"], entity["value"])
            nodes.append((entity_id, entity))
            db.execute('''INSERT INTO entity_nodes
                (entity_id,entity_type,canonical_value,display_value,first_seen,last_seen,observation_count)
                VALUES (?,?,?,?,?,?,1) ON CONFLICT(entity_id) DO UPDATE SET
                first_seen=MIN(entity_nodes.first_seen,excluded.first_seen),
                last_seen=MAX(entity_nodes.last_seen,excluded.last_seen),
                display_value=excluded.display_value,
                observation_count=entity_nodes.observation_count+CASE WHEN entity_nodes.last_seen<excluded.last_seen THEN 1 ELSE 0 END''',
                (entity_id, entity["type"], entity["value"], entity["display"],
                 record["observed_at"], record.get("last_seen", record["observed_at"])))
            db.execute('''INSERT OR IGNORE INTO entity_observations
                (evidence_id,entity_id,role,field_path,confidence,observed_at,source)
                VALUES (?,?,?,?,?,?,?)''',
                (evidence_id, entity_id, entity["role"], entity["field_path"], entity["confidence"],
                 record["observed_at"], record["source"]))
            counts["entities"] += 1
        relation_count = 0
        for index, (left_id, left) in enumerate(nodes):
            for right_id, right in nodes[index + 1:]:
                same_type_flow = left["type"] == right["type"] == "ip" and {
                    left["role"].lower(), right["role"].lower()} == {"source", "destination"}
                if (left["type"] == right["type"] and not same_type_flow) or relation_count >= MAX_RELATIONS_PER_EVIDENCE:
                    continue
                relation_type = _relation_type(left, right)
                relation_id = "rel-" + _digest(evidence_id, min(left_id, right_id), max(left_id, right_id), relation_type)
                db.execute('''INSERT OR IGNORE INTO entity_relations
                    (relation_id,source_entity_id,target_entity_id,relation_type,evidence_id,
                     observed_at,source,confidence) VALUES (?,?,?,?,?,?,?,?)''',
                    (relation_id, left_id, right_id, relation_type, evidence_id, record["observed_at"],
                     record["source"], min(left["confidence"], right["confidence"], record["confidence"])))
                relation_count += 1
        counts["relations"] += relation_count
    return counts


def enqueue_prepared(db, batch_key: str, records: Iterable[dict[str, Any] | None]) -> int:
    """Durably queue bounded entity evidence when a scan window exceeds its write budget."""
    ensure_schema(db)
    queued_at = time.time()
    rows = [(record["evidence_id"], str(batch_key)[:300],
             json.dumps(record, separators=(",", ":"), ensure_ascii=True), queued_at)
            for record in records if record and record.get("entities")]
    before = db.total_changes
    db.executemany("""INSERT OR IGNORE INTO entity_graph_queue
        (evidence_id,batch_key,payload,queued_at) VALUES (?,?,?,?)""", rows)
    return db.total_changes - before


def remove_queued(db, evidence_ids: Iterable[str]) -> None:
    ids = list(dict.fromkeys(str(value) for value in evidence_ids if value))
    for offset in range(0, len(ids), 400):
        batch = ids[offset:offset + 400]
        placeholders = ",".join("?" for _ in batch)
        db.execute(f"DELETE FROM entity_graph_queue WHERE evidence_id IN ({placeholders})", batch)


def drain_queue(db, limit: int = 100) -> dict[str, int]:
    """Materialize one small SQLite-only queue batch; never reads Wazuh or providers."""
    ensure_schema(db)
    limit = max(1, min(int(limit), 1000))
    rows = db.execute("""SELECT evidence_id,payload FROM entity_graph_queue
        ORDER BY queued_at,evidence_id LIMIT ?""", (limit,)).fetchall()
    if not rows:
        return {"processed": 0, "entities": 0, "relations": 0}
    records = [json.loads(payload) for _, payload in rows]
    counts = ingest_prepared(db, records)
    remove_queued(db, [evidence_id for evidence_id, _ in rows])
    return {"processed": len(rows), "entities": counts["entities"], "relations": counts["relations"]}


def correlate_evidence(db, defender_evidence: dict[str, Any], incident_id: str, title: str,
                       severity: str, status: str, window_days: int = 30) -> dict[str, Any] | None:
    """Correlate one Defender evidence record to durable non-Defender evidence."""
    ensure_schema(db)
    evidence_id = defender_evidence["evidence_id"]
    lower = defender_evidence["observed_at"] - max(1, min(window_days, 180)) * 86400
    upper = defender_evidence["observed_at"] + max(1, min(window_days, 180)) * 86400
    rows = db.execute('''SELECT n.entity_type,n.canonical_value,o.entity_id,
            e.evidence_id,e.source,e.source_record_id,e.observed_at,e.title,e.confidence
        FROM entity_observations own
        JOIN entity_nodes n ON n.entity_id=own.entity_id
        JOIN entity_observations o ON o.entity_id=own.entity_id AND o.evidence_id<>own.evidence_id
        JOIN entity_evidence e ON e.evidence_id=o.evidence_id
        WHERE own.evidence_id=? AND e.source NOT LIKE 'defender%' AND
              ((e.observed_at BETWEEN ? AND ?) OR e.source='cmdb')
        ORDER BY e.observed_at DESC LIMIT 500''', (evidence_id, lower, upper)).fetchall()
    by_type: dict[str, set[str]] = {}
    local: dict[str, dict[str, Any]] = {}
    for kind, value, entity_id, local_evidence, source, source_record_id, observed_at, local_title, confidence in rows:
        by_type.setdefault(str(kind), set()).add(str(value))
        item = local.setdefault(local_evidence, {
            "evidence_id": local_evidence, "source": source, "source_record_id": source_record_id,
            "observed_at": datetime.fromtimestamp(float(observed_at), timezone.utc).isoformat(),
            "title": local_title or "Local evidence", "confidence": int(confidence or 0), "entities": []})
        if entity_id not in item["entities"]:
            item["entities"].append(entity_id)
    strong = {kind for kind, values in by_type.items() if values and kind not in WEAK_CLUSTER_TYPES}
    score = min(100, sum(min(2, len(values)) * MATCH_WEIGHTS.get(kind, 10) for kind, values in by_type.items()))
    if not strong or score < 30:
        return None
    cluster_key = "defender:" + str(incident_id or defender_evidence["source_record_id"])
    cluster_id = "cluster-" + _digest(cluster_key)[:24]
    confidence = "confirmed_by_multi_source" if len(strong) >= 2 or len({v["source"] for v in local.values()}) >= 2 else "matched_local_entity"
    now = time.time()
    first_seen = min([defender_evidence["observed_at"], *[_epoch(row["observed_at"]) for row in local.values()]])
    last_seen = max([defender_evidence["observed_at"], *[_epoch(row["observed_at"]) for row in local.values()]])
    db.execute('''INSERT INTO entity_clusters
        (cluster_id,cluster_key,title,severity,status,first_seen,last_seen,confidence,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(cluster_key) DO UPDATE SET
        title=excluded.title,severity=excluded.severity,status=excluded.status,
        first_seen=MIN(entity_clusters.first_seen,excluded.first_seen),
        last_seen=MAX(entity_clusters.last_seen,excluded.last_seen),
        confidence=MAX(entity_clusters.confidence,excluded.confidence),updated_at=excluded.updated_at''',
        (cluster_id, cluster_key, title or "Defender XDR incident", severity or "unknown",
         status or "unknown", first_seen, last_seen, score, now))
    members = [(evidence_id, defender_evidence["source_record_id"], defender_evidence["source"],
                defender_evidence["confidence"], defender_evidence["observed_at"], defender_evidence["observed_at"])]
    members.extend((row["evidence_id"], row["source_record_id"], row["source"], row["confidence"],
                    _epoch(row["observed_at"]), _epoch(row["observed_at"])) for row in local.values())
    db.executemany('''INSERT INTO entity_cluster_members
        (cluster_id,evidence_id,source_record_id,source,confidence,first_seen,last_seen)
        VALUES (?,?,?,?,?,?,?) ON CONFLICT(cluster_id,evidence_id) DO UPDATE SET
        confidence=MAX(entity_cluster_members.confidence,excluded.confidence),
        first_seen=MIN(entity_cluster_members.first_seen,excluded.first_seen),
        last_seen=MAX(entity_cluster_members.last_seen,excluded.last_seen)''',
        [(cluster_id, *member) for member in members])
    matches = {
        "ip": sorted(by_type.get("ip", set()))[:12],
        "identity": sorted(by_type.get("user", set()))[:12],
        "asset": sorted(set().union(by_type.get("hostname", set()), by_type.get("device", set())))[:12],
    }
    return {
        "cluster_id": cluster_id, "score": score, "confidence": confidence,
        "signal_types": len([values for values in by_type.values() if values]), "matches": matches,
        "canonical_matches": {kind: sorted(values)[:12] for kind, values in sorted(by_type.items()) if values},
        "evidence_ids": [evidence_id, *list(local)][:50], "local_evidence": list(local.values())[:12],
    }


def materialize_correlation_candidates(db, *, lookback_hours: int = 24,
                                       window_minutes: int = 60,
                                       row_limit: int = 10000) -> dict[str, int]:
    """Persist bounded, evidence-linked candidates from the local entity graph.

    Candidates are hypotheses only. CMDB rows and weak shared values (CVE,
    package, domain, CPE) cannot create a group by themselves. This is SQLite-
    only work and does not query Wazuh, Defender, or intelligence providers.
    """
    ensure_schema(db)
    lookback_hours = max(1, min(int(lookback_hours), 24 * 30))
    window_seconds = max(5, min(int(window_minutes), 240)) * 60
    row_limit = max(100, min(int(row_limit), 20000))
    cutoff = time.time() - lookback_hours * 3600
    rows = db.execute('''SELECT n.entity_type,n.canonical_value,o.role,o.evidence_id,
            e.source,e.source_record_id,e.observed_at,e.confidence
        FROM entity_observations o
        JOIN entity_nodes n ON n.entity_id=o.entity_id
        JOIN entity_evidence e ON e.evidence_id=o.evidence_id
        WHERE e.observed_at>=? AND e.source IN ('wazuh','m365','defender_xdr')
          AND (n.entity_type IN ('user','device','hostname','hash','cloud_resource')
               OR (n.entity_type='ip' AND lower(o.role) IN
                   ('source','attacker','client','remote','sender','external_source')))
        ORDER BY e.observed_at,o.evidence_id LIMIT ?''', (cutoff, row_limit)).fetchall()
    by_entity: dict[tuple[str, str], list[tuple[Any, ...]]] = {}
    for row in rows:
        by_entity.setdefault((str(row[0]), str(row[1])), []).append(row)

    desired: dict[str, dict[str, Any]] = {}
    for (kind, value), observations in by_entity.items():
        observations.sort(key=lambda row: (float(row[6]), str(row[3])))
        start = 0
        while start < len(observations):
            first_seen = float(observations[start][6])
            end = start + 1
            while end < len(observations) and float(observations[end][6]) - first_seen <= window_seconds:
                end += 1
            group = observations[start:end]
            unique: dict[str, tuple[Any, ...]] = {str(row[3]): row for row in group}
            if len(unique) >= 2:
                sources = {str(row[4]) for row in unique.values()}
                # Repeated same-source signals need at least three evidence
                # records; a two-record group must have independent sources.
                if len(sources) >= 2 or len(unique) >= 3:
                    members = list(unique.values())
                    last_seen = max(float(row[6]) for row in members)
                    time_slot = int(first_seen // window_seconds)
                    key = _digest("candidate", kind, value, time_slot)
                    candidate_id = "cand-" + key[:24]
                    source_count = len(sources)
                    type_weight = MATCH_WEIGHTS.get(kind, 10)
                    confidence = min(85, 30 + min(20, (len(unique) - 2) * 5)
                                     + min(20, (source_count - 1) * 15)
                                     + min(15, type_weight // 6))
                    current = desired.get(candidate_id)
                    combined = {str(row[3]): row for row in (current["members"] if current else [])}
                    combined.update(unique)
                    combined_source_count = len({str(row[4]) for row in combined.values()})
                    all_members = sorted(combined.values(), key=lambda row: float(row[6]))[:100]
                    confidence = min(85, 30 + min(20, (len(combined) - 2) * 5)
                                     + min(20, (combined_source_count - 1) * 15)
                                     + min(15, type_weight // 6))
                    desired[candidate_id] = {
                        "candidate_id": candidate_id, "candidate_key": key,
                        "primary_entity_type": kind, "primary_entity_value": value,
                        "first_seen": min(first_seen, current["first_seen"] if current else first_seen),
                        "last_seen": max(last_seen, current["last_seen"] if current else last_seen),
                        "evidence_count": len(combined), "source_count": combined_source_count,
                        "confidence": confidence,
                        "members": all_members,
                    }
            # Consume this bounded window once; overlapping windows would
            # repeat work for high-volume entities without adding provenance.
            start = end

    now = time.time()
    for item in desired.values():
        db.execute('''INSERT INTO correlation_candidates
            (candidate_id,candidate_key,primary_entity_type,primary_entity_value,
             first_seen,last_seen,evidence_count,source_count,confidence,classification,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,'candidate',?)
            ON CONFLICT(candidate_key) DO UPDATE SET
              last_seen=MAX(correlation_candidates.last_seen,excluded.last_seen),
              evidence_count=MAX(correlation_candidates.evidence_count,excluded.evidence_count),
              source_count=MAX(correlation_candidates.source_count,excluded.source_count),
              confidence=MAX(correlation_candidates.confidence,excluded.confidence),
              updated_at=excluded.updated_at''',
            (item["candidate_id"], item["candidate_key"], item["primary_entity_type"],
             item["primary_entity_value"], item["first_seen"], item["last_seen"],
             item["evidence_count"], item["source_count"], item["confidence"], now))
        db.executemany('''INSERT INTO correlation_candidate_evidence
            (candidate_id,evidence_id,source,source_record_id,observed_at,confidence)
            VALUES (?,?,?,?,?,?) ON CONFLICT(candidate_id,evidence_id) DO UPDATE SET
              observed_at=MAX(correlation_candidate_evidence.observed_at,excluded.observed_at),
              confidence=MAX(correlation_candidate_evidence.confidence,excluded.confidence)''',
            [(item["candidate_id"], row[3], row[4], row[5], row[6], row[7])
             for row in item["members"]])
    db.execute("DELETE FROM correlation_candidate_evidence WHERE candidate_id IN (SELECT candidate_id FROM correlation_candidates WHERE last_seen<?)", (cutoff,))
    db.execute("DELETE FROM correlation_candidates WHERE last_seen<?", (cutoff,))
    result = {"candidates": len(desired), "observations_considered": len(rows),
              "truncated": int(len(rows) >= row_limit)}
    db.execute('''INSERT INTO correlation_candidate_state
        (singleton,last_run,observations_considered,candidates,truncated,status,error)
        VALUES (1,?,?,?,?,'ok',NULL) ON CONFLICT(singleton) DO UPDATE SET
        last_run=excluded.last_run,observations_considered=excluded.observations_considered,
        candidates=excluded.candidates,truncated=excluded.truncated,status='ok',error=NULL''',
        (now, result["observations_considered"], result["candidates"], result["truncated"]))
    return result


def correlation_candidates(db, start: float | None = None, end: float | None = None,
                           limit: int = 20) -> dict[str, Any]:
    ensure_schema(db)
    limit = max(1, min(int(limit), 100))
    filters, params = [], []
    if start is not None:
        filters.append("last_seen>=?"); params.append(float(start))
    if end is not None:
        filters.append("first_seen<?"); params.append(float(end))
    where = " WHERE " + " AND ".join(filters) if filters else ""
    total = int(db.execute("SELECT COUNT(*) FROM correlation_candidates" + where, params).fetchone()[0] or 0)
    state = db.execute('''SELECT last_run,observations_considered,candidates,truncated,status,error
        FROM correlation_candidate_state WHERE singleton=1''').fetchone()
    candidates = []
    for row in db.execute("""SELECT candidate_id,primary_entity_type,primary_entity_value,
            first_seen,last_seen,evidence_count,source_count,confidence,classification
        FROM correlation_candidates""" + where + " ORDER BY last_seen DESC,confidence DESC LIMIT ?",
        [*params, limit]).fetchall():
        evidence = db.execute('''SELECT evidence_id,source,source_record_id,observed_at,confidence
            FROM correlation_candidate_evidence WHERE candidate_id=? ORDER BY observed_at LIMIT 100''', (row[0],)).fetchall()
        candidates.append({
            "candidate_id": row[0], "classification": row[8], "confirmed": False,
            "primary_entity": {"type": row[1], "value": row[2]},
            "first_seen": datetime.fromtimestamp(row[3], timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(row[4], timezone.utc).isoformat(),
            "evidence_count": row[5], "source_count": row[6], "confidence": row[7],
            "evidence_sampled": int(row[5]) > len(evidence),
            "sources": sorted({item[1] for item in evidence}),
            "evidence": [{"evidence_id": item[0], "source": item[1],
                          "source_record_id": item[2],
                          "observed_at": datetime.fromtimestamp(item[3], timezone.utc).isoformat(),
                          "confidence": item[4]} for item in evidence],
            "reason": "Shared canonical entity in a bounded time window; this is a correlation candidate, not a confirmed incident.",
        })
    state_status = str(state[4]) if state else "materializing"
    range_covered = start is None or float(start) >= time.time() - CANDIDATE_LOOKBACK_HOURS * 3600
    status = ("unavailable" if state_status == "error" else
              "materializing" if state_status != "ok" else
              "partial" if not range_covered else
              "available" if candidates else "no_candidates")
    return {"status": status,
            "total": total, "items": candidates, "limit": limit,
            "observations_considered": int(state[1]) if state else None,
            "last_materialized_at": datetime.fromtimestamp(state[0], timezone.utc).isoformat() if state else None,
            "lookback_hours": CANDIDATE_LOOKBACK_HOURS,
            "range_covered": range_covered,
            "truncated": bool(state[3]) if state else False,
            "error": state[5] if state and state[5] else None,
            "source": "local durable entity graph"}


def record_candidate_materialization_error(db, error: str) -> None:
    ensure_schema(db)
    db.execute('''INSERT INTO correlation_candidate_state
        (singleton,last_run,observations_considered,candidates,truncated,status,error)
        VALUES (1,?,0,0,0,'error',?) ON CONFLICT(singleton) DO UPDATE SET
        last_run=excluded.last_run,status='error',error=excluded.error''',
        (time.time(), str(error)[:500]))


def cluster_id(incident_id: str) -> str:
    return "cluster-" + _digest("defender:" + str(incident_id))[:24]


def cleanup(db, retention_days: int = 30) -> dict[str, int]:
    ensure_schema(db)
    cutoff = time.time() - max(7, min(int(retention_days), 3650)) * 86400
    expired = [row[0] for row in db.execute(
        "SELECT evidence_id FROM entity_evidence WHERE last_seen<? AND source<>'cmdb'", (cutoff,)).fetchall()]
    for offset in range(0, len(expired), 500):
        batch = expired[offset:offset + 500]
        placeholders = ",".join("?" for _ in batch)
        db.execute(f"DELETE FROM correlation_candidate_evidence WHERE evidence_id IN ({placeholders})", batch)
        db.execute(f"DELETE FROM entity_cluster_members WHERE evidence_id IN ({placeholders})", batch)
        db.execute(f"DELETE FROM entity_relations WHERE evidence_id IN ({placeholders})", batch)
        db.execute(f"DELETE FROM entity_observations WHERE evidence_id IN ({placeholders})", batch)
        db.execute(f"DELETE FROM entity_evidence WHERE evidence_id IN ({placeholders})", batch)
    nodes = db.execute("DELETE FROM entity_nodes WHERE entity_id NOT IN (SELECT entity_id FROM entity_observations)").rowcount
    db.execute("DELETE FROM entity_clusters WHERE cluster_id NOT IN (SELECT cluster_id FROM entity_cluster_members)")
    db.execute("DELETE FROM correlation_candidates WHERE last_seen<? OR candidate_id NOT IN (SELECT candidate_id FROM correlation_candidate_evidence)", (cutoff,))
    db.execute("DELETE FROM entity_graph_batches WHERE committed_at<?", (cutoff,))
    return {"evidence": len(expired), "entities": nodes}


def status(db) -> dict[str, Any]:
    ensure_schema(db)
    entity_count, evidence_count, relation_count, cluster_count = (
        int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] or 0)
        for table in ("entity_nodes", "entity_evidence", "entity_relations", "entity_clusters"))
    sources = [{"source": source, "evidence": int(count), "last_seen": datetime.fromtimestamp(last, timezone.utc).isoformat()}
               for source, count, last in db.execute('''SELECT source,COUNT(*),MAX(last_seen)
                   FROM entity_evidence GROUP BY source ORDER BY COUNT(*) DESC LIMIT 12''').fetchall()]
    queued = db.execute("SELECT COUNT(*),MIN(queued_at) FROM entity_graph_queue").fetchone()
    batch = db.execute('''SELECT candidate_count,stored_count,queued_count,coalesced_count,dropped_count,committed_at
        FROM entity_graph_batches ORDER BY committed_at DESC LIMIT 1''').fetchone()
    history = db.execute('''SELECT COALESCE(SUM(candidate_count),0),COALESCE(SUM(stored_count),0),
        COALESCE(SUM(queued_count),0),COALESCE(SUM(coalesced_count),0),COALESCE(SUM(dropped_count),0),COUNT(*)
        FROM entity_graph_batches''').fetchone()
    return {"entities": entity_count, "evidence": evidence_count, "relations": relation_count,
            "clusters": cluster_count, "sources": sources, "provider_calls": 0,
            "batch_history": {"batches": int(history[5]), "candidates": int(history[0]),
                              "stored": int(history[1]), "queued": int(history[2]),
                              "coalesced": int(history[3]), "dropped": int(history[4])},
            "queue": {"pending": int(queued[0] or 0),
                      "oldest_queued_at": (datetime.fromtimestamp(queued[1], timezone.utc).isoformat()
                                           if queued[1] else None)},
            "latest_batch": ({"candidates": int(batch[0]), "stored": int(batch[1]),
                              "queued": int(batch[2]), "coalesced": int(batch[3]),
                              "dropped": int(batch[4]),
                              "committed_at": datetime.fromtimestamp(batch[5], timezone.utc).isoformat()}
                             if batch else None)}
