#!/usr/bin/env bash
set -euo pipefail

# Read-only deployment verification. Run from the repository root as a user
# permitted to access Docker. It intentionally prints no environment values.
compose=(docker compose -f mcp-dashboard/docker-compose.dashboard.yml)
infokom_compose=(docker compose -f infokom-analysis/docker-compose.infokom.yml)

echo '== Container status =='
"${compose[@]}" ps

echo '== Required runtime modules =='
"${compose[@]}" exec -T mcp-dashboard python3 - <<'PY'
import cyfirma_research
import cyfirma_taxii
import cyfirma_org_vulnerability
import defender_xdr
import detection_taxonomy
import telemetry_contract
import server

print('dashboard imports: OK')
print('research collector:', 'available')
print('TAXII collector:', 'available')
print('organization CVE collector:', 'available')
print('defender collector:', 'available')
print('detection taxonomy:', 'available')
print('telemetry contract:', 'available')
PY

echo '== CMDB and CVE exposure materialization =='
"${compose[@]}" exec -T mcp-dashboard python3 - <<'PY'
import server

assets, status = server._load_cmdb_assets()
assert status.get('authoritative_assets', 0) > 0, 'no authoritative CMDB identity is loaded'
assert status.get('sample_assets', 0) == 0, 'sample CMDB rows must not be deployed as evidence'
assert status.get('authoritative_assets', 0) == len(assets), status
server._overview_cache_init()
required = {
    'owner', 'criticality', 'environment', 'network_zone', 'asset_match',
    'component_match', 'patch_evidence',
}
with server._sqlite_db(server.OVERVIEW_CACHE_DB) as db:
    columns = {row[1] for row in db.execute('PRAGMA table_info(cve_exposure_summary)')}
assert required <= columns, f"missing exposure columns: {sorted(required - columns)}"
print('authoritative CMDB assets:', status.get('authoritative_assets', 0))
print('sample CMDB assets:', status.get('sample_assets', 0))
print('CVE exposure schema: current')
PY

echo '== Durable incident store =='
"${infokom_compose[@]}" ps infokom-mcp
"${infokom_compose[@]}" exec -T infokom-mcp python3 - <<'PY'
from mcp_server.core import case_store

required = {
    'cases', 'case_evidence', 'case_notes', 'case_entities',
    'case_transitions', 'case_assignments', 'case_audit',
}
with case_store._connection() as db:
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    quick_check = db.execute('PRAGMA quick_check').fetchone()[0]
stats = case_store.case_stats()
assert required <= tables, f"missing tables: {sorted(required - tables)}"
assert stats['journal_mode'].lower() == 'wal', stats['journal_mode']
assert stats['persistent'], 'BLUETEAM_CASE_DB or BLUETEAM_CASE_STORE must configure a persistent path'
assert quick_check == 'ok', quick_check
print('case database: OK')
print('journal mode: WAL')
print('persistent cases:', stats['cases'])
print('evidence records:', stats['case_evidence'])
PY

echo '== Static asset parity =='
for asset in index.html app.js findings.js analysis-workspace.js automation.js workflows.js styles.css; do
  host_hash="$(sha256sum "mcp-dashboard/static/${asset}" | cut -d' ' -f1)"
  container_hash="$("${compose[@]}" exec -T mcp-dashboard sha256sum "/app/static/${asset}" | cut -d' ' -f1)"
  if [[ "${host_hash}" != "${container_hash}" ]]; then
    echo "MISMATCH: ${asset} (container image is stale)" >&2
    exit 1
  fi
  echo "${asset}: current"
done

echo '== Shared dashboard/materializer code parity =='
for source in server.py soc_pipeline.py soc_automation.py entity_resolver.py detection_taxonomy.py telemetry_contract.py; do
  host_hash="$(sha256sum "mcp-dashboard/${source}" | cut -d' ' -f1)"
  for service in mcp-dashboard mcp-materializer; do
    container_hash="$("${compose[@]}" exec -T "${service}" sha256sum "/app/${source}" | cut -d' ' -f1)"
    if [[ "${host_hash}" != "${container_hash}" ]]; then
      echo "MISMATCH: ${source} in ${service} (container image is stale)" >&2
      exit 1
    fi
  done
  echo "${source}: current in both services"
done

echo '== Runtime build identity =='
expected_build_id="$(sed -n 's/^DASHBOARD_BUILD_ID = "\([^"]*\)"$/\1/p' mcp-dashboard/server.py)"
if [[ -z "${expected_build_id}" ]]; then
  echo 'Could not read expected dashboard build ID from source' >&2
  exit 1
fi
for service in mcp-dashboard mcp-materializer; do
  runtime_build_id="$("${compose[@]}" exec -T "${service}" python3 -c 'import server; print(server.DASHBOARD_BUILD_ID)')"
  if [[ "${runtime_build_id}" != "${expected_build_id}" ]]; then
    echo "MISMATCH: build ID in ${service}: expected ${expected_build_id}, got ${runtime_build_id}" >&2
    exit 1
  fi
  echo "${service}: ${runtime_build_id}"
done

echo '== Materializer worker =='
"${compose[@]}" exec -T mcp-materializer python3 - <<'PY'
import os
import materializer

assert os.environ.get('SOC_PIPELINE_WORKER_ENABLED', '').lower() == 'true'
print('materializer imports: OK')
print('pipeline worker: enabled')
PY

echo '== Retained collector and rollup state =='
"${compose[@]}" exec -T mcp-dashboard python3 - <<'PY'
import json
import server

external = server.automation.external_intelligence_status(lightweight=True)
pipeline = server.pipeline.status(lightweight=True)
def collector_state(payload):
    if not isinstance(payload, dict):
        return {}
    result = {key: payload.get(key) for key in ('enabled', 'configured', 'status', 'observations', 'items', 'detail')
              if key in payload}
    cursor = payload.get('cursor')
    if isinstance(cursor, dict):
        result['cursor_saved'] = bool(cursor.get('next'))
        result['cursor_status'] = cursor.get('status')
        result['cursor_updated_at'] = cursor.get('updated_at')
    return result
result = {
    'external_collectors': {name: collector_state(payload) for name, payload in external.items()},
    'pipeline': {
        'scan_status': pipeline.get('scan_status'),
        'lag_seconds': pipeline.get('lag_seconds'),
        'rollup_backfill': (pipeline.get('rollup') or {}).get('backfill'),
        'forti_security_backfill': (pipeline.get('rollup') or {}).get('forti_security_backfill'),
    },
}
print(json.dumps(result, indent=2, sort_keys=True, default=str))
PY

echo '== Pipeline window measurement =='
"${compose[@]}" exec -T mcp-dashboard python3 - <<'PY'
import json
import time
import server

observations = []
deadline = time.time() + 60
while len(observations) < 2:
    pipeline = server.pipeline.status(lightweight=True)
    last_scan = pipeline.get('last_scan') or {}
    if pipeline.get('enabled') and last_scan.get('status') != 'measured':
        if time.time() >= deadline:
            raise SystemExit('pipeline enabled but no measured scan window within 60s')
        time.sleep(5)
        continue
    observations.append({
        'status': pipeline.get('status'),
        'error_scope': pipeline.get('error_scope'),
        'scan_status': pipeline.get('scan_status'),
        'lag_seconds': pipeline.get('lag_seconds'),
        'last_scan': last_scan,
    })
    if len(observations) < 2:
        time.sleep(5)

if any(item['status'] != 'ok' for item in observations):
    raise SystemExit(json.dumps(observations, sort_keys=True, default=str))
print(json.dumps({'polls': observations}, indent=2, sort_keys=True, default=str))
PY

echo '== Recent dashboard logs =='
"${compose[@]}" logs --tail=80 mcp-dashboard

echo '== Recent materializer logs =='
"${compose[@]}" logs --tail=80 mcp-materializer
