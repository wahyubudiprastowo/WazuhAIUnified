#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${ROOT:-/opt/wazuh-mcp-unified}"
MANAGER="${MANAGER:-single-node-wazuh.manager-1}"
MCP="${MCP:-wazuh-main-server}"
WORKER="${WORKER:-wazuh-hld-ai-alert-worker}"
MCP_URL="${MCP_URL:-http://localhost:3000}"

if [[ -f "$ROOT/hld-platform/hld.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/hld-platform/hld.env"
  set +a
fi

if [[ "$MCP_URL" == http://wazuh-main-server:* ]]; then
  MCP_URL="http://localhost:${MCP_PORT:-3000}"
fi

section() {
  printf '\n======================================\n%s\n======================================\n' "$1"
}

section "HLD FILES"
for path in \
  "$ROOT/hld-platform/docker-compose.hld.yml" \
  "$ROOT/hld-platform/hld.env" \
  "$ROOT/hld-platform/wazuh/decoders/100-hld-platform.xml" \
  "$ROOT/hld-platform/wazuh/rules/100-hld-platform.xml" \
  "$ROOT/wazuh-stack/single-node/docker-compose.hld.yml"
do
  if [[ -f "$path" ]]; then
    echo "[OK] $path"
  else
    echo "[MISS] $path"
  fi
done

section "CONTAINER STATUS"
if docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "NAME|wazuh|hld"; then
  true
else
  echo "[WARN] no matching containers visible"
fi

section "WAZUH MANAGER HLD MOUNTS"
docker exec "$MANAGER" sh -c '
ls -l /var/ossec/etc/decoders/100-hld-platform.xml /var/ossec/etc/rules/100-hld-platform.xml 2>/dev/null || true
ls -l /var/log/pam-platform/audit.jsonl /var/log/soar/audit.jsonl 2>/dev/null || true
'

section "MCP HEALTH"
curl -fsS "$MCP_URL/health" | jq . || true

section "MCP TOOL VISIBILITY"
AUTH_HEADER=()
if [[ -n "${MCP_API_KEY:-}" ]]; then
  MCP_TOKEN="$(
    curl -fsS \
      -H "Content-Type: application/json" \
      -d "{\"api_key\":\"$MCP_API_KEY\"}" \
      "$MCP_URL/auth/token" \
      | jq -r '.access_token // empty'
  )"
  if [[ -n "$MCP_TOKEN" ]]; then
    AUTH_HEADER=(-H "Authorization: Bearer $MCP_TOKEN")
  fi
fi
curl -fsS "${AUTH_HEADER[@]}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"check-tools","method":"tools/list","params":{}}' \
  "$MCP_URL/mcp" \
  | jq -r '.result.tools[]?.name' \
  | grep -E 'advanced_three_sum_correlation|advanced_threat_intelligence|wazuh_block_ip' || true

section "WORKER LOGS"
docker logs --tail 80 "$WORKER" 2>/dev/null || echo "[WARN] worker container not running"

section "DONE"
