#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

env_value() {
  local file="$1"
  local key="$2"
  awk -F= -v k="${key}" '$1 == k {print substr($0, index($0, "=") + 1)}' "${file}" | tail -n 1
}

json_from_body() {
  local body="$1"
  if grep -q '^data: ' "${body}"; then
    sed -n 's/^data: //p' "${body}" | tail -n 1
  else
    cat "${body}"
  fi
}

echo "== Containers =="
docker ps \
  --filter "name=wazuh-main-server" \
  --filter "name=wazuh-infokom-mcp" \
  --filter "name=wazuh-mcp-dashboard" \
  --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

echo
echo "== GenSecAI MCP :3000 =="
GENSECAI_KEY="$(env_value "${ROOT_DIR}/gensecai-core/.env" MCP_API_KEY)"
TOKEN="$(curl -fsS -H "Content-Type: application/json" -d "{\"api_key\":\"${GENSECAI_KEY}\"}" http://127.0.0.1:3000/auth/token | jq -r '.access_token')"
curl -fsS \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"tools","method":"tools/list","params":{}}' \
  http://127.0.0.1:3000/mcp \
  | jq '{tool_count:(.result.tools|length), sample:(.result.tools[:8]|map(.name))}'

echo
echo "== INFOKOM MCP :8000 =="
INFOKOM_KEY="$(env_value "${ROOT_DIR}/infokom-analysis/infokom.env" MCP_API_KEY)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
init_body="${tmpdir}/infokom-init.body"
init_headers="${tmpdir}/infokom-init.headers"
curl -fsS \
  -D "${init_headers}" \
  -o "${init_body}" \
  -H "Authorization: Bearer ${INFOKOM_KEY}" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2025-06-18" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"integration-check","version":"1.0"}}}' \
  http://127.0.0.1:8000/mcp >/dev/null
SESSION_ID="$(awk 'BEGIN{IGNORECASE=1} /^mcp-session-id:/ {gsub("\r",""); print $2}' "${init_headers}" | tail -n 1)"
session_header=()
if [[ -n "${SESSION_ID}" ]]; then
  session_header=(-H "mcp-session-id: ${SESSION_ID}")
  curl -fsS \
    -H "Authorization: Bearer ${INFOKOM_KEY}" \
    -H "Accept: application/json, text/event-stream" \
    -H "MCP-Protocol-Version: 2025-06-18" \
    -H "Content-Type: application/json" \
    "${session_header[@]}" \
    -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
    http://127.0.0.1:8000/mcp >/dev/null || true
fi
tools_body="${tmpdir}/infokom-tools.body"
curl -fsS \
  -o "${tools_body}" \
  -H "Authorization: Bearer ${INFOKOM_KEY}" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2025-06-18" \
  -H "Content-Type: application/json" \
  "${session_header[@]}" \
  -d '{"jsonrpc":"2.0","id":"tools","method":"tools/list","params":{}}' \
  http://127.0.0.1:8000/mcp
json_from_body "${tools_body}" | jq '{
  tool_count:(.result.tools|length),
  new_features:(.result.tools | map(.name) | map(select(test("blueteam_(ai_bot_recon|cve_|dependency_scan|document_convert)"))))
}'

echo
echo "== Dashboard :8088 =="
curl -fsS -H "Content-Type: application/json" -d '{}' http://127.0.0.1:8088/api/tools \
  | jq '{total:(.tools|length), gensecai:(.tools|map(select(.source=="gensecai"))|length), infokom:(.tools|map(select(.source=="infokom"))|length), errors:.errors}'
