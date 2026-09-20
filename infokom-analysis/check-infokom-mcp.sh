#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ROOT_DIR}/infokom.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "ERROR: ${ENV_FILE} belum ada. Copy dari infokom.env.example dulu." >&2
  exit 1
fi

env_value() {
  local key="$1"
  awk -F= -v k="${key}" '$1 == k {print substr($0, index($0, "=") + 1)}' "${ENV_FILE}" | tail -n 1
}

HOST_PORT="$(env_value INFOKOM_MCP_HOST_PORT)"
HOST_PORT="${HOST_PORT:-8000}"
MCP_API_KEY="$(env_value MCP_API_KEY)"
MCP_HTTP_URL="http://127.0.0.1:${HOST_PORT}/mcp"
AUTH_HEADER="Authorization: Bearer ${MCP_API_KEY:-}"
ACCEPT_HEADER="Accept: application/json, text/event-stream"
PROTO_HEADER="MCP-Protocol-Version: 2025-06-18"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

post_rpc() {
  local payload="$1"
  local out_body="$2"
  local out_headers="$3"
  shift 3
  curl -fsS \
    -D "${out_headers}" \
    -o "${out_body}" \
    -H "${AUTH_HEADER}" \
    -H "${ACCEPT_HEADER}" \
    -H "${PROTO_HEADER}" \
    -H "Content-Type: application/json" \
    "$@" \
    -d "${payload}" \
    "${MCP_HTTP_URL}"
}

json_from_body() {
  local body="$1"
  if grep -q '^data: ' "${body}"; then
    sed -n 's/^data: //p' "${body}" | tail -n 1
  else
    cat "${body}"
  fi
}

echo "== INFOKOM MCP container =="
docker ps --filter "name=wazuh-infokom-mcp" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

init_body="${tmpdir}/init.body"
init_headers="${tmpdir}/init.headers"
post_rpc '{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"infokom-check","version":"1.0"}}}' "${init_body}" "${init_headers}"

SESSION_ID="$(awk 'BEGIN{IGNORECASE=1} /^mcp-session-id:/ {gsub("\r",""); print $2}' "${init_headers}" | tail -n 1)"
session_args=()
if [[ -n "${SESSION_ID}" ]]; then
  session_args=(-H "mcp-session-id: ${SESSION_ID}")
  notify_body="${tmpdir}/notify.body"
  notify_headers="${tmpdir}/notify.headers"
  post_rpc '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' "${notify_body}" "${notify_headers}" "${session_args[@]}" || true
fi

tools_body="${tmpdir}/tools.body"
tools_headers="${tmpdir}/tools.headers"
post_rpc '{"jsonrpc":"2.0","id":"tools","method":"tools/list","params":{}}' "${tools_body}" "${tools_headers}" "${session_args[@]}"
tools_json="$(json_from_body "${tools_body}")"

echo
echo "== Tool count =="
printf '%s\n' "${tools_json}" | jq -r '.result.tools | length'

echo
echo "== New INFOKOM features =="
printf '%s\n' "${tools_json}" | jq -r '.result.tools[].name' \
  | grep -E 'blueteam_(ai_bot_recon|cve_|dependency_scan|vendor_advisory|document_convert)' \
  || true

echo
echo "== Quick call: AI bot recon =="
call_body="${tmpdir}/call.body"
call_headers="${tmpdir}/call.headers"
post_rpc '{"jsonrpc":"2.0","id":"ai-recon","method":"tools/call","params":{"name":"blueteam_ai_bot_recon","arguments":{"params":{"since":"24h","top_n":5,"response_format":"json"}}}}' "${call_body}" "${call_headers}" "${session_args[@]}"
json_from_body "${call_body}" | jq '{
  isError: .result.isError,
  ai_agent_sources: (.result.content[0].text | fromjson? | .ai_agent_sources),
  top_sources: (.result.content[0].text | fromjson? | .sources[:5] | map({
    srcip: .srcip,
    alerts: .alerts,
    sensitive_hits: .sensitive_hits
  })),
  error_text: (if .result.isError then .result.content[0].text else null end)
}'
