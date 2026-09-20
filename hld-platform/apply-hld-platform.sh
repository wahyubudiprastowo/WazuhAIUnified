#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${ROOT:-/opt/wazuh-mcp-unified}"
WAZUH_SINGLE="$ROOT/wazuh-stack/single-node"
HLD_ROOT="$ROOT/hld-platform"

if [[ ! -f "$HLD_ROOT/hld.env" ]]; then
  echo "ERROR: missing $HLD_ROOT/hld.env"
  exit 1
fi

echo "Validating Wazuh compose overlay..."
docker compose \
  -f "$WAZUH_SINGLE/docker-compose.yml" \
  -f "$WAZUH_SINGLE/docker-compose.syslog.yml" \
  -f "$WAZUH_SINGLE/docker-compose.hld.yml" \
  config >/dev/null

echo "Validating HLD worker compose..."
docker compose -f "$HLD_ROOT/docker-compose.hld.yml" config >/dev/null

echo "Recreating Wazuh manager only, with HLD read-only mounts..."
docker compose \
  -f "$WAZUH_SINGLE/docker-compose.yml" \
  -f "$WAZUH_SINGLE/docker-compose.syslog.yml" \
  -f "$WAZUH_SINGLE/docker-compose.hld.yml" \
  up -d --no-deps wazuh.manager

echo "Starting HLD alert worker..."
docker compose -f "$HLD_ROOT/docker-compose.hld.yml" up -d --build

echo "Done. Run: bash $HLD_ROOT/check-hld-platform.sh"
