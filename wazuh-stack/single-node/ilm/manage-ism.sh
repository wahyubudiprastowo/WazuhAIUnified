#!/usr/bin/env bash
#
# manage-ism.sh — Wazuh Indexer ISM (Index State Management) helper.
#
# NON-DESTRUCTIVE BY DEFAULT. Recommended workflow from RETENTION.md:
#   1) inventory       (read-only)  -> measure growth & current policy state
#   2) list-policies   (read-only)  -> see existing ISM policies
#   3) dry-run         (read-only)  -> print the policy + exactly what apply would do
#   4) apply-policy    (GUARDED)    -> attach a future-only retention policy to wazuh-alerts-*
#
# Design rules:
#   - Reads config from the same env names the compose file uses (WAZUH_INDEXER_URL, USER, PASSWORD).
#   - Default target = ONLY wazuh-alerts-* daily indices. Never touches vulnerability
#     state, security, or other system indices.
#   - Nothing below deletes data by itself. apply-policy only creates/updates an ISM policy
#     and its index template; deletion of old indices happens later by ISM only if you
#     attach it AND the configured age is reached.
#   - No Wazuh manager/indexer restart, no change to docker-compose.yml or opensearch.yml.
#
set -euo pipefail

_INDEXER_URL="${WAZUH_INDEXER_URL:-https://localhost:9200}"
_INDEXER_URL="${_INDEXER_URL%/}"
_USER="${WAZUH_INDEXER_USER:-admin}"
_PASS="${WAZUH_INDEXER_PASSWORD:-SecretPassword}"
_AUTH=("-u" "${_USER}:${_PASS}")
# Self-signed stack certs -> curl insecure is expected here.
_CURL_INSECURE=(curl -ks)

_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
_POLICY_FILE="${_SCRIPT_DIR}/wazuh-alerts-ism-policy.json"
_POLICY_ID="wazuh-alerts-retention"
_TEMPLATE_NAME="wazuh-alerts-ism-retention"

usage() {
  cat <<EOF
Usage: $0 <command> [options]

Commands (read-only by default):
  inventory        Measure and list wazuh-alerts-* and wazuh-archives-* indices,
                   their age, size, shards and status. Safe to run anytime.
  list-policies    List existing ISM policies (read-only).
  dry-run [--retention-days N]   Print the policy payload and the exact apply plan
                   without changing anything. N default: 90.
  apply-policy --retention-days N [--confirm]   Create/update ISM policy and attach
                   it (future-only via template) to wazuh-alerts-*.
                   --confirm is REQUIRED to make any change.

Environment:
  WAZUH_INDEXER_URL      (default: https://localhost:9200)
  WAZUH_INDEXER_USER     (default: admin)
  WAZUH_INDEXER_PASSWORD (default: SecretPassword)
EOF
}

_retention_days="90"
_confirm=""

die() { echo "ERROR: $*" >&2; exit 1; }

_parse() {
  local cmd="$1"; shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --retention-days) _retention_days="${2:?need value}"; shift 2 ;;
      --confirm) _confirm="yes"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1" ;;
    esac
  done
  [[ "$_retention_days" =~ ^[0-9]+$ ]] || die "--retention-days must be a positive integer: $_retention_days"
  if [[ "$cmd" == "apply-policy" && "$_confirm" != "yes" ]]; then
    die "apply-policy requires --confirm (see RETENTION.md: confirm retention, backups and holds first)."
  fi
}

inventory() {
  echo "== Cluster health =="
  "${_CURL_INSECURE[@]}" "${_AUTH[@]}" "${_INDEXER_URL}/_cluster/health" \
    || die "cannot reach ${_INDEXER_URL}"
  echo
  for pat in "wazuh-alerts-*" "wazuh-archives-*"; do
    echo "== Indices: $pat =="
    echo "index | created(utc) | status | docs | size"
    "${_CURL_INSECURE[@]}" "${_AUTH[@]}" \
      "${_INDEXER_URL}/_cat/indices/${pat}?s=creation.date:desc&h=health,index,pri,rep,docs.count,store.size,creation.date"
    echo
  done
}

list_policies() {
  echo "== ISM policies =="
  "${_CURL_INSECURE[@]}" "${_AUTH[@]}" "${_INDEXER_URL}/_plugins/_ism/policies?pretty" \
    || echo "(no ISM policies endpoint response - plugin may not expose list here)"
}

dry_run() {
  echo "== Policy ID: ${_POLICY_ID} =="
  echo "== Policy payload (from ${_POLICY_FILE}) =="
  sed "s/\"min_index_age\": \"90d\"/\"min_index_age\": \"${_retention_days}d\"/" "$_POLICY_FILE"
  echo
  echo "== Apply plan (NOT executed) =="
  echo " 1) PUT _plugins/_ism/policies/${_POLICY_ID}      (create/update policy)"
  echo " 2) PUT _index_template/${_TEMPLATE_NAME}         (attach policy to FUTURE wazuh-alerts-* only)"
  echo " 3) No changes to existing indices, no restart."
}

apply_policy() {
  local tmp_policy; tmp_policy="$(mktemp)"
  sed "s/\"min_index_age\": \"90d\"/\"min_index_age\": \"${_retention_days}d\"/" "$_POLICY_FILE" > "$tmp_policy"

  echo "== [1/2] Creating/updating ISM policy ${_POLICY_ID} (future retention ${_retention_days}d) =="
  "${_CURL_INSECURE[@]}" "${_AUTH[@]}" \
    -X PUT -H 'Content-Type: application/json' \
    --data-binary "@${tmp_policy}" \
    "${_INDEXER_URL}/_plugins/_ism/policies/${_POLICY_ID}" | head -40

  echo
  echo "== [2/2] Attaching policy to FUTURE wazuh-alerts-* only (index template ${_TEMPLATE_NAME}) =="
  cat > "$tmp_policy.template" <<EOF
{
  "index_patterns": ["wazuh-alerts-*"],
  "priority": 1,
  "template": {
    "settings": {
      "index.plugins.index_state_management.policy_id": "${_POLICY_ID}"
    }
  }
}
EOF
  "${_CURL_INSECURE[@]}" "${_AUTH[@]}" \
    -X PUT -H 'Content-Type: application/json' \
    --data-binary "@${tmp_policy.template}" \
    "${_INDEXER_URL}/_index_template/${_TEMPLATE_NAME}" | head -40
  rm -f "$tmp_policy" "$tmp_policy.template"
  echo
  echo "== Apply to ALREADY-EXISTING indices only after explicit review: =="
  echo "   ${_INDEXER_URL}/_plugins/_ism/add/<index>?policy_id=${_POLICY_ID}"
}

cmd="${1:-}"
[[ -n "$cmd" ]] || { usage; exit 1; }
shift || true

case "$cmd" in
  inventory)      _parse "$cmd" "$@" && inventory ;;
  list-policies)  _parse "$cmd" "$@" && list_policies ;;
  dry-run)        _parse "$cmd" "$@" && dry_run ;;
  apply-policy)   _parse "$cmd" "$@" && apply_policy ;;
  *) usage; exit 1 ;;
esac