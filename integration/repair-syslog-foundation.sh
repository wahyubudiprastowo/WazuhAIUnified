#!/usr/bin/env bash
set -Eeuo pipefail

BASE="/opt/wazuh-mcp-unified/wazuh-stack/single-node"
ROOT="/opt/wazuh-mcp-unified/syslog-ingest"
RULE="$ROOT/rules/99-dg-network-device.xml"
DECODER="$ROOT/decoders/99-dg-network-device.xml"
MANAGER="single-node-wazuh.manager-1"

if [[ -f "$BASE/docker-compose.yml" ]]; then
    COMPOSE="$BASE/docker-compose.yml"
else
    COMPOSE="$BASE/docker-compose.yaml"
fi

OVERRIDE="$BASE/docker-compose.syslog.yml"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/opt/wazuh-mcp-unified/backups/syslog-repair-$STAMP"

mkdir -p "$BACKUP"

cp -a "$RULE" "$BACKUP/" 2>/dev/null || true
cp -a "$DECODER" "$BACKUP/" 2>/dev/null || true

echo "========================================"
echo " REPAIR WAZUH SYSLOG FOUNDATION"
echo "========================================"
echo "Backup: $BACKUP"

# ------------------------------------------------
# 1. Re-create decoder
# ------------------------------------------------

cat > "$DECODER" <<'XML'
<decoder name="dg-network-device">
  <program_name>^DG-SYSLOG$</program_name>
  <regex type="pcre2">^device=([^\s]+)\s+vendor=([^\s]+)\s+srcip=([^\s]+)\s+dstip=([^\s]+)\s+action=([^\s]+)</regex>
  <order>device_name,device_vendor,srcip,dstip,action</order>
</decoder>
XML

# ------------------------------------------------
# 2. Re-create rules
#    IMPORTANT: action is STATIC -> use <action>
# ------------------------------------------------

cat > "$RULE" <<'XML'
<group name="local,syslog,network_device,">

  <rule id="100100" level="3">
    <decoded_as>dg-network-device</decoded_as>
    <description>Network device syslog received from $(device_name) [$(device_vendor)]</description>
    <group>syslog,network_device,</group>
  </rule>

  <rule id="100101" level="6">
    <if_sid>100100</if_sid>
    <action type="pcre2">(?i)^(deny|drop|blocked)$</action>
    <description>Network device blocked traffic: $(device_name) $(srcip) to $(dstip)</description>
    <group>syslog,network_device,firewall_drop,</group>
  </rule>

</group>
XML

chmod 644 "$RULE" "$DECODER"

echo
echo "=== 1. CHECK FILES INSIDE CONTAINER ==="

docker exec "$MANAGER" \
    ls -l \
    /var/ossec/etc/decoders/99-dg-network-device.xml \
    /var/ossec/etc/rules/99-dg-network-device.xml

echo
echo "=== 2. STRICT WAZUH VALIDATION ==="

# NO "|| true" here.
if ! docker exec "$MANAGER" \
    /var/ossec/bin/wazuh-analysisd -t
then
    echo
    echo "ERROR: Wazuh rules still invalid."
    echo "Manager will NOT be restarted."
    exit 1
fi

echo "[OK] Wazuh analysis configuration valid"

echo
echo "=== 3. CHECK ACTIVE LOGALL_JSON ==="

docker exec "$MANAGER" \
    grep -n \
    '<logall_json>' \
    /var/ossec/etc/ossec.conf

echo
echo "=== 4. RESTART MANAGER ==="

docker compose \
    -f "$COMPOSE" \
    -f "$OVERRIDE" \
    restart wazuh.manager

sleep 12

echo
echo "=== 5. MANAGER STATUS ==="

docker compose \
    -f "$COMPOSE" \
    -f "$OVERRIDE" \
    ps wazuh.manager

echo
echo "=== 6. CHECK ANALYSISD PROCESS ==="

docker exec "$MANAGER" \
    sh -c '
    ps aux | grep "[w]azuh-analysisd"
    '

echo
echo "=== 7. CHECK RECENT WAZUH ERRORS ==="

docker exec "$MANAGER" \
    sh -c '
    tail -n 50 /var/ossec/logs/ossec.log |
    grep -Ei "error|critical|analysisd" || true
    '

echo
echo "=== 8. OFFLINE LOGTEST ==="

TEST='Aug 21 17:10:00 LAB-RTR-01 DG-SYSLOG: device=LAB-RTR-01 vendor=generic srcip=198.51.100.23 dstip=203.0.113.10 action=deny'

printf '%s\n' "$TEST" |
docker exec -i "$MANAGER" \
    /var/ossec/bin/wazuh-logtest

echo
echo "=== 9. SEND REAL UDP SYSLOG ==="

SYSLOG_HOST="${SYSLOG_HOST:-127.0.0.1}"
logger \
    -n "$SYSLOG_HOST" \
    -P 514 \
    -d \
    -t DG-SYSLOG \
    "device=LAB-RTR-01 vendor=generic srcip=198.51.100.23 dstip=203.0.113.10 action=deny"

echo "[OK] UDP test sent"

sleep 8

echo
echo "=== 10. SEARCH ALERT ==="

docker exec "$MANAGER" \
    sh -c '
    grep -F "LAB-RTR-01" \
    /var/ossec/logs/alerts/alerts.json \
    2>/dev/null |
    tail -5 || true
    '

echo
echo "=== 11. SEARCH RAW ARCHIVE ==="

docker exec "$MANAGER" \
    sh -c '
    grep -F "LAB-RTR-01" \
    /var/ossec/logs/archives/archives.json \
    2>/dev/null |
    tail -5 || true
    '

echo
echo "=== 12. HOST ARCHIVE DIRECTORY ==="

ls -lah "$ROOT/archives"

echo
echo "=== 13. SYSLOG PORTS ==="

echo "--- UDP ---"
ss -lunp | grep ':514 ' || true

echo "--- TCP ---"
ss -lntp | grep ':514 ' || true

echo
echo "========================================"
echo " REPAIR FINISHED"
echo "========================================"
echo
echo "Expected rule:"
echo "  100100 = generic network device"
echo "  100101 = deny/drop/blocked"
echo
echo "Raw archive:"
echo "  $ROOT/archives/archives.json"
echo
echo "Web filter:"
echo '  data.device_name:"LAB-RTR-01"'
echo
