#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="/opt/wazuh-mcp-unified/syslog-ingest"
DECODER="$ROOT/decoders/99-dg-network-device.xml"
RULE="$ROOT/rules/99-dg-network-device.xml"
MANAGER="single-node-wazuh.manager-1"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/opt/wazuh-mcp-unified/backups/syslog-decoder-$STAMP"

mkdir -p "$BACKUP"

cp -a "$DECODER" "$BACKUP/"
cp -a "$RULE" "$BACKUP/"

echo "============================================"
echo " WAZUH GENERIC SYSLOG DECODER FIX"
echo "============================================"
echo "Backup: $BACKUP"

# ==========================================================
# Decoder dibuat tidak bergantung pada pre-decoded
# program_name.
#
# Ini membuatnya bisa mengenali:
# - RFC3164
# - RFC5424
# selama marker DG-SYSLOG + payload kita tersedia.
# ==========================================================

cat > "$DECODER" <<'XML'
<decoder name="dg-network-device">
  <prematch type="pcre2">DG-SYSLOG.*device=</prematch>
  <regex type="pcre2">device=([^\s]+)\s+vendor=([^\s]+)\s+srcip=([^\s]+)\s+dstip=([^\s]+)\s+action=([^\s]+)</regex>
  <order>device_name,device_vendor,srcip,dstip,action</order>
</decoder>
XML

chmod 644 "$DECODER"

echo
echo "=== 1. STRICT VALIDATION ==="

if ! docker exec "$MANAGER" \
    /var/ossec/bin/wazuh-analysisd -t
then
    echo "ERROR: decoder/rule validation failed."

    cp -a \
        "$BACKUP/99-dg-network-device.xml" \
        "$DECODER"

    exit 1
fi

echo "[OK] Wazuh configuration valid"

echo
echo "=== 2. RESTART ONLY MANAGER ==="

docker restart "$MANAGER" >/dev/null

sleep 12

docker inspect "$MANAGER" \
    --format 'Running={{.State.Running}} Status={{.State.Status}}'

echo
echo "=== 3. TEST RFC3164 ==="

RFC3164='Aug 21 17:20:00 LAB-RTR-01 DG-SYSLOG: device=LAB-RTR-01 vendor=generic srcip=198.51.100.23 dstip=203.0.113.10 action=deny'

printf '%s\n' "$RFC3164" |
docker exec -i "$MANAGER" \
    /var/ossec/bin/wazuh-logtest

echo
echo "=== 4. TEST RFC5424 ==="

RFC5424='1 2026-08-21T10:20:00.000000+00:00 router01 DG-SYSLOG - - [timeQuality tzKnown="1"] device=LAB-RTR-02 vendor=generic srcip=198.51.100.24 dstip=203.0.113.11 action=deny'

printf '%s\n' "$RFC5424" |
docker exec -i "$MANAGER" \
    /var/ossec/bin/wazuh-logtest

echo
echo "=== 5. SEND REAL RFC5424 UDP ==="

SYSLOG_HOST="${SYSLOG_HOST:-127.0.0.1}"
logger \
    -n "$SYSLOG_HOST" \
    -P 514 \
    -d \
    -t DG-SYSLOG \
    "device=LAB-RTR-02 vendor=generic srcip=198.51.100.24 dstip=203.0.113.11 action=deny"

sleep 8

echo
echo "=== 6. ALERT CHECK ==="

docker exec "$MANAGER" sh -c '
grep -F "LAB-RTR-02" \
/var/ossec/logs/alerts/alerts.json \
2>/dev/null |
tail -5 || true
'

echo
echo "=== 7. RAW ARCHIVE CHECK ==="

docker exec "$MANAGER" sh -c '
grep -F "LAB-RTR-02" \
/var/ossec/logs/archives/archives.json \
2>/dev/null |
tail -5 || true
'

echo
echo "=== 8. RECENT MANAGER ERRORS ==="

docker exec "$MANAGER" sh -c '
tail -n 80 /var/ossec/logs/ossec.log |
grep -Ei "ERROR|CRITICAL" || true
'

echo
echo "============================================"
echo " FINISHED"
echo "============================================"
echo
echo 'Web filter:'
echo 'data.device_name:"LAB-RTR-02"'
echo
echo 'Rule filter:'
echo 'rule.id:"100101"'
