#!/bin/bash

set -e


MANAGER="single-node-wazuh.manager-1"
MCP="wazuh-main-server"
HLD_WORKER="wazuh-hld-ai-alert-worker"
HLD_ROOT="/opt/wazuh-mcp-unified/hld-platform"


echo "======================================"
echo "1. CONTAINER STATUS"
echo "======================================"

docker ps \
--format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" \
| grep -E "wazuh|NAME"


echo
echo "======================================"
echo "2. SYSLOG LISTENER"
echo "======================================"

docker exec $MANAGER sh -c '
ss -lunpt | grep -E ":514|:1514" || true
'


echo
echo "======================================"
echo "3. DISCOVERED NETWORK DEVICE IP"
echo "======================================"

docker exec $MANAGER sh -c '

echo "Archive source IP:"

grep -RhoE \
"srcip=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" \
/var/ossec/logs/archives/ 2>/dev/null \
| sort -u \
| head -50


echo

echo "Hostname/source:"

grep -RhoE \
"^[A-Za-z0-9._-]+" \
/var/ossec/logs/archives/archives.log \
2>/dev/null \
| sort -u \
| head -50

'


echo
echo "======================================"
echo "4. RECENT WAZUH ALERT"
echo "======================================"

docker exec -i $MCP python - <<'PY'

import asyncio
import os
import httpx
import json


async def main():

    url=os.getenv(
        "WAZUH_INDEXER_URL",
        "https://wazuh.indexer:9200"
    )


    user=os.getenv(
        "WAZUH_INDEXER_USER",
        "admin"
    )

    pwd=os.getenv(
        "WAZUH_INDEXER_PASSWORD",
        "SecretPassword"
    )


    query={
      "size":10,
      "sort":[
        {
          "@timestamp":{
            "order":"desc"
          }
        }
      ]
    }


    async with httpx.AsyncClient(
        verify=False,
        auth=(user,pwd)
    ) as c:


        r=await c.post(
            url+"/wazuh-alerts-*/_search",
            json=query
        )


        data=r.json()


        for x in data["hits"]["hits"]:

            s=x["_source"]


            print("================")
            print(
                "TIME:",
                s.get("@timestamp")
            )

            print(
                "RULE:",
                s.get("rule",{})
            )


            print(
                "SRC:",
                s.get("data",{})
            )


            print(
                "AGENT:",
                s.get("agent",{})
            )


asyncio.run(main())

PY



echo
echo "======================================"
echo "5. DECODER CHECK"
echo "======================================"

docker exec $MANAGER sh -c '

grep -Rho \
"decoder.*" \
/var/ossec/logs/alerts/alerts.json \
2>/dev/null \
| head -30

'


echo
echo "======================================"
echo "6. MCP HEALTH"
echo "======================================"

curl -s \
http://localhost:3000/health \
| jq .


echo
echo "======================================"
echo "7. HLD PLATFORM FILES"
echo "======================================"

for path in \
    "$HLD_ROOT/docker-compose.hld.yml" \
    "$HLD_ROOT/hld.env" \
    "$HLD_ROOT/wazuh/decoders/100-hld-platform.xml" \
    "$HLD_ROOT/wazuh/rules/100-hld-platform.xml" \
    "/opt/wazuh-mcp-unified/wazuh-stack/single-node/docker-compose.hld.yml"
do
    if [ -f "$path" ]; then
        echo "[OK] $path"
    else
        echo "[MISS] $path"
    fi
done


echo
echo "======================================"
echo "8. HLD WAZUH MOUNTS / AUDIT INPUT"
echo "======================================"

docker exec "$MANAGER" sh -c '
ls -l \
/var/ossec/etc/decoders/100-hld-platform.xml \
/var/ossec/etc/rules/100-hld-platform.xml \
/var/log/pam-platform/audit.jsonl \
/var/log/soar/audit.jsonl \
2>/dev/null || true
'


echo
echo "======================================"
echo "9. HLD MCP TOOLS / WORKER"
echo "======================================"

AUTH_HEADER=()

if [ -f "$HLD_ROOT/hld.env" ]; then
    MCP_API_KEY_FROM_ENV="$(
        grep -E '^MCP_API_KEY=' "$HLD_ROOT/hld.env" \
        | tail -1 \
        | cut -d= -f2-
    )"

    if [ -n "$MCP_API_KEY_FROM_ENV" ]; then
        MCP_TOKEN="$(
            curl -fsS \
                -H "Content-Type: application/json" \
                -d "{\"api_key\":\"$MCP_API_KEY_FROM_ENV\"}" \
                http://localhost:3000/auth/token \
            | jq -r '.access_token // empty'
        )"

        if [ -n "$MCP_TOKEN" ]; then
            AUTH_HEADER=(-H "Authorization: Bearer $MCP_TOKEN")
        fi
    fi
fi

curl -s \
    "${AUTH_HEADER[@]}" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":"check-tools","method":"tools/list","params":{}}' \
    http://localhost:3000/mcp \
| jq -r '.result.tools[]?.name' \
| grep -E 'advanced_three_sum_correlation|advanced_threat_intelligence|get_alerts_aggregated|wazuh_block_ip' \
|| true

docker ps \
--format "table {{.Names}}\t{{.Status}}" \
| grep -E "NAME|$HLD_WORKER" \
|| true

docker logs \
--tail 30 \
"$HLD_WORKER" \
2>/dev/null \
|| true


echo
echo "======================================"
echo "DONE"
echo "======================================"
