# Wazuh MCP Integration

Current local layout:

- GenSecAI MCP: `gensecai-core`, container `wazuh-main-server`, port `3000`.
- INFOKOM MCP sidecar: `infokom-analysis`, container `wazuh-infokom-mcp`, port `8000`.
- Local web dashboard/proxy: `mcp-dashboard`, container `wazuh-mcp-dashboard`, port `8088`.
- Docker/Wazuh data-root: `/data/wazuh-storage/docker` on the 5TB disk.

## Config Files

- GenSecAI: `gensecai-core/.env`
- INFOKOM sidecar: `infokom-analysis/infokom.env`
- HLD worker: `hld-platform/hld.env`
- Web dashboard/proxy: `mcp-dashboard/dashboard.env`
- INFOKOM compose: `infokom-analysis/docker-compose.infokom.yml`
- Dashboard compose: `mcp-dashboard/docker-compose.dashboard.yml`

## Check

Run:

```bash
sudo bash /opt/wazuh-mcp-unified/check-mcp-integrations.sh
sudo bash /opt/wazuh-mcp-unified/infokom-analysis/check-infokom-mcp.sh
```

Expected current counts:

- GenSecAI: 58 tools.
- INFOKOM: 133 tools + 4 resources.
- Dashboard combined view: 191 tools.

## Access

Dashboard:

```text
http://__WAZUH_HOST__:8088/
```

If `__WAZUH_HOST__:8088` times out from a laptop but works inside the VM,
open the Proxmox/VM firewall for TCP `8088`. Ports `3000` and `8000` are
API endpoints, not browser dashboards.

GenSecAI direct MCP call:

```bash
GENSECAI_KEY="$(awk -F= '/^MCP_API_KEY=/{print substr($0,index($0,"=")+1)}' /opt/wazuh-mcp-unified/gensecai-core/.env | tail -n 1)"
TOKEN="$(curl -fsS -H 'Content-Type: application/json' -d "{\"api_key\":\"${GENSECAI_KEY}\"}" http://127.0.0.1:3000/auth/token | jq -r '.access_token')"

curl -fsS http://127.0.0.1:3000/mcp \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"run","method":"tools/call","params":{"name":"advanced_three_sum_correlation","arguments":{"lookback_minutes":60,"threshold_score":35}}}'
```

Dashboard proxy call to INFOKOM:

```bash
curl -fsS http://127.0.0.1:8088/api/call \
  -H "Content-Type: application/json" \
  -d '{"source":"infokom","name":"blueteam_ai_bot_recon","arguments":{"since":"24h","top_n":5,"response_format":"json"}}'
```

INFOKOM direct MCP is available at `http://127.0.0.1:8000/mcp`, but it uses Streamable HTTP MCP session semantics. The helper script handles initialize/session headers for you.

## Notes

- `/mcp` is JSON-RPC, not a browser page.
- AI bot recon detects AI/LLM crawler or agent user-agents in Wazuh alert `full_log`; it does not run a local Codex agent.
- A real agent layer can be added above these MCP servers later. Use the dashboard/proxy or an OpenAI-compatible agent service as the caller, not the Wazuh Manager itself.

## Storage

The 5TB Proxmox disk is mounted inside the VM as:

```text
/data/wazuh-storage
```

Docker is configured with:

```json
{
  "data-root": "/data/wazuh-storage/docker"
}
```

That means Wazuh named volumes now live under:

```text
/data/wazuh-storage/docker/volumes
```

Important current Wazuh storage paths:

- Wazuh Indexer data: `/data/wazuh-storage/docker/volumes/single-node_wazuh-indexer-data/_data`
- Wazuh Manager logs: `/data/wazuh-storage/docker/volumes/single-node_wazuh_logs/_data`
- Filebeat state: `/data/wazuh-storage/docker/volumes/single-node_filebeat_var/_data`

The old Docker root was kept as a rollback backup:

```text
/var/lib/docker.bak-20260907-080607
```
