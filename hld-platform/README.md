# Wazuh + MCP AI Security Platform HLD Overlay

This package implements the HLD as an additive overlay for the current Wazuh stack.
It does not replace the running Wazuh Manager, Indexer, Dashboard, or MCP server.

## What Is Added

- AI alert worker that polls Wazuh Indexer and calls MCP tools over `/mcp`.
- Optional approval notifications through `SOAR_WEBHOOK_URL` and `TEAMS_WEBHOOK_URL`.
- Automated response gate, disabled by default with `ENABLE_AUTOMATED_RESPONSE=false`.
- Wazuh localfile ingest for PAM audit JSONL and SOAR audit JSONL.
- Wazuh rule IDs `100200` to `100212` for PAM and SOAR events.
- Compose overlays only; base compose files remain unchanged.

## HLD Mapping

| HLD block | Current implementation |
|---|---|
| Data source / managed devices | Existing syslog, Wazuh agents, API, and indexer ingest |
| Containerized Wazuh SIEM | Existing `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard` |
| MCP AI security engine | Existing `wazuh-main-server` plus worker-driven tool calls |
| Threat intelligence | MCP tools: `advanced_threat_intelligence`, OTX, ThreatFox, GreyNoise, CrowdSec when configured |
| PAM platform audit | `/opt/wazuh-mcp-unified/hld-platform/pam-audit/audit.jsonl` ingested by Wazuh |
| SOAR / automation | Approval webhook and Teams webhook; active response stays gated off by default |

## Current Location

The overlay is installed in `/opt/wazuh-mcp-unified/hld-platform`.
The Wazuh manager overlay is installed as
`/opt/wazuh-mcp-unified/wazuh-stack/single-node/docker-compose.hld.yml`.

## Settings Map

| Component | File |
|---|---|
| Wazuh Manager / Indexer / Dashboard containers | `/opt/wazuh-mcp-unified/wazuh-stack/single-node/docker-compose.yml` |
| Syslog mount override | `/opt/wazuh-mcp-unified/wazuh-stack/single-node/docker-compose.syslog.yml` |
| HLD Wazuh mount override | `/opt/wazuh-mcp-unified/wazuh-stack/single-node/docker-compose.hld.yml` |
| Wazuh manager config | `/opt/wazuh-mcp-unified/wazuh-stack/single-node/config/wazuh_cluster/wazuh_manager.conf` |
| MCP server config | `/opt/wazuh-mcp-unified/gensecai-core/.env` |
| HLD worker config | `/opt/wazuh-mcp-unified/hld-platform/hld.env` |
| HLD PAM audit input | `/opt/wazuh-mcp-unified/hld-platform/pam-audit/audit.jsonl` |
| HLD SOAR audit input | `/opt/wazuh-mcp-unified/hld-platform/soar-audit/audit.jsonl` |
| Existing device syslog registry | `/opt/wazuh-mcp-unified/syslog-ingest/devices.json` |

## Apply

Edit:

```bash
nano /opt/wazuh-mcp-unified/hld-platform/hld.env
```

Then apply:

```bash
bash /opt/wazuh-mcp-unified/hld-platform/apply-hld-platform.sh
```

The apply step recreates only `wazuh.manager` with the additional read-only mounts, then starts `wazuh-hld-ai-alert-worker`.

## Check

```bash
bash /opt/wazuh-mcp-unified/hld-platform/check-hld-platform.sh
```

## PAM And SOAR Audit Samples

Append a PAM event:

```bash
echo '{"platform":"pam","action":"session_start","user":"socadmin","target":"linux-server-01","srcip":"10.10.10.5"}' \
  | sudo tee -a /opt/wazuh-mcp-unified/hld-platform/pam-audit/audit.jsonl
```

Append a SOAR event:

```bash
echo '{"platform":"soar","action":"approval_requested","tool":"wazuh_block_ip","srcip":"203.0.113.10","case_id":"CASE-001"}' \
  | sudo tee -a /opt/wazuh-mcp-unified/hld-platform/soar-audit/audit.jsonl
```

## Safety Defaults

- `ENABLE_AUTOMATED_RESPONSE=false`, so the worker requests approval but does not block or isolate.
- `RESPONSE_AGENT_ID` is empty, so accidental active response cannot run.
- Wazuh mounts are read-only for rules, decoders, and audit input files.
- The installer creates a timestamped backup under `/opt/wazuh-mcp-unified/backups`.
