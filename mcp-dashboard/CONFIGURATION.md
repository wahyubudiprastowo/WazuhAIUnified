# Dashboard Configuration Guide

The dashboard reads `mcp-dashboard/dashboard.env`. Keep this file local: it is
ignored by Git and must never be copied into source control. Values marked
optional should remain empty or `false` until their dependency is ready.

## 1. Required baseline

Set a dashboard login and retain the existing MCP and Indexer values already
configured by the deployment:

```dotenv
DASHBOARD_ACCESS_USERNAME=soc
DASHBOARD_ACCESS_TOKEN=<long-random-token>
GENSECAI_MCP_URL=http://wazuh-main-server:3000
GENSECAI_API_KEY=<service-key>
INFOKOM_MCP_URL=http://wazuh-infokom-mcp:8000/mcp
INFOKOM_API_KEY=<service-key>
WAZUH_INDEXER_URL=https://wazuh.indexer:9200
WAZUH_INDEXER_USER=<read-only-dashboard-user>
WAZUH_INDEXER_PASSWORD=<password>
```

Use HTTPS at the reverse proxy before exposing port 8088. The browser username
is `DASHBOARD_ACCESS_USERNAME`; its password is `DASHBOARD_ACCESS_TOKEN`.

## 2. Scale and history

These values keep dashboard reads bounded and let the stream store compact
five-minute rollups instead of replaying raw Wazuh alerts for every page view:

```dotenv
SOC_OVERVIEW_CACHE_TTL_SECONDS=300
SOC_INTERVAL_SECONDS=900
SOC_ROLLUP_ENABLED=true
SOC_ROLLUP_RETENTION_DAYS=180
SOC_ENTITY_RETENTION_DAYS=30
SOC_ENTITY_MAX_EVIDENCE_PER_WINDOW=500
SOC_ROLLUP_BACKFILL_ENABLED=true
SOC_ROLLUP_BACKFILL_DAYS=30
SOC_ROLLUP_BACKFILL_CHUNK_MINUTES=30
SOC_ROLLUP_BACKFILL_MAX_CHUNK_MINUTES=120
SOC_ROLLUP_BACKFILL_INTERVAL_SECONDS=120
SOC_FORTI_SECURITY_BACKFILL_ENABLED=true
SOC_FORTI_SECURITY_BACKFILL_CHUNK_MINUTES=120
SOC_FORTI_SECURITY_BACKFILL_INTERVAL_SECONDS=60
SOC_IOC_BUDGET=10
SOC_CVE_BUDGET=5
```

Do not increase the IOC or CVE budget merely to make a dashboard page faster.
The queue, cache, provider backoff, and historical local ledger are designed to
spread provider work safely.

After the generic historical rollup is complete, the Forti security worker
uses a separate durable cursor to aggregate only `fortigate-firewall-v5` IPS
blocked/detected and malware signals. It reads five-minute Indexer
aggregations, not `archives.json`, and writes only compact counters.

## 3. CrowdSec watchlist

`CROWDSEC_WATCHLIST_IPS` is a **manual public-IP watchlist**. The listed IPs are
prioritized for the normal stored-provider enrichment workflow. It does not
claim that CrowdSec reported an IP, nor that the IP is malicious.

```dotenv
CROWDSEC_WATCHLIST_IPS=1.1.1.1,8.8.8.8
```

Use only public IPs, comma-separated, with no URLs, domains, CIDRs, private
addresses, or comments on the same line. Provider verdict, freshness, errors,
and CVE references are retained locally and visible in the intelligence views.

## 4. CYFIRMA

CYFIRMA STIX indicators are received through the existing INFOKOM integration.
Do not add the CYFIRMA API key to this file when it is already configured in
`infokom-analysis/infokom.env`.

The dashboard worker stores each accepted feed page in its local ledger and
uses a durable cursor per `tailored` and `global` scope. This is the supported
background process; do not add a random shell loop that re-reads alerts or
calls the vendor API outside the quota/circuit-breaker policy.

```dotenv
SOC_CYFIRMA_PAGE_SIZE=20
SOC_CYFIRMA_MAX_PAGES=10
SOC_CYFIRMA_MAX_SECONDS=90
```

The worker advances the next page on each scheduled cycle, then returns to
page zero only after reaching the end. Exact IOC matching uses the retained
local ledger, so a previously captured page is not downloaded again merely
because an analyst changes the dashboard date range.

The public research collector is separate from STIX IOC data:

```dotenv
SOC_CYFIRMA_RESEARCH_ENABLED=true
SOC_CYFIRMA_RESEARCH_URL=https://www.cyfirma.com/research/
SOC_CYFIRMA_RESEARCH_INTERVAL_SECONDS=21600
SOC_CYFIRMA_RESEARCH_MAX_ITEMS=25
```

After the next automation cycle, open **Event History -> CYFIRMA research**.
Date filtering reads the local SQLite ledger by publication date and makes no
additional CYFIRMA request.

## 5. Microsoft 365 and Defender XDR

Microsoft 365 audit collection and Defender XDR are separate integrations.
Keep Defender disabled until an Entra application has application permissions
and administrator consent:

```dotenv
M365_ANALYTICS_ENABLED=true
M365_TENANT_ID=<tenant-guid>
M365_CLIENT_ID=<app-client-id>
M365_CLIENT_SECRET=<app-client-secret>
M365_CONTENT_TYPES=Audit.AzureActiveDirectory,Audit.Exchange,Audit.SharePoint,Audit.General,DLP.All

DEFENDER_XDR_ENABLED=true
DEFENDER_XDR_TENANT_ID=<tenant-guid>
DEFENDER_XDR_CLIENT_ID=<defender-app-client-id>
DEFENDER_XDR_CLIENT_SECRET=<defender-app-client-secret>
DEFENDER_XDR_API_PROVIDER=graph
DEFENDER_XDR_COLLECTION_MODE=both
DEFENDER_XDR_POLL_INTERVAL_SECONDS=900
DEFENDER_XDR_BATCH_SIZE=50
```

Defender uses a separate checkpoint and local observation ledger. It does not
query Wazuh and it performs no request while disabled or incompletely configured.
For Microsoft Graph, `incidents` requires application permission
`SecurityIncident.Read.All`; `alerts` uses `GET /v1.0/security/alerts_v2` and
requires `SecurityAlert.Read.All`. Both permissions need administrator consent
when `DEFENDER_XDR_COLLECTION_MODE=both`. If only `SecurityAlert.Read.All` is
granted, set the mode to `alerts`; otherwise the alert collector will work but
the incident collector will report its own permission error.

Each collection has an independent checkpoint and bounded page size. Pending
Graph pages resume from the validated `@odata.nextLink`; results are retained
in the local Defender ledger. Alerts appear in **Security Findings** and both
record types appear in **Event History -> Defender XDR**. Date selection reads
SQLite and does not make a Microsoft API call.

## 6. CYFIRMA TAXII 2.1

The configured CYFIRMA STIX endpoints are not automatically TAXII collections.
Ask CYFIRMA for the exact TAXII 2.1 collection URL and a bearer token, then add:

```dotenv
SOC_CYFIRMA_TAXII_ENABLED=true
SOC_CYFIRMA_TAXII_COLLECTION_URL=https://api.cyfirma.com/<provider-taxii-path>/collections/<collection-id>/
SOC_CYFIRMA_TAXII_BEARER_TOKEN=<taxii-bearer-token>
SOC_CYFIRMA_TAXII_INTERVAL_SECONDS=21600
SOC_CYFIRMA_TAXII_MAX_ITEMS=50
SOC_CYFIRMA_TAXII_MAX_PAGES=2
```

The collector accepts only `https://*.cyfirma.com` collection URLs, reads one
bounded `/objects/` page sequence per cycle, persists the opaque TAXII
continuation cursor, and writes normalized indicator rows to the existing
CYFIRMA ledger. A partial sweep resumes in the background after at most 15
minutes; a completed sweep follows the configured interval. It never replaces
the existing tailored/global STIX feed. TAXII results appear in
**Vulnerabilities -> CYFIRMA intelligence** and **Event History -> CYFIRMA
intelligence** with scope `taxii`.

After rebuild, verify actual ledger intake rather than configuration alone:

```bash
cd /opt/wazuh-mcp-unified
bash tools/check_dashboard_deploy.sh
```

The output is read-only and redacts configuration values. Check that TAXII,
Organization CVE, and Defender report a checkpoint status plus a nonzero local
observation count when the provider has matching records. `not_started` means
the worker has not completed a collection cycle; `error` includes a sanitized
dependency reason in the dashboard Settings page.

## 7. CYFIRMA Organization API V2 vulnerability intelligence

Use a freshly regenerated Organization API key, not a key pasted into chat or
terminal history. This collector uses the documented Vulnerability V2 STIX list
endpoint with a bounded first page and `from-modified-date` lookback:

```dotenv
SOC_CYFIRMA_ORG_VULN_ENABLED=true
SOC_CYFIRMA_ORG_VULN_API_KEY=<regenerated-org-api-key>
SOC_CYFIRMA_ORG_VULN_URL=https://decyfir.cyfirma.com/core/api-ua/stix-v2.1/v2/vulnerabilities
SOC_CYFIRMA_ORG_VULN_INTERVAL_SECONDS=21600
SOC_CYFIRMA_ORG_VULN_LOOKBACK_DAYS=30
SOC_CYFIRMA_ORG_VULN_PAGE_SIZE=50
SOC_CYFIRMA_ORG_VULN_MAX_PAGES=2
```

Organization CVE records are deduplicated into the existing CYFIRMA ledger and
appear in **Vulnerabilities -> CYFIRMA intelligence** and **Event History ->
CYFIRMA intelligence** as scope `org_vulnerability`. The collector checkpoints
the next page and resumes partial result sets in the background. It does not
download the entire vendor archive or issue one API call per local CVE.

## 8. AI analyst and email

Enable these only after testing the provider and SMTP settings from **Settings**:

```dotenv
AI_ANALYST_ENABLED=true
AI_AUTO_ANALYZE=false
AI_PROVIDER_BASE_URL=https://<approved-ai-endpoint>/v1
AI_MODEL=<approved-model>
AI_API_KEY=<api-key>

SOC_EMAIL_ENABLED=true
SOC_SMTP_HOST=<smtp-host>
SOC_SMTP_PORT=587
SOC_SMTP_AUTH=oauth2
SOC_SMTP_USER=<service-account>
SOC_SMTP_FROM=<from-address>
SOC_REPORT_RECIPIENTS=<soc-recipient-address>
```

Keep `AI_AUTO_ANALYZE=false` initially. The per-finding button uses bounded
evidence and caches completed analyses; it does not send millions of raw logs
to the model.

## 7. CMDB and telemetry readiness

Populate the mounted CMDB file with asset owner, criticality, environment,
network zone, vendor, version, and CPE. Configure its host directory through
`DASHBOARD_CMDB_DIR`; the directory is mounted read-only and `SOC_CMDB_FILE`
selects `/app/cmdb/assets.json` inside the container. A directory mount is
required so atomic CMDB replacement does not leave the container pinned to an
old single-file bind-mount inode.

The dashboard materializes exposure paths as `asset -> component/CPE/version ->
CVE -> EPSS/KEV/PoC -> patch/case` in its SQLite summary. It will not invent
CMDB fields. Validate the supplied file before deployment:

```bash
cd /opt/wazuh-mcp-unified
python3 tools/validate_cmdb.py ../path/to/assets.json
```

Create or refresh the ignored local CMDB identity baseline from agents already
observed by Wazuh:

```bash
python3 tools/sync_cmdb_inventory.py            # dry-run
python3 tools/sync_cmdb_inventory.py --write    # atomic local update
python3 tools/validate_cmdb.py
```

The sync preserves authoritative operator annotations and excludes rows marked
`template`, `verified: false`, or with a `SAMPLE`/`EXAMPLE` purpose. It only
writes observed agent ID, hostname, IP, OS, source, and verification time.
Owner, criticality, environment, network zone, internet exposure, CPE, package
aliases, and patch ownership must come from a verified CMDB/asset owner. They
are deliberately not inferred from a public IP, hostname, or operating-system
name.

For component-level CVE correlation, define `components[]` with an exact
`name`, optional `package_names[]`, `version`, and CPE 2.3. A version-specific
CPE is attached only when both package identity and installed version are
compatible. Sample records and ambiguous identifiers never participate in
runtime correlation.

Settings -> **Telemetry Readiness** reports only fields materialized from
decoded telemetry. `not observed` means the source has not provided decoded
events in the selected range, not that the dashboard is broken.

## 8. Rebuild and verify

Run on the host as an account permitted to use Docker:

```bash
cd /opt/wazuh-mcp-unified
docker compose -f mcp-dashboard/docker-compose.dashboard.yml up -d --build
docker compose -f mcp-dashboard/docker-compose.dashboard.yml ps
docker compose -f mcp-dashboard/docker-compose.dashboard.yml logs --tail=100 mcp-dashboard
docker compose -f mcp-dashboard/docker-compose.dashboard.yml logs --tail=100 mcp-materializer
```

This rebuilds the dashboard plus its bounded rollup worker; it does not restart
Wazuh Manager or Wazuh Indexer. `mcp-materializer` has one checkpoint owner,
uses small time windows and pages, and is capped by `SOC_MATERIALIZER_CPUS` and
`SOC_MATERIALIZER_MEMORY_LIMIT`.

## 9. Capacity validation

Do not claim 10M logs/day capacity from a container build. Replay representative
sanitized telemetry in staging at **1M**, **3M**, then **10M events/day**. At
each stage retain the conservative worker limits and record: Indexer query p95,
pipeline lag, failed shards, queue depth, rollup gap count, dashboard p95, and
Wazuh manager/indexer CPU, heap, disk, and rejected requests. Advance only when
the checkpoint remains caught up, rollup gaps remain zero, and production alert
ingestion and dashboards stay within their existing latency SLOs. Increase one
limit at a time; never add worker replicas because the checkpoint is single-owner.
