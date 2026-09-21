# SOC Platform Audit Priorities

Audit baseline: 2026-09-21. The catalog contains 194 tools (58 GenSecAI and
136 INFOKOM). Every tool now has one primary dashboard menu, an execution
policy, and a dependency classification. A menu load never executes a tool.

The source audit resolves to 194 menu-mapped tools, 154 cached reads, 40
approval-required operations, and 21 contextual Security Findings recipes.
Only the bounded hot-path workflows are automatic. The remaining capabilities
are intentionally analyst-triggered and read their retained result on reuse.

## Implemented in this change

- 194/194 tools mapped: 154 cached reads and 40 operator-approved operations.
- One persistent workflow worker, atomic request deduplication, 24-job backlog,
  12 Wazuh/local and 4 external-provider new runs per hour.
- Successful provider reads cache for 6 hours; local/Wazuh reads cache for 15
  minutes. Failed calls back off for 5 minutes. History is retained for 30 days
  with a 5,000-result cap and 512 KiB per-result cap.
- Menu panels expose stored Wazuh/syslog rollups and prior tool results without
  replaying external APIs or raw logs.
- Incremental rollups now request rule, decoder, destination, application,
  firewall policy, direction, identity, asset, and MITRE fields.
- IOC updates, rollup writes, empty-window completion markers, and checkpoint
  advancement now commit in one idempotent SQLite transaction. Failed scrolls
  leave no partial IOC counts and retries do not double count.
- Five-minute rollup coverage now has a completion ledger and explicit gap
  ranges, including windows that legitimately contain zero events.
- Provider history has normalized SQL facts for snapshot, provider, and CVE
  summaries. The 7d/30d views aggregate in SQL and parse JSON only for the
  bounded detail rows; legacy rows migrate incrementally.
- Security Findings exposes 21 context-aware, analyst-triggered recipes. Its
  intelligence tab uses one cached consensus aggregate rather than repeating
  direct provider calls, and hidden tabs load only when selected.
- CYFIRMA feed snapshots are materialized into an idempotent daily SQLite
  ledger. Vulnerability and Security Findings views read the ledger and stored
  exact matches; changing 24h/7d/30d/custom ranges performs zero provider calls.
- Tool inventory/count panels were removed from operational menus. Tool catalog
  data belongs to Tool Console; operational menus now prioritize findings,
  evidence, exposure, cases, and service health.
- Historical backfill no longer sends the unsupported `request_cache` body key.
- Static-file path traversal, unbounded request bodies, cross-origin writes,
  accidental high-risk tool calls, duplicate initial dashboard load, and an
  AI provider URL leak in Settings are addressed.

## P0 - deploy before broader exposure

1. Configure `DASHBOARD_ACCESS_TOKEN` and terminate HTTPS at the reverse proxy.
   The compatibility default remains unauthenticated until the token is set.
2. Rotate API keys that have appeared in terminals, screenshots, IDE context,
   or repository history. Code-side masking cannot revoke an exposed key.
3. Rebuild and restart only the dashboard container, then verify health and the
   selected 24h/7d/30d windows. Wazuh Manager and Indexer do not need restart.
4. Confirm `/app/runtime` is physically backed by `/data/wazuh-storage`; the
   current named volume alone does not prove host-disk placement.

## P1 - data correctness and scale

1. Replace the HLD worker's latest-50 polling with a durable cursor and bounded
   retry queue; persist failures instead of marking them seen before analysis.
2. Add pagination and optimistic concurrency to the existing persistent case
   store. Owner, SLA, notes, verdict, containment, and closure reason exist, but
   list reads are currently capped to the first 100 cases and updates have no
   version guard.
3. Add source freshness and partial-result telemetry to each dashboard panel so
   an empty state clearly distinguishes no data, an incomplete rollup, and an
   unavailable dependency.

## P2 - analyst quality

1. **Implemented:** bounded, 15-minute cached CVE exposure graph:
   asset/CPE/version -> CVE -> stored EPSS/KEV/PoC -> observed exploitation ->
   patch state -> case. Missing signals remain explicit evidence gaps.
2. **Implemented:** versioned CMDB/CPE normalization for owner, criticality,
   environment, network zone, components, vendor/version, CPE quality, exposure,
   patch state, and verification time. Legacy CMDB arrays remain compatible.
3. **Implemented:** `senior-soc-ai/1.0.0` contract in prompts, cache keys,
   model/fallback results, platform health, and finding UI. Per-finding cache
   identity includes the selected window, finding timestamp/count, profile, and
   contract version.
4. Add hunt hypotheses and approval state around attack-chain, graph, and pivot
   tools instead of presenting unrelated tool output as a confirmed campaign.
5. Add an evidence-promotion action from guided Security Findings results into
   a persistent case. Workflow output is durable, but it is not yet attached to
   a case evidence timeline with analyst provenance.

## Menu maturity after this audit

- **Security Findings - mature core, targeted gaps:** local evidence, provider
  consensus, CVE context, AI contract, disposition, case sync, and 21 guided
  recipes are present. Case evidence promotion and panel freshness remain.
- **Threat Hunting - partial:** broad provider coverage exists; a durable hunt
  hypothesis, scope, approval, and conclusion workflow is still missing.
- **Vulnerabilities - partial:** the exposure graph and EPSS/KEV/PoC enrichment
  and the stored CYFIRMA update ledger exist, while confirmed exposure quality
  still depends on populated asset CPE, package version, internet exposure, and
  patch-state inputs. Current CYFIRMA STIX feeds contain indicators, not a
  complete CVE advisory/news catalog; only explicit CVE references are linked.
- **Assets/CMDB - schema ready, deployment dependent:** owner, criticality,
  environment, zone, vendor/version, CPE, and patch fields are normalized. Real
  completeness cannot exceed the configured CMDB and Wazuh inventory quality.
- **SOC Workbench - reporting mature, case workspace partial:** categorized
  reports are available, but evidence notes, approval history, ownership, and
  case lifecycle editing are not yet one integrated workspace.

## Operating rule

Wazuh rules and decoders evaluate every event. The dashboard and AI consume
five-minute/hour/day rollups, deduplicated findings, and selected evidence.
Provider and AI calls run only for high-risk or analyst-selected entities. This
keeps three to ten million daily events visible without sending every event to
an external API or language model.
