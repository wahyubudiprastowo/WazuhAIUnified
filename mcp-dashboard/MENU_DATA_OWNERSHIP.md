# Dashboard Data Ownership

The dashboard follows one-data-owner-per-purpose. Cross-menu links may open the
owning view, but panels must not repeat the same table, chart, or tool catalog.

| Menu | Owns | Does not own | Default data source |
| --- | --- | --- | --- |
| Command Center | Executive posture, trend, operational health, top action queue | Tool inventory, full findings, full CVE list | SQLite snapshots and detection rollups |
| Security Findings | Deduplicated evidence queue, provider consensus, per-finding AI, analyst disposition | Generic tool catalog, incident lifecycle | Overview snapshot, retained provider/AI results |
| SOC Workbench | Daily brief, categorized report, provider coverage, approved next actions | Duplicate findings queue, tool capability cards | Retained automation report |
| L1 Triage | Urgent validation queue and evidence-gated escalation | L2 graph, generic top-rule copy | Detection rollups and retained findings |
| L2 Investigation | Entity/network/identity correlation and evidence timeline | L1 queue copy, provider feed catalog | Rollups, bounded evidence pivots, case evidence |
| Incidents | Durable case owner, SLA, notes, verdict, containment, closure | Live telemetry dashboard | Persistent case store |
| Event History | 24h/7d/30d/custom time travel and historical summaries | Live provider refresh | Materialized rollups and retained reports |
| Threat Hunting | Hunt hypothesis, ATT&CK/decoder coverage, historical provider result, analyst pivots | Tool counts, response catalog | Rollups and retained workflow/provider results |
| Vulnerabilities | Asset exposure graph, CVE priority, patch state, CYFIRMA intelligence updates | Generic threat findings | Wazuh inventory, CVE observations/cache, CYFIRMA ledger |
| Assets | CMDB identity, owner, criticality, zone, vendor/version/CPE | Vulnerability list copy | CMDB and Wazuh inventory |
| Tool Console | Live tool discovery, manual invocation, raw execution diagnostics | Operational findings | MCP catalogs and saved workflow jobs |
| Settings | Dependency health, freshness, quota/backlog, storage and policy | Finding data | Local configuration and health snapshots |

## Collection Policy

1. Wazuh rules and decoders inspect incoming events.
2. Five-minute rollups persist dimensions needed by dashboards.
3. Scheduled automation enriches deduplicated, high-value entities within a
   strict API budget and stores the result.
4. Menu loads read SQLite materializations. They do not invoke providers.
5. Analyst-triggered refreshes use cache, circuit breakers, quotas, and durable
   workflow history.
6. Provider no-match or missing CVE reference is `unknown`, never `safe`.

## CYFIRMA Provenance

Configured CYFIRMA endpoints return STIX 2.1 indicator feeds. The platform
stores feed metadata, confidence, labels, kill-chain phases, reference links,
IOC counts, freshness, and any explicit CVE identifiers. It does not label an
indicator as a local exposure unless Wazuh/CMDB asset evidence matches. General
CVE freshness remains sourced from Wazuh vulnerability inventory plus retained
NVD, EPSS, CISA KEV, and PoC enrichment.
