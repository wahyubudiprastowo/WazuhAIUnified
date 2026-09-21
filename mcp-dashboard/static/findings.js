/* Findings preserve the distinction between observed events and external intelligence. */
(() => {
  const t = (id, en) => window.SocLocale?.t ? window.SocLocale.t(id, en) : en;
  const ax = (analysis, field) => window.SocLocale?.analysis ? window.SocLocale.analysis(analysis, field) : (analysis?.[field] || "");
  const categories = {all: "All findings", wazuh: "Wazuh rules", decoder: "Decoder coverage", m365: "Microsoft 365", ip: "Source IP / Geo", observable: "Log indicators", recon: "AI bot recon", vuln: "CVE & Exposure"};
  const severityOrder = {critical: 5, high: 4, medium: 3, low: 2, unknown: 1};
  const evidenceLabels = {observed: "Wazuh observed", inventory: "Asset inventory", intel: "External intelligence", pending: "Local evidence not verified"};
  const f = {rows: [], category: "all", selected: null, page: 0, feeds: {}, pivots: new Map(), cache: new Map(), ai: new Map(), aiJobs: new Map(), feedback: new Map(), workflowResults: new Map(), tabLoads: new Set(), sequence: 0, cveSequence: 0, tab: "overview", data: null};
  const findingRecipes = {
    wazuh: ["analyze_alert_patterns", "blueteam_attack_chain", "blueteam_pivot_suggest", "blueteam_false_positive_kb"],
    decoder: ["blueteam_wazuh_get_decoders", "get_wazuh_rules_summary", "blueteam_baseline_drift"],
    m365: ["wazuh_email_lookup", "wazuh_compromised_emails_analysis", "blueteam_attack_chain"],
    ip: ["blueteam_investigate_ip", "blueteam_unified_threat_score", "blueteam_pivot_suggest", "blueteam_campaign_watch"],
    observable: ["blueteam_threat_intel_aggregate", "blueteam_ioc_lifecycle", "blueteam_pivot_suggest"],
    recon: ["blueteam_investigate_ip", "wazuh_attack_velocity", "blueteam_attack_chain", "blueteam_campaign_watch"],
    vuln: ["blueteam_cve_epss", "blueteam_cve_kev", "blueteam_cve_poc", "blueteam_cve_ssvc", "blueteam_cve_attack_mapping", "blueteam_cve_advisory"],
  };
  const recipePurpose = {
    analyze_alert_patterns: "Compare recurrence, severity and rule patterns in a bounded window.",
    blueteam_attack_chain: "Build a hypothesis from observed evidence; it does not confirm a campaign.",
    blueteam_pivot_suggest: "Suggest evidence pivots for the current entity.",
    blueteam_false_positive_kb: "Check prior analyst knowledge before escalating.",
    blueteam_wazuh_get_decoders: "Review decoder inventory and parsing coverage.",
    get_wazuh_rules_summary: "Review loaded rule coverage without replaying raw logs.",
    blueteam_baseline_drift: "Compare the current signal against a stored baseline.",
    wazuh_email_lookup: "Correlate the selected account with stored mail evidence.",
    wazuh_compromised_emails_analysis: "Assess mailbox compromise signals.",
    blueteam_investigate_ip: "Correlate the IP with local security evidence.",
    blueteam_unified_threat_score: "Calculate a bounded multi-source risk score.",
    blueteam_campaign_watch: "Check whether the indicator belongs to a tracked campaign.",
    blueteam_threat_intel_aggregate: "Reuse the deduplicated provider consensus pipeline.",
    blueteam_ioc_lifecycle: "Review first seen, last seen and historical IOC context.",
    wazuh_attack_velocity: "Measure recurrence and acceleration from stored alert data.",
    blueteam_cve_epss: "Retrieve exploit probability context.",
    blueteam_cve_kev: "Check known-exploited status.",
    blueteam_cve_poc: "Review public exploit references.",
    blueteam_cve_ssvc: "Calculate stakeholder-specific prioritization.",
    blueteam_cve_attack_mapping: "Map vulnerability behavior to ATT&CK context.",
    blueteam_cve_advisory: "Build a remediation-oriented advisory.",
  };
  const list = (value) => Array.isArray(value) ? value : value == null ? [] : [value];
  const label = (value) => typeof value === "object" && value !== null ? value.label || value.name || value.id || value.value || "" : String(value ?? "");
  const labels = (value) => [...new Set(list(value).flatMap(item => {
    if (item && typeof item === "object") return label(item) ? [String(label(item))] : Object.values(item).flatMap(labels);
    return typeof item === "string" && item ? [item] : [];
  }))];
  const text = (value) => value === undefined || value === null || value === "" ? "Not returned" : typeof value === "object" ? JSON.stringify(value) : String(value);
  const pill = (value, tone = "unknown") => `<span class="findingBadge ${esc(tone)}">${esc(value)}</span>`;
  const chips = (values) => labels(values).map(v => `<span class="findingTag">${esc(v)}</span>`).join("") || '<span class="findingMuted">Not returned by source</span>';
  const field = (name, value) => `<div><dt>${esc(name)}</dt><dd>${esc(text(value))}</dd></div>`;
  const section = (title, body) => `<section class="findingSection"><h3>${esc(title)}</h3>${body}</section>`;
  const raw = (data) => `<details class="findingRaw"><summary>Source record</summary><pre>${esc(JSON.stringify(data, null, 2))}</pre></details>`;
  const warning = (message) => `<p class="findingNotice">${esc(message)}</p>`;
  const safeLink = (url, title) => {
    try { const u = new URL(url); if (u.protocol === "https:") return `<a href="${esc(u.href)}" target="_blank" rel="noopener noreferrer">${esc(title)}</a>`; } catch (_) {}
    return esc(title);
  };
  const indicatorOf = (row) => row.ip || row.indicator || "";
  const cveIds = (value) => [...new Set((JSON.stringify(value || {}).match(/CVE-\d{4}-\d{4,}/g) || []))];
  const cveButtons = (ids) => ids.map(id => `<button type="button" class="findingCve" data-finding-cve="${esc(id)}">${esc(id)}</button>`).join("") || '<p class="findingMuted">No CVE references returned. This does not rule out a vulnerability.</p>';
  const isHash = (value) => /^[a-f\d]{32}$|^[a-f\d]{40}$|^[a-f\d]{64}$/i.test(value || "");
  const isFullUrl = (value) => /^https?:\/\/[^/\s]+/i.test(value || "");
  function buildRows() {
    const d = f.data;
    if (!d) return;
    const rows = [];
    for (const row of f.coverage?.rules || d.threats || []) rows.push({id: `rule:${row.rule_id}`, category: "wazuh", provider: "Wazuh", title: ax(row.analysis, "title") || row.description || `Rule ${row.rule_id}`, subject: `Rule ${row.rule_id} | ${row.description}`, severity: severityClass(Number(row.level)), evidence: "observed", count: row.count, countScope: row.count_scope, ip: (row.source_ips || [])[0], rule: row.rule_id, description: ax(row.analysis, "meaning") || `Rule level ${row.level}. ${row.count} event(s) in the returned threat sample.`, types: row.groups, assets: (row.affected_agents || []).map(a => a.name || a.id), timestamp: row.last_seen, raw: row});
    for (const row of f.coverage?.decoders || []) rows.push({id: `decoder:${row.name}`, category: "decoder", provider: "Wazuh index", title: row.name, subject: row.latest_rule ? `Latest rule ${row.latest_rule_id}: ${row.latest_rule}` : "Decoded Wazuh events", severity: severityClass(Number(row.max_level)), evidence: "observed", count: row.count, countScope: "index aggregation", rule: row.latest_rule_id, description: `${fmt.format(Number(row.count || 0))} indexed event(s) decoded in the selected window. Maximum observed rule level ${Number(row.max_level || 0)}.`, types: ["decoder", row.location].filter(Boolean), assets: [row.latest_agent?.name || row.latest_agent?.id].filter(Boolean), timestamp: row.last_seen, raw: row});
    for (const [i, row] of (d.cloud_m365?.events || []).entries()) rows.push({id: `m365:${row.timestamp}:${i}`, category: "m365", provider: "Wazuh / Microsoft 365", title: row.operation || row.description, subject: row.user || row.workload, severity: severityClass(Number(row.level)), evidence: "observed", ip: row.client_ip, operation: row.operation, description: ax(row.analysis, "meaning") || row.description, types: [row.workload, row.subscription].filter(Boolean), assets: [row.user, row.object].filter(Boolean), timestamp: row.timestamp, raw: row});
    const automationFindings = window.SocAutomation?.report?.findings || [];
    const automatedByIndicator = new Map(automationFindings.map(row => [row.indicator, row]));
    const observed = new Map((d.source_ips || []).map(r => [r.ip, r]));
    const crowd = new Map((state.crowdSecIntel?.rows || []).map(r => [r.ip, r]));
    for (const ip of new Set([...observed.keys(), ...crowd.keys()])) {
      const local = observed.get(ip), ti = crowd.get(ip), automated = automatedByIndicator.get(ip);
      const cyfirmaMatches = automated?.cyfirma_matches || [];
      const providers = [local && "Wazuh", ti && "CrowdSec", cyfirmaMatches.length && "CYFIRMA"].filter(Boolean);
      rows.push({id: `ip:${ip}`, category: "ip", provider: providers.join(" / ") || "Wazuh", title: ip, subject: ti ? crowdLocation(ti) : cyfirmaMatches.length ? `${cyfirmaMatches.length} stored CYFIRMA exact match(es)` : "Location not returned", ip, severity: ti?.reputation === "malicious" || automated?.status === "suspected" ? "high" : ti?.reputation === "suspicious" ? "medium" : "unknown", evidence: local ? "observed" : "intel", count: local?.hits || automated?.event_total, description: ti ? crowdReason(ti) : cyfirmaMatches.length ? "Stored automation result matched this locally observed indicator to CYFIRMA intelligence. Validate event direction and impact before response." : "Source address in the Wazuh threat sample. Reputation has not been assessed.", types: [...(ti?.behaviors || []), ...cyfirmaMatches.flatMap(row => row.labels || [])], timestamp: automated?.enriched_at || (ti ? crowdHistory(ti) : null), crowd: ti, raw: {local, intelligence: ti, automation: automated, cyfirma_matches: cyfirmaMatches}});
    }
    for (const t of d.ai_recon?.sources || []) rows.push({id: `recon:${t.srcip}`, category: "recon", provider: "Wazuh / INFOKOM", title: t.srcip, subject: "Automated probing pattern", ip: t.srcip, evidence: "observed", severity: t.sensitive_hits > 0 ? "high" : "medium", count: t.alerts, description: `${t.sensitive_hits} sensitive-path hits; ${t.unique_paths} distinct paths. Pattern-based detection does not confirm use of AI or successful compromise.`, types: ["Reconnaissance", "Sensitive path probing"], raw: t});
    for (const [i, t] of (d.vulnerabilities?.critical_items || []).entries()) {
      const cve = t.cve || t.id || t.vulnerability?.id;
      rows.push({id: `vuln:${cve}:${i}`, category: "vuln", provider: "Wazuh inventory", title: cve, subject: t.package?.name || t.package_name, cve, severity: String(t.severity || "unknown").toLowerCase(), evidence: "inventory", description: t.description, assets: [t.agent?.name || t.agent?.id].filter(Boolean), types: [t.package?.name].filter(Boolean), raw: t});
    }
    for (const row of f.pivots.values()) if (!rows.some(r => r.id === row.id)) rows.push(row);
    const deduplicated = new Map();
    for (const row of rows) {
      const asset = labels(row.assets)[0] || "";
      const identity = row.category === "vuln"
        ? `${row.category}:${String(row.cve || row.title || "").toLowerCase()}:${asset.toLowerCase()}:${String(row.subject || "").toLowerCase()}`
        : row.category === "m365"
          ? `${row.category}:${String(row.title || "").toLowerCase()}:${String(row.subject || "").toLowerCase()}:${row.timestamp || ""}:${row.ip || ""}`
          : row.id;
      const existing = deduplicated.get(identity);
      if (!existing) {
        deduplicated.set(identity, row);
        continue;
      }
      existing.count = Math.max(Number(existing.count || 0), Number(row.count || 0)) || existing.count || row.count;
      existing.assets = labels([existing.assets, row.assets]);
      existing.types = labels([existing.types, row.types]);
    }
    f.rows = [...deduplicated.values()].sort((a,b) => (severityOrder[b.severity] || 1) - (severityOrder[a.severity] || 1));
    const replacement = f.rows.find(r => r.id === f.selected?.id);
    if (replacement && JSON.stringify(replacement) !== JSON.stringify(f.selected)) {
      const tab = f.tab; select(replacement); changeTab(tab);
    }
    renderList();
    renderHealth();
  }

  function filtered() {
    const search = q("#findingSearch").value.trim().toLowerCase();
    const evidence = q("#findingEvidence").value, severity = q("#findingSeverity").value;
    return f.rows.filter(r => (f.category === "all" || r.category === f.category) && (evidence === "all" || r.evidence === evidence) && (severity === "all" || r.severity === severity) && (!search || JSON.stringify(r).toLowerCase().includes(search)));
  }

  function renderList() {
    const rows = filtered(), pageSize = 12;
    f.page = Math.min(f.page, Math.max(0, Math.ceil(rows.length / pageSize) - 1));
    const d = f.data || {};
    q("#findingsSummary").innerHTML = [
      [t("Alert pada window terpilih", "Alerts in selected window"), fmt.format(f.coverage?.total_events ?? d.alerts?.total_alerts ?? 0), f.coverage ? t(`${f.coverage.rules.length} rule dimuat dari agregasi indeks`, `${f.coverage.rules.length} rules loaded from index aggregation`) : t(`${fmt.format(d.alerts?.sampled || 0)} disampel untuk ranking ancaman`, `${fmt.format(d.alerts?.sampled || 0)} sampled for threat ranking`)],
      [t("Record prioritas tinggi", "High-priority records"), f.rows.filter(r => r.evidence !== "intel" && ["high", "critical"].includes(r.severity)).length, t("Dari temuan yang dimuat", "From the loaded findings")],
      [t("Kerentanan kritis", "Critical vulnerabilities"), d.vulnerabilities?.critical ?? "-", t(`${d.vulnerabilities?.affected_agents ?? "-"} aset terdampak (semua severity)`, `${d.vulnerabilities?.affected_agents ?? "-"} affected assets (all severities)`)],
      ["CYFIRMA context", Object.values(f.feeds).reduce((n, r) => n + (r.data?.summary?.count || 0), 0), t("Tersimpan untuk korelasi; feed umum tidak dihitung sebagai temuan", "Stored for correlation; general feed records are not counted as findings")],
      [t("Temuan dianalisis AI", "AI analyzed findings"), f.ai.size, t("Hasil per temuan disimpan agar analisis ulang instan", "Per-finding results are cached for instant reuse")]
    ].map(([name, value, hint]) => `<div><span>${esc(name)}</span><strong>${esc(value)}</strong><small>${esc(hint)}</small></div>`).join("");
    q("#findingsCategories").innerHTML = Object.entries(categories).map(([key, name]) => `<button type="button" data-finding-category="${key}" aria-pressed="${f.category === key}">${name}<span>${key === "all" ? f.rows.length : f.rows.filter(r => r.category === key).length}</span></button>`).join("");
    q("#findingsCount").textContent = t(`${rows.length} record dimuat`, `${rows.length} loaded records`);
    const visible = rows.slice(f.page * pageSize, (f.page + 1) * pageSize);
    q("#findingsRows").innerHTML = visible.map(r => `<article class="findingRowShell ${f.selected?.id === r.id ? "selected" : ""}"><button type="button" class="findingRow" data-finding-id="${esc(r.id)}" aria-pressed="${f.selected?.id === r.id}"><span class="findingRowMeta">${pill(r.severity === "unknown" ? t("Belum dinilai", "Not assessed") : r.severity, r.severity)}<span>${esc(categories[r.category])}</span></span><strong>${esc(r.title)}</strong><span class="findingSubject">${esc(r.subject || r.description)}</span><span class="findingRowFoot"><span>${esc(evidenceLabels[r.evidence])}</span><span>${r.count == null ? esc(r.provider) : `${fmt.format(r.count)} ${r.countScope ? t("event terindeks", "indexed events") : r.category === "ip" ? t("asosiasi rule", "rule associations") : t("hit sampel", "sample hits")}`}</span></span></button><button type="button" class="findingAiButton" data-finding-ai="${esc(r.id)}" aria-label="${esc(t(`Jalankan analisis AI untuk ${r.title}`, `Run AI analysis for ${r.title}`))}">${f.ai.has(r.id) ? t("Lihat analisis AI", "View AI analysis") : f.aiJobs.has(r.id) ? t("Lihat progres AI", "View AI progress") : t("Run AI Analysis", "Run AI Analysis")}</button></article>`).join("") || `<div class="findingEmpty">${t("Tidak ada record yang cocok pada data dimuat.", "No matching records in the loaded data.")}</div>`;
    q("#findingsPagination").innerHTML = `<button type="button" data-finding-page="-1" ${f.page === 0 ? "disabled" : ""}>Previous</button><span>${rows.length ? f.page + 1 : 0} / ${Math.ceil(rows.length/pageSize)}</span><button type="button" data-finding-page="1" ${(f.page+1)*pageSize >= rows.length ? "disabled" : ""}>Next</button>`;
    if (!f.selected || !rows.some(r => r.id === f.selected.id)) {
      if (visible[0]) select(visible[0]);
      else { f.selected = null; f.sequence++; q("#findingDetail").innerHTML = `<div class="findingEmpty">${t("Tidak ada temuan dipilih.", "No finding selected.")}</div>`; }
    }
  }

  function recommendations(row) {
    if (row.raw?.analysis) return [ax(row.raw.analysis, "l1"), ax(row.raw.analysis, "l2"), ax(row.raw.analysis, "cve_context")];
    const groups = labels(row.types).join(" ").toLowerCase();
    if (row.category === "wazuh" && /syscheck|fim/.test(groups)) return ["Compare the changed file or registry value with the approved baseline and deployment record.", "Correlate the modification time with user logins, process execution and endpoint detections.", "Preserve the hashes and event evidence; restore an approved version only after validating that the change was unauthorized."];
    if (row.category === "wazuh" && /authentication|sshd|pam|auth_fail/.test(groups)) return ["Compare failed and successful logins for the same source and account, including the affected host.", "Check whether the source is an approved administrator, monitoring system or repeated brute-force origin.", "Escalate suspicious successful access and use the approved account/session containment process."];
    if (row.category === "wazuh" && /fortigate|firewall|suricata|network/.test(groups)) return ["Inspect the source, destination, port and allow/deny action. An allowed connection is not automatically malicious.", "Correlate the signature with repeated sources, target services and endpoint events to establish impact.", "Validate source reputation and business dependencies before proposing firewall or WAF containment."];
    if (row.category === "vuln") return ["Validate the installed package version against the vendor advisory and confirm whether the affected service is reachable.", "Use KEV, EPSS and public exploit evidence below to prioritize a tested patch or vendor mitigation.", "After remediation, rescan the asset and retain evidence of the installed version."];
    if (row.category === "decoder") return ["Open the latest matching rule and verify that parsed fields map to the original device log.", "Check for decoder errors or generic fallback decoding before relying on field-level correlations.", "Add or adjust rules only when a representative log sample proves a coverage gap; avoid duplicate decoder names and rule IDs."];
    if (row.category === "m365") return ["Validate the user, workload, operation, target object and source IP against expected business activity.", "For suspicious sign-in or mail activity, correlate Entra sign-ins, mailbox audit and Defender evidence before escalating.", "For confirmed account compromise, follow the incident playbook to revoke sessions and reset credentials with authorized approval."];
    if (row.category === "recon") return ["Inspect requested paths, response status and response size to distinguish blocked probes from exposed content.", "Check whether secrets or repository files were accessible; rotate only credentials confirmed exposed or at risk.", "Correlate repeated probes with WAF and endpoint events, then apply approved rate limits or source blocking."];
    if (row.evidence === "intel") return ["Search the exact indicator in available local logs. A feed or watchlist entry alone does not establish a local attack.", "Validate indicator age, confidence, provider disagreement and possible shared-hosting use before blocking.", "If local evidence confirms malicious activity, preserve the event trail and follow the incident response playbook."];
    return ["Review source, destination, asset, rule and timestamps in the matching Wazuh events.", "Correlate provider intelligence with local evidence; distinguish allowed traffic, blocked attempts and successful activity.", "Escalate confirmed impact with supporting events. Apply containment only through the approved response playbook."];
  }

  function findingWorkflowArgs(tool, row) {
    const args = {...(tool.default_arguments || {})};
    const indicator = indicatorOf(row);
    const agentId = row.raw?.agent?.id || row.raw?.latest_agent?.id || row.raw?.local?.agent?.id;
    const email = [row.subject, indicator, row.raw?.user, row.raw?.office365?.UserId].find(value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value || ""));
    const windowValue = window.SocWindow?.payload ? window.SocWindow.payload().range || "24h" : "24h";
    const values = {
      indicator, ioc: indicator, observable: indicator, search_term: indicator,
      indicators: indicator ? [indicator] : undefined, ips: row.ip ? [row.ip] : undefined,
      ip: row.ip || (isPublicIp(indicator) ? indicator : ""), source_ip: row.ip, srcip: row.ip,
      cve_id: row.cve, cve: row.cve, cve_ids: row.cve ? [row.cve] : undefined,
      rule_id: row.rule, rule: row.rule,
      agent_id: agentId, email, user: email || row.subject,
      domain: indicator && !isPublicIp(indicator) && !isHash(indicator) && !isFullUrl(indicator) ? indicator : "",
      url: isFullUrl(indicator) ? indicator : "", file_hash: isHash(indicator) ? indicator : "",
      query: indicator || row.rule || row.title, seed: indicator || row.rule || row.title,
      time_range: windowValue, window: windowValue, range: windowValue, response_format: "json",
    };
    for (const field of tool.schema_fields || []) {
      const value = values[field.name];
      if (value !== undefined && value !== null && value !== "") args[field.name] = value;
      else if (Object.hasOwn(values, field.name)) delete args[field.name];
    }
    const missing = (tool.required_fields || []).filter(name => args[name] === undefined || args[name] === null || args[name] === "");
    return missing.length ? null : args;
  }

  function findingWorkflowTools(row) {
    return (findingRecipes[row.category] || []).map(name => state.tools.find(tool =>
      tool.name === name && tool.workflow?.mode === "cached_read")).filter(Boolean).map(tool =>
      ({tool, args: findingWorkflowArgs(tool, row)})).filter(item => item.args).slice(0, 6);
  }

  function compactWorkflowResult(result) {
    const data = result?.json ?? result?.data ?? result;
    if (data === undefined || data === null) return `<p class="findingMuted">${t("Tool selesai tanpa data terstruktur.", "Tool completed without structured data.")}</p>`;
    if (typeof data !== "object") return `<p>${esc(String(data).slice(0, 2000))}</p>`;
    const rows = Object.entries(data).filter(([, value]) => value !== null && value !== undefined && typeof value !== "object").slice(0, 12);
    const collections = Object.entries(data).filter(([, value]) => Array.isArray(value) && value.length).slice(0, 4);
    const encoded = JSON.stringify(data, null, 2);
    return `${rows.length ? `<dl class="findingFields">${rows.map(([key,value]) => field(key.replaceAll("_", " "), value)).join("")}</dl>` : ""}${collections.map(([key,value]) => section(key.replaceAll("_", " "), `<div class="findingTags">${chips(value.slice(0, 10))}</div>`)).join("")}<details class="findingRaw"><summary>${t("Hasil tersimpan", "Stored result")}</summary><pre>${esc(encoded.slice(0, 12000))}${encoded.length > 12000 ? "\n... truncated in browser" : ""}</pre></details>`;
  }

  function renderFindingWorkflows(row) {
    const target = q("#findingWorkflowTools");
    if (!target) return;
    const tools = findingWorkflowTools(row);
    target.innerHTML = section(t("Investigasi terarah", "Guided investigation"), tools.length ?
      `<p class="findingMuted">${t("Tool hanya berjalan saat dipilih. Hasil disimpan dan pemanggilan identik memakai cache.", "Tools run only when selected. Results are saved and identical requests reuse cache.")}</p><div class="findingWorkflowGrid">${tools.map(({tool,args}) => {
        const key = `${row.id}:${tool.source}:${tool.name}`;
        const stateRow = f.workflowResults.get(key);
        return `<article><div><strong>${esc(tool.name)}</strong><p>${esc(recipePurpose[tool.name] || tool.description || "Bounded analyst workflow")}</p><small>${esc(tool.workflow.menu)} · cache ${Math.round(Number(tool.workflow.cache_seconds || 0) / 60)} min</small></div><button type="button" data-finding-workflow="${esc(key)}" data-tool-source="${esc(tool.source)}" data-tool-name="${esc(tool.name)}" ${stateRow?.status === "running" ? "disabled aria-busy=\"true\"" : ""}>${stateRow?.status === "running" ? t("Menjalankan...", "Running...") : stateRow?.status === "completed" ? t("Jalankan ulang", "Run again") : t("Jalankan", "Run")}</button>${stateRow ? `<div class="findingWorkflowOutput ${esc(stateRow.status)}" role="status">${stateRow.error ? warning(stateRow.error) : stateRow.status === "running" ? `<p class="findingLoading">${t("Job diantrikan; halaman tetap responsif.", "Job queued; the page remains responsive.")}</p>` : compactWorkflowResult(stateRow.result)}</div>` : ""}</article>`;
      }).join("")}</div>` : `<p class="findingMuted">${t("Tidak ada tool ter-cache dengan parameter yang cocok untuk temuan ini.", "No cached tool has compatible parameters for this finding.")}</p>`);
  }

  function select(row) {
    f.selected = row; f.tab = "overview"; const sequence = ++f.sequence;
    q("#findingDetail").innerHTML = `<div class="findingDetailHead"><div class="findingDetailLead"><div>${pill(evidenceLabels[row.evidence])}${pill(row.severity === "unknown" ? t("Belum dinilai", "Not assessed") : row.severity, row.severity)}</div><h2>${esc(row.title)}</h2><p>${esc(row.subject || row.provider)}</p><small>${esc(row.provider)}${row.timestamp ? ` | ${esc(row.timestamp)}` : ""}</small></div><button type="button" class="findingAiPrimary" data-finding-ai="${esc(row.id)}">${f.ai.has(row.id) ? t("Buka analisis AI", "Open AI analysis") : f.aiJobs.has(row.id) ? t("Lihat progres AI", "View AI progress") : t("Run AI Analysis", "Run AI Analysis")}</button></div><div class="findingDetailTabs" role="tablist"><button role="tab" aria-selected="true" data-finding-tab="overview">${t("Ringkasan", "Overview")}</button><button role="tab" aria-selected="false" data-finding-tab="evidence">${t("Bukti lokal", "Local evidence")}</button><button role="tab" aria-selected="false" data-finding-tab="intel">${t("Intelijen ancaman", "Threat intelligence")}</button><button role="tab" aria-selected="false" data-finding-tab="cve">${t("Konteks CVE", "CVE context")}</button><button role="tab" aria-selected="false" data-finding-tab="ai">AI Analyst</button></div><div class="findingTab" data-finding-panel="overview">${overview(row)}</div><div class="findingTab" data-finding-panel="evidence" hidden><div id="findingEvents" class="findingEmpty">${t("Buka tab untuk memuat bukti lokal.", "Open this tab to load local evidence.")}</div></div><div class="findingTab" data-finding-panel="intel" hidden><div id="findingProviders" class="findingEmpty">${t("Buka tab untuk memuat konsensus provider.", "Open this tab to load provider consensus.")}</div><div id="findingWorkflowTools"></div></div><div class="findingTab" data-finding-panel="cve" hidden><div id="findingCves">${section(t("Kerentanan terkait", "Referenced vulnerabilities"), cveButtons(cveIds(row.raw))) + warning(row.category === "vuln" ? t("Wazuh melaporkan CVE ini pada inventaris aset. Eksploitasi belum terkonfirmasi.", "Wazuh reported this CVE in asset inventory. Exploitation is not confirmed.") : t("Referensi CVE penyedia menjelaskan aktivitas yang dilaporkan. Paparan lokal harus dicek terpisah.", "Provider CVE references describe reported activity. Local exposure must be checked separately."))}</div></div><div class="findingTab" data-finding-panel="ai" hidden><div id="findingAiResult">${f.ai.has(row.id) ? renderFindingAi(f.ai.get(row.id)) : f.aiJobs.has(row.id) ? findingAiProgress(f.aiJobs.get(row.id)) : `<div class="findingAiEmpty"><strong>${t("Analisis terarah belum dijalankan", "Targeted analysis has not run")}</strong><p>${t("AI hanya menerima konteks terpilih yang dibatasi, bukan jutaan log mentah.", "AI receives bounded selected context, not millions of raw logs.")}</p><button type="button" class="findingAiPrimary" data-finding-ai="${esc(row.id)}">${t("Run AI Analysis", "Run AI Analysis")}</button></div>`}</div></div>`;
    document.querySelectorAll(".findingRow").forEach(el => { const selected = el.dataset.findingId === row.id; el.closest(".findingRowShell")?.classList.toggle("selected", selected); el.setAttribute("aria-pressed", String(selected)); });
    loadFeedback(row, sequence);
  }

  function overview(row) {
    const r = row.raw || {};
    let fields;
    if (row.category === "vuln") fields = field("Affected asset", labels(row.assets).join(", ")) + field("Package", r.package?.name) + field("Installed version", r.package?.version) + field("Inventory severity", r.severity) + field("Published", r.published_at) + field("Vendor advisory", r.reference);
    else if (row.category === "cyfirma") fields = field("Indicator", row.indicator) + field("Scope", row.scope) + field("Source confidence (0-100)", r.confidence) + field("Local exposure", row.raw?.local_matches?.length ? "Matched Wazuh telemetry" : "Not established") + field("Created", r.created) + field("Modified", r.modified);
    else if (row.category === "observable") fields = field(t("Indikator", "Indicator"), row.indicator) + field(t("Sumber", "Source"), row.provider) + field(t("Status bukti", "Evidence status"), t("Periksa event yang cocok di Local evidence", "Check matching events in Local evidence"));
    else fields = field("Source IP", row.ip) + field("Source address ownership", row.crowd?.as_name) + field("IP geolocation", row.crowd ? crowdLocation(row.crowd) : null) + field("Affected asset / account", labels(row.assets).join(", ")) + field("First seen", r.first_seen || r.created) + field("Last seen", row.timestamp);
    const iocFields = row.category === "cyfirma" ? section("IOC context", `<dl class="findingFields">${field("Scope", row.scope)}${field("Provider confidence (0-100)", r.confidence)}${field("Valid from", r.valid_from)}${field("Valid until", r.valid_until)}${field("STIX pattern", r.pattern)}</dl>${row.raw?.local_matches?.length ? section("Matched Wazuh indicators", `<div class="findingTags">${row.raw.local_matches.map(m => `<span class="findingTag">${esc(m.indicator)} · ${esc(m.kind)} · ${fmt.format(Number(m.occurrences || 0))} hits</span>`).join("")}</div>`) : ""}${section("Indicators", `<div class="findingTags">${chips(r.iocs)}</div>`)}${section("Kill chain phases", chips((r.kill_chain_phases || []).map(p => p.phase_name)))}`) : "";
    return section(t("Makna alert / alasan temuan", "Alert meaning / finding reason"), `<p>${esc(row.description || t("Sumber tidak memberikan deskripsi.", "Source did not provide a description."))}</p>${r.analysis ? `<p class="findingMuted">${esc(r.analysis.original)}</p><p>${esc(ax(r.analysis, "cve_context"))}</p>` : ""}${row.evidence === "intel" ? warning(t("Intelijen eksternal. Kecocokan lokal belum dibuktikan untuk record ini.", "External intelligence. No local match has been established for this record.")) : ""}`) + section("Context", `<dl class="findingFields">${fields}</dl>`) + sourceMap(row) + section(t("Klasifikasi / perilaku", "Classification / behavior"), `<div class="findingTags">${chips(row.crowd?.behaviors || row.types)}</div>`) + (row.category === "recon" ? section(t("Path sensitif yang diamati", "Observed sensitive paths"), `<div class="findingPaths">${labels(r.sensitive_paths).map(p => `<code>${esc(p)}</code>`).join("")}</div>`) : "") + iocFields + section(t("Saran tindakan analis", "Analyst recommended actions"), `<ol class="findingActions">${recommendations(row).map(item => `<li>${esc(item)}</li>`).join("")}</ol><p class="findingMuted">${t("Panduan analisis. Tidak ada tindakan pemblokiran yang dijalankan.", "Analysis guidance. No blocking action has been executed.")}</p>`) + raw(r);
  }

  function sourceMap(row) {
    const location = row.crowd?.location || {};
    const lat = Number(location.latitude), lon = Number(location.longitude);
    if (!Number.isFinite(lat) || !Number.isFinite(lon) || (!lat && !lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return "";
    const point = geoPoint({lat, lon}, 0);
    return section("Source IP geolocation", `<div class="findingGeo"><img src="/static/world-map.svg" alt="Natural Earth world basemap"><span class="findingGeoMarker" style="left:${point.x/960*100}%;top:${point.y/460*100}%" title="${esc(crowdLocation(row.crowd))}"></span></div><p class="findingMuted">${esc(crowdLocation(row.crowd))} | ${esc(row.crowd.as_name || "ASN not returned")} | ${t("Geolocation CrowdSec menjelaskan jaringan IP, bukan identitas pelaku.", "CrowdSec geolocation describes the IP network, not the attacker's identity.")}</p>`);
  }

  async function request(key, path, body) {
    let entry = f.cache.get(key);
    if (!entry || entry.expires < Date.now()) {
      entry = {expires: Date.now() + 600000, promise: postJson(path, body)};
      f.cache.set(key, entry);
      entry.promise.catch(() => f.cache.delete(key));
    }
    return entry.promise;
  }
  const intel = (kind, indicator = "") => request(`intel:${kind}:${indicator}`, "/api/findings/intel", {kind, indicator});

  async function loadEvidence(row, sequence) {
    const value = row.rule || row.operation || row.ip || row.indicator;
    const kind = row.rule ? "rule" : row.operation ? "m365" : row.ip ? "ip" : isHash(value) ? "hash" : isPublicIp(value) ? "ip" : isFullUrl(value) ? "url" : row.category === "observable" && /^[a-z\d.-]+\.[a-z]{2,}$/i.test(value || "") ? "domain" : null;
    if (!kind) { q("#findingEvents").innerHTML = row.category === "vuln" ? section(t("Bukti inventaris aset", "Asset inventory evidence"), `<dl class="findingFields">${field("Asset", row.raw.agent?.name)}${field("Package", row.raw.package?.name)}${field("Installed version", row.raw.package?.version)}${field("CVE", row.cve)}</dl>${raw(row.raw)}`) : warning(t("Pencocokan lokal otomatis tersedia untuk source IP dan file hash. Belum ada kecocokan lokal untuk tipe indikator ini.", "Automatic local matching is available for source IPs and file hashes. No local match has been checked for this indicator type.")); return; }
    try {
      const payload = window.SocWindow?.payload ? window.SocWindow.payload() : {range: els.range.value};
      const range = payload.range === "custom" ? `${payload.start} - ${payload.end}` : payload.range;
      const result = await request(`evidence:${range}:${kind}:${value}`, "/api/findings/evidence", {kind, value, ...payload});
      if (sequence !== f.sequence) return;
      q("#findingEvents").innerHTML = section(t(`${fmt.format(result.total)} event cocok`, `${fmt.format(result.total)} matching events`), `<p class="findingMuted">${esc(range)} | ${result.events.length} ${t("record terbaru", "latest records")} | fields: ${esc(result.fields_checked.join(", "))}</p>`) + (result.events.length ? result.events.map(eventCard).join("") : warning(t("Tidak ada kecocokan pada field yang dicek dan time window terpilih. Log atau window lain mungkin berisi bukti.", "No match found in the checked fields and selected time window. Other logs or time windows may contain evidence.")));
    } catch (error) { if (sequence === f.sequence) q("#findingEvents").innerHTML = warning(t(`Lookup bukti gagal: ${error.message}`, `Evidence lookup failed: ${error.message}`)); }
  }

  function eventCard(e, i) {
    const data = e.data || {}, office = data.office365 || {}, x = e.analysis;
    const ip = data.srcip || data.src_ip || office.ClientIP;
    return `<details class="findingEvent" ${i === 0 ? "open" : ""}><summary>${pill(`L${e.rule?.level ?? "?"}`, severityClass(e.rule?.level))}<span>${esc(ax(x, "title") || e.rule?.description || "Wazuh event")}<small>${esc(e["@timestamp"] || e.timestamp)} | ${esc(e.agent?.name || "manager")}</small></span></summary>${x ? `<p>${esc(ax(x, "meaning"))}</p><p class="findingMuted">${esc(x.original)}</p><dl class="findingFields">${field(t("L1 - verifikasi", "L1 - verification"), ax(x, "l1"))}${field(t("L2 - investigasi", "L2 - investigation"), ax(x, "l2"))}${field(t("Konteks CVE", "CVE context"), ax(x, "cve_context"))}</dl>` : ""}<dl class="findingFields">${field("Source IP", ip)}${field("Destination IP", data.dstip || data.dst_ip)}${field("User", office.UserId || data.srcuser || data.dstuser)}${field("Operation", office.Operation || data.action)}${field("Decoder", e.decoder?.name)}${field("Rule groups", e.rule?.groups)}${field("MITRE", e.rule?.mitre)}${field("Geo", e.GeoLocation)}</dl>${isPublicIp(ip) ? `<button type="button" data-analysis-open="${esc(ip)}">${t("Analisis sumber", "Analyze source")} ${esc(ip)}</button>` : ""}${raw(e)}</details>`;
  }

  function providerFacts(details, prefix = "", depth = 0) {
    if (!details || typeof details !== "object") return "";
    const excluded = new Set(["why", "raw_fields", "references", "behaviors", "classifications", "tags", "attack_techniques", "malware_families", "pulses", "items", "matches", "cves", "mitre_techniques", "flagged_engines"]);
    return Object.entries(details).filter(([key]) => !excluded.has(key)).map(([key, value]) => {
      const title = `${prefix}${key.replaceAll("_", " ")}`;
      if (value && typeof value === "object" && !Array.isArray(value) && depth < 2) return providerFacts(value, `${title} / `, depth + 1);
      if (Array.isArray(value)) return value.every(v => typeof v !== "object") ? field(title, value.join(", ")) : "";
      return typeof value === "object" ? "" : field(title, value);
    }).join("");
  }
  function providerCollections(data, details) {
    let html = "";
    const engines = details.flagged_engines || [];
    if (engines.length) html += section("Flagged by detection engines", `<table class="findingDataTable"><thead><tr><th>Engine</th><th>Verdict</th><th>Detection</th></tr></thead><tbody>${engines.map(e => `<tr><td>${esc(e.engine)}</td><td>${esc(e.category)}</td><td>${esc(e.result)}</td></tr>`).join("")}</tbody></table>`);
    const stats = details.analysis_stats;
    if (stats) {
      const total = Object.values(stats).reduce((sum,v) => sum + Number(v || 0), 0);
      html += section("Detection distribution", `<div class="findingDetectionBar">${Object.entries(stats).map(([key,v]) => `<span class="${esc(key)}" style="width:${total ? Number(v)/total*100 : 0}%" title="${esc(key)}: ${Number(v)}"></span>`).join("")}</div><div class="findingTags">${Object.entries(stats).map(([key,v]) => pill(`${key}: ${v}`, key === "malicious" ? "high" : "unknown")).join("")}</div>`);
    }
    if (list(data?.pulses).length) html += section("OTX pulses / campaigns", list(data.pulses).map(p => `<div class="findingCampaign"><strong>${esc(p.name || p.id || "Pulse")}</strong><p>${esc(p.description || p.adversary || "")}</p><small>${esc(label(p.author))} | ${esc(p.modified || p.created || "Date not returned")}</small><div class="findingTags">${chips([...(p.tags || []), ...(p.malware_families || []), ...(p.attack_ids || [])])}</div></div>`).join(""));
    if (list(details.matches).length) html += section("Matched CYFIRMA indicators", details.matches.map(p => `<div class="findingCampaign"><strong>${esc(p.name)}</strong><p>${esc(p.description)}</p><div class="findingTags">${chips(p.labels)}</div><small>${esc(p.scope)} | confidence ${esc(p.confidence)}</small></div>`).join(""));
    return html;
  }
  function providerBlock(name, data, error = "", subtitle = "") {
    const details = data?.detail || data || {};
    const failed = error || data?.error;
    const skipped = details.skipped;
    const verdict = data?.reputation || data?.classification || data?.risk_level;
    const status = failed ? /429|rate.limit/i.test(text(failed)) ? "API quota / rate limit" : "Unavailable" : skipped ? "Not applicable" : details.analysis_stats?.suspicious > 0 && !data?.is_malicious ? "Suspicious engine result" : verdict === "none" ? "No adverse verdict" : verdict || "Context returned";
    const types = [...list(data?.behaviors), ...list(data?.classifications), ...list(data?.tags), ...list(data?.attack_techniques), ...list(data?.malware_families)];
    const core = Object.fromEntries(Object.entries(details).filter(([key]) => ["reputation", "classification", "confidence", "background_noise", "pulse_count", "match_count", "scanned", "last_seen", "as_name", "as_owner", "country", "message", "cve_id", "cvss_score", "severity", "components", "in_kev", "known_exploited", "risk_score", "risk_label", "urgency", "epss_probability", "description"].includes(key)));
    return `<details class="findingProvider" open><summary><strong>${esc(name)}</strong>${pill(status, failed ? "medium" : data?.is_malicious || data?.reputation === "malicious" ? "high" : "unknown")}</summary><div class="findingProviderBody"><small>${esc(subtitle)}</small>${failed ? warning(text(failed)) : skipped ? warning(skipped) : `<p>${esc(data?.why || (name === "CrowdSec" && data?.reputation ? crowdReason(data) : data?.is_malicious === true ? t("Penyedia melaporkan konteks berbahaya untuk indikator ini. Validasi dampaknya pada bukti lokal.", "The provider reports adverse context for this indicator. Validate impact against local evidence.") : t("Tidak ada verdict berbahaya bukan jaminan aman. Periksa bukti, cakupan dan waktu data penyedia.", "No adverse verdict is not a safety guarantee. Check provider evidence, coverage and data timing.")))}</p><div class="findingTags">${chips(types)}</div><dl class="findingFields">${providerFacts(core)}</dl>${providerCollections(data, details)}${data?.mitre_techniques ? section("MITRE ATT&CK (provider)", chips(data.mitre_techniques)) : ""}${cveIds(data).length ? section("CVE references", cveButtons(cveIds(data))) : ""}<details class="findingRaw"><summary>${t("Detail penilaian penyedia", "Provider assessment detail")}</summary><dl class="findingFields">${providerFacts(details)}</dl></details>${raw(data)}`}</div></details>`;
  }

  async function loadIntel(row, sequence) {
    const indicator = indicatorOf(row);
    if (!indicator || (row.ip && !isPublicObservableIp(row.ip))) { q("#findingProviders").innerHTML = warning(row.ip ? t("IP internal atau tidak didukung. Lookup intelijen eksternal dilewati.", "Internal or unsupported IP. External intelligence lookup was skipped.") : t("Tidak ada indikator sumber yang didukung pada record ini. Review bukti lokal atau konteks CVE.", "No supported source indicator on this record. Review local evidence or CVE context.")); return; }
    q("#findingProviders").innerHTML = `<div class="findingIntelTarget">${esc(indicator)}</div>${section(t("Konsensus lintas provider", "Cross-provider consensus"), `<p class="findingLoading">${t("Mengambil satu hasil agregat ter-cache...", "Fetching one cached aggregate result...")}</p>`)}`;
    try {
      const result = await intel("aggregate", indicator);
      if (sequence !== f.sequence) return;
      const data = result.data || {}, results = list(data.results).filter(item => item && typeof item === "object");
      row.providerResults = results.map(item => {
        const matched = Boolean(item.is_malicious || item.matched || list(item.matches).length || ["critical","high","malicious","suspicious"].includes(String(item.risk_level || item.risk || "").toLowerCase()));
        return {provider: item.provider || "Unknown", status: item.error ? "error" : matched ? "matched" : "context", summary: text(item.summary || item.why || item.risk_level || item.classification || item.error || "Provider returned context")};
      });
      const subtitle = `${result.memory_reused ? t("Memori historis", "Historical memory") : result.cached ? t("Cache lokal", "Local cache") : t("Lookup baru", "New lookup")} · ${result.generated_at || "now"}`;
      const blocks = results.map(item => providerBlock(item.provider || "Unknown", item, item.error, subtitle)).join("");
      q("#findingProviders").innerHTML = `<div class="findingIntelTarget">${esc(indicator)}</div><div class="findingConsensusSummary"><div><span>${t("Hasil provider", "Provider results")}</span><strong>${fmt.format(results.length)}</strong></div><div><span>${t("Match berbahaya", "Adverse matches")}</span><strong>${fmt.format(row.providerResults.filter(item => item.status === "matched").length)}</strong></div><div><span>${t("Error / dilewati", "Errors / skipped")}</span><strong>${fmt.format(results.filter(item => item.error || item.detail?.skipped).length)}</strong></div><div><span>CYFIRMA</span><strong>${fmt.format(list(data.cyfirma_matches).length)}</strong></div></div>${blocks || providerBlock("Provider consensus", data, !result.ok ? result.error || result.text || "No provider result" : "", subtitle)}`;
      const crowd = results.find(item => String(item.provider || "").toLowerCase() === "crowdsec");
      if (crowd && !crowd.error) {
        row.crowd = crowd.detail || crowd;
        q('[data-finding-panel="overview"]').innerHTML = overview(row);
        const ids = cveIds(crowd);
        if (ids.length && !q("#findingCveScore")) q("#findingCves").innerHTML = section("CrowdSec CVE references", cveButtons(ids)) + warning(t("Referensi provider bukan bukti eksploitasi aset lokal.", "Provider references are not proof of local asset exploitation."));
      }
    } catch (error) {
      if (sequence === f.sequence) q("#findingProviders").innerHTML = providerBlock("Provider consensus", null, error.message);
    }
  }

  async function loadCve(cve, sequence) {
    const cveSequence = ++f.cveSequence;
    q("#findingCves").innerHTML = `<h3>${esc(cve)}</h3><div id="findingCveScore" class="findingLoading">${t("Memuat skor prioritas gabungan...", "Loading combined priority score...")}</div><div class="findingCveSources"><button type="button" data-finding-cve-source="nvd" data-cve="${esc(cve)}">NVD detail</button><button type="button" data-finding-cve-source="kev" data-cve="${esc(cve)}">CISA KEV</button><button type="button" data-finding-cve-source="poc" data-cve="${esc(cve)}">Public PoC</button></div><div id="findingCveSource"></div>`;
    try {
      const result = await intel("cve", cve);
      if (sequence !== f.sequence || cveSequence !== f.cveSequence) return;
      const data = result.data || {}, components = data.components || {}, container = q("#findingCveScore");
      container.classList.remove("findingLoading");
      container.innerHTML = result.ok ? section(t("Prioritas eksploitasi", "Exploitation priority"), `<div class="findingCveMetrics">${field("Risk score", data.risk_score)}${field("CVSS", components.cvss_base ?? components.cvss_score)}${field("EPSS probability", components.epss_probability == null ? null : `${(Number(components.epss_probability)*100).toFixed(2)}%`)}${field("CISA KEV", components.in_kev == null ? null : components.in_kev ? "Listed" : "Not listed")}${field("Public PoC", components.poc_confidence)}${field("Recommended urgency", data.urgency)}</div><p>${esc(data.recommendation || data.rationale || "Validate affected version and vendor remediation before taking action.")}</p>${raw(data)}`) : warning(result.error || result.text || "CVE lookup unavailable");
    } catch (error) {
      if (sequence === f.sequence && cveSequence === f.cveSequence) q("#findingCveScore").innerHTML = warning(error.message);
    }
  }

  async function loadCveSource(kind, cve, button) {
    const sequence = f.sequence;
    button.disabled = true;
    q("#findingCveSource").innerHTML = `<p class="findingLoading">${t("Memuat sumber terpilih...", "Loading selected source...")}</p>`;
    try {
      const result = await intel(kind, cve);
      if (sequence !== f.sequence) return;
      const data = result.data || {};
      if (!result.ok) throw new Error(result.error || result.text || "CVE source unavailable");
      if (kind === "nvd") q("#findingCveSource").innerHTML = section("NVD vulnerability record", `<p>${esc(data.description || "No description returned")}</p><dl class="findingFields">${Object.entries(data).filter(([key,value]) => !["description", "references"].includes(key) && (typeof value !== "object" || key === "weaknesses")).map(([key,value]) => field(key.replaceAll("_", " "), value)).join("")}</dl><div class="findingReferences">${list(data.references).map(record => safeLink(record.url || record, record.url || record)).join("<br>")}</div>${raw(data)}`);
      else q("#findingCveSource").innerHTML = section(kind === "kev" ? "CISA known exploited vulnerabilities" : "Public exploit references", `<dl class="findingFields">${providerFacts(data)}</dl>${kind === "poc" ? [...list(data.github_results), ...list(data.nuclei_templates)].map(record => `<div class="findingCampaign">${safeLink(record.html_url || record.url, record.full_name || record.name || record.path || record.url || "Reference")}</div>`).join("") : ""}${raw(data)}`);
    } catch (error) { if (sequence === f.sequence) q("#findingCveSource").innerHTML = warning(error.message); }
    finally { button.disabled = false; }
  }

  function renderHealth() {
    const providers = state.providerTests?.providers || [];
    q("#findingHealth").innerHTML = providers.map(p => `<div><strong>${esc(p.provider)}</strong>${pill(p.ok ? "Connected" : "Attention", p.ok ? "low" : "medium")}<small>${esc(p.ok ? "Connection test; not a local finding" : p.error || p.summary)}</small></div>`).join("") + Object.entries(f.feeds).map(([scope,r]) => `<div><strong>CYFIRMA ${esc(scope)}</strong>${pill(r.ok ? "Feed loaded" : "Unavailable", r.ok ? "low" : "medium")}<small>${esc(r.ok ? `${r.data?.items?.length || 0} shown / ${r.data?.summary?.count || 0} reported` : r.error || "No feed data")}</small></div>`).join("");
  }
  async function loadAiOperations() {
    const container = q("#findingAiOperations");
    if (!container) return;
    try {
      const data = await postJson("/api/findings/ai-jobs", {limit: 8});
      const counts = data.counts || {}, recent = list(data.recent);
      container.innerHTML = `<div class="findingAiOpsMetrics"><div><span>${t("Dalam antrean", "Queued")}</span><strong>${fmt.format(Number(counts.queued || 0))}</strong><small>${t("job menunggu worker", "jobs waiting for worker")}</small></div><div><span>${t("Sedang diproses", "Processing")}</span><strong>${fmt.format(Number(counts.processing || 0))}</strong><small>${t("satu worker terkontrol", "one controlled worker")}</small></div><div><span>${t("Rata-rata selesai", "Average completion")}</span><strong>${Number(data.average_completed_seconds || 0).toFixed(1)}s</strong><small>${t("latency job tersimpan", "stored job latency")}</small></div><div><span>${t("Kapasitas antrean", "Queue capacity")}</span><strong>${fmt.format(Number(counts.queued || 0) + Number(counts.processing || 0))} / ${fmt.format(Number(data.queue_limit || 0))}</strong><small>${t(`lease ${data.lease_seconds || 300} detik`, `${data.lease_seconds || 300}s lease`)}</small></div></div>${recent.length ? `<table class="findingAiOpsTable"><thead><tr><th>${t("Temuan", "Finding")}</th><th>${t("Skill", "Skill")}</th><th>${t("Status", "Status")}</th><th>${t("Durasi", "Duration")}</th><th>${t("Aksi", "Action")}</th></tr></thead><tbody>${recent.map(job => `<tr><td>${esc(job.finding_id)}</td><td>${esc(job.profile || "generic")}<br><small>${t("percobaan", "attempt")} ${Number(job.attempts || 0)}</small></td><td>${pill(job.status, job.status === "completed" ? "low" : job.status === "failed" ? "high" : "medium")}${job.error ? `<br><small>${esc(job.error)}</small>` : ""}</td><td>${Number(job.duration_seconds || 0).toFixed(1)}s</td><td>${job.status === "failed" ? `<button type="button" data-finding-ai-job-retry="${esc(job.job_id)}">${t("Coba lagi", "Retry")}</button>` : "-"}</td></tr>`).join("")}</tbody></table>` : `<p class="findingMuted">${t("Belum ada job AI per temuan.", "No per-finding AI jobs recorded yet.")}</p>`}`;
    } catch (error) {
      container.innerHTML = warning(t(`Status AI tidak tersedia: ${error.message}`, `AI status unavailable: ${error.message}`));
    }
  }
  async function loadFeeds() {
    try {
      const stored = await postJson("/api/intelligence/cyfirma", { ...currentWindowPayload(), limit: 1 });
      f.feeds = {};
      for (const scope of ["tailored", "global"]) {
        const items = (stored.items || []).filter(item => item.scope === scope);
        const feed = (stored.feed_status || []).find(item => item.scope === scope);
        f.feeds[scope] = {ok: Boolean(feed) && feed.status !== "error", stored: true,
          error: feed?.detail?.error,
          data: {items, next_offset: null, summary: {count: scope === "tailored" ? stored.summary?.tailored : stored.summary?.global}}};
      }
    } catch (e) {
      f.feeds = {stored: {ok: false, error: e.message, data: {items: [], summary: {count: 0}}}};
    }
    buildRows();
  }
  function aiList(title, values) {
    const rows = list(values).filter(Boolean);
    return rows.length ? section(title, `<ul class="findingAiList">${rows.map(item => `<li>${esc(typeof item === "object" ? item.detail || item.reason || item.signal || JSON.stringify(item) : item)}</li>`).join("")}</ul>`) : "";
  }
  function renderFindingAiBody(payload) {
    const result = payload?.result || {}, verdict = result.verdict || {}, actions = result.actions || {};
    const providers = list(result.provider_consensus);
    const cves = list(result.cves);
    const flow = result.network_flow || {};
    const flowSection = Object.keys(flow).length ? section(t("Arah serangan", "Attack direction"), `<dl class="findingFields">${field(t("Kategori", "Category"), result.attack_category)}${field("Source", flow.source)}${field("Destination", flow.destination)}${field("Direction", flow.direction)}${field("Protocol / ports", [flow.protocol, flow.ports].filter(Boolean).join(" / "))}${field("Action", flow.action)}${field("Evidence", list(flow.evidence).join(", "))}</dl>`) : "";
    return `<div class="findingAiAssessment"><div class="findingAiVerdict"><div><span>${t("AI ANALYST · ADVISORY", "AI ANALYST · ADVISORY")}</span><strong>${esc(verdict.status || "needs_review")}</strong><small>${esc(`${verdict.severity || "unknown"} severity · ${verdict.confidence || "low"} confidence`)}</small></div><div><span>${t("MODEL", "MODEL")}</span><strong>${esc(payload.model || "local fallback")}</strong><small>${esc(payload.cache?.status === "hit" ? t("Hasil tersimpan", "Stored result") : `${payload.elapsed_seconds || 0}s`)}</small></div></div><p class="findingAiSummary">${esc(result.summary || t("Tidak ada ringkasan AI.", "No AI summary returned."))}</p>${verdict.reason ? warning(verdict.reason) : ""}${flowSection}${aiList(t("Fakta sumber", "Source facts"), result.source_facts)}${aiList(t("Aktivitas identitas", "Identity activity"), result.identity_activity)}${aiList(t("Dampak data", "Data impact"), result.data_impact)}${section(t("Inferensi analis", "Analyst inference"), `<p>${esc(result.inference || "-")}</p>`)}${providers.length ? section(t("Konsensus provider", "Provider consensus"), `<div class="findingConsensus">${providers.map(p => `<article><strong>${esc(p.provider || "Unknown")}</strong>${pill(p.status || "unknown", /match|malicious/i.test(p.status || "") ? "high" : /error/i.test(p.status || "") ? "medium" : "unknown")}<p>${esc(p.signal || "No provider detail")}</p></article>`).join("")}</div>`) : ""}${cves.length ? section(t("Penilaian CVE", "CVE assessment"), `<div class="findingCveAi">${cves.map(c => `<article><strong>${esc(c.cve || "CVE")}</strong><span>${esc(c.relationship || "referenced")} · ${esc(c.local_exposure || "not verified")}</span><p>${esc(c.reason || "")}</p></article>`).join("")}</div>`) : ""}${["l1","l2","l3","response"].map(lane => aiList(`${lane.toUpperCase()} ${t("tindakan", "actions")}`, actions[lane])).join("")}${aiList(t("Quality checks", "Quality checks"), result.quality_checks)}${aiList(t("Kesenjangan bukti", "Evidence gaps"), result.gaps)}<p class="findingMuted">${t("Hasil AI bersifat advisory. Validasi bukti asli sebelum containment.", "AI output is advisory. Validate original evidence before containment.")}</p></div>`;
  }
  function renderFindingAi(payload) {
    const profile = payload?.analysis_profile;
    const contract = payload?.contract || payload?.result?.contract;
    const memory = payload?.memory || {};
    const metadata = (profile || contract) ? `<p class="findingMuted"><strong>${t("Kontrak analis", "Analyst contract")}:</strong> ${esc(contract?.id || "senior-soc-ai")} · v${esc(contract?.version || payload?.contract_version || "unknown")} · ${esc(contract?.validation_status || "valid")}${profile ? ` · ${esc(profile.id)} / ${esc(profile.version)}` : ""} · ${t("memory", "memory")} ${Number(memory.previous_assessments || 0) + Number(memory.indicator_history || 0) + Number(memory.analyst_feedback || 0)}</p>` : "";
    return metadata + renderFindingAiBody(payload) + findingFeedback(f.selected);
  }
  function findingFeedback(row) {
    if (!row) return "";
    const items = f.feedback.get(row.id) || [];
    const latest = items[0] || {};
    const options = [["needs_review", t("Perlu review", "Needs review")], ["true_positive", t("True positive", "True positive")], ["false_positive", t("False positive", "False positive")], ["expected_activity", t("Aktivitas wajar", "Expected activity")], ["escalated", t("Eskalasi ke insiden", "Escalate to incident")]];
    const history = items.length ? `<details class="findingRaw"><summary>${t("Riwayat keputusan analis", "Analyst decision history")} (${items.length})</summary><ol class="findingFeedbackHistory">${items.map(item => `<li><strong>${esc(item.disposition.replaceAll("_", " "))}</strong><span>${esc(new Date(Number(item.created) * 1000).toLocaleString())}</span><p>${esc(item.note || t("Tanpa catatan", "No note"))}</p></li>`).join("")}</ol></details>` : `<p class="findingMuted">${t("Belum ada keputusan analis untuk temuan ini.", "No analyst decision has been recorded for this finding.")}</p>`;
    const canSync = Boolean(row.ip || (row.category === "ip" && row.indicator));
    return `<section class="findingSection findingFeedback"><h3>${t("Keputusan analis", "Analyst disposition")}</h3><form data-finding-feedback="${esc(row.id)}"><label>${t("Disposition", "Disposition")}<select name="disposition">${options.map(([value, label]) => `<option value="${value}" ${latest.disposition === value ? "selected" : ""}>${esc(label)}</option>`).join("")}</select></label><label>${t("Catatan bukti", "Evidence note")}<textarea name="note" maxlength="1000" rows="3" placeholder="${esc(t("Tuliskan alasan berdasarkan bukti, bukan asumsi", "Record evidence-based reasoning, not assumptions"))}"></textarea></label><label class="findingFeedbackSync"><input type="checkbox" name="sync_case" ${canSync ? "checked" : "disabled"}> <span>${canSync ? t("Sinkronkan ke persistent case dan investigation memory", "Sync to persistent case and investigation memory") : t("Sinkronisasi case memerlukan source IP", "Case synchronization requires a source IP")}</span></label><div><button type="submit">${t("Simpan keputusan", "Save decision")}</button><button type="button" data-finding-ai-rerun="${esc(row.id)}">${t("Analisis ulang dengan memory", "Re-run AI with memory")}</button></div><p role="status" aria-live="polite"></p></form>${history}</section>`;
  }
  async function loadFeedback(row, sequence) {
    try {
      const data = await postJson("/api/findings/feedback/history", {finding_id: row.id, limit: 10});
      if (sequence !== f.sequence) return;
      f.feedback.set(row.id, list(data.items));
      if (f.ai.has(row.id) && f.tab === "ai") q("#findingAiResult").innerHTML = renderFindingAi(f.ai.get(row.id));
    } catch (_) {}
  }
  function findingAiProgress(job = {}) {
    const processing = job.status === "processing";
    const seconds = Math.max(0, Math.round(Number(job.elapsed_seconds || 0)));
    return `<div class="findingAiLoading" role="status" aria-live="polite"><span></span><div><strong>${processing ? t("Senior analyst sedang mengorelasikan temuan", "Senior analyst is correlating the finding") : t("Analisis masuk antrean", "Analysis queued")}</strong><p>${processing ? t("Memeriksa bukti lokal, memory, provenance provider, CVE, confidence, dan tindakan SOC.", "Reviewing local evidence, memory, provider provenance, CVEs, confidence, and SOC actions.") : t("Temuan tersimpan dan akan diproses saat AI worker tersedia.", "The finding is stored and will run when the AI worker is available.")} ${seconds ? `${seconds}s` : ""}</p></div></div>`;
  }
  function findingAiPayload(row) {
    const windowPayload = window.SocWindow?.payload ? window.SocWindow.payload() : {range: els.range.value};
    return {id: row.id, category: row.category, title: row.title, subject: row.subject, severity: row.severity,
      evidence: row.evidence, provider: row.provider, indicator: row.indicator, ip: row.ip, cve: row.cve,
      rule: row.rule, operation: row.operation, count: row.count, assets: labels(row.assets), types: labels(row.types),
      description: row.description, timestamp: row.timestamp, provider_results: row.providerResults || [],
      cyfirma: row.category === "cyfirma" ? row.raw : undefined,
      vulnerability: row.category === "vuln" ? row.raw : undefined,
      recommendations: recommendations(row), ...windowPayload};
  }
  async function runFindingAi(row, button, force = false) {
    select(row); changeTab("ai");
    if (force) { f.ai.delete(row.id); f.aiJobs.delete(row.id); }
    if (f.ai.has(row.id)) { q("#findingAiResult").innerHTML = renderFindingAi(f.ai.get(row.id)); return; }
    const existing = f.aiJobs.get(row.id);
    if (existing?.job_id) { q("#findingAiResult").innerHTML = findingAiProgress(existing); return; }
    document.querySelectorAll(`[data-finding-ai="${CSS.escape(row.id)}"]`).forEach(el => { el.disabled = true; el.setAttribute("aria-busy", "true"); el.textContent = t("Mengantrekan...", "Queuing..."); });
    q("#findingAiResult").innerHTML = findingAiProgress({status: "queued"});
    try {
      const queued = await postJson("/api/findings/ai-analysis", {finding: findingAiPayload(row), async: true, force});
      if (queued.status === "completed") {
        f.ai.set(row.id, queued);
      } else if (queued.job_id && ["queued", "processing"].includes(queued.status)) {
        f.aiJobs.set(row.id, queued);
        void pollFindingAi(row, queued.job_id);
      } else {
        throw new Error(queued.error || queued.status || "AI analysis failed");
      }
      void loadAiOperations();
      if (f.selected?.id === row.id) q("#findingAiResult").innerHTML = f.ai.has(row.id) ? renderFindingAi(f.ai.get(row.id)) : findingAiProgress(f.aiJobs.get(row.id));
      renderList();
    } catch (error) {
      q("#findingAiResult").innerHTML = warning(t(`Analisis AI gagal: ${error.message}`, `AI analysis failed: ${error.message}`));
    } finally {
      document.querySelectorAll(`[data-finding-ai="${CSS.escape(row.id)}"]`).forEach(el => { el.disabled = false; el.removeAttribute("aria-busy"); });
    }
  }
  async function pollFindingAi(row, jobId) {
    for (let attempt = 0; attempt < 300 && f.aiJobs.get(row.id)?.job_id === jobId; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 2000));
      try {
        const job = await postJson("/api/findings/ai-status", {job_id: jobId});
        if (job.status === "completed" && job.result?.status === "completed") {
          f.ai.set(row.id, job.result); f.aiJobs.delete(row.id); renderList();
          void loadAiOperations();
          if (f.selected?.id === row.id) { select(f.rows.find(item => item.id === row.id) || row); changeTab("ai"); }
          return;
        }
        if (["failed", "not_found"].includes(job.status)) throw new Error(job.error || "AI analysis failed");
        f.aiJobs.set(row.id, job);
        if (f.selected?.id === row.id && f.tab === "ai") q("#findingAiResult").innerHTML = findingAiProgress(job);
      } catch (error) {
        f.aiJobs.delete(row.id);
        if (f.selected?.id === row.id) q("#findingAiResult").innerHTML = warning(t(`Analisis AI gagal: ${error.message}`, `AI analysis failed: ${error.message}`));
        renderList(); return;
      }
    }
  }
  function changeTab(tab) {
    f.tab = tab;
    document.querySelectorAll("[data-finding-panel]").forEach(el => el.hidden = el.dataset.findingPanel !== tab);
    document.querySelectorAll("[data-finding-tab]").forEach(el => el.setAttribute("aria-selected", String(el.dataset.findingTab === tab)));
    const panel = q(`[data-finding-panel="${tab}"]`);
    if (!f.selected || !panel || panel.dataset.loaded === "true") return;
    if (tab === "evidence") {
      panel.dataset.loaded = "true";
      void loadEvidence(f.selected, f.sequence);
    } else if (tab === "intel") {
      panel.dataset.loaded = "true";
      renderFindingWorkflows(f.selected);
      void loadIntel(f.selected, f.sequence);
    } else if (tab === "cve" && f.selected.cve) {
      panel.dataset.loaded = "true";
      void loadCve(f.selected.cve, f.sequence);
    }
  }
  document.addEventListener("click", event => {
    const workflow = event.target.closest("[data-finding-workflow]");
    if (workflow) {
      const row = f.selected;
      const tool = state.tools.find(item => item.source === workflow.dataset.toolSource && item.name === workflow.dataset.toolName);
      if (!row || !tool || !window.SocWorkflows) return;
      const args = findingWorkflowArgs(tool, row);
      if (!args) return;
      const key = workflow.dataset.findingWorkflow;
      f.workflowResults.set(key, {status: "running"});
      renderFindingWorkflows(row);
      window.SocWorkflows.run(tool, args, message => {
        f.workflowResults.set(key, {status: "running", message});
        if (f.selected?.id === row.id) renderFindingWorkflows(row);
      }).then(result => {
        f.workflowResults.set(key, {status: "completed", result});
        if (f.selected?.id === row.id) renderFindingWorkflows(row);
      }).catch(error => {
        f.workflowResults.set(key, {status: "failed", error: error.message});
        if (f.selected?.id === row.id) renderFindingWorkflows(row);
      });
      return;
    }
    const cveSource = event.target.closest("[data-finding-cve-source]");
    if (cveSource) { void loadCveSource(cveSource.dataset.findingCveSource, cveSource.dataset.cve, cveSource); return; }
    const jobRetry = event.target.closest("[data-finding-ai-job-retry]");
    if (jobRetry) {
      jobRetry.disabled = true;
      postJson("/api/findings/ai-retry", {job_id: jobRetry.dataset.findingAiJobRetry}).then(loadAiOperations).catch(error => { q("#findingAiOperations").innerHTML = warning(error.message); });
      return;
    }
    const rerun = event.target.closest("[data-finding-ai-rerun]");
    if (rerun) { const row = f.rows.find(r => r.id === rerun.dataset.findingAiRerun); if (row) runFindingAi(row, rerun, true); return; }
    const ai = event.target.closest("[data-finding-ai]");
    if (ai) { const row = f.rows.find(r => r.id === ai.dataset.findingAi); if (row) runFindingAi(row, ai); return; }
    const ioc = event.target.closest("[data-finding-ioc-record]");
    if (ioc) {
      const record = JSON.parse(ioc.dataset.findingIocRecord);
      const row = {id: `tool:${record.id || record.name}`, category: "observable", provider: "CYFIRMA", title: record.name || record.iocs?.[0] || "IOC", subject: record.iocs?.[0], indicator: record.iocs?.[0], severity: "unknown", evidence: "intel", description: record.description, types: record.labels, scope: record.scope, raw: record};
      if (!f.rows.some(r => r.id === row.id)) f.rows.push(row);
      f.category = "all"; q("#findingSearch").value = ""; q("#findingEvidence").value = "all"; q("#findingSeverity").value = "all";
      setView("findings"); select(row); renderList(); return;
    }
    const category = event.target.closest("[data-finding-category]");
    if (category) { f.category = category.dataset.findingCategory; f.page = 0; renderList(); return; }
    const row = event.target.closest("[data-finding-id]");
    if (row) { const record = f.rows.find(r => r.id === row.dataset.findingId); if (record) select(record); return; }
    const page = event.target.closest("[data-finding-page]");
    if (page) { f.page += Number(page.dataset.findingPage); renderList(); return; }
    const tab = event.target.closest("[data-finding-tab]");
    if (tab) { changeTab(tab.dataset.findingTab); return; }
    const cve = event.target.closest("[data-finding-cve]");
    if (cve) { changeTab("cve"); loadCve(cve.dataset.findingCve, f.sequence); }
  });
  document.addEventListener("submit", async event => {
    const form = event.target.closest("[data-finding-feedback]");
    if (!form) return;
    event.preventDefault();
    const row = f.rows.find(item => item.id === form.dataset.findingFeedback);
    if (!row) return;
    const submit = form.querySelector('button[type="submit"]');
    const status = form.querySelector('[role="status"]');
    submit.disabled = true; status.textContent = t("Menyimpan keputusan...", "Saving decision...");
    try {
      const aiResult = f.ai.get(row.id)?.result || {};
      const data = await postJson("/api/findings/feedback", {finding_id: row.id, disposition: form.elements.disposition.value,
        note: form.elements.note.value, finding: findingAiPayload(row), sync_case: Boolean(form.elements.sync_case?.checked),
        ai_advisory: {verdict: aiResult.verdict || {}, summary: String(aiResult.summary || "").slice(0, 500)}});
      if (!data.ok) throw new Error(data.error || "Feedback was not saved");
      f.feedback.set(row.id, [data.feedback, ...(f.feedback.get(row.id) || [])].slice(0, 10));
      if (f.selected?.id === row.id) q("#findingAiResult").innerHTML = renderFindingAi(f.ai.get(row.id));
      const sync = data.case_sync;
      const message = sync?.ok ? t(`Keputusan tersimpan dan ditautkan ke ${sync.case_id}.`, `Decision saved and linked to ${sync.case_id}.`) :
        sync?.skipped ? t(`Keputusan tersimpan; case dilewati: ${sync.reason}.`, `Decision saved; case skipped: ${sync.reason}.`) :
        sync?.error ? t(`Keputusan tersimpan; sinkronisasi case gagal: ${sync.error}.`, `Decision saved; case sync failed: ${sync.error}.`) :
        t("Keputusan tersimpan.", "Decision saved.");
      const currentStatus = q(`[data-finding-feedback="${CSS.escape(row.id)}"] [role="status"]`);
      if (currentStatus) currentStatus.textContent = message;
    } catch (error) {
      status.textContent = t(`Gagal menyimpan: ${error.message}`, `Save failed: ${error.message}`);
    } finally {
      submit.disabled = false;
    }
  });
  for (const id of ["findingSearch", "findingEvidence", "findingSeverity"]) q(`#${id}`).addEventListener(id === "findingSearch" ? "input" : "change", () => { f.page = 0; renderList(); });
  q("#findingAiOperationsRefresh")?.addEventListener("click", loadAiOperations);
  document.addEventListener("soc:overview", e => { f.data = e.detail; f.coverage = null; f.selected = null; f.pivots.clear(); f.cache.clear(); buildRows(); loadFeeds(); loadAiOperations(); });
  document.addEventListener("soc:intel", () => { if (f.data) buildRows(); });
  document.addEventListener("soc:automation", () => { if (f.data) buildRows(); });
  setInterval(() => { if (q("#findingsView")?.classList.contains("active")) loadAiOperations(); }, 15000);
  viewTitles.findings = "Security Findings";
  window.SocFindings = {
    renderProvider: providerBlock,
    setCoverage(data) { f.coverage = data; buildRows(); },
    open(kind, value, inventoryRecord = null) {
      let row = f.rows.find(r => kind === "rule" ? String(r.rule) === String(value) : kind === "recon" ? r.category === "recon" && r.ip === value : indicatorOf(r) === value);
      if (!row && kind === "rule") {
        row = {id: `rule-pivot:${value}`, category: "wazuh", provider: "Wazuh index", title: `Rule ${value}`, rule: String(value), severity: "unknown", evidence: "pending", description: t("Memeriksa event untuk rule terpilih.", "Checking events for the selected rule."), raw: {rule_id: String(value)}};
        f.pivots.set(row.id, row);
      }
      if (kind === "cve" && inventoryRecord) row = {id: `inventory:${value}:${inventoryRecord.agent?.id}`, category: "vuln", provider: "Wazuh inventory", title: value, subject: inventoryRecord.package?.name, cve: value, severity: String(inventoryRecord.vulnerability?.severity || "unknown").toLowerCase(), evidence: "inventory", description: inventoryRecord.vulnerability?.description, assets: [inventoryRecord.agent?.name].filter(Boolean), types: [inventoryRecord.package?.name].filter(Boolean), raw: inventoryRecord};
      if (!row && kind === "ip") row = {id: `pivot:${value}`, category: "ip", title: value, ip: value, provider: "Wazuh index", evidence: "observed", severity: "unknown", description: t("Indikator ditemukan pada agregasi field log Wazuh. Periksa bukti lokal dan hasil intelijen.", "Indicator found in Wazuh log field aggregation. Review local evidence and intelligence results."), raw: {ip: value}};
      if (!row && kind === "cve") row = {id: `pivot-cve:${value}`, category: "vuln", title: value, cve: value, provider: "Wazuh inventory", evidence: "inventory", severity: "unknown", description: t("CVE dipilih dari ringkasan prioritas. Periksa inventaris aset dan konteks NVD/EPSS/KEV/PoC sebelum patch.", "CVE selected from the priority brief. Review asset inventory and NVD/EPSS/KEV/PoC context before patching."), raw: {cve: value}};
      if (!row && kind === "indicator") row = {id: `pivot:${value}`, category: "observable", title: value, indicator: value, provider: "Wazuh index", evidence: "observed", severity: "unknown", description: t("Indikator diekstrak dari field log. Hubungan dengan intelijen belum terverifikasi.", "Indicator extracted from log fields. The relationship with intelligence has not been verified."), raw: {indicator: value}};
      if (!row) return false;
      if (row.id.startsWith("pivot:")) {
        const observed = f.coverage?.observables?.some(r => r.indicator === value);
        row.evidence = observed ? "observed" : "pending";
        row.provider = observed ? "Wazuh index" : "Analyst pivot";
        if (!observed) row.description = t("Indikator dipilih untuk investigasi. Kecocokan dalam log lokal belum diverifikasi; periksa Local evidence.", "Indicator selected for investigation. A local log match has not been verified; check Local evidence.");
        f.pivots.set(row.id, row);
      }
      f.category = "all"; q("#findingSearch").value = ""; q("#findingEvidence").value = "all"; q("#findingSeverity").value = "all";
      if (!f.rows.some(r => r.id === row.id)) f.rows.push(row);
      f.page = Math.floor(f.rows.findIndex(r => r.id === row.id) / 12);
      setView("findings"); select(row); renderList();
      if (row.id.startsWith("rule-pivot:")) changeTab("evidence");
      return true;
    },
  };
  document.addEventListener("soc:language", () => {
    const selectedId = f.selected?.id;
    if (f.data) buildRows();
    else renderList();
    const row = f.rows.find(item => item.id === selectedId) || f.selected;
    if (row) select(row);
  });
  setView("findings");
})();
