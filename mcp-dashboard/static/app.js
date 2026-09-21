const state = {
  overview: null,
  settings: null,
  tools: [],
  toolSummary: {},
  categories: {},
  selected: null,
  incidents: [],
  l1Queue: [],
  persistentCases: [],
  selectedIncident: 0,
  filter: "all",
  category: "all",
  view: "command",
  mapMode: "geo",
  mapLimit: 16,
  mapZoom: 1,
  providerTests: null,
  providerTestsLoading: false,
  crowdSecIntel: null,
  crowdSecLoading: false,
  crowdSecRequestId: 0,
  overviewRefreshTimer: null,
  cveExposure: null,
  cveExposureLoading: false,
};

const newNames = new Set([
  "blueteam_ai_bot_recon",
  "blueteam_cve_lookup",
  "blueteam_cve_epss",
  "blueteam_cve_kev",
  "blueteam_cve_poc",
  "blueteam_cve_score",
  "blueteam_cve_ssvc",
  "blueteam_cve_advisory",
  "blueteam_cve_attack_mapping",
  "blueteam_dependency_scan",
  "blueteam_document_convert",
  "blueteam_investigate_ip",
]);

const viewTitles = {
  history: "Event History",
  command: "Command",
  workbench: "SOC Workbench",
  l1: "L1 Triage",
  l2: "L2 Investigate",
  incidents: "Incidents",
  l3: "L3 Hunt",
  vuln: "Vulnerabilities",
  assets: "Assets",
  tools: "Tool Console",
  settings: "Settings",
};

const q = (selector) => document.querySelector(selector);
const fmt = new Intl.NumberFormat("en-US");
const palette = ["#58d5f6", "#4de2a6", "#f7c76c", "#ff6b8a", "#a78bfa", "#7dd3fc"];
function ui(id, en) { return window.SocLocale?.t ? window.SocLocale.t(id, en) : en; }
function ax(analysis, field) { return window.SocLocale?.analysis ? window.SocLocale.analysis(analysis, field) : (analysis?.[field] || ""); }

const els = {
  status: q("#status"),
  title: q("#pageTitle"),
  dot: q("#connectionDot"),
  connectionText: q("#connectionText"),
  sideMeta: q("#sideMeta"),
  refresh: q("#refreshBtn"),
  range: q("#rangeSelect"),
  dateRange: q("#dateRangeControls"),
  globalStart: q("#globalStart"),
  globalEnd: q("#globalEnd"),
  search: q("#searchInput"),
  categorySelect: q("#categorySelect"),
  list: q("#toolList"),
  run: q("#runBtn"),
  args: q("#argsInput"),
  result: q("#resultBox"),
  toolName: q("#toolName"),
  toolSource: q("#toolSource"),
  toolMeta: q("#toolMeta"),
  incidentBoard: q("#incidentBoard"),
  incidentDetail: q("#incidentDetail"),
  settingsForm: q("#settingsForm"),
  settingsFields: q("#settingsFields"),
  settingsStatus: q("#settingsStatus"),
  saveSettings: q("#saveSettingsBtn"),
  resetSettings: q("#resetSettingsBtn"),
  testM365: q("#testM365Btn"),
  startM365: q("#startM365Btn"),
  m365TestResult: q("#m365TestResult"),
  testIntel: q("#testIntelBtn"),
  intelTestStatus: q("#intelTestStatus"),
  providerIntelGrid: q("#providerIntelGrid"),
  crowdSecStatus: q("#crowdSecStatus"),
  crowdSecPanel: q("#crowdSecPanel"),
  cveInput: q("#cveInput"),
  cveBtn: q("#cveBtn"),
  cveResult: q("#cveResult"),
};

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[char]));
}

function setText(selector, value) {
  const el = q(selector);
  if (el) el.textContent = value;
}

function setHtml(selector, html) {
  const el = q(selector);
  if (el) el.innerHTML = html;
}

function number(value) {
  const n = Number(value || 0);
  return Number.isFinite(n) ? n : 0;
}

function severityClass(level) {
  if (level >= 15) return "critical";
  if (level >= 12) return "high";
  if (level >= 7) return "medium";
  return "low";
}

function severityLabel(level) {
  if (level >= 15) return "Critical";
  if (level >= 12) return "High";
  if (level >= 7) return "Medium";
  return "Low";
}

function capCount(caps, key) {
  const value = caps?.[key];
  if (typeof value === "number") return value;
  return number(value?.count);
}

function humanRange(value) {
  if (value === "custom") return ui("rentang kustom", "custom range");
  const en = {
    "24h": "24 hours",
    "7d": "7 days",
    "30d": "30 days",
  }[value] || "24 hours";
  return ui({"24 hours":"24 jam","7 days":"7 hari","30 days":"30 hari"}[en] || "24 jam", en);
}

function toDatetimeLocal(date) {
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function initDateRange() {
  if (!els.globalStart || !els.globalEnd) return;
  const end = new Date();
  const start = new Date(end.getTime() - 24 * 60 * 60 * 1000);
  if (!els.globalStart.value) els.globalStart.value = toDatetimeLocal(start);
  if (!els.globalEnd.value) els.globalEnd.value = toDatetimeLocal(end);
}

function currentWindowPayload() {
  const range = els.range?.value || "24h";
  if (range !== "custom") return { range };
  initDateRange();
  const start = els.globalStart?.value ? new Date(els.globalStart.value) : null;
  const end = els.globalEnd?.value ? new Date(els.globalEnd.value) : null;
  if (!start || !end || Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start >= end) {
    throw new Error(ui("Rentang tanggal tidak valid.", "Invalid date range."));
  }
  return { range: "custom", start: start.toISOString(), end: end.toISOString() };
}

function currentRangeLabel(overview) {
  if (overview?.window?.range === "custom") {
    const start = new Date(overview.window.bounds?.gte);
    const end = new Date(overview.window.bounds?.lt);
    if (!Number.isNaN(start.getTime()) && !Number.isNaN(end.getTime())) {
      return `${start.toLocaleString()} - ${end.toLocaleString()}`;
    }
  }
  return humanRange(overview?.requested_range || els.range?.value || "24h");
}

function clientOverviewKey(payload) {
  const keyPayload = { schema: 2, ...(payload || {}) };
  delete keyPayload.force;
  return `soc-overview:${JSON.stringify(keyPayload)}`;
}

function readClientOverview(payload) {
  try {
    const raw = localStorage.getItem(clientOverviewKey(payload));
    if (!raw) return null;
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

function writeClientOverview(payload, overview) {
  try {
    localStorage.setItem(clientOverviewKey(payload), JSON.stringify(overview));
  } catch (_) {}
}

function syncDateRangeVisibility() {
  if (!els.dateRange) return;
  els.dateRange.hidden = (els.range?.value || "24h") !== "custom";
  if (!els.dateRange.hidden) initDateRange();
}

window.SocWindow = {
  payload: currentWindowPayload,
  label: currentRangeLabel,
};

function defaultArgs(tool) {
  if (!tool) return {};
  if (tool.default_arguments && Object.keys(tool.default_arguments).length) {
    return JSON.parse(JSON.stringify(tool.default_arguments));
  }
  if (tool.name === "advanced_three_sum_correlation") {
    return { lookback_minutes: 60, threshold_score: 35 };
  }
  if (tool.name === "get_top_security_threats") {
    return { hours_back: 24, limit: 10 };
  }
  if (tool.name === "get_wazuh_alert_summary") {
    return { hours_back: 24 };
  }
  if (tool.name === "blueteam_ai_bot_recon") {
    return { since: "24h", top_n: 10, response_format: "json" };
  }
  if (tool.name === "blueteam_wazuh_geo_heatmap") {
    return { since: "24h", top_n: 30, response_format: "json" };
  }
  if (tool.name === "blueteam_wazuh_syscheck") {
    return { since: "24h", top_n: 20, response_format: "json" };
  }
  if (tool.name === "blueteam_failed_logins") {
    return { bypass_redaction: false };
  }
  if (tool.name === "blueteam_read_web_log") {
    return { server: "nginx", log_type: "access", lines: 300, grep: "DVWA|.env|wp-|php|select|union|cmd|shell|passwd", bypass_redaction: false };
  }
  if (tool.name === "blueteam_investigate_ip") {
    return { srcip: "8.8.8.8", since: "24h", response_format: "markdown" };
  }
  if (tool.name === "wazuh_alert_timeline") {
    return { params: { since: "24h", bucket: "auto", response_format: "json" } };
  }
  if (tool.name === "blueteam_cve_lookup" || tool.name === "blueteam_cve_score") {
    return { cve_id: "CVE-2024-6387", response_format: "json" };
  }
  if (tool.name === "blueteam_dependency_scan") {
    return { raw_text: "requests==2.28.0\nlog4j-core:2.14.1", response_format: "json" };
  }
  return {};
}

function firstNonEmpty(...values) {
  for (const value of values) {
    if (Array.isArray(value) && value.length) return value[0];
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return "";
}

function contextualArgs(tool, base = defaultArgs(tool)) {
  const args = JSON.parse(JSON.stringify(base || {}));
  if (!tool) return args;

  const destructive = /(block|isolate|kill|disable|quarantine|active_response|firewall_drop|host_deny|restart|allow|restore|enable|unban)/i;
  if (destructive.test(tool.name || "")) return args;

  const overview = state.overview || {};
  const fields = new Set((tool.schema_fields || []).map((field) => field.name));
  const accepts = (name) => Object.prototype.hasOwnProperty.call(args, name) || fields.has(name);
  const empty = (value) =>
    value === undefined ||
    value === null ||
    value === "" ||
    (Array.isArray(value) && value.length === 0) ||
    (typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0);
  const fill = (name, value) => {
    if (accepts(name) && empty(args[name]) && value !== undefined && value !== null && value !== "") args[name] = value;
  };
  const fillAny = (names, value) => names.forEach((name) => fill(name, value));
  const fillArray = (name, value) => {
    if (accepts(name) && empty(args[name]) && value) args[name] = [value];
  };

  const agent = (overview.agents?.items || []).find((item) => item.id && item.id !== "000" && item.status === "active")
    || (overview.agents?.items || []).find((item) => item.id && item.id !== "000")
    || (overview.agents?.items || [])[0];
  const topSourceIp = firstNonEmpty(
    (overview.source_ips || []).find((item) => item.ip)?.ip,
    (overview.ai_recon?.sources || []).find((item) => item.srcip)?.srcip,
    (overview.cloud_m365?.client_ips || []).find((item) => item.key && item.key !== "::1")?.key
  );
  const topCve = firstNonEmpty(
    (overview.vulnerabilities?.critical_items || []).find((item) => item.cve || item.id)?.cve,
    (overview.vulnerabilities?.critical_items || []).find((item) => item.cve || item.id)?.id
  ) || "CVE-2024-6387";
  const threat = (overview.threats || [])[0] || {};
  const cloudEvent = (overview.cloud_m365?.events || [])[0] || {};
  const cloudUser = String(cloudEvent.user || "").includes("@") ? cloudEvent.user : "";
  const keyword = firstNonEmpty(threat.rule_id, threat.description, cloudEvent.operation, "office365");
  const range = overview.requested_range || els.range?.value || "24h";

  fillAny(["agent_id", "agent"], agent?.id);
  fillAny(["ip", "srcip", "source_ip", "src_ip", "ip_address"], topSourceIp);
  fillAny(["indicator"], topSourceIp);
  fillArray("ips", topSourceIp);
  fillArray("indicators", topSourceIp);
  fillArray("search_terms", topSourceIp);
  fillArray("cve_ids", topCve);
  fillAny(["cve_id", "cve"], topCve);
  fillAny(["query", "keyword", "search_term"], String(keyword || "office365"));
  fillAny(["email"], cloudUser || "user@example.com");
  fillAny(["domain"], "example.com");
  fillAny(["url"], "http://example.com/");
  fillArray("urls", "http://example.com/");
  fillAny(["hash", "file_hash"], "44d88612fea8a8f36de82e1278abb02f");
  fillAny(["since", "time_range", "window"], range);
  if (accepts("response_format") && (empty(args.response_format) || args.response_format === "markdown")) args.response_format = "json";
  if (accepts("format") && (empty(args.format) || args.format === "markdown")) args.format = "json";
  fillAny(["top_n", "limit", "lines"], 20);
  fillAny(["hours_back"], range === "24h" ? 24 : range === "7d" ? 168 : 720);
  fillAny(["lookback_minutes"], 60);
  fillAny(["threshold_score"], 35);
  if (accepts("grep") && empty(args.grep)) args.grep = "failed|invalid|DVWA|.env|scan|malware|office365|fortigate";
  if (accepts("indicator_type") && empty(args.indicator_type)) args.indicator_type = "ip";
  if (accepts("exact_match") && empty(args.exact_match)) args.exact_match = false;
  if (accepts("bypass_redaction") && empty(args.bypass_redaction)) args.bypass_redaction = false;

  return args;
}

function missingRequiredArgs(tool, args) {
  const required = tool?.required_fields || [];
  const payload = args?.params && typeof args.params === "object" ? args.params : args;
  return required.filter((name) => {
    const value = payload?.[name];
    return value === undefined ||
      value === null ||
      value === "" ||
      (Array.isArray(value) && value.length === 0) ||
      (typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0);
  });
}

function descriptionOf(tool) {
  return esc((tool.description || "").replace(/\s+/g, " ").slice(0, 210));
}

function visibleTools() {
  const query = (els.search?.value || "").trim().toLowerCase();
  return state.tools.filter((tool) => {
    const inFilter =
      state.filter === "all" ||
      tool.source === state.filter ||
      (state.filter === "new" && newNames.has(tool.name));
    if (!inFilter) return false;
    if (state.category !== "all" && tool.category !== state.category) return false;
    if (!query) return true;
    return `${tool.name} ${tool.description || ""} ${tool.source} ${tool.category || ""} ${tool.lane || ""}`.toLowerCase().includes(query);
  }).sort((a, b) =>
    String(a.category || "").localeCompare(String(b.category || "")) ||
    String(a.source || "").localeCompare(String(b.source || "")) ||
    String(a.name || "").localeCompare(String(b.name || ""))
  );
}

function renderCategoryOptions() {
  if (!els.categorySelect) return;
  const selected = state.category;
  const categories = Object.entries(state.categories || {}).sort((a, b) => a[0].localeCompare(b[0]));
  els.categorySelect.innerHTML = [
    '<option value="all">All categories</option>',
    ...categories.map(([name, count]) => `<option value="${esc(name)}">${esc(name)} (${fmt.format(number(count))})</option>`),
  ].join("");
  els.categorySelect.value = selected;
}

function renderTools() {
  if (!els.list) return;
  const tools = visibleTools();
  const summary = state.toolSummary || {};
  setHtml("#toolReadiness", `
    <span><strong>${fmt.format(number(summary.discovered || state.tools.length))}</strong> discovered</span>
    <span><strong>${fmt.format(number(summary.dashboard))}</strong> dashboard workflows</span>
    <span><strong>${fmt.format(number(summary.workflow))}</strong> menu workflows</span>
    <span><strong>${fmt.format(number(summary.cached_read))}</strong> cached reads</span>
    <span><strong>${fmt.format(number(summary.approval_required))}</strong> approval required</span>
    <small>All discovered tools have a menu and execution policy. Opening a page never runs a tool.</small>
  `);
  els.list.innerHTML = tools.map((tool) => `
    <button class="toolItem ${state.selected?.name === tool.name && state.selected?.source === tool.source ? "active" : ""}" type="button" data-tool="${esc(tool.source)}:${esc(tool.name)}">
      <div class="toolTitle">
        <span>${esc(tool.name)}</span>
        <span class="pill ${esc(tool.source)}">${esc(tool.source)}</span>
      </div>
      <div class="toolBadges">
        <span>${esc(tool.category || "Utility")}</span>
        <span>${esc(tool.lane || "SOC")}</span>
        <span>${tool.operational_mode === "dashboard" ? "dashboard" : "menu workflow"}</span>
        ${tool.requires_params ? "<span>params</span>" : ""}
      </div>
      <div class="desc">${descriptionOf(tool)}</div>
    </button>
  `).join("") || '<div class="emptyState">No tools found.</div>';
}

function selectTool(tool) {
  if (!tool) return;
  state.selected = tool;
  els.toolName.textContent = tool.name;
  els.toolSource.textContent = `${tool.source} MCP`;
  els.args.value = JSON.stringify(contextualArgs(tool), null, 2);
  if (els.toolMeta) {
    const required = (tool.required_fields || []).slice(0, 6);
    const fields = (tool.schema_fields || []).slice(0, 8);
    els.toolMeta.innerHTML = `
      <span>${esc(tool.category || "Utility")}</span>
      <span>${esc(tool.lane || "SOC")}</span>
      <span>${tool.requires_params ? "auto params wrapper" : "direct args"}</span>
      <span>${esc(tool.operational_mode === "dashboard" ? "cached dashboard workflow" : `${tool.workflow?.menu || "tools"} menu workflow`)}</span>
      <span>${esc(tool.dependency || "local")}</span>
      ${required.length ? `<span>required: ${esc(required.join(", "))}</span>` : ""}
      ${fields.length ? `<span>fields: ${esc(fields.map((field) => field.name).join(", "))}</span>` : ""}
      <span>${esc((tool.description || "No description").replace(/\s+/g, " ").slice(0, 180))}</span>
      <span>${esc(tool.readiness_note || "Catalog available")}</span>
    `;
  }
  els.result.innerHTML = '<div class="emptyState">Run this tool to see structured SOC output.</div>';
  els.run.disabled = false;
  renderTools();
}

function applyToolPivot(tool, pivot = {}) {
  selectTool(tool);
  if (!pivot || !Object.keys(pivot).length) return;
  const args = contextualArgs(tool);
  const fields = new Set((tool.schema_fields || []).map((field) => field.name));
  const accepts = (name) => Object.prototype.hasOwnProperty.call(args, name) || fields.has(name);
  const ip = pivot.ip || pivot.srcip || pivot.source_ip;
  if (ip) {
    if (accepts("indicator")) args.indicator = ip;
    else if (accepts("srcip") || tool.name.includes("investigate") || tool.name.includes("mark_")) args.srcip = ip;
    else if (accepts("ip")) args.ip = ip;
  }
  if (pivot.cve && accepts("cve_id")) args.cve_id = pivot.cve;
  if (pivot.ruleId) {
    if (accepts("rule_id")) args.rule_id = pivot.ruleId;
    else if (accepts("keyword")) args.keyword = pivot.ruleId;
  }
  if (pivot.keyword && accepts("keyword")) args.keyword = pivot.keyword;
  const range = pivot.timeRange || pivot.since;
  if (range) {
    if (accepts("since")) args.since = range;
    if (accepts("time_range")) args.time_range = range;
    if (accepts("timestamp_start")) args.timestamp_start = `now-${range}`;
    if (accepts("timestamp_end")) args.timestamp_end = "now";
  }
  if (els.args) els.args.value = JSON.stringify(args, null, 2);
}

function computeRisk(data) {
  const sev = data.alerts?.severity || {};
  const vulns = data.vulnerabilities || {};
  const agents = data.agents || {};
  const inactive = Math.max(0, number(agents.total) - number(agents.counts?.active));
  const score =
    Math.min(24, number(sev.critical) * 10) +
    Math.min(20, number(sev.high) * 4) +
    Math.min(8, number(sev.medium) * 0.4) +
    Math.min(28, number(vulns.critical) * 3) +
    Math.min(18, number(vulns.high) * 0.15) +
    Math.min(18, number(data.ai_recon?.ai_agent_sources) * 1.8) +
    Math.min(18, inactive * 9);
  return Math.min(100, Math.round(score));
}

function renderPosture(data) {
  const risk = computeRisk(data);
  const color = risk >= 70 ? "#ff6b8a" : risk >= 40 ? "#f7c76c" : "#4de2a6";
  const range = data.requested_range || data.alerts?.time_range || "24h";
  const rangeLabel = currentRangeLabel(data);
  setText("#riskScore", String(risk));
  setText("#postureTitle", risk >= 70 ? ui("Perlu perhatian tinggi", "High Attention Required") : risk >= 40 ? ui("Beban SOC meningkat", "Elevated SOC Load") : ui("SOC stabil", "SOC Stable"));
  setText("#postureBadge", risk >= 70 ? ui("Respons prioritas", "Priority response") : risk >= 40 ? ui("Investigasi hari ini", "Investigate today") : ui("Monitor", "Monitor"));
  setText("#riskMeta", ui("Risiko SOC", "SOC Risk"));
  setText(
    "#postureCopy",
    ui(
      `Tampilan ${humanRange(range)}: ${fmt.format(number(data.alerts?.sampled))} alert terbaru disampel dari ${fmt.format(number(data.alerts?.total_alerts))} alert terindeks, ${fmt.format(number(data.vulnerabilities?.critical))} CVE kritis, ${fmt.format(number(data.ai_recon?.ai_agent_sources))} sumber AI recon.`,
      `${rangeLabel} view: ${fmt.format(number(data.alerts?.sampled))} latest alerts sampled from ${fmt.format(number(data.alerts?.total_alerts))} indexed alerts, ${fmt.format(number(data.vulnerabilities?.critical))} critical CVEs, ${fmt.format(number(data.ai_recon?.ai_agent_sources))} AI recon source(s).`
    )
  );
  renderRiskFactors(data);
  const dial = q("#riskDial");
  if (dial) {
    dial.style.background = `conic-gradient(${color} 0deg ${risk * 3.6}deg, rgba(255,255,255,.12) ${risk * 3.6}deg 360deg)`;
  }
}

function renderRiskFactors(data) {
  const sev = data.alerts?.severity || {};
  const active = number(data.agents?.counts?.active);
  const total = number(data.agents?.total);
  const factors = [
    [`${fmt.format(number(data.vulnerabilities?.critical))}`, ui("CVE kritis", "critical CVEs")],
    [`${fmt.format(number(data.vulnerabilities?.high))}`, ui("CVE high", "high CVEs")],
    [`${fmt.format(number(data.ai_recon?.ai_agent_sources))}`, ui("sumber AI recon", "AI recon sources")],
    [`${fmt.format(number(sev.medium) + number(sev.high) + number(sev.critical))}`, ui("sampel alert non-low", "non-low alert sample")],
    [`${fmt.format(active)}/${fmt.format(total)}`, ui("agent aktif", "agents active")],
  ];
  setHtml("#riskFactors", factors.map(([value, label]) => `
    <span class="riskFactor"><b>${esc(value)}</b>${esc(label)}</span>
  `).join(""));
}

function renderLanes(data) {
  const caps = data.tools?.capabilities || {};
  const l1Load = number(data.alerts?.sampled) || number(data.threats?.length);
  const l2Load = number(data.three_sum?.candidate_count) + number(data.ai_recon?.ai_agent_sources) + number(data.vulnerabilities?.critical);
  const l3Load = capCount(caps, "hunt") + capCount(caps, "threat_intel");
  setText("#laneL1", fmt.format(l1Load));
  setText("#laneL2", fmt.format(l2Load));
  setText("#laneL3", fmt.format(l3Load));
}

function renderMetrics(data) {
  const range = data.requested_range || data.alerts?.time_range || "24h";
  const rangeLabel = currentRangeLabel(data);
  const activeAgents = number(data.agents?.counts?.active);
  const totalAgents = number(data.agents?.total);
  setText("#metricAlertsLabel", `${ui("Alert", "Alerts")} ${range === "custom" ? "" : range}`);
  setText("#metricAlerts", fmt.format(number(data.alerts?.total_alerts)));
  setText("#metricSample", ui(`${rangeLabel} window, ${fmt.format(number(data.alerts?.sampled))} disampel`, `${rangeLabel} window, ${fmt.format(number(data.alerts?.sampled))} sampled`));
  setText("#metricAgents", fmt.format(activeAgents));
  setText("#metricAgentTotal", `${fmt.format(totalAgents)} ${ui("total", "total")}`);
  setText("#metricCriticalCves", fmt.format(number(data.vulnerabilities?.critical)));
  setText("#metricVulnTotal", `${fmt.format(number(data.vulnerabilities?.total))} ${ui("total", "total")}`);
  setText("#metricAiSources", fmt.format(number(data.ai_recon?.ai_agent_sources)));
}

function chartPoints(series, width = 620, height = 180, pad = 20) {
  const max = Math.max(...series.map((row) => number(row.alerts || row.count || row.doc_count)), 1);
  const step = series.length > 1 ? (width - pad * 2) / (series.length - 1) : 0;
  return series.map((row, index) => {
    const value = number(row.alerts || row.count || row.doc_count);
    return {
      ...row,
      value,
      x: Math.round(pad + index * step),
      y: Math.round(height - pad - (value / max) * (height - pad * 2)),
    };
  });
}

function sparkAreaSvg(series, title = "Alert activity") {
  const rows = series.slice(-48);
  if (!rows.length) return '<div class="emptyState">No chart data</div>';
  const width = 620;
  const height = 190;
  const points = chartPoints(rows, width, height, 22);
  const line = points.map((p, i) => `${i ? "L" : "M"}${p.x},${p.y}`).join(" ");
  const area = `${line} L${points[points.length - 1].x},${height - 22} L${points[0].x},${height - 22} Z`;
  const maxPoint = points.reduce((best, p) => p.value > best.value ? p : best, points[0]);
  return `
    <svg class="areaChart" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="${esc(title)}">
      <defs>
        <linearGradient id="areaGradient" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stop-color="#20c7d9" stop-opacity="0.62"></stop>
          <stop offset="100%" stop-color="#4dabf7" stop-opacity="0.04"></stop>
        </linearGradient>
        <filter id="chartGlow" x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="3" result="blur"></feGaussianBlur>
          <feMerge><feMergeNode in="blur"></feMergeNode><feMergeNode in="SourceGraphic"></feMergeNode></feMerge>
        </filter>
      </defs>
      <g class="chartGrid">
        <line x1="22" y1="45" x2="598" y2="45"></line>
        <line x1="22" y1="95" x2="598" y2="95"></line>
        <line x1="22" y1="145" x2="598" y2="145"></line>
      </g>
      <path class="areaFill" d="${area}"></path>
      <path class="areaLine" d="${line}" filter="url(#chartGlow)"></path>
      <circle class="peakDot" cx="${maxPoint.x}" cy="${maxPoint.y}" r="5"></circle>
      <text class="peakLabel" x="${Math.min(maxPoint.x + 10, width - 150)}" y="${Math.max(maxPoint.y - 8, 18)}">peak ${fmt.format(maxPoint.value)}</text>
    </svg>
  `;
}

function renderSeverity(data) {
  const sev = data.alerts?.severity || {};
  const order = ["critical", "high", "medium", "low"];
  const total = Math.max(order.reduce((sum, key) => sum + number(sev[key]), 0), 1);
  const max = Math.max(...order.map((key) => number(sev[key])), 1);
  const color = { critical: "var(--red)", high: "var(--amber)", medium: "var(--blue)", low: "var(--green)" };
  let cursor = 0;
  const stops = order.map((key) => {
    const start = cursor;
    cursor += (number(sev[key]) / total) * 360;
    return `${color[key]} ${start.toFixed(1)}deg ${cursor.toFixed(1)}deg`;
  }).join(", ");
  setHtml("#severityBars", `
    <div class="severityDashboard">
      <div class="severityDonut" style="background: conic-gradient(${stops});" role="img" aria-label="Severity distribution ${fmt.format(total)} alerts">
        <div>
          <strong>${fmt.format(total)}</strong>
          <small>sampled</small>
        </div>
      </div>
      <div class="severityLegend">
        ${order.map((key) => {
          const count = number(sev[key]);
          const width = Math.max(3, Math.round((count / max) * 100));
          return `
            <button class="severityRow ${esc(key)}" type="button" data-view-link="l1">
              <span>${esc(key)}</span>
              <div class="barTrack"><div class="barFill ${esc(key)}" style="width:${width}%"></div></div>
              <b>${fmt.format(count)}</b>
            </button>
          `;
        }).join("")}
      </div>
    </div>
  `);
  setText("#severityNote", data.alerts?.truncated ? "Sampled latest alerts" : "Full query window");
}

function renderHourlySpark(data) {
  const hourly = data.alerts?.hourly || [];
  const timeline = (data.timeline?.buckets || []).map((row) => ({ hour: row.time, alerts: row.count }));
  const source = hourly.length ? hourly : timeline;
  const stride = Math.max(1, Math.ceil(source.length / 48));
  const series = source.filter((_, index) => index % stride === 0).slice(-48);
  const latest = series[series.length - 1];
  setHtml("#hourlySpark", series.length ? `
    ${sparkAreaSvg(series, "Hourly security activity")}
    <div class="chartFooter">
      <span>${fmt.format(number(latest?.alerts))} latest bucket</span>
      <span>${fmt.format(Math.max(...series.map((row) => number(row.alerts))))} peak</span>
    </div>
  ` : '<div class="emptyState">No hourly data</div>');
}

function pseudoPosition(label, index) {
  let hash = 0;
  for (const char of String(label || index)) {
    hash = ((hash << 5) - hash) + char.charCodeAt(0);
    hash |= 0;
  }
  const x = 12 + Math.abs((hash + index * 37) % 76);
  const y = 18 + Math.abs((hash * 7 + index * 19) % 64);
  return { x, y };
}

const CITY_COORDS = {
  amsterdam: [52.3676, 4.9041],
  ashburn: [39.0438, -77.4874],
  bangkok: [13.7563, 100.5018],
  bandung: [-6.9175, 107.6191],
  bekasi: [-6.2349, 106.9896],
  beijing: [39.9042, 116.4074],
  burgas: [42.5048, 27.4626],
  chicago: [41.8781, -87.6298],
  concord: [37.978, -122.0311],
  deoria: [26.5017, 83.7794],
  dubai: [25.2048, 55.2708],
  easton: [40.6884, -75.2207],
  hongkong: [22.3193, 114.1694],
  istanbul: [41.0082, 28.9784],
  jakarta: [-6.2088, 106.8456],
  johannesburg: [-26.2041, 28.0473],
  jayapura: [-2.5337, 140.7181],
  karachi: [24.8607, 67.0011],
  kyiv: [50.4501, 30.5234],
  london: [51.5072, -0.1276],
  mogoi: [47.9184, 106.9177],
  mumbai: [19.076, 72.8777],
  northbergen: [40.8043, -74.0121],
  odesa: [46.4825, 30.7233],
  panvel: [18.9894, 73.1175],
  paris: [48.8566, 2.3522],
  purwakarta: [-6.5569, 107.4433],
  semarang: [-6.9667, 110.4167],
  seattle: [47.6062, -122.3321],
  singapore: [1.3521, 103.8198],
  sydney: [-33.8688, 151.2093],
  tokyo: [35.6762, 139.6503],
  ulaanbaatar: [47.8864, 106.9057],
  utrecht: [52.0907, 5.1214],
  uludanau: [-8.275, 115.166],
  wentworthville: [-33.8066, 150.9706],
};

function geoPoint(row, index) {
  const lat = number(row.lat);
  const lon = number(row.lon);
  if ((lat || lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180) {
    return { x: Math.round(40 + ((lon + 180) / 360) * 880), y: Math.round(30 + ((90 - lat) / 180) * 390) };
  }
  const key = String(row.city || "").toLowerCase().replace(/[^a-z]/g, "");
  const known = CITY_COORDS[key];
  if (known) {
    return { x: Math.round(40 + ((known[1] + 180) / 360) * 880), y: Math.round(30 + ((90 - known[0]) / 180) * 390) };
  }
  const location = row.location || {};
  const locationKey = String(location.city || "").toLowerCase().replace(/[^a-z]/g, "");
  const knownLocation = CITY_COORDS[locationKey];
  if (knownLocation) {
    return { x: Math.round(40 + ((knownLocation[1] + 180) / 360) * 880), y: Math.round(30 + ((90 - knownLocation[0]) / 180) * 390) };
  }
  const pseudo = pseudoPosition(row.city || row.ip, index);
  return { x: Math.round((pseudo.x / 100) * 960), y: Math.round((pseudo.y / 100) * 460) };
}

function renderAttackTimeline(data) {
  const buckets = data.timeline?.buckets || [];
  const max = Math.max(...buckets.map((row) => number(row.count)), 1);
  setText("#timelineMeta", `${data.timeline?.bucket_interval || "auto"} buckets, ${fmt.format(number(data.timeline?.total_alerts))} alerts`);
  const stride = Math.max(1, Math.ceil(buckets.length / 72));
  const rows = buckets.filter((_, index) => index % stride === 0).slice(-72);
  const points = chartPoints(rows.map((row) => ({ ...row, alerts: row.count })), 960, 220, 18);
  const bars = points.map((point) => {
    const height = Math.max(4, 198 - point.y);
    const tone = point.value > max * 0.75 ? "hot" : point.value > max * 0.35 ? "warm" : "cool";
    return `
      <button class="timeBar ${tone}" type="button" title="${esc(point.time || "-")} - ${fmt.format(point.value)} alerts" style="height:${height}px">
        <span>${fmt.format(point.value)}</span>
      </button>
    `;
  }).join("");
  setHtml("#attackTimeline", rows.length ? `
    <div class="timelineScale">
      <span>low</span><span>medium</span><span>spike</span>
    </div>
    <div class="timelineBars">${bars}</div>
  ` : '<div class="emptyState">No timeline buckets returned.</div>');
}

function renderAttackMap(data) {
  const cities = data.geo_heatmap?.cities || [];
  const sources = data.source_ips || [];
  const mapRows = (cities.length ? cities : sources.slice(0, 12).map((source) => ({
    ip: source.ip,
    city: source.ip,
    alerts: source.max_score,
    unique_ips: source.hits,
  }))).slice().sort((a, b) => number(b.alerts) - number(a.alerts));
  const max = Math.max(...mapRows.map((row) => number(row.alerts)), 1);
  const limit = Math.max(6, Math.min(24, number(state.mapLimit) || 16));
  const zoom = Math.max(1, Math.min(1.8, Number(state.mapZoom) || 1));
  const viewWidth = Math.round(960 / zoom);
  const viewHeight = Math.round(460 / zoom);
  const viewX = Math.round((960 - viewWidth) / 2);
  const viewY = Math.round((460 - viewHeight) / 2);
  const mode = state.mapMode === "graph" ? "graph" : "geo";
  const controls = `
    <div class="mapControls" aria-label="Attack map controls">
      <button type="button" class="${mode === "geo" ? "active" : ""}" data-map-mode="geo">Geo Map</button>
      <button type="button" class="${mode === "graph" ? "active" : ""}" data-map-mode="graph">Attack Graph</button>
      <button type="button" data-map-action="less">Top -</button>
      <span>${limit}</span>
      <button type="button" data-map-action="more">Top +</button>
      <button type="button" data-map-action="zoom-out">-</button>
      <button type="button" data-map-action="zoom-in">+</button>
      <button type="button" data-map-action="reset">Reset</button>
    </div>
  `;
  const dots = mapRows.slice(0, limit).map((row, index) => {
    const pos = geoPoint(row, index);
    const x = pos.x;
    const y = pos.y;
    const size = 5 + Math.round((number(row.alerts) / max) * 14);
    const name = row.city || row.ip || "unknown source";
    const labelX = x > 760 ? x - 128 : x + size + 10;
    const labelY = Math.max(y - 18, 18);
    const label = index < 7 ? `
        <rect class="mapCallout" x="${labelX - 7}" y="${labelY - 15}" width="${Math.min(130, Math.max(66, String(name).length * 7 + 15))}" height="22" rx="7"></rect>
        <text x="${labelX}" y="${labelY}">${esc(name)}</text>
      ` : "";
    const pivotAttrs = row.ip ? `data-tool-name="blueteam_investigate_ip" data-auto-run="true" data-pivot-ip="${esc(row.ip)}"` : "data-view-link=\"incidents\"";
    return `
      <g class="mapThreat" tabindex="0" ${pivotAttrs} aria-label="${esc(name)} ${fmt.format(number(row.alerts))} alerts">
        <title>${esc(name)} - ${fmt.format(number(row.alerts))} alerts, ${fmt.format(number(row.unique_ips))} unique IPs</title>
        <circle class="mapPulse" cx="${x}" cy="${y}" r="${size + 7}"></circle>
        <circle class="mapCore" cx="${x}" cy="${y}" r="${size}"></circle>
        ${label}
      </g>
    `;
  }).join("");

  const graphSources = (data.source_ips || []).slice(0, Math.min(10, limit));
  const graphTargets = (data.attack_surface?.targets || data.agents?.items || []).slice(0, 7);
  const graphMax = Math.max(...graphSources.map((row) => number(row.max_score || row.alerts || row.hits)), 1);
  const graphEdges = graphSources.map((row, index) => {
    const y = 82 + index * 31;
    const score = number(row.max_score || row.alerts || row.hits);
    return `<path class="attackEdge" d="M238 ${y} C355 ${y - 8}, 404 210, 480 230" stroke-width="${Math.max(1.2, 1.2 + (score / graphMax) * 3.5)}"></path>`;
  }).join("") + graphTargets.map((row, index) => {
    const y = 88 + index * 42;
    return `<path class="attackEdge secondary" d="M494 230 C570 210, 620 ${y}, 716 ${y}"></path>`;
  }).join("");
  const graphSourceNodes = graphSources.map((row, index) => {
    const y = 82 + index * 31;
    const ip = row.ip || row.srcip || row.city || `source-${index + 1}`;
    const score = number(row.max_score || row.alerts || row.hits);
    const size = Math.max(7, 7 + (score / graphMax) * 8);
    return `
      <g class="attackMapNode graphSource" tabindex="0" data-tool-name="blueteam_investigate_ip" data-auto-run="true" data-pivot-ip="${esc(ip)}" aria-label="${esc(ip)} source score ${fmt.format(score)}">
        <circle cx="210" cy="${y}" r="${size}"></circle>
        <text x="32" y="${y + 4}">${esc(ip)}</text>
        <text class="nodeMetric" x="226" y="${y + 4}">${fmt.format(score)}</text>
      </g>
    `;
  }).join("");
  const graphTargetNodes = graphTargets.map((row, index) => {
    const y = 88 + index * 42;
    const label = row.name || row.id || row.ip || `asset-${index + 1}`;
    const alerts = number(row.alerts || row.count || row.status_code);
    return `
      <g class="attackMapNode graphTarget" tabindex="0" data-view-link="assets" aria-label="${esc(label)} target ${fmt.format(alerts)} alerts">
        <rect x="716" y="${y - 18}" width="196" height="36" rx="10"></rect>
        <text x="730" y="${y - 2}">${esc(label)}</text>
        <text class="nodeMetric" x="730" y="${y + 13}">${fmt.format(alerts)} alerts</text>
      </g>
    `;
  }).join("");
  const graphSvg = `
    <svg class="mapSvg graphSvg" viewBox="0 0 960 460" width="960" height="460" role="img" aria-label="Attack graph from source IPs through SOC correlation to affected assets">
      <defs>
        <linearGradient id="graphEdgeGradient" x1="0" x2="1" y1="0" y2="0">
          <stop offset="0%" stop-color="#ff6b8a" stop-opacity="0.74"></stop>
          <stop offset="55%" stop-color="#58d5f6" stop-opacity="0.62"></stop>
          <stop offset="100%" stop-color="#4de2a6" stop-opacity="0.54"></stop>
        </linearGradient>
      </defs>
      <g class="graphPlane" aria-hidden="true">
        <rect x="22" y="42" width="258" height="356" rx="18"></rect>
        <rect x="686" y="42" width="250" height="356" rx="18"></rect>
      </g>
      <g>${graphEdges}</g>
      <g>${graphSourceNodes}</g>
      <g class="attackMapNode graphSoc" tabindex="0" data-tool-name="advanced_three_sum_correlation" aria-label="SOC correlation core">
        <circle cx="480" cy="230" r="42"></circle>
        <text x="480" y="225" text-anchor="middle">SOC</text>
        <text class="nodeMetric" x="480" y="244" text-anchor="middle">Correlation</text>
      </g>
      <g>${graphTargetNodes}</g>
      <g class="mapLegend" aria-hidden="true">
        <text x="36" y="424">source IP score</text>
        <path d="M132 420h118"></path>
        <text x="268" y="424">Wazuh + GenSecAI + INFOKOM pivot</text>
      </g>
    </svg>
  `;
  const geoSvg = `
    <svg class="mapSvg" viewBox="${viewX} ${viewY} ${viewWidth} ${viewHeight}" width="960" height="460" role="img" aria-label="World map of security source activity">
      <defs>
        <linearGradient id="routeGradient" x1="0" x2="1" y1="0" y2="0">
          <stop offset="0%" stop-color="#36dce9" stop-opacity="0.18"></stop>
          <stop offset="100%" stop-color="#ff6b6b" stop-opacity="0.58"></stop>
        </linearGradient>
      </defs>
      <g class="mapRoutes" aria-hidden="true">
        ${mapRows.slice(0, 4).map((row, index) => {
          const pos = geoPoint(row, index);
          const x = pos.x;
          const y = pos.y;
          return `<path d="M${x} ${y} Q ${Math.round((x + 760) / 2)} ${Math.max(40, y - 110)} 760 235"></path>`;
        }).join("")}
      </g>
      <g>${dots}</g>
      <g class="mapHub">
        <circle cx="760" cy="235" r="9"></circle>
        <text x="776" y="239">SOC Core</text>
      </g>
      <g class="mapLegend" aria-hidden="true">
        <text x="38" y="418">bubble size = event volume</text>
        <path d="M38 432h120"></path>
        <text x="172" y="436">top routes to SOC</text>
      </g>
    </svg>
  `;
  setHtml("#attackMap", mapRows.length ? `${controls}${mode === "graph" ? graphSvg : geoSvg}` : '<div class="emptyState">No geo/source data.</div>');
  const attackMap = q("#attackMap");
  if (attackMap) attackMap.style.backgroundSize = mode === "geo" ? `${Math.round(100 * zoom)}% auto` : "cover";
  setHtml("#geoList", mapRows.slice(0, 10).map((row, index) => `
    <div class="geoItem" ${row.ip ? `data-tool-name="blueteam_investigate_ip" data-auto-run="true" data-pivot-ip="${esc(row.ip)}"` : 'data-view-link="incidents"'}>
      <div>
        <strong>${index + 1}. ${esc(row.city || row.ip || "Unknown")}</strong>
        <small>${fmt.format(number(row.unique_ips))} unique IPs</small>
      </div>
      <span class="pill high">${fmt.format(number(row.alerts))}</span>
    </div>
  `).join("") || '<div class="emptyState">No geo rows.</div>');
}

function renderSocCoverage(data) {
  const caps = data.tools?.capabilities || {};
  const funnel = data.analysis_funnel || {};
  const cloud = data.cloud_m365 || {};
  const layers = data.detection_layers || [];
  const layerByKey = Object.fromEntries(layers.map((layer) => [layer.key, layer]));
  const topM365 = (cloud.operations || [])[0]?.key || "waiting for operation agg";
  const topIp = (data.source_ips || [])[0]?.ip || (cloud.client_ips || [])[0]?.key || "";
  const vulnCritical = number(data.vulnerabilities?.critical);
  const vulnHigh = number(data.vulnerabilities?.high);
  const maxValue = Math.max(
    number(data.alerts?.total_alerts),
    number(cloud.total),
    number(data.vulnerabilities?.total),
    number(data.ai_recon?.ai_agent_sources),
    number(data.three_sum?.candidate_count),
    1
  );
  const rows = [
    {
      label: "SIEM Alerts",
      source: "Wazuh",
      value: number(data.alerts?.total_alerts),
      detail: `${fmt.format(number(data.alerts?.sampled))} sampled, severity/rule pivots ready`,
      tone: "high",
      tool: "get_wazuh_alerts",
    },
    {
      label: "Microsoft 365",
      source: "Wazuh Cloud",
      value: number(cloud.total),
      detail: `${topM365} | ${(cloud.workloads || [])[0]?.key || "workload"} dominant`,
      tone: cloud.ok ? "low" : "medium",
      tool: "wazuh_alert_aggregate_analysis",
    },
    {
      label: "FIM / Integrity",
      source: "Wazuh Agent",
      value: number(layerByKey.fim?.count),
      detail: "file, registry and integrity changes",
      tone: layerByKey.fim?.status === "active" ? "low" : "medium",
      tool: "blueteam_wazuh_syscheck",
    },
    {
      label: "Network IDS",
      source: "Fortigate / Syslog",
      value: number(layerByKey.network?.count),
      detail: topIp ? `top source ${topIp}` : "ICMP, scans and firewall rules",
      tone: layerByKey.network?.status === "active" ? "low" : "medium",
      tool: "blueteam_wazuh_alerts",
      ip: topIp,
    },
    {
      label: "AI Recon",
      source: "INFOKOM",
      value: number(data.ai_recon?.ai_agent_sources),
      detail: "crawler, LLM probe and sensitive path detection",
      tone: "critical",
      tool: "blueteam_ai_bot_recon",
    },
    {
      label: "Vulnerability",
      source: "Wazuh CVE",
      value: number(data.vulnerabilities?.total),
      detail: `${fmt.format(vulnCritical)} critical, ${fmt.format(vulnHigh)} high`,
      tone: vulnCritical ? "critical" : "medium",
      tool: "get_wazuh_critical_vulnerabilities",
    },
    {
      label: "3-Sum Correlation",
      source: "INFOKOM",
      value: number(data.three_sum?.candidate_count),
      detail: "recon, access anomaly and c2/exfil candidates",
      tone: "violet",
      tool: "advanced_three_sum_correlation",
    },
    {
      label: "Tool Coverage",
      source: "MCP",
      value: number(data.tools?.total),
      detail: `${capCount(caps, "l1_triage")} L1, ${capCount(caps, "l2_investigation")} L2, ${capCount(caps, "hunt")} hunt tools`,
      tone: "blue",
      view: "tools",
    },
    {
      label: "IOC Pipeline",
      source: "Background",
      value: number(funnel.queued_unique_indicators),
      detail: `${funnel.pipeline_status || "unknown"} | lag ${fmt.format(number(funnel.pipeline_lag_seconds))}s | case/rollup AI`,
      tone: funnel.pipeline_status === "caught_up" ? "low" : "medium",
      view: "history",
    },
  ];
  setHtml("#socDataCoverage", rows.map((row) => {
    const width = Math.max(5, Math.min(100, Math.round((number(row.value) / maxValue) * 100)));
    const action = row.tool
      ? `data-tool-name="${esc(row.tool)}" ${row.ip ? `data-pivot-ip="${esc(row.ip)}"` : ""}`
      : `data-view-link="${esc(row.view || "command")}"`;
    return `
      <button class="coverageSignal ${esc(row.tone)}" type="button" ${action} aria-label="${esc(row.label)} ${fmt.format(number(row.value))}">
        <span class="signalSource">${esc(row.source)}</span>
        <strong>${esc(row.label)}</strong>
        <b>${fmt.format(number(row.value))}</b>
        <small>${esc(row.detail)}</small>
        <span class="signalBar" aria-hidden="true"><i style="width:${width}%"></i></span>
      </button>
    `;
  }).join(""));
}

function renderDetectionLayers(data) {
  const layers = data.detection_layers || [];
  const max = Math.max(...layers.map((layer) => number(layer.count)), 1);
  const icon = {
    fim: "FI",
    auth: "AU",
    network: "NW",
    web: "WB",
    container: "DK",
    cloud: "M365",
    vuln: "CV",
    siem: "SI",
  };
  setHtml("#detectionLayers", layers.map((layer) => {
    const width = Math.max(3, Math.round((number(layer.count) / max) * 100));
    const statusClass = layer.status === "active" ? "low" : "medium";
    return `
      <article class="layerCard" data-tool-name="${esc(layer.tool)}">
        <span class="layerIcon">${esc(icon[layer.key] || "LY")}</span>
        <div>
          <strong>${esc(layer.name)}</strong>
          <small>${esc(layer.signal)}</small>
          <div class="layerMeter"><span style="width:${width}%"></span></div>
        </div>
        <div>
          <span class="pill ${statusClass}">${esc(layer.status || "ready")}</span>
          <small>${fmt.format(number(layer.count))}</small>
        </div>
      </article>
    `;
  }).join("") || '<div class="emptyState">No detection layers returned.</div>');
}

function renderCloudM365(data) {
  const cloud = data.cloud_m365 || {};
  const bucketList = (title, rows) => {
    const max = Math.max(...(rows || []).map((row) => number(row.doc_count)), 1);
    return `
    <section class="cloudBlock">
      <strong>${esc(title)}</strong>
      ${(rows || []).slice(0, 6).map((row) => `
        <div class="cloudRow">
          <span>${esc(row.key || "-")}</span>
          <div class="cloudBar"><i style="width:${Math.max(3, Math.round((number(row.doc_count) / max) * 100))}%"></i></div>
          <b>${fmt.format(number(row.doc_count))}</b>
        </div>
      `).join("") || '<small>No data</small>'}
    </section>
  `};
  const events = (cloud.events || []).slice(0, 5).map((event) => `
    <article class="cloudEvent" data-tool-name="wazuh_alert_aggregate_analysis">
      <div>
        <strong>${esc(event.operation || event.description || "Office 365 event")}</strong>
        <small>${esc(event.workload || "-")} | ${esc(event.user || "-")}</small>
      </div>
      <div>
        <span class="pill low">${esc(event.subscription || "M365")}</span>
        <small>${esc(event.client_ip || "-")}</small>
      </div>
    </article>
  `).join("") || '<div class="emptyState">No Microsoft 365 events in this range.</div>';
  setHtml("#cloudM365Panel", `
    <div class="cloudHero">
      <span class="pill ${cloud.total ? "low" : "medium"}">${cloud.ok ? "connected" : "degraded"}</span>
      <strong>${fmt.format(number(cloud.total))}</strong>
      <small>Office 365 events in selected range</small>
    </div>
    <div class="cloudBuckets">
      ${bucketList("Workloads", cloud.workloads)}
      ${bucketList("Operations", cloud.operations)}
      ${bucketList("Client IPs", cloud.client_ips)}
    </div>
    <div class="cloudEvents">${events}</div>
  `);
}

function renderAttackPath(data) {
  const graphHtml = (suffix) => renderExposureGraphHtml(data, suffix);
  setHtml("#attackPath", graphHtml("command"));
  setHtml("#l3AttackPath", graphHtml("l3"));
}

function exposureMetric(data, key) {
  const layers = Object.fromEntries((data.detection_layers || []).map((layer) => [layer.key, layer]));
  if (key === "m365") return number(data.cloud_m365?.total || layers.cloud?.count);
  if (key === "agents") return number(data.agents?.counts?.active || data.agents?.total);
  if (key === "cves") return number(data.vulnerabilities?.critical);
  if (key === "recon") return number(data.ai_recon?.ai_agent_sources);
  if (key === "fim") return number(data.fim?.total || layers.fim?.count);
  if (key === "network") return number(layers.network?.count);
  return 0;
}

function compactLabel(value, limit = 22) {
  const text = String(value || "-").replace(/\s+/g, " ").trim();
  return text.length > limit ? `${text.slice(0, Math.max(0, limit - 3))}...` : text;
}

function fmtBytes(value) {
  const bytes = number(value);
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / Math.pow(1024, index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}

function exposureNode({ x, y, r = 36, title, sub, kind = "neutral", tool = "", ip = "", cve = "", shape = "circle", icon = "AS" }) {
  const attrs = [
    tool ? `data-tool-name="${esc(tool)}"` : "",
    ip ? `data-pivot-ip="${esc(ip)}"` : "",
    cve ? `data-pivot-cve="${esc(cve)}"` : "",
    `aria-label="${esc(`${title} ${sub || ""}`)}"`,
    "tabindex=\"0\"",
  ].filter(Boolean).join(" ");
  const width = shape === "wide" ? 176 : 152;
  const height = 54;
  const left = x - width / 2;
  const top = y - height / 2;
  return `
    <g class="exposureNode ${esc(kind)}" ${attrs}>
      <rect class="nodeCard" x="${left}" y="${top}" width="${width}" height="${height}" rx="12"></rect>
      <circle class="nodeBadge" cx="${left + 24}" cy="${y}" r="16"></circle>
      <text class="nodeIcon" x="${left + 24}" y="${y + 5}" text-anchor="middle">${esc(icon)}</text>
      <text class="nodeTitle" x="${left + 48}" y="${y - 5}">${esc(compactLabel(title, 18))}</text>
      <text class="nodeSub" x="${left + 48}" y="${y + 13}">${esc(compactLabel(sub, 22))}</text>
    </g>
  `;
}

function renderExposureGraphHtml(data, suffix) {
  const sources = data.attack_surface?.sources || data.source_ips || [];
  const targets = data.attack_surface?.targets || data.agents?.items || [];
  const hotIp = sources[0]?.ip || (data.cloud_m365?.client_ips || [])[0]?.key || "no source IP";
  const secondIp = sources[1]?.ip || hotIp;
  const topAgent = targets[0]?.name || targets[0]?.id || (data.agents?.items || [])[0]?.name || "managed asset";
  const secondAgent = targets[1]?.name || targets[1]?.id || "cloud workload";
  const cve = data.vulnerabilities?.critical_items?.[0]?.cve || data.vulnerabilities?.critical_items?.[0]?.id || "CVE triage";
  const cloudOp = (data.cloud_m365?.operations || [])[0]?.key || "M365 audit";
  const topRule = data.threats?.[0]?.rule_id || "rule pivot";
  const m365 = exposureMetric(data, "m365");
  const agents = exposureMetric(data, "agents");
  const cves = exposureMetric(data, "cves");
  const recon = exposureMetric(data, "recon");
  const fim = exposureMetric(data, "fim");
  const network = exposureMetric(data, "network");
  const arrowId = `arrow-${suffix}`;
  const glowId = `exposureGlow-${suffix}`;
  const edges = [
    [176, 360, 234, 305, "hot"], [176, 260, 234, 190, "warn"], [176, 160, 234, 185, "weak"],
    [386, 84, 444, 240, "hot"], [386, 185, 444, 252, "weak"], [386, 305, 444, 266, "weak"], [386, 430, 444, 282, "weak"],
    [596, 255, 654, 105, "weak"], [596, 255, 654, 205, "hot"], [596, 255, 654, 305, "warn"], [596, 255, 654, 405, "weak"],
    [806, 105, 854, 110, "weak"], [806, 205, 854, 210, "weak"], [806, 305, 854, 310, "warn"], [806, 405, 854, 410, "weak"],
    [940, 310, 940, 410, "hot"], [310, 305, 730, 205, "hot"],
  ].map(([x1, y1, x2, y2, tone]) => `
    <path class="exposureEdge ${tone}" d="M${x1} ${y1} C ${Math.round((x1 + x2) / 2)} ${y1}, ${Math.round((x1 + x2) / 2)} ${y2}, ${x2} ${y2}" marker-end="url(#${arrowId})"></path>
  `).join("");
  const nodes = [
    exposureNode({ x: 100, y: 160, title: "Web app", sub: "DVWA/app logs", kind: "neutral", tool: "blueteam_read_web_log", icon: "WB" }),
    exposureNode({ x: 100, y: 260, title: "Identity", sub: "auth failures", kind: "warn", tool: "blueteam_failed_logins", icon: "ID" }),
    exposureNode({ x: 100, y: 360, title: "Public IP", sub: hotIp, kind: "hot", tool: "blueteam_investigate_ip", ip: hotIp, icon: "IP" }),
    exposureNode({ x: 310, y: 84, title: "Sensitive data", sub: `${fmt.format(m365)} M365`, kind: "hot", shape: "wide", tool: "wazuh_alert_aggregate_analysis", icon: "SD" }),
    exposureNode({ x: 310, y: 185, title: "Evidence store", sub: "Wazuh + M365", kind: "critical", shape: "wide", tool: "wazuh_alert_aggregate_analysis", icon: "LOG" }),
    exposureNode({ x: 310, y: 305, title: "Virtual machine", sub: topAgent, kind: cves ? "hot" : "neutral", tool: "blueteam_cve_score", cve, icon: "VM" }),
    exposureNode({ x: 310, y: 430, title: "SQL server", sub: `${fmt.format(fim)} FIM`, kind: "neutral", tool: "blueteam_wazuh_syscheck", icon: "DB" }),
    exposureNode({ x: 520, y: 255, title: "SOC correlation", sub: `Rule ${topRule}`, kind: "soc", shape: "wide", tool: "advanced_three_sum_correlation", icon: "SO" }),
    exposureNode({ x: 730, y: 105, title: "Network group", sub: `${fmt.format(network)} events`, kind: "neutral", tool: "blueteam_wazuh_alerts", icon: "NW" }),
    exposureNode({ x: 730, y: 205, title: "Virtual machine", sub: secondAgent, kind: "critical", shape: "wide", tool: "get_wazuh_agents", icon: "VM" }),
    exposureNode({ x: 730, y: 305, title: "SQL on VM", sub: `${fmt.format(cves)} critical CVE`, kind: cves ? "warn" : "neutral", tool: "blueteam_cve_score", cve, icon: "SQL" }),
    exposureNode({ x: 730, y: 405, title: "M365 audit", sub: cloudOp, kind: "neutral", shape: "wide", tool: "wazuh_alert_aggregate_analysis", icon: "MS" }),
    exposureNode({ x: 940, y: 110, title: "Cloud storage", sub: `${fmt.format(m365)} events`, kind: "neutral", tool: "wazuh_alert_aggregate_analysis", icon: "ST" }),
    exposureNode({ x: 940, y: 210, title: "App service", sub: "web surface", kind: "neutral", tool: "blueteam_read_web_log", icon: "AP" }),
    exposureNode({ x: 940, y: 310, title: "Internet exposed", sub: secondIp, kind: "hot", shape: "wide", tool: "blueteam_investigate_ip", ip: secondIp, icon: "EX" }),
    exposureNode({ x: 940, y: 410, title: "Public IP", sub: secondIp, kind: "hot", tool: "blueteam_investigate_ip", ip: secondIp, icon: "IP" }),
  ].join("");
  return `
    <div class="exposureShell">
      <svg class="exposureGraph" viewBox="0 0 1040 520" role="img" aria-label="Enterprise SOC external exposure relationship graph">
        <defs>
          <filter id="${glowId}" x="-35%" y="-35%" width="170%" height="170%">
            <feGaussianBlur stdDeviation="4" result="blur"></feGaussianBlur>
            <feMerge><feMergeNode in="blur"></feMergeNode><feMergeNode in="SourceGraphic"></feMergeNode></feMerge>
          </filter>
          <marker id="${arrowId}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z"></path>
          </marker>
        </defs>
        <g class="exposureBack">
          <rect x="28" y="26" width="484" height="458" rx="26"></rect>
          <rect x="558" y="26" width="454" height="458" rx="26"></rect>
          <text x="52" y="52">SOURCE, DATA, AND IDENTITY RISK</text>
          <text x="582" y="52">AFFECTED ASSETS AND INTERNET EXPOSURE</text>
        </g>
        <g class="exposureEdges">${edges}</g>
        <g class="exposureNodes" filter="url(#${glowId})">${nodes}</g>
      </svg>
      <div class="exposureLegend">
        <button type="button" data-tool-name="blueteam_investigate_ip" data-pivot-ip="${esc(hotIp)}">Investigate ${esc(hotIp)}</button>
        <button type="button" data-tool-name="wazuh_alert_aggregate_analysis">Open Wazuh evidence</button>
        <button type="button" data-tool-name="advanced_three_sum_correlation">Correlate path</button>
        <button type="button" data-tool-name="blueteam_cve_score" data-pivot-cve="${esc(cve)}">Score ${esc(cve)}</button>
      </div>
    </div>
  `;
}

function renderCoverageGrid(data) {
  const caps = data.tools?.capabilities || {};
  const rows = [
    ["Wazuh SIEM", number(data.tools?.gensecai), "gensecai", "tools"],
    ["Threat Intel", capCount(caps, "threat_intel"), "infokom", "l3"],
    ["Hunting", capCount(caps, "hunt"), "infokom", "l3"],
    ["Vulnerability", capCount(caps, "vulnerability"), "critical", "vuln"],
    ["Response", capCount(caps, "response"), "high", "l3"],
    ["Compliance", capCount(caps, "compliance"), "medium", "l3"],
  ];
  setHtml("#coverageGrid", rows.map(([label, value, tone, view]) => `
    <div class="coverageItem" data-view-link="${esc(view)}">
      <span class="pill ${esc(tone)}">${fmt.format(value)}</span>
      <strong>${esc(label)}</strong>
      <small>available tools</small>
    </div>
  `).join(""));
}

function findToolByNames(names) {
  for (const name of names) {
    const tool = state.tools.find((item) => item.name === name);
    if (tool) return tool;
  }
  return null;
}

function toolLaunchCard(title, body, names, tone = "medium", pivot = {}) {
  const tool = findToolByNames(names);
  const attrs = tool
    ? `data-tool-name="${esc(tool.name)}" ${pivot.ip ? `data-pivot-ip="${esc(pivot.ip)}"` : ""} ${pivot.cve ? `data-pivot-cve="${esc(pivot.cve)}"` : ""}`
    : "";
  return `
    <button class="launchCard ${esc(tone)}" type="button" ${attrs} ${tool ? "" : "disabled"}>
      <span>${esc(tool?.lane || "SOC")}</span>
      <strong>${esc(title)}</strong>
      <small>${esc(body)}</small>
      <em>${esc(tool?.name || "tool not available")}</em>
    </button>
  `;
}

function renderToolRail(selector, items) {
  setHtml(selector, items.map((item) => toolLaunchCard(...item)).join(""));
}

function renderSocWorkbench(data) {
  const hotIp = data.source_ips?.[0]?.ip || data.attack_surface?.sources?.[0]?.ip || "8.8.8.8";
  const firstCve = data.vulnerabilities?.critical_items?.[0]?.cve || data.vulnerabilities?.critical_items?.[0]?.id || "CVE-2024-6387";
  const deck = [
    [ui("Ringkasan Alert", "Alert Summary"), ui("Ukuran antrean L1, keparahan, rule, dan volume alert.", "L1 queue sizing, severity, rules, and alert volume."), ["get_wazuh_alert_summary", "wazuh_alert_aggregate_analysis"], "critical"],
    [ui("Drilldown Timeline", "Timeline Drilldown"), ui("Histogram alert per bucket untuk validasi spike.", "Bucketed alert histogram for spike validation."), ["wazuh_alert_timeline"], "blue"],
    [ui("Investigasi IP Panas", "Investigate Hot IP"), ui(`Pivot sumber teratas saat ini ${hotIp}.`, `Pivot current top source ${hotIp}.`), ["blueteam_investigate_ip", "check_ioc_reputation"], "high", { ip: hotIp }],
    [ui("Korelasi 3-Sum", "3-Sum Correlation"), ui("Korelasi recon, anomali akses, dan dampak.", "Recon, access anomaly, and impact correlation."), ["advanced_three_sum_correlation", "three_sum_correlation"], "violet"],
    [ui("Skor CVE", "CVE Score"), ui(`Skor dan perkaya ${firstCve}.`, `Score and enrich ${firstCve}.`), ["blueteam_cve_score", "get_wazuh_critical_vulnerabilities"], "amber", { cve: firstCve }],
    [ui("Buat Case", "Create Case"), ui("Buka objek investigasi untuk eskalasi.", "Open an investigation object for escalation."), ["blueteam_case_create", "blueteam_case_list"], "green"],
  ];
  setHtml("#socActionDeck", deck.map((item) => toolLaunchCard(...item)).join(""));
}

function renderThreatTable(selector, threats) {
  const rows = threats || [];
  setHtml(selector, `
    <div class="tableHeader threatHeader">
      <span>${ui("Deteksi", "Detection")}</span><span>${ui("Level", "Level")}</span><span>${ui("Jumlah", "Count")}</span><span>${ui("Skor", "Score")}</span><span>${ui("Aksi", "Action")}</span>
    </div>
    ${rows.map((t) => {
      const level = number(t.level);
      const groups = Array.isArray(t.groups) && t.groups.length ? ` | ${t.groups.slice(0, 3).join(", ")}` : "";
      const srcIp = (t.source_ips || [])[0] || "";
      const mitre = t.mitre?.id?.slice?.(0, 3)?.join(", ") || "";
      const keyword = t.rule_id || t.description || "";
      return `
        <article class="tableRow threatRow" tabindex="0" data-analysis-rule="${esc(t.rule_id || "")}">
          <div>
            <strong>${esc(ax(t.analysis, "title") || t.description || t.rule_id || ui("Rule tidak dikenal", "Unknown rule"))}</strong>
            ${t.analysis ? `<p class="ruleMeaning">${esc(ax(t.analysis, "meaning"))}</p><small class="muted">${esc(t.description)}</small>` : ""}
            <div class="muted">Rule ${esc(t.rule_id || "-")}${esc(groups)}${mitre ? ` | MITRE ${esc(mitre)}` : ""}</div>
            <div class="threatPivots">
              ${(t.source_ips || []).slice(0, 3).map((ip) => `<span>${esc(ip)}</span>`).join("")}
              ${(t.affected_agents || []).slice(0, 2).map((agent) => `<span>${esc(agent.name || agent.id || "asset")}</span>`).join("")}
            </div>
          </div>
          <span class="pill ${severityClass(level)}">${severityLabel(level)} ${level || "-"}</span>
          <span>${fmt.format(number(t.count))}</span>
          <strong>${t.threat_score == null ? "-" : fmt.format(number(t.threat_score))}</strong>
          <div class="rowActions">
            <button type="button" data-analysis-rule="${esc(t.rule_id || "")}">${ui("Detail", "Detail")}</button>
          </div>
        </article>
      `;
    }).join("")}
  `);
  if (!rows.length) {
    const container = q(selector);
    if (container) container.innerHTML += `<div class="emptyState">${ui("Tidak ada baris ancaman dikembalikan.", "No threat rows returned.")}</div>`;
  }
}

function renderL1Queue(data) {
  const root = q("#l1Queue");
  if (!root) return;
  const cases = state.persistentCases || [];
  const casesByIp = new Map();
  cases.forEach((item) => (item.srcips || []).forEach((ip) => casesByIp.set(ip, item)));
  const liveRows = (data.l1_queue || []).map((row) => ({ ...row, case: casesByIp.get(row.source_ip) }));
  const linked = new Set(liveRows.map((row) => row.case?.case_id).filter(Boolean));
  const caseRows = cases.filter((item) => !linked.has(item.case_id)).slice(0, 10).map((item) => ({
    event_id: item.case_id, title: item.title || "Persistent SOC case", level: 0,
    source_ip: (item.srcips || [])[0], destination_ip: "case evidence", agent: "persistent store",
    assignment: item.owner || "unassigned", status: item.status || "open", sla_due: item.sla_due,
    case: item, persisted: true,
  }));
  const rows = [...caseRows, ...liveRows].slice(0, 30);
  state.l1Queue = rows;
  root.innerHTML = `
    <div class="l1QueueHeader"><span>Detection / entity</span><span>Asset</span><span>Priority</span><span>Owner / SLA</span><span>Case</span></div>
    ${rows.map((row, index) => {
      const level = number(row.level);
      const due = row.sla_due ? new Date(row.sla_due) : row.timestamp ? new Date(new Date(row.timestamp).getTime() + number(row.sla_minutes) * 60000) : null;
      const validDue = due && !Number.isNaN(due.getTime());
      const overdue = validDue && due.getTime() < Date.now() && !["closed", "resolved"].includes(String(row.status).toLowerCase());
      const linkedCase = row.case;
      return `<article class="l1QueueRow ${overdue ? "overdue" : ""}">
        <div><strong>${esc(row.title || "Wazuh alert")}</strong><small>${esc(evidenceValue(row.timestamp, "Stored case"))}</small><span>${esc(evidenceValue(row.source_ip, "unknown"))} -> ${esc(evidenceValue(row.destination_ip, "unknown"))}${row.destination_port ? `:${esc(row.destination_port)}` : ""}</span></div>
        <div><strong>${esc(evidenceValue(row.agent, "Unknown asset"))}</strong><small>${esc(evidenceValue(row.decoder, row.identity || "No decoder/entity"))}</small></div>
        <div><span class="pill ${severityClass(level)}">${row.persisted ? esc(row.status) : `${severityLabel(level)} ${level}`}</span><small>${esc(evidenceValue(row.rule_id, row.event_id || "-"))}</small></div>
        <div><strong>${esc(evidenceValue(linkedCase?.owner || row.assignment, "Unassigned"))}</strong><small class="${overdue ? "slaOverdue" : ""}">${validDue ? `${overdue ? "Overdue" : "Due"} ${esc(due.toLocaleString())}` : "SLA not set"}</small></div>
        <div>${linkedCase ? `<button type="button" data-view-link="incidents">${esc(linkedCase.case_id)}</button>` : `<button type="button" data-create-l1-case="${index}">Create case</button>`}</div>
      </article>`;
    }).join("") || `<div class="emptyState">${data.materialization?.status === "building" ? "Historical L1 queue is materializing; retained summaries remain available in Event History." : "No individual L1 alerts matched this window."}</div>`}
  `;
}

function renderSourceIps(data) {
  const rows = data.source_ips || [];
  const max = Math.max(...rows.map((row) => number(row.max_score)), 1);
  setHtml("#sourceIpList", rows.map((row) => {
    const width = Math.max(5, Math.round((number(row.max_score) / max) * 100));
    return `
      <div class="ipItem" data-tool-name="blueteam_investigate_ip" data-auto-run="true" data-pivot-ip="${esc(row.ip)}">
        <div>
          <strong>${esc(row.ip)}</strong>
          <small>${fmt.format(number(row.hits))} ${ui("hit rule", "rule hits")}</small>
        </div>
        <div class="miniBar"><span style="width:${width}%"></span></div>
        <b>${fmt.format(number(row.max_score))}</b>
      </div>
    `;
  }).join("") || '<div class="emptyState">No source IPs in top threat sample.</div>');
}

function renderCorrelation(data) {
  const cats = data.three_sum?.categories || [];
  const config = data.three_sum?.configuration || {};
  const windowLabel = data.requested_range || "24h";
  const lookback = number(config.lookback_minutes || data.three_sum?.lookback_minutes || 60);
  const threshold = number(config.threshold_score || data.three_sum?.threshold_score || 35);
  setText("#correlationMeta", `${windowLabel} view | ${lookback}m lookback`);
  setText("#correlationIntro", ui(`Kandidat memenuhi threshold skor ${threshold}+. Hitungan di bawah adalah source IP unik per kategori sinyal.`, `Candidates meet the ${threshold}+ score threshold. Counts below are unique source IPs by signal category.`));
  const fallback = [
    { name: "Recon", ip_count: 0, entries: 0 },
    { name: "Exploit", ip_count: 0, entries: 0 },
    { name: "Impact", ip_count: 0, entries: 0 },
  ];
  const rows = (cats.length ? cats : fallback).slice(0, 6);
  setHtml("#correlationGrid", rows.map((cat) => `
    <div class="corrCell">
      <span class="muted">${esc(cat.name || cat.category || "signal")}</span>
      <strong>${fmt.format(number(cat.ip_count || cat.entries || cat.count))}</strong>
      <small>${ui("source IP terdeteksi", "source IPs detected")}</small>
    </div>
  `).join(""));
}

function renderAiRecon(data) {
  const sources = data.ai_recon?.sources || [];
  const windowLabel = data.ai_recon?.window?.since || data.requested_range || "selected window";
  const sourceCount = number(data.ai_recon?.ai_agent_sources || sources.length);
  setText("#aiReconMeta", `${windowLabel} | ${fmt.format(sourceCount)} sources`);
  setText("#aiReconIntro", ui("Pola request menyerupai probe otomatis terhadap file sensitif. Ini belum membuktikan penggunaan AI atau keberhasilan eksploitasi.", "Request patterns resemble automated probing of sensitive files. This does not prove AI usage or successful exploitation."));
  setHtml("#aiReconList", sources.map((source) => `
    <div class="intelItem">
      <div>
        <strong>${esc(source.srcip || source.source_ip || "-")}</strong>
        <div class="muted">${fmt.format(number(source.alerts))} alerts</div>
        <button type="button" data-analysis-open="${esc(source.srcip || source.source_ip || "")}">${ui("Bukti & intelijen", "Evidence & intelligence")}</button>
      </div>
      <div>
        <span class="evidenceLabel">Observed paths</span>
        <div class="evidenceList">${(source.sensitive_paths || []).slice(0, 4).map((p) => `<div>${esc(p)}</div>`).join("") || '<span class="muted">No sensitive path pattern</span>'}</div>
      </div>
      <span class="pill ${number(source.sensitive_hits) > 0 ? "high" : "low"}">${fmt.format(number(source.sensitive_hits))} ${ui("hit path", "path hits")}</span>
    </div>
  `).join("") || `<div class="emptyState">${ui("Tidak ada sumber AI bot recon pada window ini.", "No AI bot recon sources in this window.")}</div>`);
}

function renderVulnerabilities(data) {
  const vulns = data.vulnerabilities || {};
  const rows = vulns.critical_items || [];
  setHtml("#criticalVulnList", `
    <div class="vulnStats">
      <span><b>${fmt.format(number(vulns.critical))}</b> Critical</span>
      <span><b>${fmt.format(number(vulns.high))}</b> High</span>
      <span><b>${fmt.format(number(vulns.medium))}</b> Medium</span>
      <span><b>${fmt.format(number(vulns.low))}</b> Low</span>
    </div>
    ${rows.map((item) => `
      <div class="vulnItem">
        <div>
          <strong>${esc(item.cve || item.id || item.vulnerability?.id || "Unknown CVE")}</strong>
          <div class="muted">${esc(item.package_name || item.package?.name || item.title || item.name || "affected package unknown")}</div>
        </div>
        <span class="pill critical">${esc(item.severity || item.vulnerability?.severity || "critical")}</span>
      </div>
    `).join("") || '<div class="emptyState">No critical vulnerability rows returned.</div>'}
  `);
}

function evidenceSignal(value, yes = "yes", no = "no") {
  if (value === true) return `<span class="statusMark available">${esc(yes)}</span>`;
  if (value === false) return `<span class="statusMark unavailable">${esc(no)}</span>`;
  return '<span class="statusMark unavailable">unknown</span>';
}

function renderCveExposureGraph(data) {
  const root = q("#cveExposureGraph");
  if (!root) return;
  const summary = data?.summary || {};
  const coverage = data?.coverage || {};
  const rows = (data?.paths || []).slice(0, 100);
  const denominator = Math.max(1, number(coverage.denominator));
  root.innerHTML = `
    <div class="evidenceMetrics evidenceMetricsCompact">
      <div class="evidenceMetric"><span>Exposure paths</span><strong>${fmt.format(number(summary.paths))}</strong><small>${fmt.format(number(summary.assets))} assets · ${fmt.format(number(summary.cves))} CVEs</small></div>
      <div class="evidenceMetric"><span>Critical paths</span><strong>${fmt.format(number(summary.critical_paths))}</strong><small>local priority score, analyst verification required</small></div>
      <div class="evidenceMetric"><span>Valid CPE</span><strong>${fmt.format(number(summary.valid_cpe))}</strong><small>${Math.round(number(coverage.cpe) / denominator * 100)}% of loaded paths</small></div>
      <div class="evidenceMetric"><span>Patch unknown</span><strong>${fmt.format(number(summary.patch_unknown))}</strong><small>${fmt.format(number(summary.case_linked))} linked to a case</small></div>
    </div>
    <div class="cvePathList" aria-label="CVE exposure relationships">
      ${rows.map(row => `
        <article class="cvePathRow">
          <div><span>Asset</span><strong>${esc(row.asset)}</strong><small>${esc(row.owner || "owner unknown")} · ${esc(row.criticality || "criticality unknown")}${row.internet_exposed === true ? " · internet exposed" : ""}</small></div>
          <div class="cveRelation" aria-hidden="true">runs</div>
          <div><span>Component</span><strong>${esc(row.component)}</strong><small>${esc(row.version || "version unknown")} · CPE ${esc(row.cpe_status)}</small></div>
          <div class="cveRelation" aria-hidden="true">affected by</div>
          <div><span>Vulnerability</span><strong>${esc(row.cve)}</strong><small>${esc(row.severity)} · score ${fmt.format(number(row.risk_score))}</small></div>
          <div class="cvePathSignals">${evidenceSignal(row.kev, "KEV", "not KEV")}${evidenceSignal(row.poc, "PoC", "no PoC")}${evidenceSignal(row.observed_exploitation, "observed exploit", "not observed")}<span class="statusMark ${row.patch_state === "patched" ? "available" : "skipped"}">${esc(row.patch_state)}</span>${row.case_id ? `<span class="statusMark available">${esc(row.case_id)}</span>` : '<span class="statusMark unavailable">case unlinked</span>'}</div>
        </article>
      `).join("") || '<div class="emptyState">No valid CVE exposure paths were returned from the current Wazuh vulnerability state.</div>'}
    </div>
    <details class="evidenceDetails"><summary>Accessible relationship table and limitations</summary>
      <div class="evidenceTableWrap"><table class="evidenceTable"><thead><tr><th>Asset</th><th>Component / version</th><th>CPE</th><th>CVE</th><th>EPSS / KEV / PoC</th><th>Exposure / patch</th><th>Case</th></tr></thead><tbody>
      ${rows.map(row => `<tr><td>${esc(row.asset)}</td><td>${esc(row.component)} ${esc(row.version || "")}</td><td>${esc(row.cpe || row.cpe_status)}</td><td>${esc(row.cve)}</td><td>${esc(row.epss ?? "unknown")} / ${esc(row.kev ?? "unknown")} / ${esc(row.poc ?? "unknown")}</td><td>${esc(row.exposure_state)} / ${esc(row.patch_state)}</td><td>${esc(row.case_id || "unlinked")}</td></tr>`).join("") || '<tr><td colspan="7">No relationships available.</td></tr>'}
      </tbody></table></div>
      <p class="evidenceNote">${esc((data?.limitations || []).join(" "))}</p>
    </details>
  `;
}

async function loadCveExposureGraph(force = false) {
  const windowPayload = currentWindowPayload();
  const windowKey = JSON.stringify(windowPayload);
  if (state.cveExposureLoading || (state.cveExposure && state.cveExposureWindow === windowKey && !force)) {
    if (state.cveExposure) renderCveExposureGraph(state.cveExposure);
    return;
  }
  state.cveExposureLoading = true;
  setText("#cveExposureStatus", "Loading bounded current-state inventory...");
  try {
    const data = await postJsonWithTimeout("/api/vulnerabilities/exposure", {...windowPayload, limit: 100}, 35000);
    state.cveExposure = data;
    state.cveExposureWindow = windowKey;
    renderCveExposureGraph(data);
    const exposureCoverage = data.coverage || {};
    renderCveEvidenceCoverage({vulnerabilities: {evidence_coverage: {
      wazuh_inventory: Boolean(exposureCoverage.wazuh_inventory),
      cpe: number(exposureCoverage.cpe) > 0,
      epss: number(exposureCoverage.epss) > 0,
      kev: number(exposureCoverage.kev) > 0,
      poc: number(exposureCoverage.poc) > 0,
      internet_exposure: number(exposureCoverage.internet_exposure) > 0,
      patch_state: number(exposureCoverage.patch_state) > 0,
      note: `Coverage is based on ${number(exposureCoverage.denominator)} bounded current-state exposure paths. Missing enrichment is shown as unknown and is never fetched during page load.`,
    }}});
    const cache = data.cache?.status ? ` · cache ${data.cache.status} (${evidenceAge(data.cache.age_seconds)})` : "";
    const source = data.history ? `stored history · ${fmt.format(number(data.history.unique_cves))} unique CVEs · no provider calls` : "current Wazuh inventory";
    setText("#cveExposureStatus", `${fmt.format(number(data.inventory_total))} inventory records · ${fmt.format(number(data.summary?.paths))} paths loaded · ${source}${cache}`);
  } catch (error) {
    setHtml("#cveExposureGraph", `<div class="errorPanel"><strong>Exposure graph unavailable</strong><p>${esc(error.message)}</p></div>`);
    setText("#cveExposureStatus", "Current-state inventory could not be loaded");
  } finally {
    state.cveExposureLoading = false;
  }
}

function renderAgents(data) {
  const agents = data.agents?.items || [];
  const counts = data.agents?.counts || {};
  const active = number(counts.active);
  setText("#assetSummary", ui(`${fmt.format(active)} aktif dari ${fmt.format(number(data.agents?.total))} agent`, `${fmt.format(active)} active of ${fmt.format(number(data.agents?.total))} agents`));
  setText("#agentCountLabel", ui(`${fmt.format(agents.length)} ditampilkan`, `${fmt.format(agents.length)} displayed`));
  const table = `
    <div class="tableHeader">
      <span>ID</span><span>${ui("Nama", "Name")}</span><span>IP</span><span>OS</span><span>Status</span>
    </div>
    ${agents.map((agent) => `
      <div class="tableRow">
        <span>${esc(agent.id || "-")}</span>
        <strong>${esc(agent.name || "-")}</strong>
        <span>${esc(agent.ip || "-")}</span>
        <span>${esc(agent.os?.name || agent.os?.platform || "-")}</span>
        <span class="pill ${agent.status === "active" ? "low" : "high"}">${esc(agent.status || "unknown")}</span>
      </div>
    `).join("") || `<div class="emptyState">${ui("Tidak ada agent dikembalikan.", "No agents returned.")}</div>`}
  `;
  setHtml("#agentTable", table);
  setHtml("#l1Agents", table);
}

function renderInsights(data) {
  const sev = data.alerts?.severity || {};
  const nonLow = number(sev.critical) + number(sev.high) + number(sev.medium);
  const criticalCves = number(data.vulnerabilities?.critical);
  const aiSources = number(data.ai_recon?.ai_agent_sources);
  const active = number(data.agents?.counts?.active);
  const total = number(data.agents?.total);
  const cards = [
    {
      view: "l1",
      tone: nonLow > 0 ? ui("Review", "Review") : ui("Kontrol Noise", "Noise Control"),
      title: nonLow > 0 ? ui(`${fmt.format(nonLow)} alert non-low`, `${fmt.format(nonLow)} non-low alert(s)`) : ui("Sampel terbaru mayoritas low severity", "Latest sample is mostly low severity"),
      body: ui("Mulai dari rule dan source IP teratas, lalu close atau eskalasi.", "Start from top rules and source IPs, then close or escalate."),
    },
    {
      view: "vuln",
      tone: criticalCves > 0 ? ui("Risiko Patch", "Patch Risk") : ui("Vuln Stabil", "Vuln Stable"),
      title: ui(`${fmt.format(criticalCves)} CVE kritis`, `${fmt.format(criticalCves)} critical CVE(s)`),
      body: ui(`${fmt.format(number(data.vulnerabilities?.high))} CVE high perlu owner dan SLA.`, `${fmt.format(number(data.vulnerabilities?.high))} high CVEs need owner and SLA.`),
    },
    {
      view: "l2",
      tone: aiSources > 0 ? "Recon" : "Intel",
      title: `${fmt.format(aiSources)} AI recon source(s)`,
      body: ui("Pivot ke pola path dan korelasikan dengan reputasi sumber.", "Pivot to path patterns and correlate with source reputation."),
    },
    {
      view: "assets",
      tone: active === total ? ui("Sehat", "Healthy") : ui("Perhatian", "Attention"),
      title: ui(`${fmt.format(active)} dari ${fmt.format(total)} agent aktif`, `${fmt.format(active)} of ${fmt.format(total)} agents active`),
      body: active === total ? ui("Cakupan online pada aset yang dikelola.", "Coverage is online across managed assets.") : ui("Agent nonaktif perlu follow-up endpoint.", "Inactive agents need endpoint follow-up."),
    },
  ];
  setHtml("#insightStrip", cards.map((card) => `
    <article class="insightCard" data-view-link="${esc(card.view)}">
      <span>${esc(card.tone)}</span>
      <strong>${esc(card.title)}</strong>
      <small>${esc(card.body)}</small>
    </article>
  `).join(""));
}

function renderDecisions(data) {
  const sev = data.alerts?.severity || {};
  const decisions = [
    ["1", ui("Kurangi noise dahulu", "Reduce noise first"), ui(`${fmt.format(number(sev.low))} event low severity disampel; review rule berulang teratas sebelum eskalasi.`, `${fmt.format(number(sev.low))} low severity events are sampled; review top repeated rules before escalation.`)],
    ["2", ui("Eskalasi risiko material", "Escalate material risk"), ui(`${fmt.format(number(sev.medium) + number(sev.high) + number(sev.critical))} event sampel non-low dan ${fmt.format(number(data.vulnerabilities?.critical))} CVE kritis masuk L2.`, `${fmt.format(number(sev.medium) + number(sev.high) + number(sev.critical))} non-low sample events and ${fmt.format(number(data.vulnerabilities?.critical))} critical CVEs belong in L2.`)],
    ["3", ui("Jaga cakupan", "Preserve coverage"), ui(`${fmt.format(number(data.agents?.counts?.active))} agent aktif dilaporkan; konfirmasi tidak ada blind spot sebelum closing.`, `${fmt.format(number(data.agents?.counts?.active))} active agents reported; confirm no blind spots before closing.`)],
  ];
  setHtml("#l1DecisionList", decisions.map(([n, title, body]) => `
    <div class="decisionItem">
      <b>${esc(n)}</b>
      <div>
        <strong>${esc(title)}</strong>
        <small>${esc(body)}</small>
      </div>
    </div>
  `).join(""));
}

function renderInvestigationFlow(data) {
  const caps = data.tools?.capabilities || {};
  const steps = [
    ["01", ui("Cluster alert", "Cluster alert"), ui(`${fmt.format(number(data.threats?.length))} deteksi teratas diranking oleh GenSecAI.`, `${fmt.format(number(data.threats?.length))} top detections ranked by GenSecAI.`)],
    ["02", ui("Pivot sumber", "Pivot source"), ui(`${fmt.format(number(data.source_ips?.length))} source IP diekstrak dari deteksi prioritas.`, `${fmt.format(number(data.source_ips?.length))} source IPs extracted from priority detections.`)],
    ["03", ui("Perkaya IOC", "Enrich IOC"), ui(`${fmt.format(capCount(caps, "threat_intel"))} tool threat intel tersedia.`, `${fmt.format(capCount(caps, "threat_intel"))} threat intel tools available.`)],
    ["04", ui("Cek paparan", "Check exposure"), ui(`${fmt.format(number(data.vulnerabilities?.critical))} CVE critical dan ${fmt.format(number(data.vulnerabilities?.high))} high.`, `${fmt.format(number(data.vulnerabilities?.critical))} critical and ${fmt.format(number(data.vulnerabilities?.high))} high CVEs.`)],
    ["05", ui("Tentukan aksi", "Decide action"), ui(`${fmt.format(capCount(caps, "response"))} helper response dipetakan untuk aksi terkontrol.`, `${fmt.format(capCount(caps, "response"))} response helpers mapped for controlled action.`)],
  ];
  setHtml("#investigationFlow", steps.map(([n, title, body]) => `
    <div class="flowStep" data-step="${esc(n)}">
      <strong>${esc(title)}</strong>
      <small>${esc(body)}</small>
    </div>
  `).join(""));
}

function severityFromScore(score) {
  if (score >= 80) return ["Critical", "critical"];
  if (score >= 55) return ["High", "high"];
  if (score >= 25) return ["Medium", "medium"];
  return ["Low", "low"];
}

function buildIncidents(data) {
  const sources = data.attack_surface?.sources?.length ? data.attack_surface.sources : data.source_ips || [];
  const targets = data.attack_surface?.targets || [];
  const reconRows = data.attack_surface?.web_recon || data.ai_recon?.sources || [];
  const cities = data.attack_surface?.cities || data.geo_heatmap?.cities || [];
  const layers = data.detection_layers || [];
  const criticalCves = number(data.vulnerabilities?.critical);
  const layerNames = layers.filter((layer) => number(layer.count) > 0).map((layer) => layer.name);
  const rows = sources.slice(0, 10).map((source, index) => {
    const recon = reconRows.find((row) => (row.srcip || row.source_ip) === source.ip) || {};
    const target = targets[index % Math.max(targets.length, 1)] || {};
    const city = cities[index % Math.max(cities.length, 1)] || {};
    const score = Math.min(100, Math.round(
      Math.min(45, number(source.max_score) / 3) +
      Math.min(24, number(recon.sensitive_hits) * 8) +
      Math.min(18, criticalCves * 2) +
      Math.min(13, number(source.hits) * 2)
    ));
    const [severity, tone] = severityFromScore(score);
    return {
      id: `INC-${String(index + 1).padStart(3, "0")}`,
      title: number(recon.sensitive_hits) > 0 ? "Web recon with exposed-path probing" : "Repeated source IP detection cluster",
      source: source.ip || "-",
      target: target.name || "multiple assets",
      city: city.city || "unknown origin",
      score,
      severity,
      tone,
      hits: number(source.hits),
      maxScore: number(source.max_score),
      rules: source.rules || target.rules || [],
      layers: layerNames.slice(0, 4),
      sensitivePaths: (recon.sensitive_paths || []).slice(0, 5),
    };
  });
  if (rows.length) return rows;
  return (data.threats || []).slice(0, 6).map((threat, index) => {
    const score = Math.min(100, Math.round(number(threat.threat_score) / 8));
    const [severity, tone] = severityFromScore(score);
    return {
      id: `INC-${String(index + 1).padStart(3, "0")}`,
      title: threat.description || "Wazuh alert cluster",
      source: (threat.source_ips || [])[0] || "-",
      target: ((threat.affected_agents || [])[0] || {}).name || "multiple assets",
      city: "unknown origin",
      score,
      severity,
      tone,
      hits: number(threat.count),
      maxScore: number(threat.threat_score),
      rules: [threat.rule_id].filter(Boolean),
      layers: layerNames.slice(0, 4),
      sensitivePaths: [],
    };
  });
}

function renderIncidentDetail(incident) {
  if (!els.incidentDetail) return;
  if (!incident) {
    els.incidentDetail.innerHTML = '<div class="emptyState">No incident selected.</div>';
    return;
  }
  els.incidentDetail.innerHTML = `
    <div class="incidentHero ${esc(incident.tone)}">
      <span>${esc(incident.id)}</span>
      <strong>${esc(incident.title)}</strong>
      <small>${esc(incident.severity)} risk | score ${fmt.format(number(incident.score))}</small>
    </div>
    <div class="resultMetrics">
      <div class="resultMetric"><span>source ip</span><strong>${esc(incident.source)}</strong></div>
      <div class="resultMetric"><span>target</span><strong>${esc(incident.target)}</strong></div>
      <div class="resultMetric"><span>origin</span><strong>${esc(incident.city)}</strong></div>
      <div class="resultMetric"><span>hits</span><strong>${fmt.format(number(incident.hits))}</strong></div>
    </div>
    <div class="incidentSections">
      <section>
        <h3>Evidence</h3>
        ${(incident.rules || []).slice(0, 5).map((rule) => `<span class="evidenceChip">Rule ${esc(rule)}</span>`).join("") || '<span class="evidenceChip">No rule pivot</span>'}
        ${(incident.sensitivePaths || []).map((path) => `<span class="evidenceChip">${esc(path)}</span>`).join("")}
      </section>
      <section>
        <h3>Detection Layers</h3>
        ${(incident.layers || []).map((layer) => `<span class="evidenceChip">${esc(layer)}</span>`).join("") || '<span class="evidenceChip">Layer context unavailable</span>'}
      </section>
      ${incident.persisted ? `<section>
        <h3>Case Lifecycle</h3>
        <dl class="caseLifecycle">
          <dt>Owner</dt><dd>${esc(evidenceValue(incident.owner, "Unassigned"))}</dd>
          <dt>Status</dt><dd>${esc(evidenceValue(incident.caseStatus, "Open"))}</dd>
          <dt>SLA due</dt><dd>${esc(evidenceValue(incident.slaDue, "Not set"))}</dd>
          <dt>Verdict</dt><dd>${esc(evidenceValue(incident.latestVerdict, "Not recorded"))}</dd>
          <dt>Containment</dt><dd>${esc(evidenceValue(incident.containment, "Not recorded"))}</dd>
          <dt>Closure reason</dt><dd>${esc(evidenceValue(incident.closureReason, "Not recorded"))}</dd>
          <dt>Notes</dt><dd>${esc(evidenceValue(incident.caseNotes, "Not recorded"))}</dd>
        </dl>
      </section>` : ""}
    </div>
    <div class="incidentActions">
      ${incident.persisted ? '<span class="evidenceChip">Persistent case</span>' : `<button type="button" data-save-incident="${esc(incident.id)}">Save as case</button>`}
      <button type="button" data-tool-name="blueteam_investigate_ip" data-pivot-ip="${esc(incident.source)}">Investigate IP</button>
      <button type="button" data-tool-name="wazuh_alert_aggregate_analysis" data-pivot-ip="${esc(incident.source)}">Alert Aggregate</button>
      <button type="button" data-tool-name="advanced_three_sum_correlation">3-Sum Correlation</button>
      <button type="button" data-tool-name="blueteam_cve_score">CVE Exposure</button>
    </div>
  `;
}

function renderIncidentBoard(data) {
  if (!els.incidentBoard) return;
  const persistent = (state.persistentCases || []).map((item) => {
    const verdict = item.latest_verdict?.verdict || "stored";
    const verdictStyle = {
      true_positive: ["Confirmed", "critical", 100],
      suspicious: ["Suspicious", "high", 75],
      false_positive: ["False positive", "low", 10],
      clean: ["Clean", "low", 5],
      unknown: ["Needs review", "medium", 40],
      stored: ["Stored", "low", 0],
    }[verdict] || ["Stored", "low", 0];
    return {
      id: item.case_id,
      title: item.title || "Stored SOC case",
      source: (item.srcips || [])[0] || "-",
      target: "case evidence",
      city: "stored investigation",
      score: verdictStyle[2],
      severity: verdictStyle[0],
      tone: verdictStyle[1],
      hits: (item.iocs || []).length,
      rules: [],
      layers: ["Persistent case store"],
      sensitivePaths: item.latest_verdict?.notes ? [item.latest_verdict.notes] : [],
      owner: item.owner,
      slaDue: item.sla_due,
      caseStatus: item.status,
      latestVerdict: item.latest_verdict?.verdict,
      containment: item.containment,
      closureReason: item.closure_reason,
      caseNotes: item.notes,
      persisted: true,
    };
  });
  const storedSources = new Set(persistent.map(item => item.source).filter(value => value && value !== "-"));
  const incidents = [...persistent, ...buildIncidents(data).filter(item => !storedSources.has(item.source))];
  state.incidents = incidents;
  if (state.selectedIncident >= incidents.length) state.selectedIncident = 0;
  els.incidentBoard.innerHTML = incidents.map((incident, index) => `
    <button class="incidentCard ${esc(incident.tone)} ${index === state.selectedIncident ? "active" : ""}" type="button" data-incident-index="${index}">
      <div>
        <span>${esc(incident.id)}</span>
        <strong>${esc(incident.title)}</strong>
        <small>${esc(incident.source)} -> ${esc(incident.target)}</small>
      </div>
      <div>
        <b>${fmt.format(number(incident.score))}</b>
        <span class="pill ${esc(incident.tone)}">${esc(incident.severity)}</span>
      </div>
    </button>
  `).join("") || '<div class="emptyState">No incident candidates built from current telemetry.</div>';
  renderIncidentDetail(incidents[state.selectedIncident]);
}

async function loadPersistentCases() {
  try {
    const result = await postJson("/api/incidents/list", {});
    state.persistentCases = result.ok ? result.cases || [] : [];
  } catch (_) {
    state.persistentCases = [];
  }
  renderIncidentBoard(state.overview || {});
  renderL1Queue(state.overview || {});
}

async function saveIncidentCase(incident, button) {
  if (!incident || incident.persisted) return;
  button.disabled = true;
  button.textContent = "Saving...";
  try {
    const result = await postJson("/api/incidents/create", {
      title: incident.title,
      srcips: [incident.source].filter(value => value && value !== "-"),
      notes: `Dashboard candidate ${incident.id}; target ${incident.target}; severity ${incident.severity}; rules ${(incident.rules || []).join(", ")}`,
    });
    if (!result.ok) throw new Error(result.error || "Case could not be saved");
    await loadPersistentCases();
  } catch (error) {
    button.disabled = false;
    button.textContent = `Retry: ${error.message}`;
  }
}

function renderHuntMatrix(data) {
  const caps = data.tools?.capabilities || {};
  const rows = [
    ["Recon", "AI bot recon, path probes, suspicious scanners", number(data.ai_recon?.ai_agent_sources)],
    ["IOC Intel", "ThreatFox, OTX, GreyNoise, CrowdSec pivots", capCount(caps, "threat_intel")],
    ["Exposure", "CVE, EPSS, KEV, PoC, dependency scan", capCount(caps, "vulnerability") + capCount(caps, "dependency")],
    ["Response", "Block, isolate, firewall, active response", capCount(caps, "response")],
  ];
  setHtml("#huntMatrix", rows.map(([name, body, value]) => `
    <div class="huntCell">
      <em>${fmt.format(number(value))} signals/tools</em>
      <strong>${esc(name)}</strong>
      <small>${esc(body)}</small>
    </div>
  `).join(""));
}

function fallbackProviderRows(data) {
  const caps = data?.tools?.capabilities || {};
  return [
    {
      provider: "CrowdSec",
      label: "IP reputation",
      tool: "crowdsec_ip_reputation",
      ok: true,
      status: "configured",
      summary: "Reputation lookup for source IP pivots.",
      duration_ms: 0,
    },
    {
      provider: "AlienVault OTX",
      label: "IOC pulses",
      tool: "otx_lookup",
      ok: true,
      status: "configured",
      summary: "OTX pulse and indicator enrichment.",
      duration_ms: 0,
    },
    {
      provider: "CYFIRMA",
      label: "Tailored STIX IOC feed",
      tool: "cyfirma_ioc_feed",
      ok: true,
      status: "configured",
      summary: "Tailored/global STIX indicators for campaign and IOC enrichment.",
      duration_ms: 0,
    },
    {
      provider: "VirusTotal",
      label: "Domain/hash reputation",
      tool: "blueteam_lookup_domain_virustotal",
      ok: true,
      status: "configured",
      summary: "Domain and file hash reputation checks.",
      duration_ms: 0,
    },
    {
      provider: "CVE Enrichment",
      label: "EPSS, KEV, PoC, SSVC",
      tool: "blueteam_cve_score",
      ok: capCount(caps, "vulnerability") > 0,
      status: capCount(caps, "vulnerability") > 0 ? "available" : "not discovered",
      summary: `${fmt.format(capCount(caps, "vulnerability"))} vulnerability tools available.`,
      duration_ms: 0,
    },
    {
      provider: "NVD/CVE",
      label: "CVE record lookup",
      tool: "blueteam_cve_lookup",
      ok: capCount(caps, "vulnerability") > 0,
      status: capCount(caps, "vulnerability") > 0 ? "available" : "not discovered",
      summary: "NVD-style CVE record lookup through INFOKOM enrichment tools.",
      duration_ms: 0,
    },
    {
      provider: "ThreatFox",
      label: "Malware IOC",
      tool: "threatfox_ioc_search",
      ok: false,
      status: "check key",
      summary: "Run API test to confirm provider key.",
      duration_ms: 0,
    },
    {
      provider: "URLHaus",
      label: "Malicious URL",
      tool: "urlhaus_lookup",
      ok: false,
      status: "check key",
      summary: "Run API test to confirm provider key.",
      duration_ms: 0,
    },
  ];
}

function providerMetric(label, value) {
  return `<span><b>${esc(value ?? "-")}</b>${esc(label)}</span>`;
}

function providerChips(items, empty = "No detail") {
  const rows = uniqueLabels(items, 8);
  return `<div class="providerChips">${rows.map((item) => `<span>${esc(item)}</span>`).join("") || `<span>${esc(empty)}</span>`}</div>`;
}

function providerEvidence(row) {
  const data = row.data;
  if (!data || typeof data !== "object") {
    return row.error ? `<div class="providerEvidence compact">${providerMetric("error", row.error)}</div>` : "";
  }
  const name = String(row.provider || "").toLowerCase();
  if (name.includes("crowdsec")) {
    return `
      <div class="providerEvidence">
        ${providerMetric("reputation", data.reputation || "unknown")}
        ${providerMetric("confidence", data.confidence || "-")}
        ${providerMetric("noise", data.background_noise || "-")}
        ${providerMetric("range", data.ip_range_24 || data.ip_range || "-")}
      </div>
      ${providerChips(data.classifications, "No classification")}
    `;
  }
  if (name.includes("cyfirma")) {
    const summary = data.summary || {};
    const labels = summary.labels ? Object.keys(summary.labels) : [];
    const phases = summary.kill_chain_phases ? Object.keys(summary.kill_chain_phases) : [];
    const feedCounts = data.feeds ? Object.entries(data.feeds).map(([scope, feed]) => `${scope}: ${number(feed?.count)}`) : [];
    return `
      <div class="providerEvidence">
        ${providerMetric("indicators", summary.count || 0)}
        ${providerMetric("feeds", feedCounts.join(" | ") || data.scope || "-")}
        ${providerMetric("labels", labels.length)}
        ${providerMetric("kill-chain", phases.length)}
      </div>
      ${providerChips(labels.concat(phases), "No STIX labels returned")}
    `;
  }
  if (name.includes("otx")) {
    const pulses = data.pulses || [];
    const malware = pulses.flatMap((pulse) => pulse.malware_families || []);
    const adversaries = pulses.map((pulse) => pulse.adversary).filter(Boolean);
    const attacks = pulses.flatMap((pulse) => pulse.attack_ids || []);
    return `
      <div class="providerEvidence">
        ${providerMetric("indicator", data.indicator || "-")}
        ${providerMetric("type", data.indicator_type || "-")}
        ${providerMetric("pulses", data.pulse_count || 0)}
        ${providerMetric("malware", uniqueLabels(malware, 99).length)}
      </div>
      ${providerChips(malware.concat(adversaries, attacks), "No OTX pulse context")}
    `;
  }
  if (name.includes("virus")) {
    return `
      <div class="providerEvidence verdictGrid">
        ${providerMetric("malicious", data.malicious || 0)}
        ${providerMetric("suspicious", data.suspicious || 0)}
        ${providerMetric("harmless", data.harmless || 0)}
        ${providerMetric("domain/hash", data.domain || data.hash || "-")}
      </div>
    `;
  }
  if (name.includes("cve") || name.includes("nvd")) {
    const results = data.results || [];
    const first = results[0] || data;
    return `
      <div class="providerEvidence">
        ${providerMetric("CVE", first.cve_id || data.cve_id || "-")}
        ${providerMetric("severity", first.severity || data.severity || "-")}
        ${providerMetric("CVSS", first.cvss_score || data.cvss_score || "-")}
        ${providerMetric("EPSS", first.epss || first.probability || "-")}
      </div>
      ${providerChips([...(first.weaknesses || []), ...(first.references || []).slice(0, 4)], "No enrichment detail")}
    `;
  }
  if (name.includes("unified")) {
    return `
      <div class="providerEvidence">
        ${providerMetric("score", data.unified_score ?? data.score ?? "-")}
        ${providerMetric("verdict", data.verdict || "-")}
        ${providerMetric("sources", Array.isArray(data.sources) ? data.sources.length : summarizeValue(data.sources))}
        ${providerMetric("model", data.scoring_model || "-")}
      </div>
    `;
  }
  if (name.includes("threatfox")) {
    const results = data.data || data.results || [];
    return `
      <div class="providerEvidence">
        ${providerMetric("status", data.query_status || data.status || "not ready")}
        ${providerMetric("matches", Array.isArray(results) ? results.length : 0)}
        ${providerMetric("error", data.error || row.error || "-")}
      </div>
    `;
  }
  if (name.includes("urlhaus")) {
    return `
      <div class="providerEvidence">
        ${providerMetric("status", data.query_status || row.status || "-")}
        ${providerMetric("url status", data.url_status || "-")}
        ${providerMetric("threat", data.threat || "-")}
        ${providerMetric("payloads", Array.isArray(data.payloads) ? data.payloads.length : 0)}
      </div>
    `;
  }
  return `
    <div class="providerEvidence">
      ${Object.entries(data).slice(0, 4).map(([key, value]) => providerMetric(key, summarizeValue(value))).join("")}
    </div>
  `;
}

function renderProviderIntel(payload = state.providerTests) {
  document.dispatchEvent(new CustomEvent("soc:intel"));
  if (!els.providerIntelGrid) return;
  const rows = payload?.providers?.length ? payload.providers : fallbackProviderRows(state.overview);
  const ready = payload?.summary?.ready ?? rows.filter((row) => row.ok).length;
  const total = payload?.summary?.total ?? rows.length;
  if (els.intelTestStatus) {
    const suffix = payload?.generated_at ? ` | checked ${payload.generated_at}${payload.cached ? " cached" : ""}` : " | not tested yet";
    els.intelTestStatus.textContent = `${fmt.format(ready)}/${fmt.format(total)} API checks successful${suffix}`;
  }
  els.providerIntelGrid.innerHTML = rows.map((row) => {
    const tone = row.ok ? "ready" : "attention";
    const action = row.tool ? `data-tool-name="${esc(row.tool)}"` : "";
    const testSubject = Object.entries(row.arguments || {}).filter(([key]) => ["ip", "indicator", "domain", "url", "search_term", "cve_id", "cve_ids", "scope"].includes(key)).map(([, value]) => Array.isArray(value) ? value.join(", ") : value).join(" / ");
    const explanation = row.status === "rate limited" ? ui("Kuota API tercapai. Tunggu reset kuota sebelum mencoba lagi.", "API quota reached. Wait for the quota reset before retrying.")
      : row.status === "connected; no match" ? ui("Tidak ada kecocokan untuk indikator uji. Ini tidak membuktikan indikator aman.", "No match for the test indicator. This does not establish that an indicator is safe.")
      : row.status === "insufficient data" ? ui("Data provider tidak cukup untuk menghitung risiko.", "Provider data is insufficient to calculate risk.")
      : ui("Hasil uji koneksi; tidak terkait dengan alert lokal.", "Connection test result; no local alert association.");
    const evidence = `<p>${esc(explanation)}</p><details><summary>${esc(ui("Respons uji API", "API test response"))}</summary>${providerEvidence(row)}<pre style="white-space:pre-wrap;overflow-wrap:anywhere">${esc(JSON.stringify(row.data ?? row.error ?? null, null, 2))}</pre></details>`;
    return `
      <article class="providerCard ${tone}">
        <div class="providerHead">
          <div>
            <strong>${esc(row.provider)}</strong>
            <small>${esc(row.label || row.tool || "provider")} ${testSubject ? `| ${esc(testSubject)}` : ""}</small>
          </div>
          <span class="pill ${row.ok ? "low" : "high"}">${esc(row.status || (row.ok ? "ready" : "attention"))}</span>
        </div>
        <p>${esc(row.summary || row.error || "No provider result yet.")}</p>
        ${evidence}
        <div class="providerActions">
          <button type="button" ${action}>Open Tool</button>
          <span>${row.duration_ms ? `${fmt.format(number(row.duration_ms))} ms` : "safe sample"}</span>
        </div>
      </article>
    `;
  }).join("");
}

async function testThreatIntel(silent = false, force = false) {
  if (!els.providerIntelGrid) return;
  state.providerTestsLoading = true;
  if (els.testIntel) els.testIntel.disabled = true;
  if (els.intelTestStatus && !silent) els.intelTestStatus.textContent = "Testing provider APIs...";
  if (!silent) els.providerIntelGrid.innerHTML = '<div class="emptyState">Checking threat-intel providers through INFOKOM MCP...</div>';
  try {
    const payload = await postJson("/api/threat-intel/test", { force });
    state.providerTests = payload;
    renderProviderIntel(payload);
  } catch (err) {
    if (els.intelTestStatus) els.intelTestStatus.textContent = `Provider test failed: ${err.message}`;
    els.providerIntelGrid.innerHTML = `<div class="errorPanel"><strong>Threat intel test failed</strong><p>${esc(err.message)}</p></div>`;
  } finally {
    state.providerTestsLoading = false;
    if (els.testIntel) els.testIntel.disabled = false;
  }
}

function isPublicIp(ip) {
  const text = String(ip || "").trim();
  const parts = text.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  return true;
}

function isPublicObservableIp(ip) {
  const value = String(ip || "").trim();
  if (!value.includes(":")) return isPublicIp(value);
  try {
    const host = new URL(`https://[${value}]/`).hostname.slice(1, -1);
    // Conservative UI eligibility; the API validates address scope with ipaddress.
    return /^[23][0-9a-f]{3}:/i.test(host) && !/^2001:db8:/i.test(host);
  } catch (_) { return false; }
}

function reputationTone(value) {
  const rep = String(value || "unknown").toLowerCase();
  if (rep.includes("malicious") || rep.includes("aggressive")) return "critical";
  if (rep.includes("suspicious") || rep.includes("unknown")) return "high";
  if (rep.includes("safe") || rep.includes("benign")) return "low";
  return "medium";
}

function mitreFromBehaviors(behaviors = []) {
  const text = arrayify(behaviors).map((item) => {
    if (typeof item === "string") return item.toLowerCase();
    return `${item?.name || ""} ${item?.label || ""}`.toLowerCase();
  }).join(" ");
  const rows = [];
  if (/brute/.test(text)) rows.push("Brute Force");
  if (/scan|crawl|fingerprint/.test(text)) rows.push("Active Scanning");
  if (/exploit|cve/.test(text)) rows.push("Exploit Public-Facing App");
  if (/dos|denial/.test(text)) rows.push("Network Denial of Service");
  if (/imap|pop3|ssh|http/.test(text)) rows.push("Valid Accounts");
  return rows.slice(0, 5);
}

function arrayify(value) {
  if (Array.isArray(value)) return value;
  if (!value) return [];
  return [value];
}

function collectionValues(value) {
  if (Array.isArray(value)) return value.flatMap(collectionValues);
  if (value == null || value === "") return [];
  if (typeof value !== "object") return [value];
  if (itemLabel(value)) return [value];
  const nested = value.classifications ?? value.items ?? value.behaviors ?? value.values;
  if (nested !== undefined && nested !== value) return collectionValues(nested);
  return Object.entries(value).flatMap(([key, item]) => {
    if (item === true) return [key];
    if (item === false || item == null || item === "") return [];
    return collectionValues(item);
  });
}

function itemLabel(item) {
  if (!item) return "";
  if (typeof item === "string") return item;
  if (typeof item === "number") return String(item);
  if (typeof item === "object") {
    return item.label || item.name || item.value || item.classification || item.technique || item.id || item.cve || item.key || "";
  }
  return String(item);
}

function uniqueLabels(items, limit = 8) {
  const seen = new Set();
  const labels = [];
  collectionValues(items).forEach((item) => {
    const label = itemLabel(item);
    if (!label) return;
    const key = label.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      labels.push(label);
    }
  });
  return labels.slice(0, limit);
}

function crowdLocation(row) {
  const loc = row.location || {};
  return [loc.city, loc.country].filter(Boolean).join(", ") || loc.country || "-";
}

function crowdHistory(row) {
  const history = row.history || {};
  return history.last_seen || history.lastSeen || row.last_seen || "-";
}

function crowdAttackDetails(row) {
  const details = row.attack_details;
  if (Array.isArray(details)) return uniqueLabels(details, 8);
  if (!details || typeof details !== "object") return [];
  const rows = [];
  Object.entries(details).forEach(([key, value]) => {
    if (Array.isArray(value)) {
      uniqueLabels(value, 4).forEach((label) => rows.push(`${key}: ${label}`));
    } else if (value && typeof value === "object") {
      const label = itemLabel(value);
      if (label) rows.push(`${key}: ${label}`);
    } else if (value !== undefined && value !== null && value !== "") {
      rows.push(`${key}: ${value}`);
    }
  });
  return rows.slice(0, 8);
}

function crowdMitreLabels(row) {
  const direct = uniqueLabels(row.mitre_techniques, 8);
  return direct.length ? direct : mitreFromBehaviors(row.behaviors || []);
}

function cveId(cve) {
  if (!cve) return "";
  if (typeof cve === "string") return cve;
  return cve.id || cve.cve || cve.cve_id || cve.name || "";
}

function cveType(row, cve) {
  return (typeof cve === "object" && (cve.description || cve.type)) || "Provider CVE reference; local exposure not verified";
}

function providerStatus(row) {
  if (!row) return "unknown";
  if (row.error) return "error";
  if (row.is_malicious) return "matched";
  if (row.detail?.skipped) return "skipped";
  return row.risk_level && row.risk_level !== "none" ? row.risk_level : "context";
}

function providerDisplayName(name) {
  const normalized = String(name || "").toLowerCase();
  return {
    crowdsec: "CrowdSec",
    threatfox: "ThreatFox",
    otx: "AlienVault OTX",
    greynoise: "GreyNoise",
    abuseipdb: "AbuseIPDB",
    virustotal: "VirusTotal",
    cyfirma: "CYFIRMA",
    urlhaus: "URLHaus",
  }[normalized] || name || "Provider";
}

function providerRow(providers, name) {
  return (providers || []).find((row) => String(row.provider || "").toLowerCase() === name);
}

function extractCves(value, bag = new Set()) {
  if (value == null) return bag;
  if (typeof value === "string") {
    for (const match of value.toUpperCase().matchAll(/CVE-\d{4}-\d{4,}/g)) bag.add(match[0]);
    return bag;
  }
  if (Array.isArray(value)) {
    for (const item of value) extractCves(item, bag);
    return bag;
  }
  if (typeof value === "object") {
    for (const item of Object.values(value)) extractCves(item, bag);
  }
  return bag;
}

function providerCves(providers, cyMatches = []) {
  const cves = new Set();
  for (const row of providers || []) {
    extractCves(row.cves, cves);
    extractCves(row.detail?.cves, cves);
    extractCves(row.detail?.threat_classification, cves);
    extractCves(row.detail?.malware_samples, cves);
    extractCves(row.detail?.pulses, cves);
  }
  extractCves(cyMatches, cves);
  return [...cves].slice(0, 12);
}

function providerTags(row) {
  const detail = row?.detail || {};
  return uniqueLabels([
    ...collectionValues(row?.tags),
    ...collectionValues(detail.tags),
    ...collectionValues(detail.classifications),
    ...collectionValues(detail.behaviors),
    detail.classification,
    detail.message,
    detail.as_owner,
    detail.country,
  ].filter(Boolean), 8);
}

function threatReason(row) {
  if (row.why) return row.why;
  const providers = row.providers || [];
  const matched = providers.filter((provider) => provider.is_malicious || providerStatus(provider) === "matched");
  const errors = providers.filter((provider) => provider.error);
  const cves = row.cves || [];
  const tags = uniqueLabels(providers.flatMap(providerTags), 8);
  const parts = [];
  if (matched.length) parts.push(`${matched.map((provider) => providerDisplayName(provider.provider)).join(", ")} returned adverse or matching intelligence.`);
  if (tags.length) parts.push(`Context: ${tags.join(", ")}.`);
  if (cves.length) parts.push(`Related CVE references: ${cves.join(", ")}.`);
  if (row.cyfirma_matches?.length) parts.push(`CYFIRMA has ${row.cyfirma_matches.length} exact IOC match(es) against loaded feeds.`);
  if (errors.length) parts.push(`${errors.length} provider(s) unavailable; treat missing data as unknown, not benign.`);
  return parts.join(" ") || "No provider returned malicious context yet; this indicator is still shown because Wazuh observed it in source telemetry.";
}

function crowdReason(row) {
  if (row.providers) return threatReason(row);
  if (row.why) return row.why;
  const behaviors = uniqueLabels(row.behaviors || [], 5);
  const classes = uniqueLabels(row.classifications || [], 4);
  const cves = arrayify(row.cves).map(cveId).filter(Boolean).slice(0, 5);
  const parts = [];
  const rep = row.reputation || "unknown";
  if (String(rep).toLowerCase() !== "unknown") parts.push(`CrowdSec marks this IP as ${rep}.`);
  if (classes.length) parts.push(`Classifications: ${classes.join(", ")}.`);
  if (behaviors.length) parts.push(`Observed behaviors: ${behaviors.join(", ")}.`);
  if (cves.length) parts.push(`Related CVE activity: ${cves.join(", ")}.`);
  if (row.background_noise) parts.push(`Background noise is ${row.background_noise}.`);
  if (row.confidence) parts.push(`Confidence ${row.confidence}.`);
  return parts.join(" ") || "No CrowdSec malicious context returned yet; this IP is still shown because Wazuh observed it in source telemetry.";
}

function providerMiniCards(providers) {
  const rows = providers || [];
  if (!rows.length) {
    return `<div class="intelProviderMini attention">
      <div><strong>Provider enrichment</strong><span>queued</span></div>
      <p>Waiting for provider results. Wazuh evidence is already loaded.</p>
    </div>`;
  }
  return rows.map((row) => {
    const status = providerStatus(row);
    const tone = row.error ? "attention" : row.is_malicious ? "danger" : "ready";
    const tags = providerTags(row);
    const detail = row.detail || {};
    const stat = detail.pulse_count ?? detail.detections ?? detail.reputation ?? detail.classification ?? row.risk_level ?? status;
    const scanned = detail.scanned || {};
    const scannedSummary = row.provider === "cyfirma" && (scanned.tailored || scanned.global)
      ? `Feed scanned: ${fmt.format(number(scanned.tailored))} tailored, ${fmt.format(number(scanned.global))} global. No exact IOC match for this IP.`
      : "";
    const displayTags = scannedSummary ? [`tailored ${fmt.format(number(scanned.tailored))}`, `global ${fmt.format(number(scanned.global))}`] : tags.slice(0, 3);
    const summary = row.error ? "Provider returned an error or quota response." : (scannedSummary || row.summary || summarizeValue(stat));
    const detailText = row.error || row.summary || summarizeValue(stat) || "No additional detail returned.";
    return `<div class="intelProviderMini ${tone}">
      <div><strong>${esc(providerDisplayName(row.provider))}</strong><span>${esc(status)}</span></div>
      <p>${esc(summary)}</p>
      ${providerChips(displayTags, "No provider detail")}
      <details>
        <summary>Details</summary>
        <small>${esc(scannedSummary || detailText)}</small>
      </details>
    </div>`;
  }).join("");
}

function providerQuality(row) {
  if (!row) return 0;
  let score = 0;
  if (!row.error) score += 10;
  if (row.is_malicious) score += 8;
  if (row.risk_level && row.risk_level !== "none") score += 4;
  score += Math.min(6, providerTags(row).length);
  score += Math.min(4, providerCves([row], []).length);
  return score;
}

function mergeProviderRows(rows) {
  const byProvider = new Map();
  arrayify(rows).forEach((row) => {
    if (!row || typeof row !== "object") return;
    const rawProvider = String(row.provider || "unknown").trim().toLowerCase().replace(/[^a-z0-9]+/g, "");
    const provider = {
      alienvault: "otx",
      alienvaultotx: "otx",
      otxalienvault: "otx",
      vt: "virustotal",
      crowdsecurity: "crowdsec",
    }[rawProvider] || rawProvider;
    const existing = byProvider.get(provider);
    if (!existing || providerQuality(row) > providerQuality(existing)) byProvider.set(provider, row);
  });
  return [...byProvider.values()].sort((a, b) => providerQuality(b) - providerQuality(a));
}

function mergeIntelRows(rows) {
  const byIp = new Map();
  arrayify(rows).forEach((row) => {
    if (!row?.ip) return;
    const existing = byIp.get(row.ip) || { ip: row.ip, providers: [], cyfirma_matches: [], cves: [] };
    const providers = mergeProviderRows([...(existing.providers || []), ...(row.providers || [])]);
    const cyMatches = [...arrayify(existing.cyfirma_matches), ...arrayify(row.cyfirma_matches)];
    const cves = uniqueLabels([...arrayify(existing.cves), ...arrayify(row.cves)], 20);
    byIp.set(row.ip, {
      ...existing,
      ...row,
      providers,
      cyfirma_matches: cyMatches.filter((item, index, arr) => {
        const label = String(item?.id || item?.pattern || item?.name || itemLabel(item) || JSON.stringify(item)).trim().toLowerCase();
        return arr.findIndex((other) => String(other?.id || other?.pattern || other?.name || itemLabel(other) || JSON.stringify(other)).trim().toLowerCase() === label) === index;
      }),
      cves,
      malicious: Boolean(existing.malicious || row.malicious),
      observed_hits: Math.max(number(existing.observed_hits), number(row.observed_hits)),
      observed_score: Math.max(number(existing.observed_score), number(row.observed_score)),
      watchlist: Boolean(existing.watchlist || row.watchlist),
    });
  });
  return [...byIp.values()];
}

function renderCrowdSecIntel(payload = state.crowdSecIntel) {
  document.dispatchEvent(new CustomEvent("soc:intel"));
  if (!els.crowdSecPanel) return;
  if (state.crowdSecLoading && !payload) {
    els.crowdSecPanel.innerHTML = '<div class="emptyState">Enriching Wazuh source IPs with multi-provider threat intelligence...</div>';
    return;
  }
  const rows = payload?.rows || [];
  const malicious = rows.filter((row) => row.malicious || reputationTone(row.reputation) === "critical").length;
  const unknown = rows.filter((row) => !row.malicious && !row.providers?.some((provider) => !provider.error && !provider.detail?.skipped)).length;
  const enriched = rows.filter((row) => row.providers?.length).length;
  const pending = rows.length - enriched;
  if (els.crowdSecStatus) {
    els.crowdSecStatus.textContent = payload
      ? `${fmt.format(enriched)}/${fmt.format(rows.length)} enriched${pending > 0 ? ` | ${fmt.format(pending)} pending` : ""} | ${fmt.format(malicious)} suspicious/malicious | ${fmt.format(unknown)} unknown | ${payload.generated_at || "now"}`
      : "Waiting for Wazuh source IPs";
  }
  if (!payload) {
    els.crowdSecPanel.innerHTML = '<div class="emptyState">CrowdSec CTI will load automatically from Wazuh source IPs.</div>';
    return;
  }
  if (!rows.length) {
    els.crowdSecPanel.innerHTML = `
      <div class="emptyState">
        No public source IPs found in the current Wazuh threat sample. Private/internal IPs are skipped for CrowdSec CTI lookup.
      </div>
    `;
    return;
  }
  const leader = rows[0] || {};
  const totalCves = rows.reduce((sum, row) => sum + number(row.cves?.length), 0);
  const totalProviders = rows.reduce((sum, row) => sum + number(row.providers?.filter((provider) => !provider.error).length), 0);
  const totalCyfirma = rows.reduce((sum, row) => sum + number(row.cyfirma_matches?.length), 0);
  els.crowdSecPanel.innerHTML = `
    <div class="crowdHero ${esc(reputationTone(leader.reputation))}">
      <div>
        <span>Multi-provider threat intelligence</span>
        <strong>${fmt.format(malicious)} suspicious or malicious indicators</strong>
        <small>Auto-enriched from Wazuh source IPs with CrowdSec, OTX, GreyNoise, VirusTotal, ThreatFox, AbuseIPDB, URLHaus, CYFIRMA and CVE context where available.</small>
      </div>
      <div class="crowdScore">
        <b>${fmt.format(totalProviders)}</b>
        <small>provider results</small>
      </div>
      <div class="crowdScore">
        <b>${fmt.format(totalCves)}</b>
        <small>CVE refs</small>
      </div>
      <div class="crowdScore">
        <b>${fmt.format(totalCyfirma)}</b>
        <small>CYFIRMA matches</small>
      </div>
    </div>
    <div class="crowdList">
      ${rows.map((row) => {
        const providers = mergeProviderRows(row.providers);
        const crowd = providerRow(providers, "crowdsec")?.detail || {};
        const cyMatches = arrayify(row.cyfirma_matches);
        const behaviors = collectionValues(row.behaviors || crowd.behaviors);
        const cves = uniqueLabels(row.cves, 20);
        const classifications = uniqueLabels(row.classifications || crowd.classifications || [], 8);
        const attacks = crowdAttackDetails({...crowd, ...row});
        const mitre = crowdMitreLabels({...crowd, ...row});
        const tone = row.malicious ? "critical" : row.providers?.some((provider) => provider.error) ? "high" : reputationTone(row.reputation);
        const location = crowdLocation(row);
        const range = row.ip_range_24 || row.ip_range || crowd.ip_range_24 || crowd.ip_range || "-";
        const sourceLabel = row.historical_only
          ? "Retained provider history"
          : row.watchlist && !number(row.observed_hits) ? "CrowdSec watchlist" : "Wazuh observed";
        return `
          <article class="crowdCard ${esc(tone)}" tabindex="0" data-tool-name="blueteam_threat_intel_aggregate" data-pivot-ip="${esc(row.ip)}">
            <div class="crowdCardHead">
              <div>
                <strong>${esc(row.ip)}</strong>
                <small>${esc(sourceLabel)} | ${fmt.format(number(row.observed_hits))} Wazuh hit(s) | max score ${fmt.format(number(row.observed_score))} | ${esc(location)}</small>
              </div>
              <span class="pill ${esc(tone)}">${esc(row.malicious ? "suspected" : row.reputation || row.aggregate_risk || "unknown")}</span>
            </div>
            <div class="crowdWhy">
              <b>Analyst meaning</b>
              <p>${esc(crowdReason(row))}</p>
            </div>
            <div class="intelProviderGrid">${providerMiniCards(providers)}</div>
            <div class="crowdMetaGrid">
              <span><b>${esc(row.confidence ?? crowd.confidence ?? "-")}</b> confidence</span>
              <span><b>${esc(row.background_noise || crowd.background_noise || "-")}</b> noise</span>
              <span><b>${esc(range)}</b> IP range</span>
              <span><b>${esc(row.as_name || crowd.as_name || providerRow(providers, "virustotal")?.detail?.as_owner || "-")}</b> ASN</span>
              <span><b>${esc(crowdHistory(row))}</b> last seen</span>
              <span><b>${fmt.format(cves.length)}</b> CVE refs</span>
            </div>
            <div class="crowdSections">
              <div>
                <b>Behaviors</b>
                <div class="crowdChips">${uniqueLabels(behaviors, 10).map((item) => `<span>${esc(item)}</span>`).join("") || "<span>No behavior returned</span>"}</div>
              </div>
              <div>
                <b>Classifications</b>
                <div class="crowdChips">${classifications.map((item) => `<span>${esc(item)}</span>`).join("") || "<span>No classification returned</span>"}</div>
              </div>
              <div>
                <b>Attack Details</b>
                <div class="crowdChips attackChips">${attacks.map((item) => `<span>${esc(item)}</span>`).join("") || "<span>No attack details returned</span>"}</div>
              </div>
              <div>
                <b>CVE Context</b>
                <div class="crowdChips cveChips">
                  ${cves.slice(0, 12).map((item) => `<span>${esc(cveId(item) || itemLabel(item))}<em>${esc(cveType(row, item))}</em></span>`).join("") || "<span>No CVE references</span>"}
                </div>
              </div>
              <div>
                <b>CYFIRMA matches</b>
                <div class="crowdChips">${cyMatches.slice(0, 8).map((item) => `<span>${esc(item?.name || item?.id || item?.pattern || itemLabel(item) || "CYFIRMA IOC")}<em>${esc(uniqueLabels([collectionValues(item?.labels), collectionValues(item?.iocs)], 4).join(", ") || item?.description || "feed context")}</em></span>`).join("") || "<span>No exact CYFIRMA IOC match</span>"}</div>
              </div>
            </div>
            <div class="crowdMitre">
              ${mitre.map((item) => `<span>${esc(item)}</span>`).join("") || "<span>MITRE inference unavailable</span>"}
            </div>
          </article>
        `;
      }).join("")}
    </div>
  `;
}

async function loadCrowdSecIntel(silent = true, live = false) {
  if (!els.crowdSecPanel || !state.overview || state.crowdSecLoading) return;
  const observed = Object.fromEntries((state.overview.source_ips || []).map((row) => [row.ip, row]));
  const candidatesByIp = new Map();
  const addCandidate = (ip, source, rank = 0) => {
    if (!isPublicIp(ip)) return;
    const existing = candidatesByIp.get(ip) || { ip, sources: new Set(), rank: 0 };
    existing.sources.add(source);
    existing.rank = Math.max(existing.rank, rank);
    candidatesByIp.set(ip, existing);
  };
  (state.overview.source_ips || []).slice(0, 14).forEach((row, index) => addCandidate(row.ip, "Wazuh observed", 100 - index));
  (window.SocAutomation?.report?.findings || []).slice(0, 12).forEach((row, index) => addCandidate(row.indicator, "Automation finding", 90 - index));
  (state.overview.crowdsec_watchlist_ips || []).slice(0, 8).forEach((ip, index) => addCandidate(ip, "Watchlist", 80 - index));
  state.crowdSecLoading = true;
  const automationByIndicator = new Map((window.SocAutomation?.report?.findings || []).map((row) => [row.indicator, row]));
  let historicalByIndicator = new Map();
  let historicalCatalog = [];
  try {
    const stored = await postJson("/api/history/intelligence", {...currentWindowPayload(), offset: 0});
    historicalByIndicator = new Map((stored.intelligence || []).map((row) => [row.indicator, row]));
    historicalCatalog = arrayify(stored.indicator_catalog);
  } catch (_) {
    historicalByIndicator = new Map();
  }
  // Historical provider observations may not be in the current Wazuh top-IP
  // sample. Keep them discoverable with a small local-only catalog.
  historicalCatalog.slice(0, 32).forEach((row, index) => {
    addCandidate(row.indicator, "Retained provider history", 70 - Math.min(index, 31) / 100);
  });
  const candidates = [...candidatesByIp.values()]
    .sort((a, b) => b.rank - a.rank)
    .slice(0, 16);
  const ips = candidates.map((row) => row.ip);
  if (!ips.length) {
    state.crowdSecIntel = {
      generated_at: state.overview.generated_at,
      rows: [],
    };
    renderCrowdSecIntel(state.crowdSecIntel);
    return;
  }
  const historicalOnlyCandidates = candidates
    .filter((candidate) => candidate.sources.has("Retained provider history") && !historicalByIndicator.has(candidate.ip))
    .slice(0, 8);
  if (historicalOnlyCandidates.length) {
    const detailResponses = await Promise.allSettled(historicalOnlyCandidates.map((candidate) =>
      postJson("/api/history/intelligence", {...currentWindowPayload(), query: candidate.ip, offset: 0})
    ));
    detailResponses.forEach((response) => {
      if (response.status !== "fulfilled") return;
      (response.value?.intelligence || []).forEach((row) => historicalByIndicator.set(row.indicator, row));
    });
  }
  const storedRows = candidates.map((candidate) => {
    const automation = automationByIndicator.get(candidate.ip) || {};
    const historical = historicalByIndicator.get(candidate.ip) || {};
    const result = historical.result || {};
    const data = result.data || {};
    const providers = mergeProviderRows([
      ...arrayify(automation.providers),
      ...arrayify(data.results),
    ].filter((provider) => provider && typeof provider === "object"));
    const cyMatches = [...arrayify(automation.cyfirma_matches), ...arrayify(data.cyfirma_matches)];
    const cves = uniqueLabels([
      ...providerCves(providers, cyMatches), ...arrayify(historical.cve_refs), ...arrayify(data.historical_cves),
    ], 20);
    const hasStored = providers.length > 0 || cyMatches.length > 0 || Boolean(historical.observed_at);
    return {
      ip: candidate.ip, providers, cyfirma_matches: cyMatches, cves,
      aggregate_risk: data.aggregated_risk_level || historical.risk || automation.status || "unknown",
      reputation: data.aggregated_risk_level || historical.risk || "unknown",
      malicious: Boolean(data.consensus_malicious || historical.malicious || automation.status === "suspected"),
      why: hasStored
        ? "Loaded from retained provider intelligence; opening the dashboard did not call external APIs."
        : "No retained provider result in the selected window; scheduled enrichment will process this indicator by priority.",
      observed_hits: observed[candidate.ip]?.hits || automation.event_total || 0,
      observed_score: observed[candidate.ip]?.max_score || automation.level || 0,
      watchlist: (state.overview.crowdsec_watchlist_ips || []).includes(candidate.ip),
      historical_only: !observed[candidate.ip] && !automation.indicator && !((state.overview.crowdsec_watchlist_ips || []).includes(candidate.ip)),
      enriched_at: historical.observed_at || automation.enriched_at,
    };
  });
  state.crowdSecIntel = {
    generated_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    ok: true, loading: false, errors: [], ips,
    rows: mergeIntelRows(storedRows),
    stored_only: !live,
  };
  renderCrowdSecIntel(state.crowdSecIntel);
  if (!live) {
    state.crowdSecLoading = false;
    return;
  }
  const requestId = ++state.crowdSecRequestId;
  const watchlistIps = (state.overview.crowdsec_watchlist_ips || []).filter(isPublicIp);
  state.crowdSecIntel = {
    generated_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    ok: true,
    loading: true,
    errors: [],
    ips,
    rows: candidates.map((candidate) => ({
      ip: candidate.ip,
      providers: [],
      cyfirma_matches: [],
      cves: [],
      aggregate_risk: "pending",
      reputation: "pending",
      malicious: false,
      why: `Queued for multi-provider enrichment from ${[...candidate.sources].join(", ")}.`,
      observed_hits: observed[candidate.ip]?.hits || 0,
      observed_score: observed[candidate.ip]?.max_score || 0,
      watchlist: watchlistIps.includes(candidate.ip),
    })),
  };
  renderCrowdSecIntel(state.crowdSecIntel);
  try {
    const batchErrors = [];
    for (let offset = 0; offset < ips.length; offset += 4) {
      if (requestId !== state.crowdSecRequestId) return;
      const chunk = ips.slice(offset, offset + 4);
      const responses = await Promise.allSettled(chunk.map((ip) => postJsonWithTimeout("/api/findings/intel", {
        kind: "aggregate",
        indicator: ip,
      }, 25000)));
      const enrichedRows = [];
      responses.forEach((response, index) => {
        const ip = chunk[index];
        if (response.status !== "fulfilled") {
          batchErrors.push(`${ip}: ${response.reason?.message || response.reason}`);
          enrichedRows.push({ip, providers: [], error: response.reason?.message || String(response.reason || "lookup failed"), reputation: "unknown"});
          return;
        }
        const result = response.value || {};
        const data = result.data || {};
        const providers = arrayify(data.results).filter((provider) => provider && typeof provider === "object").map((provider) => ({
          ...provider,
          provider: provider.provider || "unknown",
          detail: provider.detail || {},
        }));
        const automation = automationByIndicator.get(ip) || {};
        const cyMatches = [...arrayify(automation.cyfirma_matches), ...arrayify(data.cyfirma_matches)];
        const cves = uniqueLabels([...providerCves(providers, cyMatches), ...arrayify(data.historical_cves)], 20);
        enrichedRows.push({
          ip,
          providers: mergeProviderRows(providers),
          cyfirma_matches: cyMatches,
          cves,
          aggregate_risk: data.aggregated_risk_level,
          malicious: Boolean(data.consensus_malicious) || providers.some((provider) => provider.is_malicious) || cyMatches.length > 0,
          reputation: data.aggregated_risk_level || providerRow(providers, "crowdsec")?.detail?.reputation || "unknown",
          why: result.memory_reused ? "Using historical provider enrichment from the SOC automation cache while live provider data refreshes." : automation.status === "suspected" ? "Matched automation finding from local Wazuh evidence and provider/CYFIRMA context." : "",
          error: result.error,
        });
      });
      const rows = mergeIntelRows([...(state.crowdSecIntel?.rows || []), ...enrichedRows]).sort((a, b) => {
        const toneScore = { critical: 4, high: 3, medium: 2, low: 1 };
        if (Number(b.malicious) !== Number(a.malicious)) return Number(b.malicious) - Number(a.malicious);
        return (toneScore[reputationTone(b.reputation)] || 0) - (toneScore[reputationTone(a.reputation)] || 0)
          || number(b.cves?.length) - number(a.cves?.length)
          || number(b.providers?.filter((provider) => !provider.error).length) - number(a.providers?.filter((provider) => !provider.error).length)
          || number(b.observed_score) - number(a.observed_score);
      });
      state.crowdSecIntel = {
        ...state.crowdSecIntel,
        generated_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
        ok: batchErrors.length === 0,
        errors: batchErrors,
        rows,
      };
      renderCrowdSecIntel(state.crowdSecIntel);
    }
    if (!state.crowdSecIntel?.rows?.length && batchErrors.length) throw new Error(batchErrors.join("; "));
    state.crowdSecIntel = {...state.crowdSecIntel, loading: false, ok: batchErrors.length === 0, errors: batchErrors};
    renderCrowdSecIntel(state.crowdSecIntel);
    if (batchErrors.length && els.crowdSecStatus) els.crowdSecStatus.textContent += ` | ${batchErrors.length} batches unavailable`;
  } catch (err) {
    state.crowdSecIntel = {
      ...(state.crowdSecIntel || {}),
      ok: false,
      loading: false,
      error: err.message,
      rows: state.crowdSecIntel?.rows || [],
    };
    if (els.crowdSecStatus) els.crowdSecStatus.textContent = `Threat intelligence lookup failed: ${err.message}`;
    if (!state.crowdSecIntel.rows.length) {
      els.crowdSecPanel.innerHTML = `<div class="errorPanel"><strong>Threat intelligence lookup failed</strong><p>${esc(err.message)}</p></div>`;
    } else {
      renderCrowdSecIntel(state.crowdSecIntel);
      els.crowdSecPanel.insertAdjacentHTML("afterbegin", `<div class="errorPanel compact"><strong>Some intelligence could not be rendered</strong><p>${esc(err.message)}</p></div>`);
    }
  } finally {
    if (requestId === state.crowdSecRequestId) state.crowdSecLoading = false;
  }
}

function renderDonut(donutSelector, legendSelector, values) {
  const donut = q(donutSelector);
  const legend = q(legendSelector);
  if (!donut || !legend) return;
  const entries = Object.entries(values || {}).filter(([, value]) => number(value) > 0);
  const total = entries.reduce((sum, [, value]) => sum + number(value), 0);
  if (!entries.length || !total) {
    donut.style.background = "rgba(255,255,255,.08)";
    legend.innerHTML = '<div class="emptyState">No data</div>';
    return;
  }
  let cursor = 0;
  const segments = entries.map(([, value], index) => {
    const start = cursor;
    cursor += (number(value) / total) * 360;
    return `${palette[index % palette.length]} ${start}deg ${cursor}deg`;
  });
  donut.style.background = `conic-gradient(${segments.join(", ")})`;
  legend.innerHTML = entries.map(([label, value], index) => `
    <div class="legendRow">
      <span class="legendSwatch" style="background:${palette[index % palette.length]}"></span>
      <span>${esc(label)}</span>
      <strong>${fmt.format(number(value))}</strong>
    </div>
  `).join("");
}

function capabilityCard(name, value, desc) {
  return `
    <div class="capabilityItem">
      <span class="pill infokom">${fmt.format(number(value))}</span>
      <div>
        <strong>${esc(name)}</strong>
        <small>${esc(desc)}</small>
      </div>
    </div>
  `;
}

function renderCapabilities(data) {
  const caps = data.tools?.capabilities || {};
  const huntRows = [
    ["Threat Hunting", capCount(caps, "hunt"), "INFOKOM/Wazuh hunt and IOC pivots"],
    ["Threat Intel", capCount(caps, "threat_intel"), "OTX, GreyNoise, ThreatFox, CrowdSec checks"],
    ["AI Recon", data.ai_recon?.ai_agent_sources, "Bot and suspicious path recon findings"],
    ["Correlation", data.three_sum?.candidate_count, "Three-sum multi-signal candidates"],
  ];
  const responseRows = [
    ["Response/SOAR", capCount(caps, "response"), "Containment and response helper tools"],
    ["Compliance", capCount(caps, "compliance"), "PCI/GDPR/HIPAA/NIST evidence helpers"],
    ["Dependency Scan", capCount(caps, "dependency"), "Package and software dependency triage"],
    ["CVE Enrichment", capCount(caps, "vulnerability"), "EPSS, KEV, PoC, advisory, SSVC scoring"],
  ];
  setHtml("#huntCapabilities", huntRows.map(([name, value, desc]) => capabilityCard(name, value, desc)).join(""));
  setHtml("#responseCapabilities", responseRows.map(([name, value, desc]) => capabilityCard(name, value, desc)).join(""));
}

function inputTypeForSetting(field) {
  if (field.type === "integer") return "number";
  if (field.type === "email") return "email";
  if (field.type === "secret") return "password";
  if (field.type === "url" || field.type === "url_optional") return "url";
  return "text";
}

function settingPlaceholder(field) {
  if (field.type === "secret") return field.configured ? "Configured - leave blank to keep" : "Paste secret";
  if (field.type === "path") return "/absolute/path";
  if (field.type === "url" || field.type === "url_optional") return "http://service:port";
  if (field.type === "csv_ips") return "104.28.217.137,104.28.202.178";
  return "";
}

function renderSettingsForm(settings) {
  if (!els.settingsFields) return;
  const config = settings?.config || {};
  const fields = config.fields || [];
  const groups = fields.reduce((acc, field) => {
    (acc[field.group] ||= []).push(field);
    return acc;
  }, {});
  els.settingsFields.innerHTML = Object.entries(groups).map(([group, rows]) => `
    <section class="settingsGroup">
      <div class="settingsGroupHead">
        <h3>${esc(group)}</h3>
        <span>${fmt.format(rows.length)} fields</span>
      </div>
      ${rows.map((field) => field.type === "boolean" ? `
        <label class="settingField toggleField">
          <span>
            <strong>${esc(field.label)}</strong>
            <small>${esc(field.key)}${field.restart ? " | restart" : ""}</small>
          </span>
          <input type="checkbox" name="${esc(field.key)}" ${field.value === "true" ? "checked" : ""}>
        </label>
      ` : `
        <label class="settingField">
          <span>
            <strong>${esc(field.label)}</strong>
            <small>${esc(field.key)}${field.required ? " | required" : ""}${field.restart ? " | restart" : ""}</small>
          </span>
          ${field.type === "choice" ? `<select name="${esc(field.key)}">${field.options.map(value => `<option value="${esc(value)}" ${field.value === value ? "selected" : ""}>${esc(({en: "English", id: "Indonesia", oauth2: "OAuth2 (Microsoft 365)", password: "Password"})[value] || value)}</option>`).join("")}</select>` : `<input
            type="${inputTypeForSetting(field)}"
            name="${esc(field.key)}"
            value="${esc(field.value || "")}"
            placeholder="${esc(settingPlaceholder(field))}"
            ${field.required && field.type !== "secret" ? "required" : ""}
          >`}
        </label>
      `).join("")}
    </section>
  `).join("") || '<div class="emptyState">No settings schema returned.</div>';
  if (els.settingsStatus) {
    els.settingsStatus.textContent = `${config.enabled ? "editable" : "read-only"} | ${config.writable ? "writable" : "not writable"}`;
  }
  if (els.saveSettings) {
    els.saveSettings.disabled = !config.enabled || !config.writable;
  }
}

function renderSettings() {
  const s = state.settings;
  if (!s) return;
  const rootDisk = s.storage?.root_disk || {};
  const dataDisk = s.storage?.data_disk || {};
  const runtimeDisk = s.storage?.runtime_disk || {};
  const cache = s.storage?.cache || {};
  const automationStore = s.storage?.automation || {};
  const pipeline = s.pipeline || {};
  const backfill = pipeline.rollup?.backfill || {};
  const rollupGaps = pipeline.rollup?.gaps || {};
  const backfillEta = number(backfill.estimated_completion_seconds) > 0
    ? `${Math.max(1, Math.ceil(number(backfill.estimated_completion_seconds) / 3600))}h ETA`
    : (backfill.complete ? "complete" : "calculating ETA");
  renderSettingsForm(s);
  setHtml("#settingsList", `
    <dt>GenSecAI URL</dt><dd>${esc(s.urls?.gensecai)}</dd>
    <dt>INFOKOM URL</dt><dd>${esc(s.urls?.infokom)}</dd>
    <dt>GenSecAI key</dt><dd>${s.auth?.gensecai_key_set ? "configured" : "missing"}</dd>
    <dt>INFOKOM key</dt><dd>${s.auth?.infokom_key_set ? "configured" : "missing"}</dd>
    <dt>AI Analyst</dt><dd>${esc(s.ai_agent?.mode || "rules-only")} | auto ${s.ai_agent?.auto_analyze ? "enabled" : "disabled"}</dd>
    <dt>AI Model</dt><dd>${esc(s.ai_agent?.model || "not configured")}</dd>
    <dt>AI Provider</dt><dd>${esc(s.ai_agent?.provider_base_url || "not configured")}</dd>
    <dt>Tools</dt><dd>${fmt.format(number(s.tools?.total))} total, ${fmt.format(number(s.tools?.gensecai))} GenSecAI, ${fmt.format(number(s.tools?.infokom))} INFOKOM | ${fmt.format(number(s.tools?.dashboard))} direct dashboard, ${fmt.format(number(s.tools?.workflow))} menu workflows, ${fmt.format(number(s.tools?.approval_required))} approval required</dd>
  `);
  setHtml("#storageList", `
    <dt>Docker data-root</dt><dd>${esc(s.storage?.docker_data_root)}</dd>
    <dt>Docker storage target</dt><dd>${s.storage?.docker_on_data_disk ? "OK - using /data/wazuh-storage" : "Attention - not on /data/wazuh-storage"}</dd>
    <dt>Root filesystem</dt><dd>${fmtBytes(rootDisk.used)} / ${fmtBytes(rootDisk.total)} used (${esc(rootDisk.used_percent ?? "-")}%)</dd>
    <dt>Runtime volume</dt><dd>${fmtBytes(runtimeDisk.used)} / ${fmtBytes(runtimeDisk.total)} used (${esc(runtimeDisk.used_percent ?? "-")}%)</dd>
    <dt>Host data filesystem</dt><dd>${dataDisk.ok ? `${fmtBytes(dataDisk.used)} / ${fmtBytes(dataDisk.total)} used (${esc(dataDisk.used_percent ?? "-")}%)` : "visible from host; mounted through Docker volume"}</dd>
    <dt>Indexer volume</dt><dd>${esc(s.storage?.wazuh_indexer_volume)}</dd>
    <dt>Wazuh logs</dt><dd>${esc(s.storage?.wazuh_logs_volume)}</dd>
    <dt>Overview cache</dt><dd>${esc(s.storage?.overview_cache_db || "-")}</dd>
    <dt>Cache snapshots</dt><dd>${fmt.format(number(cache.overview_snapshots))} overview, ${fmt.format(number(cache.api_snapshots))} API | ${fmtBytes(cache.db_bytes)}</dd>
    <dt>SOC history database</dt><dd>${esc(s.storage?.automation_db || "-")}</dd>
    <dt>Historical snapshots</dt><dd>${fmt.format(number(automationStore.report_summaries))} summaries, ${fmt.format(number(automationStore.reports))} reports, ${fmt.format(number(automationStore.ai_runs))} AI runs | ${fmtBytes(automationStore.db_bytes)}</dd>
    <dt>CYFIRMA ledger</dt><dd>${fmt.format(number(automationStore.cyfirma_observations))} daily observations, ${fmt.format(number(automationStore.cyfirma_feed_runs))} feed runs</dd>
    <dt>Prewarm</dt><dd>${s.storage?.prewarm_enabled ? "enabled" : "disabled"} | ${(s.storage?.prewarm_ranges || []).join(", ")} | TTL ${fmt.format(number(s.storage?.overview_cache_ttl_seconds))}s</dd>
    <dt>IOC stream</dt><dd>${pipeline.enabled ? "enabled" : "disabled"} | ${esc(pipeline.scan_status || "unknown")} | ${fmt.format(number(pipeline.checkpoint_events_scanned))} checkpoint events | ${fmt.format(number(pipeline.queued_indicators))} unique indicators | lag ${fmt.format(number(pipeline.lag_seconds))}s</dd>
    <dt>Detection rollup</dt><dd>${pipeline.rollup?.enabled ? "enabled" : "disabled"} | ${fmt.format(number(pipeline.rollup?.events))} events in ${fmt.format(number(pipeline.rollup?.buckets))} five-minute buckets | ${fmt.format(number(pipeline.rollup?.retention_days))} day retention</dd>
    <dt>Historical backfill</dt><dd>${backfill.enabled ? (backfill.complete ? "complete" : esc(backfill.mode || "throttled")) : "disabled"} | ${fmt.format(number(rollupGaps.coverage_percent))}% coverage, ${fmt.format(number(rollupGaps.missing))} gaps | ${fmt.format(number(backfill.current_chunk_minutes))} min adaptive chunk, ${esc(backfillEta)} | ${fmt.format(number(backfill.chunks))} committed chunks ${backfill.error ? `| cooldown: ${esc(backfill.error)}` : `| last query ${fmt.format(number(backfill.last_query_took_ms))} ms`}</dd>
    <dt>Historical scan</dt><dd>${pipeline.historical_scope_complete ? "complete" : "live stream protected; historical coverage progresses only while caught up"}</dd>
  `);
}

async function saveSettings(event) {
  event?.preventDefault();
  if (!els.settingsForm) return;
  const formData = new FormData(els.settingsForm);
  const fields = state.settings?.config?.fields || [];
  const update = {};
  for (const field of fields) {
    if (field.type === "boolean") {
      update[field.key] = formData.has(field.key) ? "true" : "false";
    } else {
      const value = String(formData.get(field.key) || "").trim();
      if (field.type === "secret" && !value) continue;
      update[field.key] = value;
    }
  }
  const urlFields = fields.filter((field) => ["url", "url_optional"].includes(field.type));
  for (const field of urlFields) {
    const value = update[field.key];
    if (value && !/^https?:\/\/.+/i.test(value)) {
      els.settingsStatus.textContent = `${field.label}: invalid URL`;
      return;
    }
  }
  els.saveSettings.disabled = true;
  els.settingsStatus.textContent = "Saving...";
  try {
    const result = await postJson("/api/settings/save", { settings: update });
    state.settings = result.settings;
    renderSettings();
    const restart = result.restart_required?.length ? ` | restart: ${result.restart_required.join(", ")}` : "";
    els.settingsStatus.textContent = `Saved${restart}`;
    await loadDashboard();
  } catch (err) {
    els.settingsStatus.textContent = err.message;
  } finally {
    els.saveSettings.disabled = false;
  }
}

function renderM365Test(data) {
  if (!els.m365TestResult) return;
  const roles = data.token?.roles || [];
  const content = Object.entries(data.content || {});
  els.m365TestResult.innerHTML = `
    <div class="resultHeader">
      <div>
        <span class="pill ${data.ok ? "low" : "critical"}">${data.ok ? "ready" : "blocked"}</span>
        <strong>Microsoft 365 Test</strong>
      </div>
      <small>${esc(data.token?.audience || "manage.office.com")}</small>
    </div>
    <div class="resultContent">
      <div class="resultMetrics">
        <div class="resultMetric"><span>token</span><strong>${data.token?.ok ? "valid" : "failed"}</strong></div>
        <div class="resultMetric"><span>roles</span><strong>${esc(roles.join(", ") || "-")}</strong></div>
        <div class="resultMetric"><span>subscriptions</span><strong>${data.subscriptions?.ok ? fmt.format(number(data.subscriptions?.count)) : `HTTP ${esc(data.subscriptions?.status || "-")}`}</strong></div>
        <div class="resultMetric"><span>content types</span><strong>${fmt.format(content.length)}</strong></div>
      </div>
      <div class="toolRail">
        ${content.map(([name, row]) => `
          <div class="sourceTile ${row.ok ? "active" : "ready"}">
            <span>${row.ok ? "ok" : "blocked"}</span>
            <strong>${esc(name)}</strong>
            <small>${row.ok ? "content blobs available" : esc(row.body || row.reason || "no response")}</small>
            <b>${row.ok ? fmt.format(number(row.count)) : esc(row.status || "-")}</b>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

async function testM365() {
  if (!els.testM365) return;
  els.testM365.disabled = true;
  els.settingsStatus.textContent = "Testing M365...";
  if (els.m365TestResult) els.m365TestResult.innerHTML = '<div class="emptyState">Checking Microsoft 365 API...</div>';
  try {
    const data = await postJson("/api/m365/test", { hours: 24 });
    renderM365Test(data);
    els.settingsStatus.textContent = data.ok ? "M365 ready" : "M365 blocked";
  } catch (err) {
    els.settingsStatus.textContent = err.message;
    if (els.m365TestResult) els.m365TestResult.innerHTML = `<div class="errorPanel"><strong>M365 test failed</strong><p>${esc(err.message)}</p></div>`;
  } finally {
    els.testM365.disabled = false;
  }
}

function renderM365Start(data) {
  if (!els.m365TestResult) return;
  const rows = Object.entries(data.started || {});
  els.m365TestResult.innerHTML = `
    <div class="resultHeader">
      <div>
        <span class="pill ${data.ok ? "low" : "critical"}">${data.ok ? "enabled" : "attention"}</span>
        <strong>Microsoft 365 Feed</strong>
      </div>
      <small>${esc(data.token?.audience || "manage.office.com")}</small>
    </div>
    <div class="resultContent">
      <div class="resultMetrics">
        <div class="resultMetric"><span>token</span><strong>${data.token?.ok ? "valid" : "failed"}</strong></div>
        <div class="resultMetric"><span>roles</span><strong>${esc((data.token?.roles || []).join(", ") || "-")}</strong></div>
        <div class="resultMetric"><span>started</span><strong>${fmt.format(rows.filter(([, row]) => row.ok).length)}</strong></div>
        <div class="resultMetric"><span>content types</span><strong>${fmt.format(rows.length)}</strong></div>
      </div>
      <div class="toolRail">
        ${rows.map(([name, row]) => `
          <div class="sourceTile ${row.ok ? "active" : "ready"}">
            <span>${row.already_enabled ? "already on" : row.ok ? "started" : "blocked"}</span>
            <strong>${esc(name)}</strong>
            <small>${row.ok ? "Subscription enabled for future audit content" : esc(row.body || row.reason || "no response")}</small>
            <b>${row.ok ? "OK" : esc(row.status || "-")}</b>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

async function startM365Feed() {
  if (!els.startM365) return;
  els.startM365.disabled = true;
  els.settingsStatus.textContent = "Starting M365 feed...";
  if (els.m365TestResult) els.m365TestResult.innerHTML = '<div class="emptyState">Enabling Microsoft 365 Activity Feed subscriptions...</div>';
  try {
    const data = await postJson("/api/m365/start-subscriptions", {});
    renderM365Start(data);
    els.settingsStatus.textContent = data.ok ? "M365 feed enabled" : "M365 feed needs attention";
    await loadDashboard();
  } catch (err) {
    els.settingsStatus.textContent = err.message;
    if (els.m365TestResult) els.m365TestResult.innerHTML = `<div class="errorPanel"><strong>M365 start failed</strong><p>${esc(err.message)}</p></div>`;
  } finally {
    els.startM365.disabled = false;
  }
}

function tryParseJson(value) {
  if (value && typeof value === "object") return value;
  if (typeof value !== "string") return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function summarizeValue(value) {
  if (Array.isArray(value)) return `${fmt.format(value.length)} items`;
  if (value && typeof value === "object") return `${fmt.format(Object.keys(value).length)} fields`;
  if (value === null || value === undefined || value === "") return "-";
  return String(value).slice(0, 140);
}

function renderArraySummaryItem(item, index) {
  if (!item || typeof item !== "object" || Array.isArray(item)) {
    return `<div class="jsonRow"><b>${index + 1}</b><span>${esc(summarizeValue(item))}</span></div>`;
  }
  const title = firstNonEmpty(
    item.name,
    item.id,
    item.rule_id,
    item.cve,
    item.ip,
    item.srcip,
    item.key,
    item.operation,
    item.description,
    `Row ${index + 1}`
  );
  const details = Object.entries(item)
    .filter(([, value]) => value === null || typeof value !== "object")
    .slice(0, 5)
    .map(([key, value]) => `<span><b>${esc(key)}</b>${esc(summarizeValue(value))}</span>`)
    .join("");
  return `
    <div class="jsonListItem">
      <strong>${esc(title)}</strong>
      <div>${details || `<span>${esc(summarizeValue(item))}</span>`}</div>
    </div>
  `;
}

function renderObjectCards(obj) {
  const entries = Object.entries(obj || {});
  const primitives = entries.filter(([, value]) => value === null || typeof value !== "object");
  const complex = entries.filter(([, value]) => value && typeof value === "object");
  const cards = primitives.slice(0, 12).map(([key, value]) => `
    <div class="resultMetric">
      <span>${esc(key)}</span>
      <strong>${esc(summarizeValue(value))}</strong>
    </div>
  `).join("");
  const sections = complex.slice(0, 8).map(([key, value]) => {
    const rows = Array.isArray(value) ? value.slice(0, 12) : Object.entries(value).slice(0, 12);
    const body = Array.isArray(value)
      ? rows.map((item, index) => renderArraySummaryItem(item, index)).join("")
      : rows.map(([k, v]) => `<div class="jsonRow"><b>${esc(k)}</b><span>${esc(summarizeValue(v))}</span></div>`).join("");
    return `
      <details class="jsonSection" open>
        <summary>${esc(key)} <span>${esc(summarizeValue(value))}</span></summary>
        ${body || '<div class="emptyState">Empty object</div>'}
      </details>
    `;
  }).join("");
  return `
    ${cards ? `<div class="resultMetrics">${cards}</div>` : ""}
    ${sections}
  `;
}

function renderIocCard(item, index = 0) {
  const iocs = collectionValues(item.iocs);
  const title = firstNonEmpty(item.name, item.id, iocs[0], item.pattern, `IOC ${index + 1}`);
  const phases = arrayify(item.kill_chain_phases).map((phase) => phase?.phase_name || itemLabel(phase)).filter(Boolean);
  return `
    <article class="iocCard">
      <div>
        <strong>${esc(title)}</strong>
        <small>${esc(item.scope || item.type || "indicator")} | confidence ${esc(item.confidence ?? "-")}</small>
      </div>
      <p>${esc(item.description || item.pattern || "No description returned.")}</p>
      ${providerChips([collectionValues(item.labels), iocs, phases], "No labels")}
      <button type="button" data-finding-ioc-record="${esc(JSON.stringify(item))}">View finding details</button>
    </article>
  `;
}

function renderThreatIntelResult(parsed) {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "";
  if (parsed.results && parsed.aggregated_risk_level !== undefined) {
    const rows = arrayify(parsed.results).filter((row) => row && typeof row === "object");
    return `
      <div class="resultMetrics">
        <div class="resultMetric"><span>Indicator</span><strong>${esc(parsed.indicator || "-")}</strong></div>
        <div class="resultMetric"><span>Type</span><strong>${esc(parsed.indicator_type || "-")}</strong></div>
        <div class="resultMetric"><span>Risk</span><strong>${esc(parsed.aggregated_risk_level || "unknown")}</strong></div>
        <div class="resultMetric"><span>Votes</span><strong>${fmt.format(number(parsed.consensus_malicious))}/${fmt.format(rows.filter((row) => !row.error).length)}</strong></div>
      </div>
      <div class="toolProviderEvidence">
        <p>Hasil intelijen bukan bukti eksploitasi lokal. Tidak ada data, tidak ada kecocokan, dan hasil tidak tersedia memiliki makna berbeda.</p>
        ${rows.map(row => window.SocFindings?.renderProvider(row.provider, row, row.error) || renderObjectCards(row)).join("")}
      </div>
    `;
  }
  if (parsed.provider === "cyfirma" || parsed.feeds || parsed.matches) {
    const items = arrayify(parsed.matches || parsed.items).filter((item) => item && typeof item === "object");
    const summary = parsed.summary || {};
    return `
      <div class="resultMetrics">
        <div class="resultMetric"><span>Provider</span><strong>CYFIRMA</strong></div>
        <div class="resultMetric"><span>Scope</span><strong>${esc(parsed.scope || "both")}</strong></div>
        <div class="resultMetric"><span>Indicators</span><strong>${fmt.format(number(summary.count || items.length))}</strong></div>
        <div class="resultMetric"><span>${parsed.match_count !== undefined ? "IOC matches" : "Loaded records"}</span><strong>${fmt.format(number(parsed.match_count ?? items.length))}</strong></div>
      </div>
      <div class="iocGrid">${items.slice(0, 18).map((item, index) => renderIocCard(item, index)).join("") || '<div class="emptyState">No CYFIRMA indicators returned for this query.</div>'}</div>
      ${Object.keys(parsed.errors || {}).length ? `<div class="errorPanel"><strong>CYFIRMA feed warnings</strong><p>${esc(JSON.stringify(parsed.errors))}</p></div>` : ""}
    `;
  }
  if (parsed.reputation || parsed.why || parsed.behaviors || parsed.cves) {
    return `
      <div class="resultMetrics">
        <div class="resultMetric"><span>Reputation</span><strong>${esc(parsed.reputation || "unknown")}</strong></div>
        <div class="resultMetric"><span>Confidence</span><strong>${esc(parsed.confidence || "-")}</strong></div>
        <div class="resultMetric"><span>Behaviors</span><strong>${fmt.format(number(parsed.behaviors?.length))}</strong></div>
        <div class="resultMetric"><span>CVEs</span><strong>${fmt.format(number(parsed.cves?.length))}</strong></div>
      </div>
      <div class="crowdWhy"><b>Why flagged</b><p>${esc(parsed.why || "No adverse context returned.")}</p></div>
      <div class="crowdSections">
        <div><b>Behaviors</b>${providerChips(parsed.behaviors, "No behavior")}</div>
        <div><b>CVE Context</b>${providerChips(arrayify(parsed.cves).map((item) => cveId(item) || itemLabel(item)), "No CVE")}</div>
      </div>
    `;
  }
  if (parsed.pulses || parsed.pulse_count !== undefined) {
    const pulses = parsed.pulses || [];
    return `
      <div class="resultMetrics">
        <div class="resultMetric"><span>Indicator</span><strong>${esc(parsed.indicator || "-")}</strong></div>
        <div class="resultMetric"><span>Type</span><strong>${esc(parsed.indicator_type || "-")}</strong></div>
        <div class="resultMetric"><span>Pulses</span><strong>${fmt.format(number(parsed.pulse_count))}</strong></div>
        <div class="resultMetric"><span>Campaigns</span><strong>${fmt.format(pulses.length)}</strong></div>
      </div>
      <div class="iocGrid">${pulses.slice(0, 12).map((pulse, index) => renderIocCard({
        ...pulse,
        type: "otx-pulse",
        labels: [...(pulse.tags || []), ...(pulse.malware_families || []), ...(pulse.attack_ids || [])],
        description: `${pulse.adversary || "Unknown actor"} | ${pulse.indicator_count || 0} indicators | ${pulse.modified || pulse.created || "-"}`
      }, index)).join("") || '<div class="emptyState">No OTX pulse context returned.</div>'}</div>
    `;
  }
  if (parsed.malicious !== undefined || parsed.harmless !== undefined || parsed.suspicious !== undefined) {
    return `
      <div class="resultMetrics">
        <div class="resultMetric critical"><span>Malicious</span><strong>${fmt.format(number(parsed.malicious))}</strong></div>
        <div class="resultMetric high"><span>Suspicious</span><strong>${fmt.format(number(parsed.suspicious))}</strong></div>
        <div class="resultMetric low"><span>Harmless</span><strong>${fmt.format(number(parsed.harmless))}</strong></div>
        <div class="resultMetric"><span>Target</span><strong>${esc(parsed.domain || parsed.hash || parsed.ip || "-")}</strong></div>
      </div>
    `;
  }
  return "";
}

function renderLogText(text) {
  const lines = String(text || "").split("\n");
  return `<div class="logPane">${lines.slice(0, 220).map((line, index) => `
    <div class="logLine">
      <b>${String(index + 1).padStart(3, "0")}</b>
      <span>${esc(line || " ")}</span>
    </div>
  `).join("")}</div>`;
}

function renderReportText(text) {
  const lines = String(text || "").split("\n").map((line) => line.trim()).filter(Boolean);
  const blocks = [];
  let current = { title: "Summary", rows: [] };
  for (const line of lines) {
    if (line.startsWith("#")) {
      if (current.rows.length) blocks.push(current);
      current = { title: line.replace(/^#+\s*/, ""), rows: [] };
    } else if (line.startsWith("- ")) {
      current.rows.push(line.slice(2));
    } else {
      current.rows.push(line.replace(/\*\*/g, ""));
    }
  }
  if (current.rows.length) blocks.push(current);
  return `
    <div class="reportGrid">
      ${blocks.slice(0, 8).map((block) => `
        <section class="reportCard">
          <h3>${esc(block.title)}</h3>
          ${block.rows.slice(0, 14).map((row) => {
            const parts = row.split(":");
            return parts.length > 1
              ? `<div class="reportRow"><b>${esc(parts.shift())}</b><span>${esc(parts.join(":").replace(/`/g, ""))}</span></div>`
              : `<p>${esc(row.replace(/`/g, ""))}</p>`;
          }).join("")}
        </section>
      `).join("")}
    </div>
  `;
}

function renderToolResult(data) {
  const parsed = data.json || tryParseJson(data.text);
  const statusClass = data.ok ? "low" : "critical";
  const summary = `
    <div class="resultHeader">
      <div>
        <span class="pill ${statusClass}">${data.ok ? "success" : "error"}</span>
        <strong>${esc(data.name || state.selected?.name || "tool result")}</strong>
        ${data.category ? `<span class="pill infokom">${esc(data.category)}</span>` : ""}
        ${data.lane ? `<span class="pill gensecai">${esc(data.lane)}</span>` : ""}
      </div>
      <small>${esc(data.source || state.selected?.source || "-")} | ${fmt.format(number(data.duration_ms))} ms</small>
    </div>
  `;
  const errorText = !data.ok ? `
    <div class="errorPanel">
      <strong>Tool returned an error</strong>
      <p>${esc(data.text || data.raw?.error?.message || "Unknown error")}</p>
    </div>
  ` : "";
  const hasParsedRows = parsed && typeof parsed === "object" && (Array.isArray(parsed) ? parsed.length : Object.keys(parsed).length);
  const text = String(data.text || "").trim();
  const threatIntelView = hasParsedRows && !Array.isArray(parsed) ? renderThreatIntelResult(parsed) : "";
  const content = hasParsedRows
    ? (threatIntelView || (Array.isArray(parsed) ? `<div class="jsonSection openArray">${parsed.slice(0, 24).map((item, index) => renderArraySummaryItem(item, index)).join("")}</div>` : renderObjectCards(parsed)))
    : text
      ? (text.startsWith("#") ? renderReportText(data.text) : renderLogText(data.text))
      : '<div class="emptyState">Tool returned success, but no rows matched the selected parameters/time range.</div>';
  els.result.innerHTML = `
    ${summary}
    ${errorText}
    <div class="resultContent">${content}</div>
    <details class="rawJson">
      <summary>Raw JSON</summary>
      <pre>${esc(JSON.stringify(data.raw || data, null, 2))}</pre>
    </details>
  `;
  document.dispatchEvent(new CustomEvent("soc:tool-result", { detail: data }));
}

function evidenceValue(value, fallback = "Not observed") {
  if (value === null || value === undefined || value === "" || (Array.isArray(value) && !value.length)) return fallback;
  if (typeof value === "object") {
    const text = JSON.stringify(value);
    return text.length > 90 ? `${text.slice(0, 87)}...` : text;
  }
  return String(value);
}

function evidenceAge(seconds) {
  const age = number(seconds);
  if (age < 60) return `${Math.round(age)}s`;
  if (age < 3600) return `${Math.round(age / 60)}m`;
  if (age < 86400) return `${Math.round(age / 3600)}h`;
  return `${Math.round(age / 86400)}d`;
}

function renderTelemetryEvidence(data) {
  const root = q("#telemetryEvidence");
  if (!root) return;
  const telemetry = data.operational_evidence?.telemetry || {};
  const indexer = telemetry.indexer || {};
  const quality = data.operational_evidence?.data_quality || {};
  const health = indexer.health || "unavailable";
  const decoderCoverage = quality.decoder_coverage_percent === null || quality.decoder_coverage_percent === undefined
    ? "-" : `${number(quality.decoder_coverage_percent).toFixed(2)}%`;
  const decoderMissing = quality.decoder_unmatched_events === null || quality.decoder_unmatched_events === undefined
    ? "-" : fmt.format(number(quality.decoder_unmatched_events));
  const rollupCoverage = quality.rollup_coverage_percent === null || quality.rollup_coverage_percent === undefined
    ? "" : ` · rollup ${number(quality.rollup_coverage_percent).toFixed(2)}%`;
  root.innerHTML = `
    <div class="evidenceMetrics">
      <div class="evidenceMetric"><span>Indexed events</span><strong>${fmt.format(number(quality.indexed_events))}</strong><small>${quality.partial ? "partial response" : "exact window count"}</small></div>
      <div class="evidenceMetric"><span>Indexer query</span><strong>${fmt.format(number(indexer.query_took_ms))} ms</strong><small>${esc(health)}</small></div>
      <div class="evidenceMetric"><span>Failed shards</span><strong>${fmt.format(number(indexer.shards_failed))}</strong><small>${fmt.format(number(indexer.shards_successful))}/${fmt.format(number(indexer.shards_total))} successful</small></div>
      <div class="evidenceMetric"><span>Decoder coverage</span><strong>${esc(decoderCoverage)}</strong><small>${esc(decoderMissing)} without decoder</small></div>
    </div>
    <p class="evidenceNote"><b>Scope:</b> ${esc(indexer.scope || "Operational aggregation unavailable.")}${esc(rollupCoverage)} ${quality.note ? ` ${esc(quality.note)}` : ""}</p>
    <p class="evidenceNote"><b>Signals:</b> ${fmt.format(number(telemetry.dropped_events))} dropped, ${fmt.format(number(telemetry.agent_flooding))} agent flooding, ${fmt.format(number(telemetry.manager_queue))} manager queue.</p>
  `;
}

function renderNetworkIdentityEvidence(data) {
  const root = q("#networkIdentityEvidence");
  if (!root) return;
  const evidence = data.operational_evidence || {};
  const network = evidence.network?.events || [];
  const identity = evidence.identity?.events || [];
  const networkRows = network.map((row) => `
    <tr><td>${esc(evidenceValue(row.timestamp, "-"))}</td><td>${esc(evidenceValue(row.source, "-"))}</td><td>${esc(evidenceValue(row.destination, "-"))}:${esc(evidenceValue(row.port, "-"))}</td><td>${esc(evidenceValue(row.application, "-"))}</td><td>${esc(evidenceValue(row.policy, "-"))}</td><td>${esc(evidenceValue(row.direction, row.action || "-"))}</td></tr>
  `).join("");
  const identityRows = identity.map((row) => `
    <tr><td>${esc(evidenceValue(row.timestamp, "-"))}</td><td>${esc(evidenceValue(row.user, "-"))}</td><td>${esc(evidenceValue(row.mailbox, "-"))}</td><td>${esc(evidenceValue(row.operation, "-"))}</td><td>${esc(evidenceValue(row.privilege, "-"))}</td><td>${esc(evidenceValue(row.session, row.authentication || "-"))}</td></tr>
  `).join("");
  root.innerHTML = `
    <div class="evidenceSplit">
      <section><div class="evidenceSubhead"><h3>Network flow</h3><span>${network.length} bounded samples</span></div><div class="evidenceTableWrap"><table class="evidenceTable"><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>App</th><th>Policy</th><th>Direction</th></tr></thead><tbody>${networkRows || '<tr><td colspan="6">No network fields were observed in this window.</td></tr>'}</tbody></table></div></section>
      <section><div class="evidenceSubhead"><h3>Identity chain</h3><span>${identity.length} bounded samples</span></div><div class="evidenceTableWrap"><table class="evidenceTable"><thead><tr><th>Time</th><th>User</th><th>Mailbox</th><th>Operation</th><th>Privilege</th><th>Session / auth</th></tr></thead><tbody>${identityRows || '<tr><td colspan="6">No identity fields were observed in this window.</td></tr>'}</tbody></table></div></section>
    </div>
  `;
}

function renderMitreEvidence(data) {
  const root = q("#mitreEvidence");
  if (!root) return;
  const mitre = data.operational_evidence?.mitre || {};
  const techniques = mitre.techniques || [];
  const max = Math.max(1, ...techniques.map((row) => number(row.count)));
  const bars = techniques.slice(0, 12).map((row) => `
    <div class="coverageRow"><b>${esc(row.technique)}</b><span><i style="width:${Math.max(3, Math.round(number(row.count) / max * 100))}%"></i></span><strong>${fmt.format(number(row.count))}</strong></div>
  `).join("");
  const timeline = (mitre.timeline || []).slice(-8).map((row) => `
    <div class="timelineEvidence"><time>${esc(evidenceValue(row.timestamp, "-"))}</time><span>${(row.techniques || []).map((item) => `${esc(item.technique)} (${fmt.format(number(item.count))})`).join(" | ")}</span></div>
  `).join("");
  root.innerHTML = techniques.length ? `
    <div class="coverageBars">${bars}</div>
    <details class="evidenceDetails"><summary>Technique timeline (${(mitre.timeline || []).length} buckets)</summary>${timeline || '<p class="evidenceNote">No timeline buckets contained ATT&CK techniques.</p>'}</details>
  ` : '<div class="emptyState">No MITRE technique fields were observed in the selected window.</div>';
}

function renderDecoderEvidence(data) {
  const root = q("#decoderEvidence");
  if (!root) return;
  const decoders = data.operational_evidence?.decoders || {};
  const rows = (decoders.items || []).map((row) => `
    <tr><td>${esc(row.name)}</td><td>${fmt.format(number(row.count))}</td><td>${fmt.format(number(row.max_level))}</td><td>${esc(evidenceValue(row.last_seen, "-"))}</td><td>${esc(evidenceValue(row.rule, "-"))}</td></tr>
  `).join("");
  root.innerHTML = `
    <div class="evidenceMetrics evidenceMetricsCompact">
      <div class="evidenceMetric"><span>Decoder buckets</span><strong>${fmt.format(number(decoders.observed))}</strong><small>top ${fmt.format(number(decoders.bucket_limit || 20))}</small></div>
      <div class="evidenceMetric"><span>Named decoder events</span><strong>${decoders.named_events === null || decoders.named_events === undefined ? "-" : fmt.format(number(decoders.named_events))}</strong><small>${decoders.coverage_percent === null || decoders.coverage_percent === undefined ? "coverage unavailable" : `${number(decoders.coverage_percent).toFixed(2)}% of window`}</small></div>
      <div class="evidenceMetric"><span>Missing decoder field</span><strong>${decoders.unmatched_events === null || decoders.unmatched_events === undefined ? "-" : fmt.format(number(decoders.unmatched_events))}</strong><small>not equal to decoder failure</small></div>
    </div>
    <div class="evidenceTableWrap"><table class="evidenceTable"><thead><tr><th>Decoder</th><th>Events</th><th>Max level</th><th>Last seen</th><th>Latest rule</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No decoder buckets were returned.</td></tr>'}</tbody></table></div>
    <p class="evidenceNote">${esc(decoders.note || "Decoder failure telemetry was not available.")}</p>
  `;
}

function renderProviderFreshness(data) {
  const root = q("#providerFreshness");
  if (!root) return;
  const freshness = data.provider_freshness || {};
  const rows = (freshness.providers || []).map((row) => `
    <tr><td><span class="statusMark ${esc(row.status || "unavailable")}">${esc(row.status || "unavailable")}</span> ${esc(row.provider)}</td><td>${esc(evidenceAge(row.age_seconds))}</td><td>${esc(evidenceValue(row.quota_remaining, "Not reported"))}</td><td>${esc(evidenceValue(row.reason_not_used, "Available in latest snapshot"))}</td><td>${esc(evidenceValue(row.observed_at, "-"))}</td></tr>
  `).join("");
  root.innerHTML = `
    <div class="evidenceSubhead"><h3>Persisted provider state</h3><span>${fmt.format(number(freshness.retention_days))} day retention</span></div>
    <div class="evidenceTableWrap"><table class="evidenceTable"><thead><tr><th>Provider</th><th>Cache age</th><th>Quota left</th><th>Usage state</th><th>Observed</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No persisted provider snapshots are available yet.</td></tr>'}</tbody></table></div>
  `;
}

function renderCveEvidenceCoverage(data) {
  const root = q("#cveEvidenceCoverage");
  if (!root) return;
  const coverage = data.vulnerabilities?.evidence_coverage || {};
  const labels = {
    wazuh_inventory: "Wazuh inventory", cpe: "CPE identity", epss: "EPSS", kev: "CISA KEV",
    poc: "PoC / exploit", internet_exposure: "Internet exposure", patch_state: "Patch state",
  };
  root.innerHTML = `
    <div class="coverageChecklist">${Object.entries(labels).map(([key, label]) => `
      <div><span class="statusMark ${coverage[key] ? "available" : "unavailable"}">${coverage[key] ? "observed" : "not observed"}</span><strong>${esc(label)}</strong></div>
    `).join("")}</div>
    <p class="evidenceNote">${esc(coverage.note || "Evidence coverage is calculated from the current Wazuh summary.")}</p>
  `;
}

function renderAssetContextEvidence(data) {
  const root = q("#assetContextEvidence");
  if (!root) return;
  const agents = data.agents || {};
  const status = agents.context_status || {};
  const rows = (agents.context || []).map((row) => `
    <tr><td>${esc(evidenceValue(row.name, row.id || "-"))}<br><small>${esc(evidenceValue(row.ip, ""))}</small></td><td><span class="statusMark ${row.managed ? "available" : "unavailable"}">${row.managed ? "managed" : "CMDB only"}</span></td><td>${esc(evidenceValue(row.owner))}</td><td>${esc(evidenceValue(row.criticality))}</td><td>${esc(evidenceValue(row.environment))}</td><td>${esc(evidenceValue(row.network_zone))}</td><td>${esc(evidenceValue(row.vendor))} ${esc(evidenceValue(row.version, ""))}<br><small>${fmt.format(number(row.components?.length))} component(s)</small></td><td>${esc(evidenceValue(row.cpe))}<br><span class="statusMark ${row.cpe_status === "valid" ? "available" : row.cpe_status === "invalid" ? "error" : "unavailable"}">${esc(row.cpe_status || "missing")}</span></td><td>${esc(evidenceValue(row.patch_state, "unknown"))}<br><small>${esc(evidenceValue(row.last_verified, "not verified"))}</small></td><td>${esc(evidenceValue(row.source))}</td></tr>
  `).join("");
  const total = Math.max(1, (agents.context || []).length);
  const coverage = agents.context_coverage || {};
  root.innerHTML = `
    <div class="evidenceMetrics evidenceMetricsCompact">
      <div class="evidenceMetric"><span>CMDB</span><strong>${status.available ? "Loaded" : "Not loaded"}</strong><small>${esc(evidenceValue(status.file, "No file"))}${status.error ? ` · ${esc(status.error)}` : ""}</small></div>
      <div class="evidenceMetric"><span>CMDB assets</span><strong>${fmt.format(number(status.assets))}</strong><small>${status.cached ? "cached by file version" : "fresh file read"}</small></div>
      <div class="evidenceMetric"><span>Matched agents</span><strong>${fmt.format(number(status.matched_agents))}</strong><small>${fmt.format(number(status.unmatched_agents))} without CMDB match</small></div>
      <div class="evidenceMetric"><span>CMDB only</span><strong>${fmt.format(number(status.unmanaged_assets))}</strong><small>not currently matched to a Wazuh agent</small></div>
    </div>
    <div class="coverageInline">${["owner", "criticality", "environment", "network_zone", "vendor", "version", "valid_cpe", "components", "patch_state", "last_verified"].map((key) => `<span><b>${esc(key.replace("_", " "))}</b> ${Math.round(number(coverage[key]) / total * 100)}%</span>`).join("")}</div>
    <div class="evidenceTableWrap"><table class="evidenceTable"><thead><tr><th>Asset</th><th>State</th><th>Owner</th><th>Criticality</th><th>Environment</th><th>Zone</th><th>Vendor / components</th><th>CPE quality</th><th>Patch / verified</th><th>Source</th></tr></thead><tbody>${rows || '<tr><td colspan="10">No Wazuh agent or CMDB context is available.</td></tr>'}</tbody></table></div>
    <p class="evidenceNote">${esc(agents.context_source || "Asset context source is unavailable.")}</p>
  `;
}

function renderDataQuality(data) {
  const root = q("#dataQualitySummary");
  if (!root) return;
  const quality = data.operational_evidence?.data_quality || {};
  const funnel = data.analysis_funnel || {};
  const materialization = data.materialization || {};
  const providers = data.provider_freshness?.providers || [];
  const availableProviders = providers.filter((row) => row.status === "available").length;
  const providerErrors = providers.filter((row) => row.status === "error").length;
  const decoderCoverage = quality.decoder_coverage_percent === null || quality.decoder_coverage_percent === undefined
    ? "-" : `${number(quality.decoder_coverage_percent).toFixed(2)}%`;
  const rollupCoverage = quality.rollup_coverage_percent === null || quality.rollup_coverage_percent === undefined
    ? (materialization.exact ? "100%" : "building") : `${number(quality.rollup_coverage_percent).toFixed(2)}%`;
  const lag = funnel.pipeline_lag_seconds === null || funnel.pipeline_lag_seconds === undefined
    ? "-" : `${fmt.format(number(funnel.pipeline_lag_seconds))}s`;
  const window = data.window?.label || data.requested_range || "selected window";
  const status = materialization.exact ? "complete" : (materialization.status || "building");
  const tone = materialization.exact && !quality.partial ? "available" : "skipped";
  const metrics = [
    ["Indexed events", fmt.format(number(quality.indexed_events ?? funnel.indexed_events)), quality.partial ? "partial response" : "exact window count"],
    ["Decoder coverage", decoderCoverage, quality.decoder_unmatched_events == null ? "exact coverage unavailable" : `${fmt.format(number(quality.decoder_unmatched_events))} without decoder`],
    ["Rollup coverage", rollupCoverage, `${status} · 5-minute summaries`],
    ["Pipeline lag", lag, funnel.pipeline_status || "unavailable"],
    ["IOC queue", fmt.format(number(funnel.queued_unique_indicators)), "deduplicated indicators"],
    ["Provider history", `${fmt.format(availableProviders)}/${fmt.format(providers.length)}`, providerErrors ? `${fmt.format(providerErrors)} cached errors` : "persisted snapshots"],
  ];
  root.innerHTML = metrics.map(([label, value, note]) => `<div class="evidenceMetric"><span>${esc(label)}</span><strong>${esc(value)}</strong><small>${esc(note)}</small></div>`).join("");
  const meta = q("#dataQualityMeta");
  if (meta) meta.textContent = `${window} · ${quality.source || materialization.source || "local evidence"}`;
  const note = q("#dataQualityNote");
  if (note) note.innerHTML = `<span class="statusMark ${tone}">${esc(status)}</span> ${esc(quality.note || funnel.ai_note || "Data is served from the selected window and persisted summaries.")}`;
}

function renderOverview(data) {
  document.dispatchEvent(new CustomEvent("soc:overview", { detail: data }));
  renderPosture(data);
  renderLanes(data);
  renderMetrics(data);
  renderInsights(data);
  renderSeverity(data);
  renderHourlySpark(data);
  renderAttackTimeline(data);
  renderAttackMap(data);
  renderDetectionLayers(data);
  renderDataQuality(data);
  renderTelemetryEvidence(data);
  renderNetworkIdentityEvidence(data);
  renderMitreEvidence(data);
  renderDecoderEvidence(data);
  renderProviderFreshness(data);
  renderCloudM365(data);
  renderSocCoverage(data);
  renderAttackPath(data);
  renderIncidentBoard(data);
  renderSocWorkbench(data);
  renderThreatTable("#overviewThreats", data.threats || []);
  renderL1Queue(data);
  renderSourceIps(data);
  renderCorrelation(data);
  renderAiRecon(data);
  renderVulnerabilities(data);
  renderCveEvidenceCoverage(data);
  renderAgents(data);
  renderAssetContextEvidence(data);
  renderDonut("#platformDonut", "#platformLegend", data.agents?.platforms || {});
  renderDecisions(data);
  renderInvestigationFlow(data);
  renderProviderIntel();
  renderCrowdSecIntel();
}

async function postJson(path, body = {}) {
  const resp = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.error || (data.errors || []).join(", ") || `${resp.status} ${resp.statusText}`);
  }
  return data;
}

async function postJsonWithTimeout(path, body = {}, timeoutMs = 30000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || (data.errors || []).join(", ") || `${resp.status} ${resp.statusText}`);
    return data;
  } catch (err) {
    if (err.name === "AbortError") throw new Error(`Request timed out after ${Math.round(timeoutMs / 1000)}s`);
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function loadDashboard(force = false) {
  els.status.textContent = force ? "Refreshing live SOC telemetry..." : "Loading SOC telemetry...";
  els.dot.className = "";
  els.connectionText.textContent = "Loading";
  els.refresh.disabled = true;
  try {
    syncDateRangeVisibility();
    const windowPayload = currentWindowPayload();
    const cachePayload = { ...windowPayload };
    const clientSnapshot = force ? null : readClientOverview(cachePayload);
    if (clientSnapshot) {
      state.overview = clientSnapshot;
      renderOverview(clientSnapshot);
      els.status.textContent = `Showing local snapshot | ${currentRangeLabel(clientSnapshot)} | refreshing telemetry...`;
    }
    if (force) windowPayload.force = true;
    const settingsPromise = postJson("/api/settings").then(settings => { state.settings = settings; renderSettings(); });
    const toolsPromise = postJson("/api/tools").then(toolsData => {
        state.tools = toolsData.tools || [];
        state.toolSummary = toolsData.summary || {};
        state.categories = toolsData.categories || {};
        renderCategoryOptions(); renderTools();
        document.dispatchEvent(new CustomEvent("soc:tools"));
        if (!state.selected && state.tools.length) selectTool(state.tools[0]);
    });
    const overview = await postJson("/api/overview", windowPayload);
    state.overview = overview;
    writeClientOverview(cachePayload, overview);
    state.crowdSecRequestId += 1;
    state.crowdSecLoading = false;
    state.crowdSecIntel = null;
    const errors = Object.keys(overview.errors || {});
    const cache = overview.cache ? ` | cache ${overview.cache.status}${overview.cache.age_seconds ? ` ${overview.cache.age_seconds}s` : ""}` : "";
    const toolTotal = number(overview.tools?.total) || state.tools.length;
    const materialization = overview.materialization?.status === "building" ? " | exact snapshot building in background" : "";
    els.status.textContent = `Updated ${overview.generated_at || "now"} | ${currentRangeLabel(overview)} | ${fmt.format(toolTotal)} tools${cache}${materialization}${errors.length ? " | degraded: " + errors.join(", ") : ""}`;
    els.dot.className = errors.length ? "bad" : "ok";
    els.connectionText.textContent = errors.length ? "Degraded" : "Operational";
    els.sideMeta.textContent = `${fmt.format(number(overview.tools?.gensecai))} GenSecAI + ${fmt.format(number(overview.tools?.infokom))} INFOKOM tools`;
    renderOverview(overview);
    if (state.view === "vuln") void loadCveExposureGraph();
    void loadPersistentCases();
    if (["stale-refreshing", "building"].includes(overview.cache?.status) && !state.overviewRefreshTimer) {
      state.overviewRefreshTimer = setTimeout(() => {
        state.overviewRefreshTimer = null;
        loadDashboard().catch(showLoadError);
      }, 12000);
    }
    renderCategoryOptions();
    renderTools();
    if (!state.selected && state.tools.length) {
      selectTool(state.tools.find((tool) => tool.name === "advanced_three_sum_correlation") || state.tools[0]);
    }
    if (state.providerTests) {
      renderProviderIntel();
    } else if (els.providerIntelGrid) {
      els.providerIntelGrid.innerHTML = '<div class="emptyState">Provider connection tests are on demand. Stored intelligence and scheduled enrichment remain available without spending API quota.</div>';
    }
    if (state.view === "l3") loadCrowdSecIntel(true).catch(() => {});
    await Promise.allSettled([settingsPromise, toolsPromise]);
  } finally {
    els.refresh.disabled = false;
  }
}

async function runTool() {
  if (!state.selected) return;
  let args;
  try {
    args = JSON.parse(els.args.value || "{}");
  } catch (err) {
    els.result.textContent = `Invalid JSON: ${err.message}`;
    return;
  }
  const missing = missingRequiredArgs(state.selected, args);
  if (missing.length) {
    els.result.innerHTML = `
      <div class="errorPanel">
        <strong>Required parameters missing</strong>
        <p>Isi dulu field wajib berikut: ${esc(missing.join(", "))}. Dashboard tidak mengirim request kosong supaya hasil MCP tidak gagal atau membingungkan.</p>
      </div>
    `;
    return;
  }
  els.run.disabled = true;
  els.result.textContent = "Running...";
  try {
    if (state.selected.workflow?.mode === "cached_read" && window.SocWorkflows) {
      const data = await window.SocWorkflows.run(state.selected, args, message => { els.result.textContent = message; });
      renderToolResult(data);
      return;
    }
    const confirmed = state.selected.workflow?.mode === "approval"
      ? window.confirm(`Confirm execution of ${state.selected.name}? This tool may change data, affect a host, or run an expensive query.`) : false;
    if (state.selected.workflow?.mode === "approval" && !confirmed) {
      els.result.textContent = "Cancelled";
      return;
    }
    const data = await postJson("/api/call", {
      source: state.selected.source,
      name: state.selected.name,
      arguments: args,
      confirmed,
    });
    renderToolResult(data);
  } catch (err) {
    els.result.innerHTML = `<div class="errorPanel"><strong>Request failed</strong><p>${esc(err.message)}</p></div>`;
  } finally {
    els.run.disabled = false;
  }
}

async function scoreCve() {
  const cve = els.cveInput.value.trim();
  if (!cve) return;
  els.cveBtn.disabled = true;
  els.cveResult.textContent = "Scoring CVE...";
  try {
    const data = await postJson("/api/call", {
      source: "infokom",
      name: "blueteam_cve_score",
      arguments: { cve_id: cve, response_format: "json" },
    });
    els.cveResult.textContent = data.text || JSON.stringify(data.json || data.raw || data, null, 2);
  } catch (err) {
    els.cveResult.textContent = err.message;
  } finally {
    els.cveBtn.disabled = false;
  }
}

function setView(view) {
  if (!viewTitles[view]) return;
  state.view = view;
  document.querySelectorAll(".view").forEach((el) => el.classList.remove("active"));
  document.querySelectorAll(".nav button").forEach((el) => el.classList.remove("active"));
  q(`#${view}View`)?.classList.add("active");
  q(`.nav button[data-view="${view}"]`)?.classList.add("active");
  els.title.textContent = viewTitles[view];
  if (view === "vuln") void loadCveExposureGraph();
  document.dispatchEvent(new CustomEvent("soc:view", { detail: { view } }));
}

function showLoadError(err) {
  els.status.textContent = `Load failed: ${err.message}`;
  els.dot.className = "bad";
  els.connectionText.textContent = "Error";
  els.sideMeta.textContent = "Check MCP services";
  if (els.result) els.result.textContent = err.message;
}

document.querySelectorAll(".nav button").forEach((button) => {
  button.addEventListener("click", () => setView(button.dataset.view));
});

document.addEventListener("click", async (event) => {
  const mapMode = event.target.closest("[data-map-mode]");
  if (mapMode) {
    state.mapMode = mapMode.dataset.mapMode || "geo";
    if (state.overview) renderAttackMap(state.overview);
    return;
  }
  const mapAction = event.target.closest("[data-map-action]");
  if (mapAction) {
    const action = mapAction.dataset.mapAction;
    if (action === "more") state.mapLimit = Math.min(24, (number(state.mapLimit) || 16) + 4);
    if (action === "less") state.mapLimit = Math.max(6, (number(state.mapLimit) || 16) - 4);
    if (action === "zoom-in") state.mapZoom = Math.min(1.8, Math.round(((Number(state.mapZoom) || 1) + 0.2) * 10) / 10);
    if (action === "zoom-out") state.mapZoom = Math.max(1, Math.round(((Number(state.mapZoom) || 1) - 0.2) * 10) / 10);
    if (action === "reset") {
      state.mapMode = "geo";
      state.mapLimit = 16;
      state.mapZoom = 1;
    }
    if (state.overview) renderAttackMap(state.overview);
    return;
  }
  const incidentTrigger = event.target.closest("[data-incident-index]");
  if (incidentTrigger) {
    state.selectedIncident = number(incidentTrigger.dataset.incidentIndex);
    renderIncidentBoard(state.overview || {});
    return;
  }
  const saveIncident = event.target.closest("[data-save-incident]");
  if (saveIncident) {
    const incident = state.incidents.find(item => item.id === saveIncident.dataset.saveIncident);
    void saveIncidentCase(incident, saveIncident);
    return;
  }
  const createL1Case = event.target.closest("[data-create-l1-case]");
  if (createL1Case) {
    const row = state.l1Queue[number(createL1Case.dataset.createL1Case)];
    if (!row) return;
    createL1Case.disabled = true;
    createL1Case.textContent = "Saving...";
    try {
      const result = await postJson("/api/incidents/create", {
        title: row.title || "L1 alert investigation",
        srcips: [row.source_ip].filter(Boolean),
        notes: `L1 queue event ${row.event_id || "-"}; rule ${row.rule_id || "-"}; asset ${row.agent || "-"}; destination ${row.destination_ip || "-"}:${row.destination_port || "-"}`,
        owner: row.assignment === "unassigned" ? "" : row.assignment,
        sla_due: row.sla_due || (row.timestamp ? new Date(new Date(row.timestamp).getTime() + number(row.sla_minutes) * 60000).toISOString() : ""),
        status: "open",
      });
      if (!result.ok) throw new Error(result.error || "Case could not be saved");
      await loadPersistentCases();
    } catch (error) {
      createL1Case.disabled = false;
      createL1Case.textContent = `Retry: ${error.message}`;
    }
    return;
  }
  const toolTrigger = event.target.closest("[data-tool-name]");
  if (toolTrigger) {
    const tool = state.tools.find((item) => item.name === toolTrigger.dataset.toolName);
    if (tool) {
      applyToolPivot(tool, {
        ip: toolTrigger.dataset.pivotIp,
        cve: toolTrigger.dataset.pivotCve,
        ruleId: toolTrigger.dataset.pivotRuleId,
        keyword: toolTrigger.dataset.pivotKeyword,
        since: state.overview?.requested_range || els.range?.value || "24h",
        timeRange: state.overview?.requested_range || els.range?.value || "24h",
      });
      setView("tools");
      if (toolTrigger.dataset.autoRun === "true") {
        await runTool();
      }
    }
    return;
  }
  const link = event.target.closest("[data-view-link]");
  if (!link) return;
  setView(link.dataset.viewLink);
});

document.addEventListener("keydown", (event) => {
  if (!["Enter", " "].includes(event.key)) return;
  const target = event.target.closest?.("[data-tool-name], [data-view-link], [data-incident-index]");
  if (!target || target.tagName === "BUTTON") return;
  event.preventDefault();
  target.click();
});

document.querySelectorAll(".segments button").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".segments button").forEach((b) => b.classList.remove("active"));
    button.classList.add("active");
    state.filter = button.dataset.filter;
    renderTools();
  });
});

els.list?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-tool]");
  if (!button) return;
  const [source, ...nameParts] = button.dataset.tool.split(":");
  const name = nameParts.join(":");
  selectTool(state.tools.find((tool) => tool.source === source && tool.name === name));
});

els.search?.addEventListener("input", renderTools);
els.categorySelect?.addEventListener("change", () => {
  state.category = els.categorySelect.value;
  renderTools();
});
els.run?.addEventListener("click", runTool);
els.refresh?.addEventListener("click", () => loadDashboard(true).catch(showLoadError));
els.range?.addEventListener("change", () => {
  syncDateRangeVisibility();
  loadDashboard().catch(showLoadError);
});
els.globalStart?.addEventListener("change", () => loadDashboard().catch(showLoadError));
els.globalEnd?.addEventListener("change", () => loadDashboard().catch(showLoadError));
els.settingsForm?.addEventListener("submit", saveSettings);
els.resetSettings?.addEventListener("click", () => loadDashboard().catch(showLoadError));
els.testM365?.addEventListener("click", testM365);
els.startM365?.addEventListener("click", startM365Feed);
els.testIntel?.addEventListener("click", () => testThreatIntel(false, true));
els.cveBtn?.addEventListener("click", scoreCve);
els.cveInput?.addEventListener("keydown", (event) => {
  if (event.key === "Enter") scoreCve();
});
document.addEventListener("soc:automation", () => {
  if (state.view === "l3" && state.overview) {
    state.crowdSecIntel = null;
    loadCrowdSecIntel(true).catch(() => {});
  } else {
    renderCrowdSecIntel();
  }
});

loadDashboard().catch(showLoadError);
