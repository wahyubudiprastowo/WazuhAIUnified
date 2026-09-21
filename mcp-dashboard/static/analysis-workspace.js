/* Shared analyst context across operational views. */
(() => {
  const t = (id, en) => window.SocLocale?.t ? window.SocLocale.t(id, en) : en;
  const ax = (analysis, field) => window.SocLocale?.analysis ? window.SocLocale.analysis(analysis, field) : (analysis?.[field] || "");
  const a = {coverage: null, coverageWindow: "", coverageLoadedAt: 0, loadingWindow: "", selected: "", results: new Map(), pending: new Map(), generation: 0, busy: false};
  const providers = ["otx", "greynoise", "virustotal", "cyfirma"];
  const names = {otx: "AlienVault OTX", greynoise: "GreyNoise", virustotal: "VirusTotal", cyfirma: "CYFIRMA"};
  const areas = ["workbench", "l1", "l2"];
  const coverageViews = new Set(["findings", ...areas]);
  const coverageEnabled = view => coverageViews.has(view) ||
    (view === "command" && new URLSearchParams(window.location.search).get("enterprise") === "1");
  for (const view of areas) {
    const node = document.createElement("section");
    node.className = "analysisOverview glassPanel";
    node.dataset.analysisView = view;
    if (view === "workbench") q('#automationPanel').after(node);
    else if (view === "l1") q(`#${view}View`).append(node);
    else q(`#${view}View`).prepend(node);
  }
  const coveragePayload = () => window.SocWindow?.payload ? window.SocWindow.payload() : {range: els.range.value};
  const coverageKey = payload => JSON.stringify(payload);
  const activeAreas = () => [...document.querySelectorAll("[data-analysis-view]")].filter(el => el.dataset.analysisView === state.view);
  function eligible() { return (a.coverage?.observables || []).filter(r => r.public && r.indicator); }
  function verdict(row) {
    if (!row) return t("Belum dianalisis", "Not analyzed");
    if (row.error) return /429|rate.limit/i.test(row.error) ? t("Batas API tercapai", "API rate limit reached") : t("Tidak tersedia", "Unavailable");
    if (row.detail?.skipped) return t("Tipe tidak didukung", "Unsupported type");
    if (row.is_malicious) return t("Indikasi berbahaya", "Adverse intelligence");
    if (row.detail?.analysis_stats?.suspicious > 0) return t("Deteksi suspicious; perlu verifikasi", "Suspicious detection; verify");
    if (row.detail?.classification === "unknown" || row.detail?.message?.includes("No data")) return t("Tidak ada data", "No data");
    if (row.risk_level === "medium" || row.risk_level === "high") return t("Perlu pemeriksaan", "Needs review");
    return t("Tidak ada indikasi dari penyedia", "No adverse indication from provider");
  }
  function reason(row) {
    if (!row) return t("Pilih indikator untuk memuat bukti.", "Select an indicator to load evidence.");
    if (row.error) return String(row.error).slice(0, 240);
    const d = row.detail || {};
    if (d.skipped) return t("Penyedia tidak mendukung tipe indikator ini.", "This provider does not support this indicator type.");
    if (row.provider === "otx") return t(`${d.pulse_count || 0} pulse cocok. Keluarga malware: ${(row.malware_families || []).join(", ") || "belum dilaporkan"}. Tidak ada pulse bukan jaminan aman.`, `${d.pulse_count || 0} matching pulses. Malware families: ${(row.malware_families || []).join(", ") || "not reported"}. No pulses does not guarantee safety.`);
    if (row.provider === "greynoise") return d.message || t(`Klasifikasi: ${(row.tags || []).filter(Boolean).join(", ") || "unknown"}. Terakhir terlihat: ${d.last_seen || "tidak tersedia"}.`, `Classification: ${(row.tags || []).filter(Boolean).join(", ") || "unknown"}. Last seen: ${d.last_seen || "not available"}.`);
    if (row.provider === "virustotal") { const s = d.analysis_stats || {}; return t(`${s.malicious ?? "?"} malicious, ${s.suspicious ?? "?"} suspicious, ${s.undetected ?? "?"} undetected. ${d.as_owner || ""} Undetected bukan verdict aman.`, `${s.malicious ?? "?"} malicious, ${s.suspicious ?? "?"} suspicious, ${s.undetected ?? "?"} undetected. ${d.as_owner || ""} Undetected is not a safe verdict.`); }
    if (row.provider === "cyfirma") return t(`${d.match_count || 0} IOC cocok; tailored ${d.scanned?.tailored ?? "?"}, global ${d.scanned?.global ?? "?"} diperiksa. ${(row.tags || []).join(", ")}`, `${d.match_count || 0} IOC matches; tailored ${d.scanned?.tailored ?? "?"}, global ${d.scanned?.global ?? "?"} checked. ${(row.tags || []).join(", ")}`);
    return t("Periksa bukti penyedia.", "Review provider evidence.");
  }
  function providerRows(indicator) {
    const result = a.results.get(indicator), rows = result?.data?.results || [];
    return providers.map(provider => {
      const row = rows.find(r => r.provider === provider);
      return `<tr><th>${names[provider]}</th><td><span class="analysisStatus ${row?.is_malicious ? "danger" : row?.error ? "warning" : ""}">${esc(a.pending.has(indicator) ? t("Memuat...", "Loading...") : result?.error && !rows.length ? t("Tidak tersedia", "Unavailable") : verdict(row))}</span></td><td>${esc(result?.error && !rows.length ? String(result.error).slice(0, 240) : reason(row))}</td></tr>`;
    }).join("");
  }
  function ruleText(rule, compact = false) {
    const x = rule?.analysis;
    if (!x) return "";
    return `<div class="analystExplanation"><strong>${esc(ax(x, "title"))}</strong><p>${esc(ax(x, "meaning"))}</p><dl><dt>L1 · ${t("Verifikasi awal", "Initial verification")}</dt><dd>${esc(ax(x, "l1"))}</dd>${compact ? "" : `<dt>L2 · ${t("Investigasi", "Investigation")}</dt><dd>${esc(ax(x, "l2"))}</dd><dt>${t("Hubungan CVE", "CVE relationship")}</dt><dd>${esc(ax(x, "cve_context"))}</dd>`}</dl><small>Rule ${esc(rule.rule_id)} | ${esc(x.original)}</small><button type="button" data-analysis-rule="${esc(rule.rule_id)}">${t("Buka bukti rule", "Open rule evidence")}</button></div>`;
  }
  function render() {
    const c = a.coverage;
    if (!c) return;
    const candidates = eligible(), target = candidates.find(r => r.indicator === a.selected);
    const completed = [...a.results.keys()].filter(k => candidates.some(r => r.indicator === k)).length;
    const decoders = (c.decoders || []).length ? c.decoders : (c.sources || []).map(row => ({name: row.key, count: row.doc_count}));
    const decoderSummary = decoders.slice(0, 5).map(row => `${row.name || "unknown"} (${fmt.format(row.count || 0)})`).join(", ") || t("belum tersedia", "not available");
    for (const area of activeAreas()) {
      const view = area.dataset.analysisView;
      area.innerHTML = `<div class="panelHead"><h2>${view === "l1" ? t("Konteks triage", "Triage context") : view === "l2" ? t("Bukti investigasi lintas sumber", "Cross-source investigation evidence") : t("Analisis indikator dari log Wazuh", "Indicator analysis from Wazuh logs")}</h2><span>${esc(c.range)} | ${esc(c.index)}</span></div><div class="analysisBody"><div class="analysisMetrics"><div><span>${t("Alert terindeks", "Indexed alerts")}</span><b>${fmt.format(c.total_events)}</b></div><div><span>${t("Event dengan field indikator", "Events with indicator fields")}</span><b>${fmt.format(c.events_with_observable)}</b></div><div><span>${t("Kandidat publik dimuat", "Public candidates loaded")}</span><b>${candidates.length}</b></div><div><span>${t("Indikator diproses", "Indicators processed")}</span><b>${completed} / ${candidates.length}</b></div></div><p class="analysisScope"><strong>${t("Cakupan decoder", "Decoder coverage")}:</strong> ${esc(decoderSummary)} | <strong>${t("Rule unik dimuat", "Unique rules loaded")}:</strong> ${fmt.format(number(c.rule_candidates?.unique || c.rules?.length))}</p><p class="analysisScope">${esc(SocLocale.language === "en" ? "Indexed alert aggregation for the selected range; raw archives are not read. Candidates are limited to 30 values per field. Enrichment only covers processed indicators, not every log." : c.scope_note)} ${c.other_rule_events ? t(`${fmt.format(c.other_rule_events)} event berada di luar daftar rule yang dimuat.`, `${fmt.format(c.other_rule_events)} events are outside the loaded rule list.`) : ""}</p><div class="analysisControls"><label>${t("Indikator dari log", "Indicator from logs")}<select data-analysis-select>${candidates.map(r => `<option value="${esc(r.indicator)}" ${r.indicator === a.selected ? "selected" : ""}>${esc(r.indicator)} · ${r.kind} · ${fmt.format(r.occurrences)} ${t("kemunculan field", "field occurrences")}</option>`).join("")}</select></label><button type="button" data-analysis-batch ${a.busy || completed >= candidates.length ? "disabled" : ""}>${a.busy ? t("Analisis berjalan...", "Analysis running...") : t("Analisis 3 berikutnya", "Analyze next 3")}</button><button type="button" data-analysis-open="${esc(a.selected)}" ${a.selected ? "" : "disabled"}>${t("Bukti lengkap", "Full evidence")}</button></div><p class="analysisScope">Field: ${esc(target?.fields?.join(", ") || "-")} | Rule: ${esc(target?.rules?.join(", ") || "-")} | ${t("Hitungan kemunculan antar-field dapat tumpang tindih.", "Field occurrence counts can overlap.")}</p><div class="analysisTableWrap"><table class="analysisTable"><thead><tr><th>${t("Penyedia", "Provider")}</th><th>${t("Hasil", "Result")}</th><th>${t("Makna untuk analis", "Meaning for analyst")}</th></tr></thead><tbody>${providerRows(a.selected)}</tbody></table></div><p class="analysisScope">${a.results.get(a.selected)?.generated_at ? t(`Hasil diperiksa ${esc(a.results.get(a.selected).generated_at)}. `, `Result checked ${esc(a.results.get(a.selected).generated_at)}. `) : ""}${t("Tidak semua log memiliki IP publik, domain atau hash yang dapat diperiksa oleh layanan intelijen.", "Not every log contains a public IP, domain or hash that can be checked by intelligence services.")}</p><details class="analysisRuleGuide" ${view === "l1" ? "open" : ""}><summary>${t("Penjelasan rule prioritas dan saran", "Priority rule explanation and guidance")} ${view === "l1" ? "L1" : "L2"}</summary>${(c.rules || []).slice(0, view === "l1" ? 3 : 5).map(r => ruleText(r, view === "l1")).join("")}</details></div>`;
    }
  }
  async function analyze(indicator) {
    if (!indicator || a.results.has(indicator)) return;
    if (a.pending.has(indicator)) return a.pending.get(indicator);
    const generation = a.generation;
    const promise = postJson("/api/findings/intel", {kind: "aggregate", indicator}).then(result => {
      if (generation === a.generation) {
        a.results.set(indicator, result);
        document.dispatchEvent(new CustomEvent("soc:indicator", {detail: {indicator, result}}));
      }
    }).catch(e => { if (generation === a.generation) a.results.set(indicator, {ok: false, error: e.message}); }).finally(() => {
      if (generation === a.generation) { a.pending.delete(indicator); render(); }
    });
    a.pending.set(indicator, promise); render(); return promise;
  }
  async function loadCoverage(force = false) {
    if (!coverageEnabled(state.view)) return;
    const payload = coveragePayload();
    const windowKey = coverageKey(payload);
    if (!force && a.coverage && a.coverageWindow === windowKey && Date.now() - a.coverageLoadedAt < 120000) {
      window.SocFindings?.setCoverage(a.coverage);
      render();
      return;
    }
    if (a.loadingWindow === windowKey) return;
    const generation = ++a.generation;
    a.loadingWindow = windowKey;
    if (a.coverageWindow !== windowKey) {
      a.coverage = null; a.results.clear(); a.pending.clear(); a.busy = false;
    }
    activeAreas().forEach(el => el.innerHTML = `<div class="analysisBody">${t("Menghitung cakupan alert terindeks...", "Calculating indexed alert coverage...")}</div>`);
    try {
      const data = await postJson("/api/analysis/coverage", payload);
      if (generation !== a.generation) return;
      if (!data.ok) throw new Error(t("Indexer mengembalikan hasil parsial atau timeout. Cakupan belum dapat dinyatakan lengkap.", "Indexer returned partial results or timed out. Coverage cannot be declared complete."));
      a.coverage = data;
      a.coverageWindow = windowKey;
      a.coverageLoadedAt = Date.now();
      document.dispatchEvent(new CustomEvent("soc:coverage", {detail: data}));
      window.SocFindings?.setCoverage(data);
      if (state.view === "l1") renderThreatTable("#l1Queue", data.rules.slice(0, 25));
      if (!eligible().some(row => row.indicator === a.selected)) a.selected = eligible()[0]?.indicator || "";
      render();
    } catch (e) { if (generation === a.generation) activeAreas().forEach(el => el.innerHTML = `<div class="analysisBody">${t("Cakupan belum tersedia", "Coverage unavailable")}: ${esc(e.message)}</div>`); }
    finally { if (generation === a.generation) a.loadingWindow = ""; }
  }
  document.addEventListener("soc:overview", () => { if (coverageEnabled(state.view)) setTimeout(loadCoverage, 0); });
  document.addEventListener("soc:view", event => { if (coverageEnabled(event.detail.view)) setTimeout(loadCoverage, 0); });
  document.querySelector("#refreshBtn")?.addEventListener("click", () => { if (coverageEnabled(state.view)) setTimeout(() => loadCoverage(true), 0); });
  document.addEventListener("soc:language", render);
  document.addEventListener("change", e => {
    if (!e.target.matches("[data-analysis-select]")) return;
    a.selected = e.target.value; render(); analyze(a.selected);
  });
  document.addEventListener("click", async e => {
    const rule = e.target.closest("[data-analysis-rule]");
    const open = e.target.closest("[data-analysis-open]");
    const batch = e.target.closest("[data-analysis-batch]");
    if (!rule && !open && !batch) return;
    e.stopImmediatePropagation();
    if (rule) { window.SocFindings?.open("rule", rule.dataset.analysisRule); return; }
    if (open) { const value = open.dataset.analysisOpen; const candidate = (a.coverage?.observables || []).find(r => r.indicator === value); window.SocFindings?.open(candidate?.kind === "ip" || isPublicObservableIp(value) ? "ip" : "indicator", value); return; }
    if (a.busy) return;
    const generation = a.generation;
    a.busy = true; render();
    for (const row of eligible().filter(r => !a.results.has(r.indicator)).slice(0, 3)) {
      if (generation !== a.generation) return;
      await analyze(row.indicator);
    }
    if (generation === a.generation) { a.busy = false; render(); }
  }, true);
  document.addEventListener("keydown", e => {
    const row = e.target.closest("article[data-analysis-rule]");
    if (row && ["Enter", " "].includes(e.key)) { e.preventDefault(); row.click(); }
  });
  document.addEventListener("soc:tool-result", e => {
    const parsed = e.detail.json || tryParseJson(e.detail.text) || {}, ip = parsed.srcip || parsed.ip || parsed.indicator;
    const ruleIds = (parsed.top_rules || []).map(r => String(r.rule_id || r.id || r.key));
    if (parsed.rule?.id) ruleIds.push(String(parsed.rule.id));
    const matched = (a.coverage?.rules || state.overview?.threats || []).filter(r => ruleIds.includes(String(r.rule_id)));
    const block = document.createElement("section"); block.className = "toolAnalystContext";
    block.innerHTML = `<h3>${t("Ringkasan untuk analis", "Analyst summary")}</h3>${ip ? `<p>${t("Indikator", "Indicator")}: <strong>${esc(ip)}</strong>. ${t("Angka alert menunjukkan aktivitas, bukan jumlah serangan yang berhasil.", "Alert counts show activity, not the number of successful attacks.")}</p><button type="button" data-analysis-open="${esc(ip)}">${t("Buka bukti dan intelijen", "Open evidence and intelligence")}</button>` : ""}${matched.map(r => ruleText(r)).join("")}${!ip && !matched.length ? `<p>${t("Makna mengikuti field dan verdict pada hasil tool. Tidak ada hubungan CVE atau status kompromi yang dapat disimpulkan tanpa bukti tambahan.", "Meaning follows the fields and verdicts in the tool result. No CVE relationship or compromise status can be concluded without additional evidence.")}</p>` : ""}`;
    els.result.querySelector(".resultHeader")?.after(block);
  });
})();
