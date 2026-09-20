/* Interface language is separate from unmodified vendor evidence. */
(() => {
  let language = "id";
  try { language = localStorage.getItem("soc-language") === "en" ? "en" : "id"; } catch (_) {}
  const titles = {
    history: ["Riwayat Event", "Event History"],
    findings: ["Temuan Keamanan", "Security Findings"], command: ["Pusat Operasi", "Command Center"],
    workbench: ["Ruang Kerja SOC", "SOC Workbench"], l1: ["Triase L1", "L1 Triage"],
    l2: ["Investigasi L2", "L2 Investigation"], incidents: ["Insiden", "Incidents"],
    l3: ["Perburuan Ancaman", "Threat Hunting"], vuln: ["Kerentanan", "Vulnerabilities"],
    assets: ["Aset", "Assets"], tools: ["Konsol Tool", "Tool Console"], settings: ["Pengaturan", "Settings"]
  };
  const labels = {"Refresh": "Perbarui", "Search findings": "Cari temuan", "Evidence": "Bukti", "Severity": "Keparahan",
    "All evidence": "Semua bukti", "All severities": "Semua keparahan", "Critical": "Kritis", "High": "Tinggi", "Medium": "Sedang", "Low": "Rendah",
    "Wazuh observed": "Teramati di Wazuh", "Asset inventory": "Inventaris aset", "Not assessed": "Belum dinilai", "Most urgent first": "Prioritas tertinggi",
    "Integration health": "Kesehatan integrasi", "Overview": "Ringkasan", "Local evidence": "Bukti lokal", "Threat intelligence": "Intelijen ancaman", "CVE context": "Konteks CVE",
    "Previous": "Sebelumnya", "Next": "Berikutnya", "Source record": "Rekaman sumber", "All findings": "Semua temuan", "Wazuh alerts": "Alert Wazuh",
    "Source IP / Geo": "IP sumber / Geo", "Log indicators": "Indikator log", "CVE & Exposure": "CVE & Paparan", "Settings": "Pengaturan",
    "SOC Action Deck": "Aksi Analis SOC", "Threat Intel Workbench": "Analisis Intelijen", "Response Guardrails": "Kontrol Respons",
    "Cloud and Container": "Cloud dan Container", "Compliance Evidence": "Bukti Kepatuhan", "L1 Alert Triage": "Triase Alert L1",
    "Agent Availability": "Ketersediaan Agent", "Investigation Flow": "Alur Investigasi", "Detection Layers": "Lapisan Deteksi",
    "Source Geo and IP Map": "Peta Geo dan IP Sumber", "Priority Threat Queue": "Antrean Ancaman Prioritas", "Microsoft 365 Analytics": "Analitik Microsoft 365"};
  const originals = new WeakMap();
  function translateLabels() {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      if (node.parentElement.closest('script,style,pre,code,textarea,.findingFields,.analystExplanation')) continue;
      const value = node.textContent.trim();
      let original = originals.get(node);
      if (!original && Object.hasOwn(labels, value)) { original = value; originals.set(node, original); }
      if (!original) continue;
      const target = language === "id" ? labels[original] : original;
      if (value !== target && (value === original || value === labels[original])) node.textContent = node.textContent.replace(value, target);
    }
  }
  function apply() {
    document.documentElement.lang = language;
    Object.entries(titles).forEach(([key, values]) => {
      viewTitles[key] = values[language === "id" ? 0 : 1];
      const button = document.querySelector(`.nav [data-view="${key}"]`);
      if (button) for (const node of button.childNodes) if (node.nodeType === Node.TEXT_NODE) node.textContent = values[language === "id" ? 0 : 1];
    });
    els.title.textContent = viewTitles[state.view];
    translateLabels();
  }
  function analysis(value, field) {
    if (!value) return "";
    if (language === "en") return value[`${field}_en`] || value[field] || "";
    return value[field] || value[`${field}_en`] || "";
  }
  window.SocLocale = {get language() { return language; }, t: (id, en) => language === "id" ? id : en, analysis};
  const select = document.createElement("select");
  select.id = "languageSelect"; select.setAttribute("aria-label", "Bahasa / Language");
  select.innerHTML = '<option value="id">Indonesia</option><option value="en">English</option>';
  select.value = language; document.querySelector(".topbar .actions").prepend(select);
  select.addEventListener("change", () => {
    language = select.value;
    try { localStorage.setItem("soc-language", language); } catch (_) {}
    apply(); document.dispatchEvent(new CustomEvent("soc:language"));
  });
  let scheduled = false;
  new MutationObserver(() => {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => { scheduled = false; translateLabels(); });
  }).observe(document.querySelector("main"), {childList: true, subtree: true});
  apply();
})();
