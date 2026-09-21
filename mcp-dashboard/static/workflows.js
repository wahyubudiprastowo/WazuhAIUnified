(() => {
  "use strict";
  const menus = ["l1", "l2", "l3", "vuln", "assets", "incidents", "workbench", "history", "settings"];
  const stamp = value => value ? new Date(value * 1000).toLocaleString() : "-";
  const dialog = document.createElement("dialog");
  dialog.className = "workflowDialog";
  dialog.setAttribute("aria-labelledby", "workflowDialogTitle");
  dialog.innerHTML = `<form method="dialog"><button class="workflowClose" aria-label="Close" title="Close">&times;</button></form>
    <h2 id="workflowDialogTitle">Tool workflow</h2><p id="workflowPolicy"></p>
    <form id="workflowRunForm"><label for="workflowArgs">Arguments (JSON)</label>
      <textarea id="workflowArgs" rows="8" spellcheck="false" required></textarea>
      <button id="workflowExecute" type="submit">Queue analysis</button></form>
    <p id="workflowRunStatus" role="status" aria-live="polite"></p><pre id="workflowResult"></pre>`;
  document.body.append(dialog);
  let selected = null;

  async function run(tool, args, update) {
    let job = await postJson("/api/workflows/run", { source: tool.source, name: tool.name, arguments: args });
    for (let attempt = 0; attempt < 60 && ["queued", "running"].includes(job.status); attempt++) {
      update(`${job.status === "queued" ? "Queued" : "Running"} | ${tool.name} | Job ${job.id}`);
      await new Promise(resolve => setTimeout(resolve, 2000));
      job = await postJson("/api/workflows/job", { id: job.id });
    }
    if (job.status === "failed") throw new Error(job.error || "Workflow failed");
    if (job.status !== "completed") throw new Error(`Still ${job.status}. Saved job ${job.id}; check workflow history.`);
    update(`${job.cached ? "Cached result" : "Completed"} | ${stamp(job.finished)}`);
    return job.result;
  }
  window.SocWorkflows = { run };

  function openTool(tool) {
    selected = tool;
    q("#workflowDialogTitle").textContent = tool.name;
    q("#workflowPolicy").textContent = `${tool.source} | ${tool.workflow.mode} | ${tool.workflow.dependency} | cache ${tool.workflow.cache_seconds / 60} min`;
    q("#workflowArgs").value = JSON.stringify(contextualArgs(tool), null, 2);
    q("#workflowRunStatus").textContent = "";
    q("#workflowResult").textContent = "";
    q("#workflowRunForm").hidden = false;
    q("#workflowExecute").textContent = tool.workflow.mode === "approval" ? "Confirm and run" : "Queue analysis";
    dialog.showModal();
  }
  q("#workflowRunForm").addEventListener("submit", async event => {
    event.preventDefault();
    const tool = selected;
    const button = q("#workflowExecute");
    const update = message => { q("#workflowRunStatus").textContent = message; };
    button.disabled = true;
    q("#workflowResult").textContent = "";
    try {
      const args = JSON.parse(q("#workflowArgs").value);
      const missing = missingRequiredArgs(tool, args);
      if (missing.length) throw new Error(`Required: ${missing.join(", ")}`);
      let result;
      if (tool.workflow.mode === "approval") {
        if (!window.confirm(`Run ${tool.name}? Review the arguments: this operation may change data, affect a host, or run an expensive query.`)) {
          update("Cancelled"); return;
        }
        update("Running confirmed operation...");
        result = await postJson("/api/call", { source: tool.source, name: tool.name, arguments: args, confirmed: true });
        update(result.ok ? "Completed" : "Tool returned an error");
      } else {
        result = await run(tool, args, update);
      }
      q("#workflowResult").textContent = result.json != null ? JSON.stringify(result.json, null, 2) : result.text;
    } catch (error) { update(error.message); }
    finally { button.disabled = false; loadMenu(tool.workflow.menu, true); }
  });

  function mount() {
    for (const menu of menus) {
      const view = q(`#${menu}View`);
      if (!view) continue;
      let panel = q(`#workflow-${menu}`);
      if (!panel) {
        panel = document.createElement("section");
        panel.id = `workflow-${menu}`;
        panel.className = "workflowBand";
        panel.innerHTML = `<details><summary><span>Advanced actions</span><small data-workflow-summary>Cached analyses and operator-approved tools</small></summary>
          <div class="workflowBody"><div class="workflowControls"><label>Tool<select aria-label="${esc(viewTitles[menu])} tools"></select></label>
          <button type="button" data-prepare>Prepare</button><button type="button" data-history>Refresh history</button></div>
          <p class="workflowStatus" role="status" aria-live="polite"></p>
          <div class="workflowHistory"></div></div></details>`;
        view.append(panel);
        panel.querySelector("[data-prepare]").addEventListener("click", () => {
          const key = panel.querySelector("select").value;
          const tool = state.tools.find(t => `${t.source}:${t.name}` === key);
          if (tool) openTool(tool);
        });
        panel.querySelector("[data-history]").addEventListener("click", () => loadMenu(menu, true));
        panel.querySelector("details").addEventListener("toggle", event => {
          if (event.currentTarget.open) loadMenu(menu, true);
        });
        panel.addEventListener("click", async event => {
          const target = event.target.closest("[data-workflow-job]");
          if (!target) return;
          try {
            const job = await postJson("/api/workflows/job", { id: target.dataset.workflowJob });
            q("#workflowDialogTitle").textContent = job.name;
            q("#workflowPolicy").textContent = `${job.source} | ${stamp(job.finished || job.created)}`;
            q("#workflowRunForm").hidden = true;
            q("#workflowRunStatus").textContent = job.error || job.status;
            q("#workflowResult").textContent = job.result?.json != null ? JSON.stringify(job.result.json, null, 2) : (job.result?.text || "");
            dialog.showModal();
          } catch (error) { panel.querySelector(".workflowStatus").textContent = error.message; }
        });
      }
      const tools = state.tools.filter(t => t.workflow?.menu === menu);
      const select = panel.querySelector("select");
      const previous = select.value;
      select.innerHTML = tools.map(t => `<option value="${esc(t.source)}:${esc(t.name)}">${esc(t.name)} [${esc(t.workflow.mode)}]</option>`).join("");
      if (tools.some(t => `${t.source}:${t.name}` === previous)) select.value = previous;
      panel.querySelector("[data-prepare]").disabled = tools.length === 0;
      panel.querySelector("[data-workflow-summary]").textContent = `${tools.length} mapped actions · collapsed to keep operational evidence in focus`;
    }
  }

  async function loadMenu(menu, force = false) {
    const panel = q(`#workflow-${menu}`);
    if (!panel) return;
    if (!force && !panel.querySelector("details")?.open) return;
    const version = String(Number(panel.dataset.request || 0) + 1);
    panel.dataset.request = version;
    const status = panel.querySelector(".workflowStatus");
    status.textContent = "Loading saved evidence...";
    const windowPayload = currentWindowPayload();
    const now = Math.floor(Date.now() / 60000) * 60000;
    const end = windowPayload.end || new Date(now).toISOString();
    const hours = { "24h": 24, "7d": 168, "30d": 720 }[windowPayload.range] || 24;
    const start = windowPayload.start || new Date(now - hours * 3600000).toISOString();
    try {
      const history = await postJson("/api/workflows/history", { menu, start, end });
      if (panel.dataset.request !== version) return;
      status.textContent = `${history.jobs.length} saved runs in selected window | ${history.counts.queued || 0} queued | ${history.counts.running || 0} running | budgets ${history.local_runs_per_hour} local / ${history.external_runs_per_hour} provider per hour | retention ${history.retention_days}d`;
      panel.querySelector(".workflowHistory").innerHTML = history.jobs.length ?
        `<table><thead><tr><th>Tool</th><th>Status</th><th>Collected</th></tr></thead><tbody>${history.jobs.map(job =>
          `<tr><td><button type="button" data-workflow-job="${esc(job.id)}">${esc(job.name)}</button></td><td>${esc(job.status)}</td><td>${esc(stamp(job.finished || job.created))}</td></tr>`).join("")}</tbody></table>` :
        `<p>No saved tool runs in this period.</p>`;
    } catch (error) { if (panel.dataset.request === version) status.textContent = `Saved evidence unavailable: ${error.message}`; }
  }
  document.addEventListener("soc:tools", mount);
  document.addEventListener("soc:view", event => { mount(); loadMenu(event.detail.view); });
  mount();
})();
