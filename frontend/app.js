"use strict";

const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[c]));

let mode = "local";
let jobId = null;
let allFindings = [];
let activeFilter = "ALL";
let counters = { found: 0, confirmed: 0, verified: 0, pass: 0, reject: 0 };

// ── View Navigation ─────────────────────────────────────────────
function switchView(viewName) {
  const views = { setup: $("#viewSetup"), scanning: $("#viewScanning"), report: $("#viewReport") };
  Object.values(views).forEach((v) => v && v.classList.add("hidden"));
  if (views[viewName]) {
    views[viewName].classList.remove("hidden");
    views[viewName].scrollIntoView({ behavior: "smooth" });
  }
}

// ── System Engine Status ─────────────────────────────────────────
async function checkSystemEngine() {
  const host = $("#host").value.trim();
  const box = $("#llmStatus");
  const sel = $("#model");
  try {
    const res = await fetch("/api/health?host=" + encodeURIComponent(host));
    const data = await res.json();
    if (data.ollama_available) {
      box.className = "llm-status on";
      $("#llmText").textContent = `System Engine Online (${data.models.length} model${data.models.length === 1 ? "" : "s"})`;
      const prev = sel.value;
      sel.innerHTML = "";
      data.models.forEach((m) => {
        const opt = document.createElement("option");
        opt.value = opt.textContent = m;
        sel.appendChild(opt);
      });
      const preferred = data.models.find((m) => m.includes("qwen2.5-coder")) || data.models[0];
      sel.value = data.models.includes(prev) ? prev : preferred;
    } else {
      box.className = "llm-status off";
      $("#llmText").textContent = "System Engine Offline (Deterministic Fallback Active)";
      if (!sel.options.length) {
        const opt = document.createElement("option");
        opt.value = opt.textContent = "qwen2.5-coder:7b";
        sel.appendChild(opt);
      }
    }
  } catch {
    box.className = "llm-status off";
    $("#llmText").textContent = "Backend Offline";
  }
}
$("#host").addEventListener("change", checkSystemEngine);
checkSystemEngine();

// ── Source Mode Tabs ─────────────────────────────────────────────
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    mode = tab.dataset.mode;
    $("#localField").classList.toggle("hidden", mode !== "local");
    $("#githubField").classList.toggle("hidden", mode !== "github");
  });
});

// ── Start Scan ───────────────────────────────────────────────────
function showError(msg) {
  const err = $("#formError");
  err.textContent = msg;
  err.classList.toggle("hidden", !msg);
}

$("#startBtn").addEventListener("click", async () => {
  showError("");
  const payload = {
    source_type: mode,
    local_path: mode === "local" ? $("#localPath").value : $("#parityPath").value,
    github_url: mode === "github" ? $("#githubUrl").value.trim() : null,
    ollama_model: $("#model").value || "qwen2.5-coder:7b",
    ollama_host: $("#host").value.trim(),
    use_llm: $("#useLlm").checked,
  };

  const startBtn = $("#startBtn");
  startBtn.disabled = true;
  startBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Initializing scan...`;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Scan request failed");
    jobId = data.job_id;
    initScanUI(data.label, data.parity);
    listenToEvents();
  } catch (err) {
    showError(err.message);
  } finally {
    startBtn.disabled = false;
    startBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Start Security Scan`;
  }
});

function initScanUI(label, parity) {
  switchView("scanning");
  $("#jobLabel").textContent = label;
  $("#terminalStatus").textContent = "RUNNING";
  $("#terminalStatus").className = "terminal-status-tag";
  $("#terminalLog").innerHTML = `<div class="term-line info"><span class="prompt">$</span> sentinel-ai initializing for [${esc(label)}]</div>`;
  $("#progressBar").style.width = "3%";
  $("#completionBanner").classList.add("hidden");
  document.querySelectorAll(".flow-step").forEach((n) => n.classList.remove("active", "done"));
  ["foundCount", "confirmedCount", "verifiedCount"].forEach((id) => ($("#" + id).textContent = "–"));
  $("#judgeText").textContent = "PASS / REJECT";
  counters = { found: 0, confirmed: 0, verified: 0, pass: 0, reject: 0 };

  if (parity) {
    const box = $("#parityBox");
    box.classList.remove("hidden");
    box.innerHTML = parity.in_sync
      ? `✔ Local matches GitHub (${parity.local_count} files)`
      : `⚠ Mismatch: ${parity.only_in_local.length} local-only, ${parity.only_in_remote.length} remote-only. Scanning remote.`;
  } else {
    $("#parityBox").classList.add("hidden");
  }
}

// ── Live Event Stream ────────────────────────────────────────────
function updateStep(nodeName, state) {
  const step = document.querySelector(`[data-node="${nodeName}"]`);
  if (!step) return;
  step.classList.toggle("active", state === "active");
  step.classList.toggle("done", state === "done");
}

function appendLog(text, level = "") {
  const box = $("#terminalLog");
  const line = document.createElement("div");
  line.className = `term-line ${level}`;
  const time = new Date().toLocaleTimeString("en-US", { hour12: false });
  line.innerHTML = `<span class="prompt">[${time}]</span> ${text}`;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

function listenToEvents() {
  const sse = new EventSource(`/api/scan/${jobId}/events`);
  sse.onmessage = (msg) => {
    const ev = JSON.parse(msg.data);
    switch (ev.type) {
      case "source_validated":
        appendLog(`Source confirmed: <span class="tag">[${esc(ev.label)}]</span>`, "ok");
        break;
      case "files_discovered":
        appendLog(`Found <b>${ev.count}</b> source file${ev.count !== 1 ? "s" : ""} to scan.`, "info");
        break;
      case "stage":
        if (ev.stage === "analyzing") { updateStep("analyst", "active"); }
        else if (ev.stage === "validating") { updateStep("analyst", "done"); updateStep("found", "done"); updateStep("validator", "active"); }
        else if (ev.stage === "patching") { updateStep("validator", "done"); updateStep("confirmed", "done"); updateStep("patcher", "active"); }
        if (ev.message) appendLog(`[STAGE] ${esc(ev.message)}`);
        break;
      case "analyzing_file":
        $("#progressBar").style.width = Math.min(45, Math.round((ev.index / ev.total) * 45)) + "%";
        appendLog(`Scanning file ${ev.index}/${ev.total}: <code>${esc(ev.file)}</code>`);
        break;
      case "analysis_complete":
        counters.found = ev.findings_count;
        $("#foundCount").textContent = `${ev.findings_count} found`;
        appendLog(`Analysis complete: <b>${ev.findings_count}</b> potential issue${ev.findings_count !== 1 ? "s" : ""} detected.`, "ok");
        $("#progressBar").style.width = "50%";
        break;
      case "finding_confirmed":
        counters.confirmed++;
        $("#confirmedCount").textContent = `${counters.confirmed} confirmed`;
        appendLog(`Confirmed exploit: <span class="tag bad">[${esc(ev.severity?.toUpperCase())}]</span> ${esc(ev.title)} in <code>${esc(ev.file)}</code>`, "warn");
        break;
      case "finding_not_exploitable":
        appendLog(`Benign pattern — not exploitable: ${esc(ev.title)} in <code>${esc(ev.file)}</code>`, "info");
        break;
      case "finding_patching":
        appendLog(`Generating fix for: ${esc(ev.title)} (attempt ${ev.attempt})…`);
        break;
      case "finding_patched":
        updateStep("patcher", "done");
        updateStep("judge", "active");
        if (ev.verdict === "PASS") {
          counters.pass++;
          appendLog(`Judge: <span class="tag ok">[PASS]</span> — fix verified on attempt ${ev.attempt} (${esc(ev.file)})`, "ok");
        } else {
          counters.reject++;
          appendLog(`Judge: <span class="tag bad">[REJECT]</span> — retrying with feedback: ${esc(ev.reason || "")} (${esc(ev.file)})`, "bad");
        }
        $("#judgeText").textContent = `${counters.pass}P · ${counters.reject}R`;
        $("#progressBar").style.width = "80%";
        break;
      case "finding_manual_review":
        appendLog(`Auto-patch failed after 3 attempts — flagged for manual review.`, "warn");
        break;
      case "file_regression_complete":
        updateStep("judge", "done");
        updateStep("regression", "done");
        appendLog(
          `Regression check — ${esc(ev.file)}: Syntax ${ev.syntax_ok ? "✓ OK" : "✗ FAIL"} | Structure ${ev.structure_preserved ? "✓ Preserved" : "✗ Mutated"}`,
          ev.syntax_ok ? "ok" : "bad"
        );
        break;
      case "done":
        sse.close();
        updateStep("judge", "done");
        updateStep("regression", "done");
        updateStep("verified", "done");
        $("#progressBar").style.width = "100%";
        $("#terminalStatus").textContent = "COMPLETE";
        $("#terminalStatus").classList.add("complete");
        appendLog(`✔ Sentinel AI analysis complete. All fixes staged.`, "ok");
        prepareResults(ev.summary);
        break;
      case "error":
        sse.close();
        $("#terminalStatus").textContent = "ERROR";
        appendLog(`✖ Error: ${esc(ev.message)}`, "bad");
        showError(ev.message);
        break;
    }
  };
}

// ── Results Rendering ────────────────────────────────────────────
async function prepareResults(summary) {
  const res = await fetch(`/api/scan/${jobId}`);
  const data = await res.json();
  allFindings = data.findings;
  const s = data.summary || summary || {};

  $("#verifiedCount").textContent = `${s.verified_fixed || 0} fixed`;
  $("#reportSourceLabel").textContent = data.source || $("#jobLabel").textContent;
  $("#downloadZipBtn").href = `/api/scan/${jobId}/download`;

  // KPI Metrics
  $("#metricsStats").innerHTML = `
    <div class="metric-box"><span class="num">${data.files_total || 0}</span><span class="label">Files Scanned</span></div>
    <div class="metric-box crit"><span class="num">${s.total_findings || 0}</span><span class="label">Vulnerabilities Found</span></div>
    <div class="metric-box ok"><span class="num">${s.verified_fixed || 0}</span><span class="label">Auto-Patched &amp; Verified</span></div>
    <div class="metric-box warn"><span class="num">${s.manual_review_required || 0}</span><span class="label">Manual Review Required</span></div>
  `;

  // Filter chips
  const statuses = ["ALL", ...new Set(allFindings.map((f) => f.final_status))];
  $("#filterChips").innerHTML = statuses.map((st) =>
    `<span class="chip ${st === activeFilter ? "active" : ""}" data-status="${esc(st)}">
      ${esc(st === "ALL" ? "All Findings" : st.replace(/_/g, " "))}
    </span>`
  ).join("");

  document.querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      activeFilter = chip.dataset.status;
      document.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      renderFindings();
    });
  });

  renderFindings();

  $("#completionSummary").textContent = `Sentinel AI patched ${s.verified_fixed || 0} vulnerabilities across ${data.files_total || 0} file${data.files_total !== 1 ? "s" : ""}.`;
  $("#completionBanner").classList.remove("hidden");
}

$("#openResultsBtn").addEventListener("click", () => switchView("report"));
$("#backToScanBtn").addEventListener("click", () => switchView("scanning"));
$("#newScanBtn").addEventListener("click", () => {
  $("#localPath").value = "";
  $("#githubUrl").value = "";
  $("#parityPath").value = "";
  $("#formError").classList.add("hidden");
  switchView("setup");
});

// ── Findings Cards ───────────────────────────────────────────────
const severityRanks = { critical: 0, high: 1, medium: 2, low: 3 };

function renderFindings() {
  const container = $("#findingsList");
  const filtered = allFindings
    .filter((lc) => activeFilter === "ALL" || lc.final_status === activeFilter)
    .sort((a, b) => (severityRanks[a.finding.severity] ?? 9) - (severityRanks[b.finding.severity] ?? 9));

  if (!filtered.length) {
    container.innerHTML = `<div class="card" style="text-align:center;color:var(--text-muted);padding:30px;">No findings match the selected filter.</div>`;
    return;
  }

  container.innerHTML = filtered.map((lc, index) => {
    const f = lc.finding;
    const pa = lc.patch_attempts[lc.patch_attempts.length - 1];
    const judge = lc.judge_verdicts[lc.judge_verdicts.length - 1];

    const originalSnippet = (pa && pa.original_snippet) ? pa.original_snippet : f.snippet;
    const patchedSnippet = (pa && pa.patched_snippet)
      ? pa.patched_snippet
      : "// Automated patch not available. Manual inspection required.";

    // Build a plain-English description
    const plainDesc = f.description
      ? f.description.charAt(0).toUpperCase() + f.description.slice(1)
      : "This code contains a pattern that could be exploited by an attacker.";

    const attackRisk = lc.validation && lc.validation.attack_vector
      ? lc.validation.attack_vector
      : null;

    return `
      <div class="finding-card ${index === 0 ? "open" : ""}">
        <div class="finding-header">
          <div class="fh-main">
            <span class="badge ${esc(f.severity)}">${esc(f.severity)}</span>
            <span class="fh-title">${esc(f.title)}</span>
            <span class="fh-path"><code>${esc(f.file)}:${esc(f.line)}</code></span>
          </div>
          <span class="badge ${esc(lc.final_status)}">${esc((lc.final_status || "").replace(/_/g, " "))}</span>
        </div>

        <div class="finding-body">

          <!-- Plain English Explanation -->
          <div class="explanation-callout">
            <div class="explanation-callout-title">What was found</div>
            <p class="explanation-text">${esc(plainDesc)}</p>
            ${attackRisk ? `<p class="explanation-risk">If exploited, an attacker could ${esc(attackRisk.toLowerCase())}.</p>` : ""}
            <div class="explanation-meta">Reference: ${esc(f.cwe)}</div>
          </div>

          <!-- Code Comparison -->
          <div class="diff-label">Code comparison</div>
          <div class="code-diff-viewer">
            <div class="code-pane vulnerable">
              <div class="code-pane-header">
                <span>⚠ Vulnerable snippet</span>
                <span>Line ${esc(f.line)}</span>
              </div>
              <pre><code>${esc(originalSnippet)}</code></pre>
            </div>
            <div class="code-pane patched">
              <div class="code-pane-header">
                <span>✓ Corrected snippet</span>
                <span>${esc(pa ? pa.strategy : "unchanged")}</span>
              </div>
              <pre><code>${esc(patchedSnippet)}</code></pre>
            </div>
          </div>

          ${judge ? `
            <div class="judge-verdict-box">
              <div class="judge-header">
                <span>Security Judge decision</span>
                <span class="judge-verdict-tag ${esc(judge.verdict)}">${esc(judge.verdict)}</span>
              </div>
              <p style="margin:0;color:var(--text-muted);font-size:12.5px;">${esc(judge.reasoning)}</p>
            </div>
          ` : ""}

        </div>
      </div>
    `;
  }).join("");

  // Accordion toggle
  document.querySelectorAll(".finding-header").forEach((h) => {
    h.addEventListener("click", () => h.parentElement.classList.toggle("open"));
  });
}
