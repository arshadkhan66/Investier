const $ = (id) => document.getElementById(id);
let LAST = null;
const HISTORY = [];

document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    const ins = chip.dataset.ins;
    const box = $("instruction");
    if (ins === "everything") {
      box.value = "Test everything — security, performance, mobile, accessibility, SEO, links, forms, API and infrastructure. Find anything missing, broken or wrong.";
    } else {
      box.value = (box.value.trim() + " " + ins).trim();
    }
  });
});

let planTimer;
$("instruction").addEventListener("input", previewPlan);
$("target").addEventListener("input", previewPlan);

function previewPlan() {
  clearTimeout(planTimer);
  planTimer = setTimeout(async () => {
    const target = $("target").value.trim();
    if (!target) { $("planLine").textContent = ""; return; }
    try {
      const r = await fetch("/api/plan", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, instruction: $("instruction").value }),
      });
      const d = await r.json();
      const p = d.plan;
      $("planLine").textContent =
        `→ plan [${p.source}${p.model ? ":" + p.model : ""}]: ${p.groups.join(", ")}` +
        (p.run_load ? "  + load probe" : "") + "   |   profile: " + p.mode;
    } catch { /* ignore */ }
  }, 350);
}

$("runBtn").addEventListener("click", run);
$("target").addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });

async function run() {
  const target = $("target").value.trim();
  if (!target) { $("target").focus(); return; }

  const options = {
    auth_header: $("authHeader").value.trim() || null,
    samples: parseInt($("samples").value, 10) || 5,
    max_links: parseInt($("maxLinks").value, 10) || 15,
    timeout: parseInt($("timeout").value, 10) || 20,
    concurrency: parseInt($("concurrency").value, 10) || 10,
    insecure: $("insecure").checked,
    check_links: $("checkLinks").checked,
  };
  const useLlm = $("useLlm").checked;

  $("runBtn").disabled = true;
  $("results").classList.add("hidden");
  $("progress").classList.remove("hidden");
  $("connStatus").classList.add("busy");
  $("connStatus").innerHTML = "<i></i> testing";

  const phases = [
    "Asking the local model to build a test plan…",
    "Resolving target & checking availability…",
    "Inspecting TLS and transport security…",
    "Probing performance, caching and compression…",
    "Auditing security headers & cookies…",
    "Scanning HTML, links, forms and content…",
    "Checking SEO, mobile and accessibility…",
    "Probing DNS, email and certificate controls…",
    "Classifying findings & writing the report…",
  ];
  let p = 0;
  const tick = setInterval(() => {
    $("progSub").textContent = phases[Math.min(p++, phases.length - 1)];
  }, 1400);

  try {
    const res = await fetch("/api/test", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, instruction: $("instruction").value, options, use_llm: useLlm }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Test failed");
    }
    LAST = await res.json();
    render(LAST);
    HISTORY.unshift({ target: LAST.target, score: LAST.score, grade: LAST.grade, at: new Date().toLocaleTimeString() });
    renderHistory();
    refreshModel();
  } catch (e) {
    $("progress").classList.add("hidden");
    alert("Could not complete the test:\n\n" + e.message);
  } finally {
    clearInterval(tick);
    $("runBtn").disabled = false;
    $("connStatus").classList.remove("busy");
    $("connStatus").innerHTML = "<i></i> ready";
  }
}

function render(d) {
  $("progress").classList.add("hidden");
  $("results").classList.remove("hidden");

  const score = d.score, circ = 327, fill = $("gaugeFill");
  fill.style.stroke = score >= 75 ? "var(--pass)" : score >= 50 ? "var(--warn)" : "var(--fail)";
  fill.style.strokeDashoffset = circ - (circ * score) / 100;
  $("scoreNum").textContent = score;
  $("gradeText").textContent = d.grade;
  $("verdictText").textContent = verdictLine(d);
  $("metaRow").innerHTML = `
    <span>${esc(d.target)}</span>
    <span>profile: ${d.mode}</span>
    <span>plan: ${d.plan ? d.plan.source : "-"}</span>
    <span>${d.summary.total} checks</span>
    <span>${d.duration_s}s</span>`;

  const sc = d.summary;
  $("scoreCards").innerHTML = [
    ["Passed", sc.pass, "var(--pass)"],
    ["Warnings", sc.warn, "var(--warn)"],
    ["Failures", sc.fail, "var(--fail)"],
    ["Informational", sc.info, "var(--info)"],
  ].map(([k, v, c]) => `<div class="sc"><span>${k}</span><b style="color:${c}">${v}</b></div>`).join("");

  if (d.narrative) {
    $("narrativePanel").classList.remove("hidden");
    $("narrativeText").textContent = d.narrative;
    $("narrativeSrc").textContent = d.narrative_source;
  } else {
    $("narrativePanel").classList.add("hidden");
  }

  $("defects").innerHTML = d.defects.length
    ? d.defects.map(defectHtml).join("")
    : `<p class="hint">No problems found. 🎉</p>`;

  $("missing").innerHTML = d.missing.length
    ? d.missing.map((m) => `<div class="missing-item"><span class="pill ${m.severity}">${m.severity}</span>
        <div><strong>${esc(m.item)}</strong><div class="hint" style="margin:2px 0 0">${esc(m.reason)}</div></div></div>`).join("")
    : `<p class="hint">Nothing material appears to be missing.</p>`;

  $("risks").innerHTML = d.risks.map((r) =>
    `<div class="risk-item"><span class="pill ${r.level}">${r.level}</span><span>${esc(r.text)}</span></div>`).join("");

  $("categories").innerHTML = Object.entries(d.categories).sort().map(([cat, c]) => {
    const pct = c.total ? Math.round((c.pass / c.total) * 100) : 0;
    return `<div class="cat"><div class="c-top"><span>${cat}</span>
      <span style="font-family:var(--mono);color:var(--ink-faint)">${c.pass}/${c.total}</span></div>
      <div class="bar"><i style="width:${pct}%"></i></div></div>`;
  }).join("");

  $("passed").innerHTML = d.passed.length
    ? d.passed.map((r) => `<div class="p">${esc(r.category)} · ${esc(r.name)}</div>`).join("")
    : `<p class="hint">No passing checks.</p>`;

  $("reportText").textContent = d.report;
}

function verdictLine(d) {
  const s = d.summary;
  if (s.fail) return `${s.fail} check(s) failed and ${s.warn} produced warnings. Fix the critical items before shipping.`;
  if (s.warn) return `Everything critical passed, but ${s.warn} warning(s) deserve attention.`;
  return "All checks passed in this pass. The target looks healthy.";
}

function defectHtml(r) {
  return `<div class="defect ${r.status}">
    <div class="d-head"><span class="d-name">${esc(r.name)}</span>
      <span class="pill ${r.severity}">${r.status === "fail" ? "FAIL" : "WARN"} · ${r.severity}</span></div>
    <div class="d-cat">${esc(r.category)}</div>
    <div class="d-detail">${esc(r.detail)}</div>
    ${r.evidence ? `<div class="d-evidence">evidence: ${esc(String(r.evidence)).slice(0, 300)}</div>` : ""}
  </div>`;
}

function renderHistory() {
  if (!HISTORY.length) return;
  $("historyPanel").classList.remove("hidden");
  $("history").innerHTML = HISTORY.map((h) => `
    <div class="h-row" data-t="${esc(h.target)}"><span>${esc(h.target)}</span>
    <span class="h-score">${h.score}/100 · ${h.grade} · ${h.at}</span></div>`).join("");
  document.querySelectorAll("#history .h-row").forEach((row) => {
    row.addEventListener("click", () => { $("target").value = row.dataset.t; run(); });
  });
}

$("copyBtn").addEventListener("click", async () => {
  if (!LAST) return;
  await navigator.clipboard.writeText(LAST.report);
  $("copyBtn").textContent = "Copied ✓";
  setTimeout(() => ($("copyBtn").textContent = "Copy"), 1600);
});
$("downloadBtn").addEventListener("click", () => download(LAST.report, `investier-report-${stamp()}.txt`, "text/plain"));
$("jsonBtn").addEventListener("click", () => download(JSON.stringify(LAST, null, 2), `investier-report-${stamp()}.json`, "application/json"));

function download(content, name, type) {
  if (!content) return;
  const blob = new Blob([content], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}
function stamp() { return new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19); }
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function refreshModel() {
  try {
    const s = await (await fetch("/api/model")).json();
    const badge = $("modelBadge");
    badge.classList.remove("on", "off");
    if (s.available) {
      badge.classList.add("on");
      $("modelText").textContent = `model: ${s.model || "local"} (loaded)`;
    } else {
      badge.classList.add("off");
      $("modelText").textContent = "model: rules fallback";
      badge.title = s.error || "model not loaded";
    }
  } catch { /* ignore */ }
}
refreshModel();
