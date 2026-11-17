// Scam & Phishing Infrastructure Triage Workbench Frontend Script

let currentReport = null;
let allSubdomains = [];

document.addEventListener("DOMContentLoaded", () => {
  checkHealth();

  const form = document.getElementById("triage-form");
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const input = document.getElementById("target-input").value.trim();
      if (input) {
        await executeTriage(input);
      }
    });
  }
});

async function checkHealth() {
  try {
    const res = await fetch("/api/health");
    if (!res.ok) return;
    const data = await res.json();
    const badge = document.getElementById("mode-badge");
    if (badge) {
      if (data.demo_mode) {
        badge.className = "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-950/60 text-amber-400 border border-amber-800/60";
        badge.textContent = "⚡ Demo Mode Only";
      } else {
        badge.className = "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-950/60 text-emerald-400 border border-emerald-800/60";
        badge.textContent = "🟢 Live Scanner Ready";
      }
    }
  } catch (err) {
    console.error("Healthcheck error:", err);
  }
}

async function loadSample(sampleId) {
  dismissError();
  setLoading(true);
  try {
    const res = await fetch(`/api/samples/${sampleId}`);
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to load sample case");
    }
    const report = await res.json();
    document.getElementById("target-input").value = report.target.defanged_target;
    renderReport(report);
  } catch (err) {
    showError("Sample Load Error", err.message);
  } finally {
    setLoading(false);
  }
}

async function executeTriage(target) {
  dismissError();
  setLoading(true);
  try {
    const res = await fetch("/api/triage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });

    if (!res.ok) {
      const err = await res.json();
      if (res.status === 400 && err.detail && err.detail.includes("SSRF")) {
        showError("SSRF Guardrail Alert", err.detail, "🚨", true);
        return;
      } else if (res.status === 403) {
        showError("Demo Mode Active", err.detail, "⚡");
        return;
      } else if (res.status === 429) {
        showError("Rate Limit Exceeded", err.detail, "⏳");
        return;
      }
      throw new Error(err.detail || `Server returned HTTP ${res.status}`);
    }

    const report = await res.json();
    renderReport(report);
  } catch (err) {
    showError("Triage Execution Error", err.message);
  } finally {
    setLoading(false);
  }
}

function setLoading(isLoading) {
  const btn = document.getElementById("submit-btn");
  const spinner = document.getElementById("btn-spinner");
  const text = document.getElementById("btn-text");

  if (isLoading) {
    btn.disabled = true;
    spinner.classList.remove("hidden");
    text.textContent = "Scanning...";
  } else {
    btn.disabled = false;
    spinner.classList.add("hidden");
    text.textContent = "Run Triage";
  }
}

function showError(title, message, icon = "⚠️", isSSRF = false) {
  const banner = document.getElementById("error-banner");
  const titleEl = document.getElementById("error-title");
  const descEl = document.getElementById("error-desc");
  const iconEl = document.getElementById("error-icon");

  titleEl.textContent = title;
  descEl.textContent = message;
  iconEl.textContent = icon;

  if (isSSRF) {
    banner.className = "rounded-xl border border-rose-500/80 bg-rose-950/60 text-rose-200 p-4 font-mono text-sm shadow-lg shadow-rose-950/50";
  } else {
    banner.className = "rounded-xl border border-amber-500/80 bg-amber-950/60 text-amber-200 p-4 font-mono text-sm shadow-lg shadow-amber-950/50";
  }
  banner.classList.remove("hidden");
}

function dismissError() {
  const banner = document.getElementById("error-banner");
  if (banner) banner.classList.add("hidden");
}

function renderReport(report) {
  currentReport = report;
  const resultsEl = document.getElementById("results-dashboard");
  resultsEl.classList.remove("hidden");

  // Header Details
  document.getElementById("badge-type").textContent = report.target.target_type;
  document.getElementById("header-timestamp").textContent = report.timestamp;
  document.getElementById("header-defanged-target").textContent = report.target.defanged_target;
  document.getElementById("header-host").textContent = report.target.defanged_host;
  document.getElementById("header-domain").textContent = report.target.domain;

  const portCont = document.getElementById("header-port-container");
  if (report.target.port) {
    portCont.classList.remove("hidden");
    document.getElementById("header-port").textContent = report.target.port;
  } else {
    portCont.classList.add("hidden");
  }

  // Risk Score & Tier Styling
  const ra = report.risk_assessment;
  const scoreCard = document.getElementById("score-card");
  const scoreCircle = document.getElementById("score-circle");
  const scoreNum = document.getElementById("score-num");
  const scoreTier = document.getElementById("score-tier");
  const scorePointsSub = document.getElementById("score-points-sub");

  scoreNum.textContent = ra.score;
  scoreTier.textContent = `${ra.tier} RISK`;
  scorePointsSub.textContent = `Score: ${ra.score}/100`;

  // Color classes based on tier
  if (ra.tier === "CRITICAL") {
    scoreCard.className = "p-4 rounded-xl border border-rose-800/80 bg-rose-950/40 flex items-center gap-4 min-w-[220px]";
    scoreCircle.className = "w-16 h-16 rounded-full flex flex-col items-center justify-center font-mono font-extrabold text-2xl border-2 border-rose-500 bg-rose-900/60 text-rose-300 shadow-md shadow-rose-950";
    scoreTier.className = "text-base font-mono font-bold tracking-tight text-rose-400 block";
  } else if (ra.tier === "HIGH") {
    scoreCard.className = "p-4 rounded-xl border border-orange-800/80 bg-orange-950/40 flex items-center gap-4 min-w-[220px]";
    scoreCircle.className = "w-16 h-16 rounded-full flex flex-col items-center justify-center font-mono font-extrabold text-2xl border-2 border-orange-500 bg-orange-900/60 text-orange-300 shadow-md shadow-orange-950";
    scoreTier.className = "text-base font-mono font-bold tracking-tight text-orange-400 block";
  } else if (ra.tier === "MEDIUM") {
    scoreCard.className = "p-4 rounded-xl border border-amber-800/80 bg-amber-950/40 flex items-center gap-4 min-w-[220px]";
    scoreCircle.className = "w-16 h-16 rounded-full flex flex-col items-center justify-center font-mono font-extrabold text-2xl border-2 border-amber-500 bg-amber-900/60 text-amber-300 shadow-md shadow-amber-950";
    scoreTier.className = "text-base font-mono font-bold tracking-tight text-amber-400 block";
  } else {
    scoreCard.className = "p-4 rounded-xl border border-emerald-800/80 bg-emerald-950/40 flex items-center gap-4 min-w-[220px]";
    scoreCircle.className = "w-16 h-16 rounded-full flex flex-col items-center justify-center font-mono font-extrabold text-2xl border-2 border-emerald-500 bg-emerald-900/60 text-emerald-300 shadow-md shadow-emerald-950";
    scoreTier.className = "text-base font-mono font-bold tracking-tight text-emerald-400 block";
  }

  // Risk Flags Rendering
  const flagsContainer = document.getElementById("flags-container");
  flagsContainer.innerHTML = "";
  document.getElementById("flags-count").textContent = ra.flags.length;

  if (ra.flags.length === 0) {
    flagsContainer.innerHTML = `
      <div class="col-span-full p-4 rounded-xl border border-emerald-900/60 bg-emerald-950/30 text-emerald-300 text-xs font-mono">
        ✓ No automated heuristic risk flags triggered during passive evaluation.
      </div>
    `;
  } else {
    ra.flags.forEach((f) => {
      const card = document.createElement("div");
      let borderStyle = "border-slate-800 bg-slate-900/70";
      let badgeStyle = "bg-slate-800 text-slate-300";

      if (f.severity === "CRITICAL" || f.severity === "HIGH") {
        borderStyle = "border-rose-900/60 bg-rose-950/20";
        badgeStyle = "bg-rose-950 text-rose-300 border border-rose-800";
      } else if (f.severity === "MEDIUM") {
        borderStyle = "border-amber-900/60 bg-amber-950/20";
        badgeStyle = "bg-amber-950 text-amber-300 border border-amber-800";
      }

      card.className = `p-4 rounded-xl border ${borderStyle} space-y-2 font-mono text-xs shadow-sm`;
      card.innerHTML = `
        <div class="flex items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${badgeStyle}">${f.severity}</span>
            <span class="text-slate-400 font-bold">${f.name}</span>
          </div>
          <span class="text-amber-400 font-bold">+${f.score_impact}</span>
        </div>
        <p class="text-slate-300 font-sans text-xs leading-relaxed">${f.description}</p>
        ${f.evidence ? `<div class="p-2 rounded bg-slate-950/80 border border-slate-800/80 text-slate-400 text-[11px] truncate"><strong>Evidence:</strong> ${f.evidence}</div>` : ""}
      `;
      flagsContainer.appendChild(card);
    });
  }

  // DNS IP Records
  const dnsIpsBody = document.getElementById("dns-ips-body");
  dnsIpsBody.innerHTML = "";
  const allIps = [
    ...(report.dns.a_records || []).map((r) => ({ type: "A (IPv4)", val: r.value.replace(/\./g, "[.]"), ttl: r.ttl })),
    ...(report.dns.aaaa_records || []).map((r) => ({ type: "AAAA (IPv6)", val: r.value.replace(/:/g, "[:]"), ttl: r.ttl })),
  ];

  if (allIps.length === 0) {
    dnsIpsBody.innerHTML = `<tr><td colspan="3" class="py-2 text-slate-500">None resolved</td></tr>`;
  } else {
    allIps.forEach((rec) => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-slate-800/30";
      tr.innerHTML = `
        <td class="py-1.5 text-slate-400">${rec.type}</td>
        <td class="py-1.5 text-slate-200 font-bold">${rec.val}</td>
        <td class="py-1.5 text-right text-slate-500">${rec.ttl ? rec.ttl + "s" : "N/A"}</td>
      `;
      dnsIpsBody.appendChild(tr);
    });
  }

  // MX and Nameservers
  const mxList = document.getElementById("dns-mx-list");
  if (report.dns.mx_records && report.dns.mx_records.length > 0) {
    mxList.textContent = report.dns.mx_records.map((m) => `[Pref ${m.preference}] ${m.host}`).join("; ");
  } else {
    mxList.textContent = "None detected";
  }

  const nsList = document.getElementById("dns-ns-list");
  if (report.dns.ns_records && report.dns.ns_records.length > 0) {
    nsList.textContent = report.dns.ns_records.join(", ");
  } else {
    nsList.textContent = "None detected";
  }

  // Email Security
  document.getElementById("spf-record-val").textContent = report.dns.spf_record || "None published";
  document.getElementById("dmarc-record-val").textContent = report.dns.dmarc_record || "None published";

  // RDAP
  const rdap = report.rdap;
  if (rdap && rdap.queried && !rdap.error) {
    document.getElementById("rdap-age").textContent = rdap.age_days !== null ? `${rdap.age_days} days` : "Unknown";
    document.getElementById("rdap-expiry-days").textContent = rdap.days_until_expiration !== null ? `${rdap.days_until_expiration} days` : "Unknown";
    document.getElementById("rdap-registrar").textContent = rdap.registrar || "Unknown";
    document.getElementById("rdap-created").textContent = rdap.creation_date || "N/A";
    document.getElementById("rdap-expires").textContent = rdap.expiration_date || "N/A";
    document.getElementById("rdap-updated").textContent = rdap.updated_date || "N/A";

    const statusTags = document.getElementById("rdap-status-tags");
    statusTags.innerHTML = "";
    (rdap.status || []).forEach((st) => {
      const span = document.createElement("span");
      span.className = "px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]";
      span.textContent = st;
      statusTags.appendChild(span);
    });
  } else {
    document.getElementById("rdap-age").textContent = "N/A";
    document.getElementById("rdap-expiry-days").textContent = "N/A";
    document.getElementById("rdap-registrar").textContent = (rdap && rdap.error) || "Unregistered / Skipped";
  }

  // ASN Table
  const asnBody = document.getElementById("asn-table-body");
  asnBody.innerHTML = "";
  if (!report.ip_enrichments || report.ip_enrichments.length === 0) {
    asnBody.innerHTML = `<tr><td colspan="4" class="py-2 text-slate-500">No ASN details found</td></tr>`;
  } else {
    report.ip_enrichments.forEach((e) => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-slate-800/30";
      tr.innerHTML = `
        <td class="py-1.5 text-slate-200">${e.defanged_ip}</td>
        <td class="py-1.5 text-amber-400 font-bold">${e.asn || "N/A"}</td>
        <td class="py-1.5 text-slate-300 truncate max-w-[180px]">${e.as_name || "Unknown"}</td>
        <td class="py-1.5 text-right text-slate-400">${e.country_code || "N/A"}</td>
      `;
      asnBody.appendChild(tr);
    });
  }

  // Certificate Transparency Subdomains
  const ct = report.ct_logs;
  const ctBadge = document.getElementById("ct-count-badge");
  allSubdomains = (ct && ct.subdomains) || [];
  ctBadge.textContent = `${allSubdomains.length} discovered`;
  renderSubdomainList(allSubdomains);

  // Smooth scroll down to results
  resultsEl.scrollIntoView({ behavior: "smooth" });
}

function renderSubdomainList(subs) {
  const container = document.getElementById("ct-subdomains-list");
  container.innerHTML = "";
  if (!subs || subs.length === 0) {
    container.innerHTML = `<span class="text-slate-500">No subdomains discovered</span>`;
    return;
  }
  subs.forEach((s) => {
    const div = document.createElement("div");
    div.className = "py-0.5 px-1 hover:bg-slate-800/40 rounded truncate";
    div.textContent = s;
    container.appendChild(div);
  });
}

function filterSubdomains() {
  const query = document.getElementById("ct-search").value.toLowerCase().trim();
  if (!query) {
    renderSubdomainList(allSubdomains);
    return;
  }
  const filtered = allSubdomains.filter((s) => s.toLowerCase().includes(query));
  renderSubdomainList(filtered);
}

// Action Bar: Download Markdown Brief
async function downloadMarkdownBrief() {
  if (!currentReport) return;
  try {
    const res = await fetch("/api/export/markdown", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentReport),
    });
    if (!res.ok) throw new Error("Failed to generate Markdown brief");

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `triage_${currentReport.target.host.replace(/\./g, "_")}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    showToast("Downloaded Markdown brief!");
  } catch (err) {
    alert("Error downloading markdown: " + err.message);
  }
}

// Action Bar: Copy Defanged IoCs
function copyDefangedIoCs() {
  if (!currentReport) return;
  const lines = [
    `# Defanged IoCs - Scam Triage Workbench`,
    `Target: ${currentReport.target.defanged_target}`,
    `Host: ${currentReport.target.defanged_host}`,
    `Registrable Domain: ${currentReport.target.domain}`,
    ``,
    `## Resolved IPs:`,
    ...(currentReport.dns.a_records || []).map((r) => `IP: ${r.value.replace(/\./g, "[.]")}`),
    ...(currentReport.dns.aaaa_records || []).map((r) => `IPv6: ${r.value.replace(/:/g, "[:]").replace(/\./g, "[.]")}`),
    ``,
    `## Discovered Subdomains:`,
    ...(allSubdomains.slice(0, 50).map((s) => `Subdomain: ${s}`)),
  ];

  const text = lines.join("\n");
  navigator.clipboard.writeText(text).then(() => {
    showToast("Defanged IoCs copied to clipboard!");
  }).catch((e) => {
    prompt("Copy IoCs:", text);
  });
}

// Action Bar: Download JSON
function downloadJSONReport() {
  if (!currentReport) return;
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentReport, null, 2));
  const dlAnchor = document.createElement("a");
  dlAnchor.setAttribute("href", dataStr);
  dlAnchor.setAttribute("download", `triage_${currentReport.target.host.replace(/\./g, "_")}.json`);
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  document.body.removeChild(dlAnchor);
  showToast("Exported JSON report!");
}

function showToast(msg) {
  const toast = document.getElementById("toast-msg");
  if (!toast) return;
  toast.textContent = msg;
  toast.classList.remove("hidden");
  setTimeout(() => {
    toast.classList.add("hidden");
  }, 2500);
}
