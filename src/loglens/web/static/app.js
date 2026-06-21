"use strict";
mermaid.initialize({ startOnLoad: false, theme: "dark" });

const $ = (id) => document.getElementById(id);

function confLabel(c) {
  if (c >= 0.8) return "high";
  if (c >= 0.55) return "moderate";
  if (c >= 0.35) return "low";
  return "tentative";
}
function badge(c) {
  const l = confLabel(c);
  return `<span class="badge ${l}">conf ${c.toFixed(2)} ${l}</span>`;
}

async function analyze() {
  const path = $("path").value;
  const file = $("upload").files[0];
  if (!path && !file) { setStatus("Choose a file or upload one first."); return; }
  const fd = new FormData();
  if (file) fd.append("upload", file); else fd.append("path", path);
  fd.append("min_level", $("min_level").value);
  fd.append("drain", $("drain").checked);
  fd.append("semantic", $("semantic").checked);
  setStatus("Analyzing…");
  try {
    const res = await fetch("/api/analyze", { method: "POST", body: fd });
    if (!res.ok) { setStatus("Error: " + (await res.text())); return; }
    render(await res.json());
    setStatus("Done.");
  } catch (e) { setStatus("Request failed: " + e); }
}

function render(data) {
  renderOnset(data.findings);
  renderClusters(data.clusters);
  renderCascade(data.findings);
  renderReport(data.report);
}

function renderOnset(f) {
  const el = $("onset");
  if (!f || !f.onset) { el.classList.add("hidden"); return; }
  const t = f.onset.split("T")[1]?.slice(0, 8) || f.onset;
  el.classList.remove("hidden");
  el.innerHTML = `<strong>Onset ${t}</strong> ${badge(f.onset_confidence)} ·
    baseline ~${f.baseline_errors} → peak ${f.peak_errors} errors/${f.bucket_seconds}s ·
    ${f.spikes.length} spike(s)`;
}

function renderClusters(clusters) {
  const tb = $("clusters").querySelector("tbody");
  tb.innerHTML = (clusters || []).map((c) =>
    `<tr><td class="lvl-${c.level}">${c.level}</td><td>${c.count}</td>
     <td>${c.component || "?"}</td><td class="sig">${escapeHtml(c.template).slice(0, 120)}</td></tr>`
  ).join("") || `<tr><td colspan="4" class="dim">No clusters.</td></tr>`;
}

function renderCascade(f) {
  const list = $("cascade_list");
  const box = $("cascade");
  if (!f || !f.cascade || !f.cascade.length) {
    box.innerHTML = "graph LR; A[no cascade detected];";
    list.innerHTML = "";
  } else {
    const edges = f.cascade.map((l) => {
      const a = (l.cause_component || ("c" + l.cause)).replace(/[^A-Za-z0-9_]/g, "_");
      const b = (l.effect_component || ("c" + l.effect)).replace(/[^A-Za-z0-9_]/g, "_");
      return `${a}["${l.cause_component || l.cause}"] -->|${l.confidence.toFixed(2)}| ${b}["${l.effect_component || l.effect}"];`;
    });
    box.innerHTML = "graph LR;\n" + edges.join("\n");
    list.innerHTML = f.cascade.map((l) =>
      `${l.cause_component || l.cause} → ${l.effect_component || l.effect} ` +
      `(+${l.lag_seconds.toFixed(0)}s, overlap ${l.jaccard}, ${badge(l.confidence)})`
    ).join("<br>");
  }
  box.removeAttribute("data-processed");
  mermaid.run({ nodes: [box] }).catch(() => { list.textContent = "(cascade graph unavailable)"; });
}

function renderReport(r) {
  const sec = $("report");
  if (!r) { sec.classList.add("hidden"); return; }
  sec.classList.remove("hidden");
  $("r_summary").textContent = r.summary;
  $("r_cause").textContent = r.root_cause;
  $("r_affected").textContent = r.affected_components;
  $("r_rem").textContent = r.remediation;
}

let evtSource = null;
function toggleLive() {
  if ($("live").checked) startLive(); else stopLive();
}
function startLive() {
  const path = $("path").value;
  if (!path) { setStatus("Live tail needs a server-side file (not upload)."); $("live").checked = false; return; }
  const feed = $("livefeed");
  feed.innerHTML = "";
  evtSource = new EventSource(`/api/stream?path=${encodeURIComponent(path)}&min_level=${$("min_level").value}`);
  evtSource.onmessage = (e) => {
    const d = JSON.parse(e.data);
    if (d.type !== "line") return;
    const div = document.createElement("div");
    div.className = (d.is_new ? "new " : "") + d.level;
    div.textContent = `${d.time} ${d.is_new ? "NEW " : "    "}${d.level.padEnd(8)} ${d.message}`;
    feed.appendChild(div);
    feed.scrollTop = feed.scrollHeight;
  };
  evtSource.onerror = () => setStatus("Live stream disconnected.");
  setStatus("Live tail connected.");
}
function stopLive() {
  if (evtSource) { evtSource.close(); evtSource = null; }
  setStatus("Live tail stopped.");
}

function setStatus(s) { $("status").textContent = s; }
function escapeHtml(s) {
  return (s || "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

$("analyze").addEventListener("click", analyze);
$("live").addEventListener("change", toggleLive);
