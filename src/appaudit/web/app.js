"use strict";

const state = { apps: [], summary: null, scan: null, view: "mismatch", search: "", showSystem: false, open: null };
const $ = (selector) => document.querySelector(selector);

// Build DOM nodes with textContent only, so names read from the registry are never parsed as HTML.
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function ago(iso) {
  if (!iso) return null;
  const days = Math.max(Math.floor((Date.now() - new Date(iso).getTime()) / 86400000), 0);
  if (days === 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 60) return `${days} days ago`;
  if (days < 730) return `${Math.floor(days / 30)} months ago`;
  return `${Math.floor(days / 365)} years ago`;
}

const fullDate = (iso) => (iso ? new Date(iso).toLocaleString() : "");
const plural = (count, word, many = `${word}s`) => `${count} ${count === 1 ? word : many}`;

function minutes(value) {
  if (value >= 120) return `${Math.round(value / 60)} h in focus`;
  return `${Math.round(value)} min in focus`;
}

// --- cells -------------------------------------------------------------------

function appCell(app) {
  const tags = [];
  if (app.kind === "store") tags.push(el("span", { class: "chip tag", text: "Store app" }));
  if (!app.launchable && !app.is_system) tags.push(el("span", { class: "chip tag", text: "Background component" }));
  if (app.is_system) tags.push(el("span", { class: "chip tag", text: "Windows" }));
  return el("td", {},
    el("div", { class: "name", text: app.name }),
    el("div", { class: "sub", text: app.publisher || "" }),
    tags.length ? el("div", {}, tags) : null);
}

function usageCell(app) {
  const usage = app.usage;
  if (!usage) return el("td", {}, el("span", { class: "none", text: "No record" }));
  const headline = usage.last_used
    ? el("div", { title: fullDate(usage.last_used), text: ago(usage.last_used) })
    : el("div", { text: "Used, date unknown" });
  const facts = [];
  if (usage.run_count) facts.push(plural(usage.run_count, "launch", "launches"));
  if (usage.focus_minutes >= 1) facts.push(minutes(usage.focus_minutes));
  return el("td", {}, headline, el("div", { class: "sub", text: facts.join(" · ") }));
}

function autostartCell(app) {
  if (!app.autostart.length) return el("td", {}, el("span", { class: "none", text: "No" }));
  const chips = [];
  const enabled = new Map();
  let disabled = 0;
  for (const entry of app.autostart) {
    if (entry.enabled) enabled.set(entry.mechanism_title, (enabled.get(entry.mechanism_title) || 0) + 1);
    else disabled += 1;
  }
  for (const [title, count] of enabled) {
    chips.push(el("span", { class: "chip", text: count > 1 ? `${title} ×${count}` : title }));
  }
  if (disabled) chips.push(el("span", { class: "chip off", text: `${disabled} switched off` }));
  return el("td", {}, chips);
}

function runningCell(app) {
  const running = app.running;
  if (!running) return el("td", {}, el("span", { class: "none", text: "No" }));
  return el("td", {},
    el("span", { class: "chip live", text: plural(running.process_count, "process", "processes") }),
    el("div", { class: "sub", text: [
      `${Math.round(running.memory_mb)} MB`,
      running.connection_count ? plural(running.connection_count, "connection") : null,
    ].filter(Boolean).join(" · ") }));
}

function sensorCell(app) {
  if (!app.sensors.length) return el("td", {}, el("span", { class: "none", text: "No record" }));
  return el("td", {}, app.sensors.map((sensor) => el("span", {
    class: sensor.in_use ? "chip live" : "chip",
    title: fullDate(sensor.last_start),
    text: `${sensor.title} · ${sensor.in_use ? "in use now" : ago(sensor.last_start)}`,
  })));
}

function findingCell(app) {
  if (!app.findings.length) return el("td", {}, el("span", { class: "none", text: "Nothing unusual" }));
  return el("td", {}, app.findings.map((finding) => el("span", { class: "chip flag", title: finding.detail, text: finding.title })));
}

// --- detail row --------------------------------------------------------------

function section(title, ...children) {
  return el("div", {}, el("h3", { text: title }), children);
}

function detailRow(app) {
  const blocks = [];
  if (app.findings.length) {
    blocks.push(section("Why it is listed", el("ul", {}, app.findings.map((f) => el("li", { text: f.detail })))));
  }
  if (app.autostart.length) {
    blocks.push(section("How it starts", el("ul", {}, app.autostart.map((entry) => {
      const facts = [entry.enabled ? "on" : "switched off"];
      if (entry.triggers && entry.triggers.length) facts.push(`runs ${entry.triggers.join(", ")}`);
      if (entry.last_run) facts.push(`last ran ${ago(entry.last_run)}`);
      if (entry.status) facts.push(`service is ${entry.status}`);
      return el("li", {},
        `${entry.mechanism_title}: ${entry.display_name || entry.name} (${facts.join("; ")})`,
        entry.command ? el("div", {}, el("code", { text: entry.command })) : null);
    }))));
  }
  if (app.sensors.length) {
    blocks.push(section("Camera, mic, location", el("ul", {}, app.sensors.map((sensor) => el("li", {
      text: `${sensor.title}: last used ${fullDate(sensor.last_start)}` + (sensor.in_use ? " (in use now)" : ""),
    })))));
  }
  if (app.running) {
    const running = app.running;
    const lines = [el("li", { text: `Running since ${fullDate(running.since)}, using ${Math.round(running.memory_mb)} MB` })];
    for (const exe of running.executables) lines.push(el("li", {}, el("code", { text: exe })));
    if (running.remotes.length) {
      const shown = running.remotes.slice(0, 12).map((r) => `${r.ip}:${r.port}${r.lan ? " (local network)" : ""}`);
      const extra = running.remotes.length > 12 ? ` and ${running.remotes.length - 12} more` : "";
      lines.push(el("li", { text: `Connected to ${shown.join(", ")}${extra}` }));
    }
    blocks.push(section("Running now", el("ul", {}, lines)));
  }
  if (app.install_dir) blocks.push(section("Installed in", el("code", { text: app.install_dir })));
  return el("tr", { class: "detail" }, el("td", { colspan: "6" }, el("div", { class: "detail-grid" }, blocks)));
}

// --- rendering ---------------------------------------------------------------

function visibleApps() {
  const needle = state.search.trim().toLowerCase();
  let apps = state.apps.filter((app) => state.showSystem || !app.is_system);
  if (needle) {
    apps = apps.filter((app) => `${app.name} ${app.publisher || ""}`.toLowerCase().includes(needle));
  }
  if (state.view === "mismatch") {
    apps = apps.filter((app) => app.findings.length).sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  } else if (state.view === "used") {
    apps = apps.filter((app) => app.usage)
      .sort((a, b) => b.usage.focus_minutes - a.usage.focus_minutes || b.usage.run_count - a.usage.run_count);
  } else {
    apps = [...apps].sort((a, b) => a.name.localeCompare(b.name));
  }
  return apps;
}

function renderTable() {
  const body = $("#apps tbody");
  const apps = visibleApps();
  const rows = [];
  for (const app of apps) {
    const row = el("tr", { class: state.open === app.id ? "app open" : "app" },
      appCell(app), usageCell(app), autostartCell(app), runningCell(app), sensorCell(app), findingCell(app));
    row.addEventListener("click", () => {
      state.open = state.open === app.id ? null : app.id;
      renderTable();
    });
    rows.push(row);
    if (state.open === app.id) rows.push(detailRow(app));
  }
  body.replaceChildren(...rows);
  const empty = $("#empty");
  empty.hidden = apps.length > 0;
  $("#apps").hidden = apps.length === 0;
  if (!apps.length) {
    empty.textContent = state.scan ? "No apps match this view." : "Scanning this PC for the first time…";
  }
}

function renderTiles() {
  const summary = state.summary;
  const tiles = summary ? [
    ["hot", summary.flagged, "apps doing something you may not expect"],
    ["hot", summary.starts_unused, "start by themselves but go unopened"],
    ["", summary.running_unused, "running or ran recently without you"],
    ["", summary.sensor_apps, "have used camera, mic or location"],
  ] : [];
  $("#tiles").replaceChildren(...tiles.map(([kind, value, label]) =>
    el("div", { class: `tile ${kind}` }, el("strong", { text: value }), el("span", { text: label }))));
}

function renderStatus(status) {
  const scan = status.scan;
  $("#rescan").disabled = status.scanning;
  $("#rescan").textContent = status.scanning ? "Scanning…" : "Scan again";
  $("#scan-time").textContent = status.scanning
    ? status.step
    : scan ? `Scanned ${ago(scan.finished)} at ${new Date(scan.finished).toLocaleTimeString()}` : "";

  const notice = $("#notice");
  if (status.error) {
    notice.hidden = false;
    notice.textContent = `The last scan failed: ${status.error}`;
  } else if (!status.elevated) {
    notice.hidden = false;
    notice.textContent = "Running without administrator rights. Run history, 30-day usage and network totals, "
      + "and domain names are not collected, so \"no record\" can mean the app was started in a way Windows did not log.";
  } else {
    notice.hidden = true;
  }

  const chips = [];
  for (const source of (scan ? scan.sources : [])) {
    chips.push(el("span", { class: "chip", title: source.detail || "", text:
      `${source.title}: ${source.status === "ok" ? plural(source.count, "record") : source.status.replace("_", " ")}` }));
  }
  for (const source of status.pending_sources) {
    chips.push(el("span", { class: "chip missing", text: `${source.title}: not collected yet` }));
  }
  $("#sources").replaceChildren("Data sources: ", ...chips);
}

// --- data --------------------------------------------------------------------

async function loadApps() {
  const data = await (await fetch("/api/apps")).json();
  state.apps = data.apps;
  state.summary = data.summary;
  state.scan = data.scan;
  renderTiles();
  renderTable();
}

let wasScanning = false;
async function poll() {
  try {
    const status = await (await fetch("/api/state")).json();
    renderStatus(status);
    if (wasScanning && !status.scanning) await loadApps();
    wasScanning = status.scanning;
  } catch (error) {
    $("#scan-time").textContent = "Lost contact with the local service";
  }
  setTimeout(poll, wasScanning ? 800 : 4000);
}

document.querySelectorAll(".tabs button").forEach((button) => button.addEventListener("click", () => {
  document.querySelectorAll(".tabs button").forEach((other) => other.classList.toggle("active", other === button));
  state.view = button.dataset.view;
  state.open = null;
  renderTable();
}));
$("#search").addEventListener("input", (event) => { state.search = event.target.value; renderTable(); });
$("#show-system").addEventListener("change", (event) => { state.showSystem = event.target.checked; renderTable(); });
$("#rescan").addEventListener("click", async () => {
  await fetch("/api/scan", { method: "POST" });
  wasScanning = true;
  $("#rescan").disabled = true;
  $("#rescan").textContent = "Scanning…";
});

loadApps().then(poll);
