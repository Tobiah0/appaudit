"use strict";

// Navigation, the watcher status, and the three live pages: Activity, Companies, Background runs.

const live = { dismissed: [], showDismissed: false, procShowDismissed: false, blocks: [], data: null, hours: 24, search: "", hideSystem: false, reportingOnly: false, open: null,
               processes: [], procSystem: true, procSearch: "" };

const CATEGORY_TITLES = {
  telemetry: "Usage reporting", advertising: "Advertising and tracking", update: "Updates", content: "Content",
  cloud: "Cloud hosting", "sign-in": "Sign-in", security: "Security checks", sync: "Sync",
  communication: "Messaging and calls", gaming: "Gaming", cdn: "Content delivery network",
  connectivity: "Connectivity", store: "App store", ai: "AI services", developer: "Developer tools",
  licensing: "Licensing", local: "Your local network", unknown: "Not identified",
};
const REPORTING = new Set(["telemetry", "advertising"]);

function bytes(value) {
  if (!value) return "0";
  if (value < 1024) return `${value} B`;
  if (value < 1048576) return `${(value / 1024).toFixed(value < 10240 ? 1 : 0)} KB`;
  if (value < 1073741824) return `${(value / 1048576).toFixed(1)} MB`;
  return `${(value / 1073741824).toFixed(2)} GB`;
}

function since(unixSeconds) {
  const seconds = Math.max(Date.now() / 1000 - unixSeconds, 0);
  if (seconds < 90) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} days ago`;
}

const clock = (unixSeconds) => new Date(unixSeconds * 1000).toLocaleString();

function categoryChip(category, title) {
  const kind = REPORTING.has(category) ? "chip flag" : "chip";
  return el("span", { class: kind, title, text: CATEGORY_TITLES[category] || category });
}

// --- navigation ------------------------------------------------------------------------

const pageLoaders = {};
function showPage(name) {
  document.querySelectorAll(".pages button").forEach((b) => b.classList.toggle("active", b.dataset.page === name));
  document.querySelectorAll(".page").forEach((page) => { page.hidden = page.id !== `page-${name}`; });
  try { localStorage.setItem("appaudit-page", name); } catch (error) { /* private mode */ }
  if (pageLoaders[name]) pageLoaders[name]();
}
document.querySelectorAll(".pages button").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));

// --- watcher status --------------------------------------------------------------------

async function refreshWatcher() {
  let helper = null;
  try { helper = (await (await fetch("/api/state")).json()).helper; } catch (error) { /* server gone */ }
  if (typeof updateContentToggle === "function") updateContentToggle(helper);
  const label = $("#watch-state");
  const button = $("#watch-toggle");
  button.hidden = false;
  if (helper && helper.running) {
    const lost = helper.lost > 0 ? `, ${helper.lost} missed` : "";
    label.textContent = `Watching since ${new Date(helper.since * 1000).toLocaleTimeString()} · `
      + `${helper.events.toLocaleString()} events${lost}`;
    button.textContent = "Stop watching";
    button.dataset.action = "stop";
  } else {
    label.textContent = helper && helper.ever_ran ? "Not watching. Showing what was recorded earlier."
      : "Not watching yet. Watching needs administrator rights.";
    button.textContent = "Start watching";
    button.dataset.action = "start";
  }
}
$("#watch-toggle").addEventListener("click", async () => {
  const button = $("#watch-toggle");
  button.disabled = true;
  await post(`/api/helper/${button.dataset.action}`);
  setTimeout(async () => { await refreshWatcher(); button.disabled = false; }, 2500);
});

// --- activity ----------------------------------------------------------------------------

// "Dismissed" is the user saying "I have looked at this and it is fine". It only hides the row.
const isDismissed = (kind, key) => live.dismissed.some((d) => d.kind === kind && d.key === String(key).toLowerCase());
async function setDismissed(kind, key, label, remove) {
  const response = await post("/api/dismissed", { kind, key, label, remove: Boolean(remove) });
  if (response.ok) live.dismissed = (await response.json()).dismissed;
  renderLive();
  renderProcesses();
}
function dismissButton(kind, key, label) {
  const hidden = isDismissed(kind, key);
  const button = el("button", { type: "button", class: "small", text: hidden ? "Show again" : "This is fine, hide it" });
  button.addEventListener("click", (event) => { event.stopPropagation(); setDismissed(kind, key, label, hidden); });
  return button;
}

function actorMatches(actor) {
  if (!live.showDismissed && isDismissed("actor", actor.id)) return false;
  if (live.hideSystem && actor.is_system) return false;
  if (live.reportingOnly && !actor.reporting_sent) return false;
  const needle = live.search.trim().toLowerCase();
  if (!needle) return true;
  const haystack = [actor.name, actor.publisher, actor.process, ...actor.processes,
    ...actor.destinations.map((d) => `${d.name || ""} ${d.company || ""} ${d.address}`)].join(" ").toLowerCase();
  return haystack.includes(needle);
}

function whoCell(actor) {
  const tags = [];
  if (actor.role) tags.push(el("span", { class: "chip tag", text: actor.role }));
  else if (actor.host) tags.push(el("span", { class: "chip tag", text: actor.host }));
  if (actor.is_system && !actor.role) tags.push(el("span", { class: "chip tag", text: "Windows" }));
  const sub = [actor.publisher, actor.processes.join(", ")].filter(Boolean).join(" · ");
  return el("td", {}, el("div", { class: "name", text: actor.name }), el("div", { class: "sub", text: sub }),
    tags.length ? el("div", {}, tags) : null);
}

function goesToCell(actor) {
  const companies = new Map();
  for (const d of actor.destinations) {
    const key = d.company || "Unknown";
    companies.set(key, (companies.get(key) || 0) + d.sent + d.received);
  }
  const top = [...companies.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([name]) => name);
  const more = companies.size > 3 ? ` and ${companies.size - 3} more` : "";
  return el("td", {}, el("div", { text: top.join(", ") + more }),
    el("div", { class: "sub", text: plural(actor.destination_count, "destination") }));
}

function purposeCell(actor) {
  const sorted = Object.entries(actor.categories).sort((a, b) => b[1] - a[1]).slice(0, 4);
  return el("td", {}, sorted.map(([category, volume]) => categoryChip(category, bytes(volume))));
}

function actorDetail(actor) {
  const rows = [];
  for (const d of actor.destinations) {
    const key = `${actor.id}|${d.name || d.address}`;
    const row = el("tr", { class: live.openDest === key ? "dest open" : "dest", title: "Show what a message to this destination looks like" },
      el("td", {}, el("div", { class: "mono", text: d.name || d.address }),
        el("div", { class: "sub", text: [d.name ? d.addresses.join(", ") : null, d.ports.join(", ")].filter(Boolean).join(" · ") })),
      el("td", { text: d.company || d.owner || "Unknown" }),
      el("td", {}, d.category ? categoryChip(d.category) : el("span", { class: "none", text: "Not identified" }),
        d.tracker ? el("div", { class: "sub", text: d.tracker }) : null),
      el("td", {}, el("div", { text: d.purpose || "" }), d.breaks ? el("div", { class: "sub", text: `If blocked: ${d.breaks}` }) : null),
      el("td", { class: "num", text: bytes(d.sent) }), el("td", { class: "num", text: bytes(d.received) }),
      el("td", { text: since(d.last) }));
    row.addEventListener("click", (event) => { event.stopPropagation(); live.openDest = live.openDest === key ? null : key; renderLive(); });
    rows.push(row);
    if (live.openDest === key) rows.push(exampleRow(actor, d));
  }
  const facts = [];
  if (actor.about) facts.push(el("li", {}, el("strong", { text: "What it is: " }), actor.about,
    actor.needed ? el("span", { class: "sub", text: ` Needed by Windows: ${actor.needed}.` }) : null));
  if (actor.services && actor.services.length) {
    for (const service of actor.services) {
      facts.push(el("li", {}, el("strong", { text: `${service.title} (${service.name})` }),
        service.description ? el("div", { class: "sub", text: service.description }) : null));
    }
  }
  if (actor.tasks.length) facts.push(el("li", { text: `Started by scheduled task: ${actor.tasks.join(", ")}` }));
  if (actor.on_behalf_of) facts.push(el("li", { text: `Running on behalf of ${actor.on_behalf_of}` }));
  facts.push(el("li", { text: `${plural(actor.runs, "process run")} in this window; first seen ${clock(actor.first)}` }));
  const blockable = (actor.exes || []).filter((exe) => !/^[a-z]:\\windows\\/i.test(exe));
  const blockRows = blockable.map((exe) => {
    const existing = live.blocks.find((b) => b.exe.toLowerCase() === exe.toLowerCase());
    const button = el("button", { type: "button", class: "small", text: existing ? "Remove block" : "Block its network access…" });
    button.addEventListener("click", async (event) => {
      event.stopPropagation();
      if (!existing && button.dataset.armed !== "1") {
        button.dataset.armed = "1";
        button.textContent = "Confirm: add a Windows Firewall rule";
        return;
      }
      button.disabled = true;
      const response = existing ? await post(`/api/blocks/${existing.id}/remove`) : await post("/api/blocks", { exe });
      if (!response.ok) button.textContent = (await response.json()).detail;
      await loadLive();
    });
    return el("div", { class: "row" }, el("div", { class: "grow mono", text: exe }),
      existing ? el("span", { class: "state private", text: "Blocked" }) : null, button);
  });
  return el("tr", { class: "detail" }, el("td", { colspan: "6" },
    el("div", { style: "float:right" }, dismissButton("actor", actor.id, actor.name)),
    el("ul", { class: "facts" }, facts),
    blockRows.length ? el("div", { class: "card" }, el("h2", { text: "Network block" }),
      el("div", { class: "sub", text: "Adds an outgoing block rule for the program in Windows Firewall. You can remove it here or in Windows." }), blockRows) : null,
    sdkSection(actor), askSection(actor),
    el("p", { class: "sub", text: "Select a destination to see what a message to it looks like." }),
    el("div", { class: "scroll" }, el("table", { class: "inner" },
      el("thead", {}, el("tr", {}, ["Destination", "Company", "Kind", "What it is for", "Sent", "Received", "Last"].map((t) => el("th", { text: t })))),
      el("tbody", {}, rows))),
    actor.destination_count > actor.destinations.length
      ? el("p", { class: "sub", text: `Showing the ${actor.destinations.length} largest of ${actor.destination_count} destinations.` }) : null));
}

function renderLive() {
  const data = live.data;
  if (!data) return;
  const totals = data.totals || {};
  const tiles = [
    ["", totals.actors || 0, "apps and components used the network"],
    ["", bytes(totals.sent || 0), "sent from this PC"],
    ["hot", bytes(totals.reporting_sent || 0), "sent to usage-reporting or ad services"],
    ["", `${totals.named || 0} of ${totals.destinations || 0}`, "destinations identified by name"],
  ];
  $("#live-tiles").replaceChildren(...tiles.map(([kind, value, label]) =>
    el("div", { class: `tile ${kind}` }, el("strong", { text: value }), el("span", { text: label }))));

  $("#live-dismissed-label").textContent = `Show dismissed (${data.actors.filter((a) => isDismissed("actor", a.id)).length})`;
  const actors = data.actors.filter(actorMatches);
  const rows = [];
  for (const actor of actors) {
    const row = el("tr", { class: live.open === actor.id ? "app open" : "app" },
      whoCell(actor),
      el("td", { class: "num" }, el("div", { text: bytes(actor.sent) }),
        actor.reporting_sent ? el("div", { class: "sub warn", text: `${bytes(actor.reporting_sent)} to reporting or ads` }) : null),
      el("td", { class: "num", text: bytes(actor.received) }),
      goesToCell(actor), purposeCell(actor), el("td", { title: clock(actor.last), text: since(actor.last) }));
    row.addEventListener("click", () => { live.open = live.open === actor.id ? null : actor.id; renderLive(); });
    rows.push(row);
    if (live.open === actor.id) rows.push(actorDetail(actor));
  }
  $("#live-table tbody").replaceChildren(...rows);
  $("#live-table").hidden = actors.length === 0;
  $("#live-empty").hidden = actors.length > 0;
  $("#live-empty").textContent = data.actors.length ? "Nothing matches this filter."
    : "Nothing recorded in this window. Start watching to record activity.";
  renderCompanies();
}

function renderCompanies() {
  const companies = (live.data && live.data.companies) || [];
  const askable = (name) => !["Unknown", "Your local network", "Public time servers"].includes(name);
  const rows = companies.map((company) => el("tr", {},
    el("td", {}, el("div", { class: "name", text: company.company }),
      el("div", { class: "sub", text: plural(company.destinations, "destination") }),
      askable(company.company) ? draftButton(company.company, "Ask what they hold") : null),
    el("td", { class: "num", text: bytes(company.sent) }), el("td", { class: "num", text: bytes(company.received) }),
    el("td", {}, Object.entries(company.categories).sort((a, b) => b[1] - a[1]).slice(0, 4)
      .map(([category, volume]) => categoryChip(category, bytes(volume)))),
    el("td", { text: company.actors.slice(0, 8).join(", ") + (company.actors.length > 8 ? ` and ${company.actors.length - 8} more` : "") })));
  $("#company-table tbody").replaceChildren(...rows);
  $("#company-table").hidden = rows.length === 0;
  $("#company-empty").hidden = rows.length > 0;
}

async function loadLive() {
  try {
    live.data = await (await fetch(`/api/live?hours=${live.hours}`)).json();
    live.blocks = (await (await fetch("/api/blocks")).json()).blocks;
    live.dismissed = (await (await fetch("/api/dismissed")).json()).dismissed;
    renderLive();
  } catch (error) { /* keep the previous view */ }
}

document.querySelectorAll("#live-window button").forEach((button) => button.addEventListener("click", () => {
  document.querySelectorAll("#live-window button").forEach((other) => other.classList.toggle("active", other === button));
  live.hours = Number(button.dataset.hours);
  live.open = null;
  loadLive();
}));
$("#live-search").addEventListener("input", (event) => { live.search = event.target.value; renderLive(); });
$("#live-hide-system").addEventListener("change", (event) => { live.hideSystem = event.target.checked; renderLive(); });
$("#live-reporting").addEventListener("change", (event) => { live.reportingOnly = event.target.checked; renderLive(); });

// --- background runs ---------------------------------------------------------------------

function renderProcesses() {
  const needle = live.procSearch.trim().toLowerCase();
  const hiddenPrograms = live.processes.filter((p) => isDismissed("program", p.exe || p.process)).length;
  $("#proc-dismissed-label").textContent = `Show dismissed (${hiddenPrograms})`;
  const list = live.processes.filter((p) => (live.procPlumbing || !p.plumbing)
    && (live.procShowDismissed || !isDismissed("program", p.exe || p.process)) && (!needle
    || `${p.process} ${p.actor} ${p.task || ""} ${p.parent || ""}`.toLowerCase().includes(needle)));
  const rows = list.map((p) => el("tr", {},
    el("td", { title: clock(p.when) }, el("div", { text: since(p.when) }),
      p.runs > 1 ? el("div", { class: "sub", text: `first ${since(p.first)}` }) : null),
    el("td", {}, el("div", { class: "name" }, p.process, p.runs > 1 ? el("span", { class: "chip", style: "margin-left:6px", text: `ran ${p.runs.toLocaleString()} times` }) : null), el("div", { class: "sub mono", text: p.exe || "" })),
    el("td", {}, el("div", { text: p.actor }), p.about ? el("div", { class: "sub", text: p.about }) : null,
      p.reports ? el("span", { class: "chip flag", text: "Reports to its maker" }) : null,
      p.role ? el("span", { class: "chip tag", text: p.role }) : null),
    el("td", { text: p.parent || "" }), el("td", { class: "mono", text: p.task || "" }),
    el("td", {}, dismissButton("program", p.exe || p.process, p.process))));
  $("#proc-table tbody").replaceChildren(...rows);
  $("#proc-table").hidden = rows.length === 0;
  $("#proc-empty").hidden = rows.length > 0;
}
async function loadProcesses() {
  const data = await (await fetch(`/api/live/processes?system_only=${live.procSystem}`)).json();
  live.processes = data.processes;
  live.dismissed = (await (await fetch("/api/dismissed")).json()).dismissed;
  renderProcesses();
}
pageLoaders.processes = loadProcesses;
$("#proc-system").addEventListener("change", (event) => { live.procSystem = event.target.checked; loadProcesses(); });
$("#proc-dismissed").addEventListener("change", (event) => { live.procShowDismissed = event.target.checked; renderProcesses(); });
$("#live-dismissed").addEventListener("change", (event) => { live.showDismissed = event.target.checked; renderLive(); });
$("#proc-plumbing").addEventListener("change", (event) => { live.procPlumbing = event.target.checked; renderProcesses(); });
$("#proc-search").addEventListener("input", (event) => { live.procSearch = event.target.value; renderProcesses(); });

// --- start ---------------------------------------------------------------------------------

refreshWatcher();
loadLive();
setInterval(refreshWatcher, 5000);
setInterval(() => { if (!$("#page-activity").hidden || !$("#page-companies").hidden) loadLive(); }, 15000);
window.addEventListener("load", () => {
  let saved = null;
  try { saved = localStorage.getItem("appaudit-page"); } catch (error) { /* private mode */ }
  showPage(saved && document.getElementById(`page-${saved}`) ? saved : "summary");
});
