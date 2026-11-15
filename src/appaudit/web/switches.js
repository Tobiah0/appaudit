"use strict";

// The Switches page: every known privacy switch, its current state, and apply / undo.

const sw = { data: null, search: "", show: "exposed", planFor: null, plan: null, busy: false, message: null };

const STATE_LABEL = {
  private: ["private", "Off (private)"], exposed: ["exposed", "On"], partly: ["exposed", "Partly on"],
  not_installed: ["na", "Not on this PC"], unknown: ["na", "Could not read"], manual: ["na", "Steps to follow"],
};

// A unified diff with added and removed lines marked, so the change can be checked line by line.
function diffView(text) {
  const lines = text.replace(/\r/g, "").split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  return el("pre", { class: "plan" }, lines.map((line) => {
    const kind = line.startsWith("+++") || line.startsWith("---") || line.startsWith("@@") ? "meta"
      : line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : "ctx";
    return el("span", { class: kind, text: line || " " });
  }));
}

function stepsView(steps) {
  return el("ol", { class: "steps" }, steps.map((step) => el("li", {},
    el("strong", { text: step.name }), " ", el("span", { text: step.description }),
    step.link ? [" ", el("a", { href: step.link, target: "_blank", rel: "noreferrer", text: "Open" })] : null)));
}

function buildSwitchPage() {
  const page = $("#page-switches");
  if (page.dataset.built) return;
  page.dataset.built = "1";
  page.append(
    el("p", { class: "lead", text: "Each switch is a real setting in Windows or in an app. \"On\" means data can leave "
      + "the PC or be collected. Every change is recorded and can be undone. Nothing changes until you press Apply." }),
    el("section", { id: "sw-tiles", class: "tiles" }),
    el("section", { class: "toolbar" },
      el("div", { class: "tabs", id: "sw-show" },
        el("button", { type: "button", "data-show": "exposed", class: "active", text: "Still on" }),
        el("button", { type: "button", "data-show": "private", text: "Already off" }),
        el("button", { type: "button", "data-show": "all", text: "All" }),
        el("button", { type: "button", "data-show": "journal", text: "Changes made" })),
      el("input", { id: "sw-search", type: "search", placeholder: "Search switches", "aria-label": "Search switches" })),
    el("div", { id: "sw-message", class: "notice", hidden: "" }),
    el("div", { id: "sw-list" }));
  page.querySelectorAll("#sw-show button").forEach((button) => button.addEventListener("click", () => {
    page.querySelectorAll("#sw-show button").forEach((other) => other.classList.toggle("active", other === button));
    sw.show = button.dataset.show;
    renderSwitches();
  }));
  $("#sw-search").addEventListener("input", (event) => { sw.search = event.target.value; renderSwitches(); });
}

function valueText(value) {
  return value === null || value === undefined ? "not set" : String(value);
}

function planPanel(item) {
  if (sw.planFor !== item.id || !sw.plan) return null;
  return planView(item, sw.plan, sw.busy, () => applySwitch(item),
    () => { sw.planFor = null; sw.plan = null; renderSwitches(); });
}

// The exact changes a switch would make, and the buttons to apply or cancel them. Used on the
// Switches page and in each app's view on the Activity page.
function planView(item, plan, busy, onApply, onCancel) {
  if (plan.error) return el("div", { class: "notice warn", text: plan.error });
  if (!plan.length) return el("pre", { class: "plan", text: "Nothing to change: every part is already off." });
  const settings = plan.filter((change) => !change.file);
  const files = new Map();                      // one diff per file: the last change carries the full edit
  for (const change of plan.filter((c) => c.file)) files.set(change.file, change);
  const parts = [];
  if (settings.length) {
    parts.push(el("pre", { class: "plan", text: settings.map((change) =>
      `${change.what}\n    now: ${valueText(change.before)}   ->   after: ${valueText(change.after)}`
      + (change.admin ? "   (needs administrator rights)" : "")).join("\n") }));
  }
  for (const [file, change] of files) {
    parts.push(el("div", { class: "sub", style: "margin-top:8px",
      text: change.exists ? `This file will be changed. A copy of it is kept first, so Undo puts it back exactly: ${file}`
        : `This file does not exist yet and will be created; Undo removes it again: ${file}` }));
    parts.push(diffView(change.diff));
    if (change.running.length) {
      parts.push(el("div", { class: "warn", style: "margin-top:6px",
        text: `${change.running.join(", ")} is running. Close it first: some apps write their old settings back when they exit.` }));
    }
  }
  if (item.origin && item.origin !== "catalogue") {
    parts.push(el("div", { class: "sub", style: "margin-top:6px",
      text: "This switch comes from a community list, not from this tool's own catalogue. Check the change above before applying it." }));
  }
  const apply = el("button", { type: "button", class: "primary small", text: busy ? "Applying…" : "Apply these changes" });
  apply.disabled = busy;
  apply.addEventListener("click", (event) => { event.stopPropagation(); onApply(); });
  const cancel = el("button", { type: "button", class: "small", text: "Cancel" });
  cancel.addEventListener("click", (event) => { event.stopPropagation(); onCancel(); });
  return el("div", {}, parts, el("div", { style: "margin-top:8px; display:flex; gap:8px" }, apply, cancel));
}

function switchRow(item) {
  const [kind, label] = STATE_LABEL[item.state] || ["na", item.state];
  const facts = [];
  if (item.breaks) facts.push(el("div", { class: "sub", text: `If you switch it off: ${item.breaks}` }));
  if (item.note) facts.push(el("div", { class: "sub", text: `Note: ${item.note}` }));
  const tags = [];
  if (item.needs_admin) tags.push(el("span", { class: "chip tag", text: "Needs administrator rights" }));
  if (item.risk !== "low") tags.push(el("span", { class: "chip tag", text: `${item.risk} risk` }));
  if (item.source) tags.push(el("a", { class: "chip tag", href: item.source, target: "_blank", rel: "noreferrer", text: "Source" }));
  const actions = [];
  if (item.state === "exposed" || item.state === "partly") {
    const button = el("button", { type: "button", class: "small", text: "Switch off…" });
    button.addEventListener("click", () => previewSwitch(item));
    actions.push(button);
  }
  if (item.origin && item.origin !== "catalogue") tags.push(el("span", { class: "chip tag", text: "From a community list" }));
  const checks = item.checks.length ? el("details", {}, el("summary", { class: "sub", text: "What it checks" }),
    el("pre", { class: "plan", text: item.checks.map((c) => `${c.state.padEnd(8)} ${c.what}   (now: ${valueText(c.current)})`).join("\n") })) : null;
  // Settings only the app or the vendor's website can change: the steps are the action.
  const steps = item.steps && item.steps.length ? (item.checks.length
    ? el("details", {}, el("summary", { class: "sub", text: "Other ways to turn it off" }), stepsView(item.steps))
    : el("div", {}, el("div", { class: "sub", style: "margin-top:6px", text: "This tool cannot change this setting. Turn it off yourself:" }),
      stepsView(item.steps))) : null;
  return el("div", { class: "row" },
    el("div", { class: "grow" }, el("div", { class: "name", text: item.title }), el("div", { text: item.explain }),
      facts, tags.length ? el("div", { style: "margin-top:4px" }, tags) : null, checks, steps, planPanel(item)),
    el("div", { style: "text-align:right; display:flex; flex-direction:column; gap:6px; align-items:flex-end" },
      el("span", { class: `state ${kind}`, text: label }), actions));
}

function journalView(entries) {
  if (!entries.length) return [el("p", { class: "empty", text: "No changes have been made through this tool." })];
  return [el("div", { class: "card" }, entries.map((entry) => {
    const item = (sw.data.switches.find((s) => s.id === entry.switch_id) || { title: entry.switch_id });
    const undo = el("button", { type: "button", class: "small", text: "Undo" });
    undo.addEventListener("click", async () => {
      undo.disabled = true;
      const response = await post(`/api/switches/undo/${entry.id}`);
      sw.message = response.ok ? `Restored: ${item.title}` : `Undo failed: ${(await response.json()).detail}`;
      await loadSwitches();
    });
    return el("div", { class: "row" },
      el("div", { class: "grow" }, el("div", { class: "name", text: item.title }),
        el("div", { class: "sub", text: new Date(entry.applied * 1000).toLocaleString() }),
        el("pre", { class: "plan", text: entry.changes.map((c) => `${c.what}\n    was: ${valueText(c.before)}   set to: ${valueText(c.after)}`
          + (c.backup ? `\n    copy of the file before the change: ${c.backup}` : "")).join("\n") })),
      entry.undone ? el("span", { class: "state na", text: "Undone" }) : undo);
  }))];
}

function renderSwitches() {
  if (!sw.data) return;
  const counts = sw.data.counts;
  const on = (counts.exposed || 0) + (counts.partly || 0);
  $("#sw-tiles").replaceChildren(...[
    ["hot", on, "switches still on"], ["", counts.private || 0, "already off"],
    ["", counts.not_installed || 0, "for software not on this PC"], ["", sw.data.switches.length, "switches known"],
  ].map(([kind, value, label]) => el("div", { class: `tile ${kind}` }, el("strong", { text: value }), el("span", { text: label }))));
  const message = $("#sw-message");
  message.hidden = !sw.message;
  message.textContent = sw.message || "";
  if (sw.show === "journal") {
    const reverted = (sw.data.drift || []).filter((item) => item.turned_back_on);
    const other = (sw.data.drift || []).filter((item) => !item.turned_back_on);
    const driftCard = (sw.data.drift || []).length ? el("div", { class: "card" }, el("h2", { text: "Changed outside this tool" }),
      [...reverted, ...other].map((item) => el("div", { class: "row" },
        el("div", { class: "grow" }, el("div", { class: "name", text: item.title }),
          el("div", { class: "sub", text: `Noticed ${new Date(item.noticed * 1000).toLocaleString()}: was ${item.before}, now ${item.after}` })),
        item.turned_back_on ? el("span", { class: "state exposed", text: "Turned back on" }) : el("span", { class: "state na", text: "Changed" })))) : null;
    $("#sw-list").replaceChildren(...[driftCard, ...journalView(sw.data.journal)].filter(Boolean));
    return;
  }
  const needle = sw.search.trim().toLowerCase();
  const groups = new Map();
  for (const item of sw.data.switches) {
    if (sw.show === "exposed" && !["exposed", "partly", "manual"].includes(item.state)) continue;
    if (sw.show === "private" && item.state !== "private") continue;
    if (needle && !`${item.title} ${item.explain} ${item.group} ${item.id}`.toLowerCase().includes(needle)) continue;
    if (!groups.has(item.group)) groups.set(item.group, []);
    groups.get(item.group).push(item);
  }
  const cards = [...groups.entries()].map(([group, items]) =>
    el("div", { class: "card" }, el("h2", { text: `${group} (${items.length})` }), items.map(switchRow)));
  $("#sw-list").replaceChildren(...(cards.length ? cards : [el("p", { class: "empty", text: "Nothing matches this view." })]));
}

async function previewSwitch(item) {
  sw.planFor = item.id;
  sw.plan = await fetchPlan(item);
  renderSwitches();
}

async function fetchPlan(item) {
  const response = await fetch(`/api/switches/${encodeURIComponent(item.id)}/plan`);
  const body = await response.json();
  return response.ok ? body.plan : { error: body.detail || "The change could not be prepared." };
}

// Apply a switch and describe the outcome in one sentence.
async function applyAndDescribe(item) {
  const response = await post(`/api/switches/${encodeURIComponent(item.id)}/apply`);
  const body = await response.json();
  if (!response.ok) return `Not applied: ${body.detail}`;
  if (body.failed.length) return `${item.title}: ${body.changed.length} changed, ${body.failed.length} refused (${body.failed[0].error}).`;
  return `${item.title} is now off. Undo it on the Switches page under "Changes made". The Proof page will show whether its traffic stops.`;
}

async function applySwitch(item) {
  sw.busy = true;
  renderSwitches();
  sw.message = await applyAndDescribe(item);
  sw.busy = false;
  sw.planFor = null;
  sw.plan = null;
  await loadSwitches();
}

async function loadSwitches() {
  buildSwitchPage();
  sw.data = await (await fetch("/api/switches")).json();
  renderSwitches();
}
pageLoaders.switches = loadSwitches;
