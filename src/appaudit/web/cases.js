"use strict";

// Cases: the home page. A short list of plain sentences, each with its evidence and what can be done.

const casesState = { data: null, hours: 24, show: "open", open: null, plan: null, planFor: null, busy: false, message: null, loading: false };

const CASE_KINDS = {
  says_vs_does: "Switched off, still active", switchable: "Can be switched off", third_party: "Sends to another company",
  unused_active: "Active though you don't use it", new_company: "New company",
};
const SEVERITY_LABEL = { high: ["exposed", "Look at this first"], medium: ["partly", "Worth a look"], low: ["na", "Minor"] };

function buildCasesPage() {
  const page = $("#page-cases");
  if (page.dataset.built) return;
  page.dataset.built = "1";
  page.append(
    el("p", { class: "lead", text: "What App Audit found, as plain sentences. Each says what was observed on this PC, "
      + "not what anyone intended, and what you can do about it. Mark one as fine and it stays hidden until something about it changes." }),
    el("section", { class: "toolbar" },
      el("div", { class: "tabs", id: "cases-window" },
        el("button", { type: "button", "data-hours": "24", class: "active", text: "Last 24 hours" }),
        el("button", { type: "button", "data-hours": "168", text: "Last 7 days" })),
      el("div", { class: "tabs", id: "cases-show" })),
    el("div", { id: "cases-message", class: "notice", hidden: "" }),
    el("div", { id: "cases-list" }));
  page.querySelectorAll("#cases-window button").forEach((button) => button.addEventListener("click", () => {
    page.querySelectorAll("#cases-window button").forEach((other) => other.classList.toggle("active", other === button));
    casesState.hours = Number(button.dataset.hours);
    loadCases();
  }));
}

function caseAction(item, action) {
  if (action.type === "switch") {
    const key = `${item.id}|${action.id}`;
    const button = el("button", { type: "button", class: "small", text: casesState.planFor === key ? "Hide the change" : `Switch off: ${action.title}…` });
    button.addEventListener("click", async () => {
      if (casesState.planFor === key) { casesState.planFor = null; renderCases(); return; }
      casesState.planFor = key;
      casesState.plan = null;
      renderCases();
      casesState.plan = await fetchPlan({ id: action.id });
      renderCases();
    });
    return button;
  }
  if (action.type === "open_app" && action.actor) {
    const button = el("button", { type: "button", class: "small", text: "Look at the app" });
    button.addEventListener("click", () => openActor(action.actor));
    return button;
  }
  if (action.type === "proof") {
    const button = el("button", { type: "button", class: "small", text: "See the proof" });
    button.addEventListener("click", () => showPage("proof"));
    return button;
  }
  return null;
}

// Open an app's view on the Activity page.
function openActor(actorId) {
  live.open = actorId;
  live.hours = Math.max(live.hours || 24, casesState.hours);
  showPage("activity");
  let tries = 0;
  const scroll = () => {                       // the Activity data can take a few seconds to load
    const row = document.querySelector("#live-table tr.detail");
    if (row) row.previousElementSibling.scrollIntoView({ block: "start" });
    else if (tries++ < 40) setTimeout(scroll, 250);
  };
  scroll();
}

function evidenceView(item) {
  const evidence = item.evidence || {};
  const rows = [];
  for (const company of evidence.companies || []) {
    if (typeof company === "string") rows.push(el("li", { text: company }));
    else rows.push(el("li", {}, el("strong", { text: company.company }), ` received ${bytes(company.sent)}`,
      company.purpose ? ` · ${company.purpose}` : "", company.hosts && company.hosts.length ? el("div", { class: "sub mono", text: company.hosts.join(", ") }) : null));
  }
  if (evidence.window) {
    const w = evidence.window;
    rows.push(el("li", { text: `In this window: sent ${bytes(w.sent)}, received ${bytes(w.received)}, ran ${w.runs} times, observed for ${w.hours_observed} hours` }));
    for (const [name, sent] of w.senders || []) rows.push(el("li", { class: "sub", text: `${name} sent ${bytes(sent)}` }));
    for (const [name, size] of w.destinations || []) rows.push(el("li", { class: "sub mono", text: `${name}: ${bytes(size)}` }));
  }
  for (const app of evidence.apps || []) rows.push(el("li", { text: app }));
  if (evidence.presence && (evidence.presence.present || evidence.presence.away)) {
    const p = evidence.presence;
    rows.push(el("li", { text: `Sent while you were at the PC: ${bytes(p.present)}; while nobody was: ${bytes(p.away)}`
      + (p.unknown ? `; at times App Audit was not running: ${bytes(p.unknown)}` : "") }));
  }
  if (evidence.starts_itself) rows.push(el("li", { text: "It is set to start by itself." }));
  return rows.length ? fold(`case|${item.id}|evidence`, "Evidence", el("ul", { class: "facts" }, rows)) : null;
}

function caseCard(item) {
  const [kind, label] = SEVERITY_LABEL[item.severity] || ["na", item.severity];
  const actions = item.actions.map((action) => caseAction(item, action)).filter(Boolean);
  const decide = async (state) => {
    await post("/api/cases/decide", { id: item.id, state, fingerprint: item.fingerprint });
    casesState.message = state === "accepted" ? `Marked as fine: it stays hidden until something about it changes.` : "Opened again.";
    await loadCases();
  };
  if (item.state === "open") {
    const fine = el("button", { type: "button", class: "small", text: "It's fine" });
    fine.addEventListener("click", () => decide("accepted"));
    actions.push(fine);
  } else {
    const reopen = el("button", { type: "button", class: "small", text: "Show it again" });
    reopen.addEventListener("click", () => decide("open"));
    actions.push(reopen);
  }
  const plans = item.actions.filter((action) => action.type === "switch" && casesState.planFor === `${item.id}|${action.id}`).map((action) =>
    !casesState.plan ? el("div", { class: "sub", text: "Preparing the change…" })
      : planView({ id: action.id, title: action.title }, casesState.plan, casesState.busy, async () => {
        casesState.busy = true;
        renderCases();
        casesState.message = await applyAndDescribe({ id: action.id, title: action.title });
        casesState.busy = false;
        casesState.planFor = null;
        await loadCases(true);
      }, () => { casesState.planFor = null; renderCases(); }));
  return el("div", { class: "card case" },
    el("div", { class: "row" },
      el("div", { class: "grow" },
        el("div", { class: "sub", text: `${CASE_KINDS[item.kind] || item.kind}${item.reopened ? " · changed since you marked it fine" : ""}` }),
        el("div", { class: "case-title", text: item.title }),
        evidenceView(item), plans,
        el("div", { class: "actions" }, actions)),
      el("span", { class: `state ${kind}`, text: label })));
}

function renderCases() {
  const data = casesState.data;
  const list = $("#cases-list");
  const message = $("#cases-message");
  message.hidden = !casesState.message;
  message.textContent = casesState.message || "";
  if (!data) { list.replaceChildren(el("p", { class: "sub", text: casesState.loading ? "Working out the cases…" : "" })); return; }
  const tabs = $("#cases-show");
  tabs.replaceChildren(...[["open", `Open (${data.counts.open})`], ["accepted", `Marked fine (${data.counts.accepted})`],
    ["fixed", `Fixed (${data.fixed.length})`]].map(([value, text]) => {
    const button = el("button", { type: "button", class: casesState.show === value ? "active" : "", text });
    button.addEventListener("click", () => { casesState.show = value; renderCases(); });
    return button;
  }));
  if (casesState.show === "fixed") {
    list.replaceChildren(...(data.fixed.length ? data.fixed.map((item) => el("div", { class: "card" },
      el("div", { class: "case-title", text: item.id.split(":").slice(1).join(":") }),
      el("div", { class: "sub", text: "Was switched off but still active; the latest evidence no longer shows it." })))
      : [el("p", { class: "empty", text: "Nothing has been fixed yet. A case moves here when proof shows its activity stopped." })]));
    return;
  }
  const shown = data.cases.filter((item) => (casesState.show === "open" ? item.state === "open" : item.state !== "open"));
  list.replaceChildren(...(shown.length ? shown.map(caseCard)
    : [el("p", { class: "empty", text: casesState.show === "open" ? "Nothing open. Everything found is either fine or fixed." : "Nothing marked as fine." })]));
}

async function loadCases(fresh) {
  buildCasesPage();
  casesState.loading = true;
  if (!casesState.data) renderCases();
  const response = await fetch(`/api/cases?hours=${casesState.hours}${fresh ? `&t=${Date.now()}` : ""}`);
  casesState.data = response.ok ? await response.json() : null;
  casesState.loading = false;
  renderCases();
}
pageLoaders.cases = () => loadCases();
