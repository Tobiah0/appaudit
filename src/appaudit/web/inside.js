"use strict";

// What is inside the traffic: real captured requests, documented examples, components built into
// an app, and asking a company what it holds. Everything is shown with how we know it.

const inside = { examples: new Map(), sdks: new Map(), contacts: new Map(), openSdkExample: null,
                 requests: null, draft: null, helper: null };

const HOW_WE_KNOW = {
  captured: ["chip live", "Captured on this PC"],
  documented: ["chip tag", "Illustration from the vendor's published format"],
  files: ["chip tag", "Found in the app's files"],
};
const howChip = (kind) => el("span", { class: HOW_WE_KNOW[kind][0], text: HOW_WE_KNOW[kind][1] });
const SDK_KINDS = { analytics: "Usage analytics", crash: "Crash reports", monitoring: "Logs and monitoring",
  advertising: "Advertising", flags: "Feature switches and experiments", messaging: "In-app messaging", platform: "Platform" };

function link(text, url) {
  return el("a", { href: url, target: "_blank", rel: "noopener noreferrer", text });
}

// --- request content switch ---------------------------------------------------------------------

function updateContentToggle(helper) {
  inside.helper = helper;
  const button = $("#content-toggle");
  if (!helper || !helper.running) { button.hidden = true; $("#content-panel").hidden = true; return; }
  button.hidden = false;
  button.textContent = helper.content ? "Request content: on" : "Request content: off";
  button.classList.toggle("on", Boolean(helper.content));
}

async function setContent(on, clear) {
  const response = await post("/api/content", { on });
  if (response.ok && clear) await post("/api/content/clear");
  inside.examples.clear();
  $("#content-panel").hidden = true;
  if (response.ok && inside.helper) updateContentToggle({ ...inside.helper, content: on });
  renderLive();
}

$("#content-toggle").addEventListener("click", () => {
  const panel = $("#content-panel");
  if (!panel.hidden) { panel.hidden = true; return; }
  const on = inside.helper && inside.helper.content;
  const actions = el("div", { class: "actions" });
  const add = (text, handler, kind) => {
    const button = el("button", { type: "button", class: kind || "", text });
    button.addEventListener("click", handler);
    actions.append(button);
  };
  if (on) {
    add("Turn off", () => setContent(false, false));
    add("Turn off and delete what was captured", () => setContent(false, true));
  } else {
    add("Turn on", () => setContent(true, false));
  }
  add("Cancel", () => { panel.hidden = true; }, "small");
  panel.replaceChildren(
    el("strong", { text: on ? "Request content is being recorded" : "Record what is inside requests?" }),
    el("p", { text: "When this is on, the watcher also records the headers and the first 4,000 characters of the body of "
      + "web requests that programs make through Windows' own web library. It works for Windows components and for "
      + "apps that use that library. Browsers, Electron apps and most games use their own and cannot be read this way." }),
    el("p", { text: "Cookies, sign-in tokens and passwords are replaced before anything is saved. The five most recent "
      + "requests per program and destination are kept for seven days, on this PC only." }),
    actions);
  panel.hidden = false;
});

// --- one destination: what a message to it looks like ---------------------------------------------

function sampleBlock(text) {
  return el("pre", { class: "sample", text });
}

function documentedBlock(doc) {
  return el("div", { class: "example" },
    el("div", { class: "example-head" }, el("strong", { text: doc.title }), howChip("documented")),
    el("div", { class: "sub", text: "The field names follow the vendor's documentation. The values are made up; this was not captured from your PC." }),
    sampleBlock(doc.sample),
    doc.fields.length ? el("ul", { class: "facts" }, doc.fields.map((field) =>
      el("li", {}, el("span", { class: "mono", text: field.name }), ` — ${field.meaning}`))) : null,
    doc.note ? el("p", { class: "sub", text: doc.note }) : null,
    el("p", { class: "sub" }, "Source: ", link(doc.source, doc.url)));
}

function capturedBlock(item) {
  const shown = item.body ? item.body.length : 0;
  return el("div", { class: "example" },
    el("div", { class: "example-head" }, el("strong", { text: `${item.method || "Request"} ${item.url}` }), howChip("captured")),
    el("div", { class: "sub", text: `${clock(item.at)}. Sign-in values are hidden.` }),
    item.request_headers ? sampleBlock(item.request_headers) : null,
    item.body ? sampleBlock(item.body) : el("div", { class: "sub", text: "This request had no body, or the body was not seen." }),
    item.body_size > shown && item.body ? el("div", { class: "sub", text: `The body was ${bytes(item.body_size)}; this is the start of it.` }) : null,
    item.response_headers ? el("div", { class: "sub mono", text: `Answer: ${item.response_headers.split("\n")[0]}` }) : null);
}

function exampleRow(actor, destination) {
  const host = destination.name || destination.address;
  const key = `${actor.id}|${host}`;
  const cached = inside.examples.get(key);
  if (!cached) {
    inside.examples.set(key, { loading: true });
    fetch(`/api/examples?actor=${encodeURIComponent(actor.id)}&host=${encodeURIComponent(host)}`
      + `&addresses=${encodeURIComponent((destination.addresses || []).join(","))}`)
      .then((response) => response.json()).then((data) => { inside.examples.set(key, data); renderLive(); })
      .catch(() => inside.examples.delete(key));
  }
  const blocks = [];
  if (!cached || cached.loading) {
    blocks.push(el("div", { class: "sub", text: "Looking…" }));
  } else {
    const contentOn = inside.helper && inside.helper.content;
    blocks.push(el("h3", { text: `What a message to ${host} looks like` }));
    for (const item of cached.captured) blocks.push(capturedBlock(item));
    if (!cached.captured.length) {
      blocks.push(el("p", { class: "sub", text: contentOn
        ? "No real request from this app to this destination has been captured yet. Only programs that use Windows' own web library can be read."
        : "No real request captured: request content is switched off (see the button at the top of the page)." }));
    }
    if (cached.documented) blocks.push(documentedBlock(cached.documented));
    else if (!cached.captured.length) {
      blocks.push(el("p", { class: "none", text: "There is no example for this destination. Its owner does not publish the format, "
        + "so what is inside can only be learned by capturing it or by asking the company." }));
    }
  }
  return el("tr", { class: "example-row" }, el("td", { colspan: "7" }, blocks));
}

// --- turning off the app's reporting --------------------------------------------------------------
// The switches that concern this app (its own settings, policies, config files and steps), with
// the same exact-change preview as the Switches page.

const reporting = { byActor: new Map(), open: null, plan: null, busy: false, message: null };

async function loadReporting(actor) {
  const response = await fetch(`/api/switches/for-app?actor=${encodeURIComponent(actor.id)}`);
  const body = await response.json();
  reporting.byActor.set(actor.id, response.ok ? body.switches : { error: body.detail || "Could not read the switches." });
  renderLive();
}

function reportingRow(actor, item) {
  const [kind, label] = STATE_LABEL[item.state] || ["na", item.state];
  const key = `${actor.id}|${item.id}`;
  const actions = [];
  if (item.state === "exposed" || item.state === "partly") {
    const button = el("button", { type: "button", class: "small", text: reporting.open === key ? "Hide the change" : "Switch off…" });
    button.addEventListener("click", async (event) => {
      event.stopPropagation();
      if (reporting.open === key) { reporting.open = null; renderLive(); return; }
      reporting.open = key;
      reporting.plan = null;
      renderLive();
      reporting.plan = await fetchPlan(item);
      renderLive();
    });
    actions.push(button);
  }
  let detail = null;
  if (reporting.open === key) {
    detail = !reporting.plan ? el("div", { class: "sub", text: "Preparing the change…" })
      : planView(item, reporting.plan, reporting.busy, async () => {
        reporting.busy = true;
        renderLive();
        reporting.message = { actor: actor.id, text: await applyAndDescribe(item) };
        reporting.busy = false;
        reporting.open = null;
        await loadReporting(actor);
      }, () => { reporting.open = null; renderLive(); });
  }
  const steps = item.steps && item.steps.length && !item.checks.length ? stepsView(item.steps) : null;
  return el("div", { class: "row" },
    el("div", { class: "grow" }, el("div", { class: "name", text: item.title }),
      el("div", { class: "sub", text: item.explain }),
      item.breaks ? el("div", { class: "sub", text: `If you switch it off: ${item.breaks}` }) : null,
      item.origin !== "catalogue" ? el("div", { class: "sub", text: "From a community list" }) : null,
      steps, detail),
    el("div", { style: "text-align:right; display:flex; flex-direction:column; gap:6px; align-items:flex-end" },
      el("span", { class: `state ${kind}`, text: label }), actions));
}

function reportingSection(actor) {
  const data = reporting.byActor.get(actor.id);
  if (data === undefined) {
    reporting.byActor.set(actor.id, null);
    loadReporting(actor);
  }
  const card = el("div", { class: "card" }, el("h2", { text: "Turn off its reporting" }));
  if (!data) { card.append(el("div", { class: "sub", text: "Looking for this app's settings…" })); return card; }
  if (data.error) { card.append(el("div", { class: "none", text: data.error })); return card; }
  if (reporting.message && reporting.message.actor === actor.id) card.append(el("div", { class: "notice", text: reporting.message.text }));
  if (!data.length) {
    card.append(el("div", { class: "sub", text: "No known setting turns off this app's reporting. Blocking it is the remaining option, "
      + "and that usually stops the app working too." }));
    return card;
  }
  card.append(el("div", { class: "sub", text: "The app's own settings. Each change is shown exactly before it is made, and can be undone." }),
    ...data.map((item) => reportingRow(actor, item)));
  return card;
}

// --- components built into the app ----------------------------------------------------------------

async function loadSdks(actor, scan) {
  const response = scan ? await post("/api/sdks/scan", { actor: actor.id }) : await fetch(`/api/sdks?actor=${encodeURIComponent(actor.id)}`);
  const data = await response.json();
  inside.sdks.set(actor.id, response.ok ? data : { error: data.detail || "Could not read this app's files." });
  renderLive();
  if (response.ok && data.scanning) setTimeout(() => { if (live.open === actor.id) loadSdks(actor, false); }, 2000);
}

function sdkSection(actor) {
  const data = inside.sdks.get(actor.id);
  const card = el("div", { class: "card" }, el("h2", { text: "Built into this app" }));
  if (!data) {
    inside.sdks.set(actor.id, { loading: true });
    loadSdks(actor, false);
  }
  if (!data || data.loading) { card.append(el("div", { class: "sub", text: "Looking…" })); return card; }
  if (data.error) { card.append(el("div", { class: "none", text: data.error })); return card; }
  if (!data.folders.length) {
    card.append(el("div", { class: "sub", text: "This is part of Windows or sits in a shared folder, so there is no app folder to read." }));
    return card;
  }
  const scanButton = (text) => {
    const button = el("button", { type: "button", class: "small", text });
    button.addEventListener("click", (event) => { event.stopPropagation(); button.disabled = true; loadSdks(actor, true); });
    return button;
  };
  if (data.scanning) {
    card.append(el("div", { class: "sub", text: "Reading the app's files…" }));
    return card;
  }
  if (!data.scanned) {
    card.append(el("div", { class: "sub", text: "Reads the app's own files and looks for known reporting components. "
      + "It only reads; it takes a few seconds." }), el("div", { class: "actions" }, scanButton("Check this app's files")));
    return card;
  }
  if (!data.found.length) {
    card.append(el("div", { text: "No known reporting component was found." }),
      el("div", { class: "sub", text: "An app can also report through code its maker wrote, which this check cannot recognise." }));
  }
  for (const sdk of data.found) {
    const evidence = sdk.evidence[0];
    const exampleKey = `${actor.id}|${sdk.id}`;
    const more = sdk.example ? el("button", { type: "button", class: "small", text: inside.openSdkExample === exampleKey ? "Hide the example" : "Show what one message looks like" }) : null;
    if (more) more.addEventListener("click", async (event) => {
      event.stopPropagation();
      inside.openSdkExample = inside.openSdkExample === exampleKey ? null : exampleKey;
      if (!inside.examples.has(`doc|${sdk.example}`)) {
        inside.examples.set(`doc|${sdk.example}`, await (await fetch(`/api/examples?example=${encodeURIComponent(sdk.example)}`)).json());
      }
      renderLive();
    });
    const doc = inside.openSdkExample === exampleKey ? inside.examples.get(`doc|${sdk.example}`) : null;
    card.append(el("div", { class: "sdk" },
      el("div", { class: "example-head" }, el("strong", { text: sdk.name }),
        el("span", { class: sdk.kind === "advertising" || sdk.kind === "analytics" ? "chip flag" : "chip", text: SDK_KINDS[sdk.kind] || sdk.kind }),
        sdk.seen_talking_to.length ? el("span", { class: "chip flag", text: "Seen in use" }) : el("span", { class: "chip tag", text: "Not seen sending in this window" })),
      el("div", { text: sdk.collects }),
      el("div", { class: "sub" }, howChip("files"), ` ${evidence.file}`, evidence.match === "file name" ? "" : ` contains “${evidence.match}”`,
        sdk.files > 1 ? ` and ${sdk.files - 1} more` : ""),
      sdk.seen_talking_to.length ? el("div", { class: "sub", text: `This app talked to ${sdk.seen_talking_to.join(", ")}.` }) : null,
      more ? el("div", { class: "actions" }, more) : null,
      doc && doc.documented ? documentedBlock(doc.documented) : null));
  }
  card.append(el("p", { class: "sub" }, `Read ${data.files.toLocaleString()} files (${bytes(data.bytes)}) ${since(data.scanned)}`
    + `${data.complete ? "" : "; the folder is large, so only part of it was read"}. `
    + "Finding a component shows what the app is built to do, not what it sent. ", scanButton("Check again")));
  return card;
}

// --- ask the company -------------------------------------------------------------------------------

const ROLE_TEXT = {
  controller: "You are their customer, so they must answer a request for your data.",
  processor: "This company stores data on behalf of app makers. It will usually refer you to the maker of the app that sent the data.",
  carrier: "This company carries or hosts traffic. It rarely holds anything that identifies you beyond connection logs.",
  unknown: "The dashboard has no contact details for this company. Its privacy policy names where to send a request.",
};

function contactLinks(contact) {
  const links = [];
  if (contact.export) links.push(link("Open their download-your-data page", contact.export));
  if (contact.request) links.push(link("Open their request page", contact.request));
  if (contact.policy) links.push(link("Open their privacy policy", contact.policy));
  if (contact.unchecked && links.length) links.push(el("span", { class: "sub", text: "(link not verified automatically)" }));
  return links;
}

function draftButton(company, text) {
  const button = el("button", { type: "button", class: "small", text: text || "Draft a request letter" });
  button.addEventListener("click", (event) => { event.stopPropagation(); openDraft(company); });
  return button;
}

function askSection(actor) {
  if (!actor.publisher || actor.is_system) return null;
  const key = `pub|${actor.publisher}`;
  const contact = inside.contacts.get(key);
  if (!contact) {
    inside.contacts.set(key, { loading: true });
    fetch(`/api/requests/contact?publisher=${encodeURIComponent(actor.publisher)}`).then((r) => r.json())
      .then((data) => { inside.contacts.set(key, data); renderLive(); });
  }
  const card = el("div", { class: "card" }, el("h2", { text: "Ask what they hold about you" }));
  if (!contact || contact.loading) { card.append(el("div", { class: "sub", text: "Looking…" })); return card; }
  const others = [...new Set(actor.destinations.map((d) => d.company).filter((name) =>
    name && name !== contact.company && (contact.processors || []).includes(name)))].slice(0, 6);
  card.append(
    el("div", {}, el("strong", { text: contact.company }), `. ${ROLE_TEXT[contact.known ? contact.role : "unknown"]}`),
    contact.how ? el("div", { class: "sub", text: contact.how }) : null,
    others.length ? el("div", { class: "sub", text: `This app also sent data to ${others.join(", ")}, which store data on behalf of app makers. The letter asks ${contact.company} to include what they hold for it.` }) : null,
    el("div", { class: "actions" }, draftButton(contact.company), contactLinks(contact)));
  return card;
}

// --- data requests page ----------------------------------------------------------------------------

async function openDraft(company) {
  const response = await post("/api/requests/draft", { company });
  inside.draft = response.ok ? await response.json() : null;
  showPage("requests");
}

function field(label, input) {
  return el("label", { class: "field" }, el("span", { text: label }), input);
}

function profileCard(data) {
  const profile = data.profile;
  const name = el("input", { type: "text", value: profile.name, placeholder: "Your full name" });
  const email = el("input", { type: "email", value: profile.email, placeholder: "The email address on your accounts" });
  const account = el("input", { type: "text", value: profile.account, placeholder: "Optional: a username or customer number" });
  const law = el("select", {}, Object.entries(data.laws).map(([key, item]) =>
    el("option", { value: key, selected: key === profile.law ? "selected" : null, text: `${item.title} — answer due in ${item.days} days` })));
  const saved = el("span", { class: "sub" });
  const button = el("button", { type: "button", text: "Save" });
  button.addEventListener("click", async () => {
    await post("/api/requests/profile", { name: name.value, email: email.value, account: account.value, law: law.value });
    saved.textContent = "Saved on this PC.";
    if (inside.draft) openDraft(inside.draft.company); else loadRequests();
  });
  return el("div", { class: "card" }, el("h2", { text: "About you" }),
    el("div", { class: "sub", text: "Used only to fill in the letters. It is stored on this PC and sent nowhere." }),
    el("div", { class: "fields" }, field("Name", name), field("Email", email), field("Other identifier", account), field("Where you live", law)),
    el("div", { class: "actions" }, button, saved));
}

function draftCard() {
  const draft = inside.draft;
  const contact = draft.contact;
  const copy = el("button", { type: "button", text: "Copy the letter" });
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(`${draft.subject}\n\n${draft.body}`); copy.textContent = "Copied"; }
    catch (error) { copy.textContent = "Select the text and copy it"; }
  });
  const mail = el("a", { class: "button", href: `mailto:?subject=${encodeURIComponent(draft.subject)}&body=${encodeURIComponent(draft.body)}`,
    text: "Open in my mail program" });
  const save = el("button", { type: "button", text: "Add to my list" });
  save.addEventListener("click", async () => {
    await post("/api/requests", { company: draft.company });
    inside.draft = null;
    loadRequests();
  });
  const close = el("button", { type: "button", class: "small", text: "Close" });
  close.addEventListener("click", () => { inside.draft = null; loadRequests(); });
  const steps = [];
  if (contact.export) steps.push(el("li", {}, "Fastest: ", link("their download-your-data page", contact.export), ". No letter needed."));
  if (contact.request) steps.push(el("li", {}, "Their request page: ", link(contact.request, contact.request)));
  if (contact.policy) steps.push(el("li", {}, "Their privacy policy names the address for requests: ", link(contact.policy, contact.policy)));
  if (!steps.length) steps.push(el("li", { text: `Search for “${draft.company} privacy policy”. The policy names the address for data requests.` }));
  return el("div", { class: "card" }, el("h2", { text: `Request to ${draft.company}` }),
    el("div", {}, ROLE_TEXT[contact.known ? contact.role : "unknown"]),
    contact.how ? el("div", { class: "sub", text: contact.how }) : null,
    el("ul", { class: "facts" }, steps),
    contact.unchecked ? el("div", { class: "sub", text: "This company's page refuses automated checks, so the link above has not been verified." }) : null,
    el("div", { class: "sub", text: draft.apps.length
      ? `The letter quotes what this PC observed from ${draft.apps.join(", ")} in the last 7 days. Written for: ${draft.law_title}.`
      : `Nothing was observed for this company in the last 7 days, so the letter is general. Written for: ${draft.law_title}.` }),
    sampleBlock(`Subject: ${draft.subject}\n\n${draft.body}`),
    el("div", { class: "sub", text: "Nothing is sent by this dashboard. You send the letter yourself, then press “I sent it” in the list so the due date is tracked." }),
    el("div", { class: "actions" }, copy, mail, save, close));
}

const REQUEST_STATES = { draft: ["na", "Not sent yet"], waiting: ["private", "Waiting for an answer"],
  overdue: ["exposed", "Overdue"], answered: ["private", "Answered"] };

function requestRow(item) {
  const act = (text, action) => {
    const button = el("button", { type: "button", class: "small", text });
    button.addEventListener("click", async () => { await post(`/api/requests/${item.id}`, { action }); loadRequests(); });
    return button;
  };
  const show = el("button", { type: "button", class: "small", text: "Show the letter" });
  const letter = el("div", { hidden: "hidden" });
  show.addEventListener("click", async () => {
    if (!letter.hidden) { letter.hidden = true; return; }
    let text = `Subject: ${item.subject}\n\n${item.body}`;
    if (item.state === "overdue") {
      const reminder = await (await fetch(`/api/requests/${item.id}/reminder`)).json();
      text = `Subject: ${reminder.subject}\n\n${reminder.body}`;
    }
    letter.replaceChildren(item.state === "overdue" ? el("div", { class: "sub", text: "The answer is overdue. This is a reminder you can send." }) : "", sampleBlock(text));
    letter.hidden = false;
  });
  const when = item.state === "draft" ? "" : item.state === "answered" ? `answered ${since(item.answered)}`
    : item.state === "overdue" ? `was due ${new Date(item.due * 1000).toLocaleDateString()}`
      : `due ${new Date(item.due * 1000).toLocaleDateString()} (${item.days_left} days left)`;
  const buttons = [show];
  if (item.state === "draft") buttons.push(act("I sent it", "sent"));
  if (item.state === "waiting" || item.state === "overdue") buttons.push(act("They answered", "answered"));
  if (item.state === "answered") buttons.push(act("Reopen", "reopen"));
  buttons.push(act("Remove", "delete"));
  return el("div", { class: "request" },
    el("div", { class: "example-head" }, el("strong", { text: item.company }),
      el("span", { class: `state ${REQUEST_STATES[item.state][0]}`, text: REQUEST_STATES[item.state][1] }),
      el("span", { class: "sub", text: [item.sent ? `sent ${new Date(item.sent * 1000).toLocaleDateString()}` : `drafted ${since(item.created)}`, when].filter(Boolean).join(" · ") })),
    item.about.length ? el("div", { class: "sub", text: `About: ${item.about.join(", ")}` }) : null,
    el("div", { class: "actions" }, buttons, contactLinks(item.contact)), letter);
}

async function loadRequests() {
  const page = $("#page-requests");
  const data = await (await fetch("/api/requests")).json();
  inside.requests = data;
  const companies = new Set();
  for (const actor of (live.data && live.data.actors) || []) {
    for (const d of actor.destinations) if (d.company && !["Unknown", "Your local network"].includes(d.company)) companies.add(d.company);
  }
  const pick = el("select", {}, [...companies].sort().map((name) => el("option", { value: name, text: name })));
  const start = el("button", { type: "button", text: "Draft a letter" });
  start.addEventListener("click", () => { if (pick.value) openDraft(pick.value); });
  const blocks = [
    el("p", { class: "lead", text: "The watcher shows that data left this PC and where it went. Only the company can show what "
      + "it kept. Privacy laws in many places give you the right to ask. This page prepares the request and keeps track of the answer." }),
    inside.draft ? draftCard() : el("div", { class: "card" }, el("h2", { text: "Start a request" }),
      el("div", { class: "sub", text: "Companies that received data from this PC in the last 24 hours. You can also start from an app on the Activity page." }),
      el("div", { class: "actions" }, pick, start)),
    profileCard(data),
    el("div", { class: "card" }, el("h2", { text: "Your requests" }),
      data.requests.length ? data.requests.map(requestRow) : el("div", { class: "sub", text: "None yet." })),
  ];
  page.replaceChildren(...blocks);
}
pageLoaders.requests = loadRequests;
