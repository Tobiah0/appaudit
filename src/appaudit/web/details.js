"use strict";

// "Everything recorded": the full detail of one app, in collapsed sections. Nothing here collects
// anything new; it shows what the watcher, the history import and the inventory already hold.

const details = { byActor: new Map(), open: new Set() };

// A collapsed section that stays open across redraws of the Activity table.
function fold(key, summary, ...content) {
  const node = el("details", { class: "fold" }, el("summary", {}, summary), ...content);
  if (details.open.has(key)) node.open = true;
  node.addEventListener("toggle", () => { if (node.open) details.open.add(key); else details.open.delete(key); });
  node.addEventListener("click", (event) => event.stopPropagation());
  return node;
}

function smallTable(headers, rows) {
  return el("div", { class: "scroll" }, el("table", { class: "inner" },
    el("thead", {}, el("tr", {}, headers.map((text) => el("th", { text })))), el("tbody", {}, rows)));
}

function minutes(seconds) {
  if (!seconds) return "0";
  return seconds < 3600 ? `${Math.round(seconds / 60)} min` : `${(seconds / 3600).toFixed(1)} h`;
}

async function loadDetails(actor) {
  const response = await fetch(`/api/app-details?actor=${encodeURIComponent(actor.id)}&hours=168`);
  const body = await response.json();
  details.byActor.set(actor.id, response.ok ? body : { error: body.detail || "Could not read the records." });
  renderLive();
}

// Bars per hour: total sent, with the part that went to reporting or advertising services marked.
function timelineView(hours) {
  if (!hours.length) return el("div", { class: "sub", text: "Nothing recorded in this window." });
  const peak = Math.max(...hours.map((h) => h.sent + h.received), 1);
  const bars = hours.map((h) => {
    const total = h.sent + h.received;
    const height = Math.max(2, Math.round((total / peak) * 60));
    const reportHeight = total ? Math.round(height * (h.reporting / total)) : 0;
    return el("div", { class: "bar", title: `${new Date(h.hour * 1000).toLocaleString()}: sent ${bytes(h.sent)}, received ${bytes(h.received)}`
        + (h.reporting ? `, ${bytes(h.reporting)} to reporting or ads` : "") },
      el("div", { class: "bar-total", style: `height:${height}px` }, reportHeight ? el("div", { class: "bar-report", style: `height:${reportHeight}px` }) : null));
  });
  const first = new Date(hours[0].hour * 1000), last = new Date(hours[hours.length - 1].hour * 1000);
  return el("div", {}, el("div", { class: "bars" }, bars),
    el("div", { class: "sub" }, `${first.toLocaleString()} to ${last.toLocaleString()} · one bar per hour with traffic · `,
      el("span", { class: "legend-report" }, "■"), " to reporting or advertising services"));
}

function historyView(days) {
  if (!days.length) return el("div", { class: "sub", text: "Windows has no record of this app's network use." });
  const away = days.filter((d) => d.sent + d.received > 0 && !d.focus_seconds).length;
  const used = days.filter((d) => d.focus_seconds > 0).length;
  const rows = days.slice().reverse().map((d) => el("tr", {},
    el("td", { text: d.day }), el("td", { class: "num", text: bytes(d.sent) }), el("td", { class: "num", text: bytes(d.received) }),
    el("td", { class: "num", text: minutes(d.focus_seconds) }), el("td", { class: "num", text: minutes(d.input_seconds) })));
  return el("div", {},
    el("div", { text: `${days.length} days with a record: in front of you on ${used}, used the network without being in front of you on ${away}.` }),
    smallTable(["Day", "Sent", "Received", "In front of you", "You typed or clicked"], rows));
}

function inventoryView(inv) {
  if (!inv) return el("div", { class: "sub", text: "Not matched to an installed app in the inventory." });
  const facts = [];
  facts.push(el("li", { text: `Installed in ${inv.install_dir}` }));
  if (inv.usage && inv.usage.last_used) facts.push(el("li", { text: `Last opened by you: ${new Date(inv.usage.last_used).toLocaleString()}`
    + (inv.usage.run_count ? ` (${inv.usage.run_count} times recorded)` : "") }));
  for (const entry of inv.autostart || []) {
    facts.push(el("li", { text: `Starts by itself: ${Object.entries(entry).filter(([, v]) => v !== null && v !== "" && typeof v !== "object")
      .map(([k, v]) => `${k} ${v}`).join(" · ")}` }));
  }
  for (const sensor of inv.sensors || []) {
    facts.push(el("li", { text: `${sensor.title}: last used ${sensor.last_start ? new Date(sensor.last_start).toLocaleString() : "unknown"}`
      + (sensor.in_use ? " (in use now)" : "") }));
  }
  if (inv.running && inv.running.process_count) facts.push(el("li", { text: `Running at the last scan: ${inv.running.process_count} processes, `
    + `${inv.running.memory_mb} MB, ${inv.running.connection_count} connections` }));
  return el("ul", { class: "facts" }, facts);
}

function programsView(programs) {
  return programs.map((p) => el("div", { class: "row" }, el("div", { class: "grow" },
    el("div", { class: "mono", text: p.exe }),
    el("div", { class: "sub", text: [`${plural(p.runs, "run")}`, p.parents.length ? `started by ${p.parents.join(", ")}` : null,
      p.tasks.length ? `scheduled task ${p.tasks.join(", ")}` : null, p.services.length ? `services ${p.services.join(", ")}` : null,
      p.package ? `package ${p.package}` : null].filter(Boolean).join(" · ") }),
    p.commands.length ? el("pre", { class: "plan", text: p.commands.join("\n") }) : null)));
}

function payloadView(item) {
  const summary = item.summary || {};
  const identifying = Object.entries(summary.identifying || {});
  const key = `payload|${item.at}|${item.url}`;
  return el("div", { class: "row" }, el("div", { class: "grow" },
    el("div", { class: "mono", text: `${item.method || ""} ${item.url || item.host}` }),
    el("div", { class: "sub", text: `${item.program} · ${new Date(item.at * 1000).toLocaleString()} · body ${bytes(item.body_size || 0)}`
      + (summary.records ? ` · ${plural(summary.records, "record")}` : "") }),
    summary.event_names && summary.event_names.length ? el("div", {}, el("strong", { text: "Events in it: " }),
      summary.event_names.map(([name, count]) => el("span", { class: "chip tag", text: count > 1 ? `${name} ×${count}` : name }))) : null,
    identifying.length ? el("div", {}, el("strong", { text: "Fields that identify you or this PC" }),
      kv(identifying.map(([field, value]) => [field, secret(value)]))) : null,
    item.request_headers ? fold(`${key}|h`, "Request headers", el("pre", { class: "plan", text: item.request_headers })) : null,
    item.body ? fold(`${key}|b`, "The body as recorded (first 4,000 characters)", el("pre", { class: "plan", text: item.body })) : null));
}

// --- what the app keeps on disk to send ----------------------------------------------------------

const ondiskState = { byActor: new Map() };

async function loadOndisk(actor) {
  const response = await fetch(`/api/app-ondisk?actor=${encodeURIComponent(actor.id)}`);
  const body = await response.json();
  ondiskState.byActor.set(actor.id, response.ok ? body : { error: body.detail || "Could not read the app's folders." });
  renderLive();
}

// A value that identifies you or this PC: hidden until clicked.
function secret(value) {
  if (value === null || value === undefined || value === "") return el("span", { class: "sub", text: "none" });
  const node = el("span", { class: "redacted", title: "Click to show", text: "•••••• show" });
  node.addEventListener("click", (event) => { event.stopPropagation(); node.textContent = String(value); node.classList.remove("redacted"); });
  return node;
}

function kv(rows) {
  return el("table", { class: "inner kv" }, el("tbody", {}, rows.filter(Boolean).map(([key, value]) =>
    el("tr", {}, el("td", { class: "sub", text: key }), el("td", {}, value instanceof Node ? value : String(value))))));
}

function when(value) {
  if (!value) return "unknown";
  const date = typeof value === "number" ? new Date(value > 1e12 ? value : value * 1000) : new Date(value);
  return isNaN(date) ? String(value) : date.toLocaleString();
}

function queuedView(item, key) {
  const parts = item.items.map((part) => {
    const facts = [`${part.type}`, part.status ? `status ${part.status}` : null, part.error ? part.error : null,
      part.message ? `"${part.message}"` : null, part.release ? `version ${part.release}` : null,
      part.breadcrumbs ? `${part.breadcrumbs} activity entries` : null, part.size ? bytes(part.size) : null].filter(Boolean);
    return el("div", {}, el("div", { text: facts.join(" · ") }),
      part.device_id ? el("div", { class: "sub" }, "device ID ", secret(part.device_id)) : null,
      part.user ? el("div", { class: "sub" }, "user ", secret(JSON.stringify(part.user))) : null,
      part.raw ? fold(`${key}|${item.file}|${part.type}`, "The whole report as stored", el("pre", { class: "plan", text: part.raw })) : null);
  });
  return el("div", { class: "row" }, el("div", { class: "grow" },
    el("div", { class: "sub", text: `${item.file} · written ${when(item.modified)}${item.sent_at ? ` · prepared ${when(item.sent_at)}` : ""}` }), parts));
}

function sentryView(source, key) {
  const blocks = [];
  if (source.user) {
    blocks.push(fold(`${key}|user`, `Who you are to it (${Object.keys(source.user).length} fields)`,
      el("div", { class: "sub", text: "Attached to every error report this app sends." }),
      kv(Object.entries(source.user).map(([field, value]) => [field, secret(typeof value === "object" ? JSON.stringify(value) : value)]))));
  }
  if (source.device) {
    blocks.push(fold(`${key}|device`, `How it describes your PC (${Object.keys(source.device).length} sections)`,
      Object.entries(source.device).map(([section, values]) => el("div", {}, el("div", { class: "name", text: section }),
        kv(Object.entries(values).map(([field, value]) => [field, /id$|uuid|serial|machine/i.test(field) ? secret(value) : value]))))));
  }
  if (source.breadcrumbs && source.breadcrumbs.length) {
    blocks.push(fold(`${key}|crumbs`, `Its log of your recent activity (${source.breadcrumbs_total} entries; newest ${source.breadcrumbs.length} shown)`,
      el("div", { class: "sub", text: "Sent along with an error report so the developer can see what led up to it." }),
      smallTable(["When", "Kind", "What"], source.breadcrumbs.map((crumb) => el("tr", {},
        el("td", { text: when(crumb.time) }), el("td", { text: crumb.category }), el("td", { class: "mono", text: crumb.text }))))));
  }
  if (source.session) {
    blocks.push(fold(`${key}|session`, "Current session", kv([["device ID", secret(source.session.device_id)],
      ["status", source.session.status || ""], ["started", when(source.session.started)], ["errors", source.session.errors ?? ""],
      source.session.user_agent ? ["browser identity", source.session.user_agent] : null])));
  }
  if (source.tags && Object.keys(source.tags).length) {
    blocks.push(fold(`${key}|tags`, "Labels on every report", kv(Object.entries(source.tags).map(([k, v]) => [k, String(v)]))));
  }
  blocks.push(fold(`${key}|queue`, `Reports waiting to be sent (${source.queued_total})`, source.queued && source.queued.length
    ? source.queued.map((item) => queuedView(item, key))
    : el("div", { class: "sub", text: "None waiting." }),
    source.queued_total > (source.queued || []).length ? el("div", { class: "sub", text: `Showing the newest ${source.queued.length}.` }) : null));
  return blocks;
}

function crashpadView(source, key) {
  const settings = source.settings;
  return [kv([
    ["crash reports sent automatically", settings ? (settings.uploads_enabled ? "yes" : "no") : "unknown"],
    settings ? ["this install's crash-report ID", secret(settings.client_id)] : null,
    settings && settings.last_upload_attempt ? ["last upload attempt", when(settings.last_upload_attempt)] : null,
    ["crash dumps stored", source.dumps_total]]),
    source.dumps.length ? fold(`${key}|dumps`, `Crash dumps (${source.dumps_total})`, el("div", { class: "sub",
      text: "A crash dump is a copy of part of the app's memory at the moment it crashed; it can contain whatever the app was working on." }),
      smallTable(["File", "State", "Size", "Written"], source.dumps.map((d) => el("tr", {},
        el("td", { class: "mono", text: d.file }), el("td", { text: d.state }), el("td", { class: "num", text: bytes(d.size) }),
        el("td", { text: when(d.modified) }))))) : null];
}

// Bugsnag, Unreal crash reports, Unity logs, Local Storage IDs: facts (identifying ones hidden) and items.
function factsView(source, key) {
  return [source.note ? el("div", { class: "sub", text: source.note }) : null,
    source.facts.length ? kv(source.facts.map(([label, value, identifying]) => [label, identifying ? secret(value) : String(value)])) : null,
    source.items && source.items.length ? fold(`${key}|items`, `Stored items (${source.total})`, smallTable(["Item", "Written", "Size", "Detail"],
      source.items.map((item) => el("tr", {}, el("td", { class: "mono", text: item.name }), el("td", { text: when(item.modified) }),
        el("td", { class: "num", text: item.size ? bytes(item.size) : "" }), el("td", { class: "sub", text: item.detail || "" }))))) : null];
}

function genericView(source, key) {
  return [el("div", { text: `${plural(source.files_total, "file")}, ${bytes(source.bytes_total)}` }),
    fold(`${key}|files`, "Files", smallTable(["File", "Size", "Written"], source.files.map((f) => el("tr", {},
      el("td", { class: "mono", text: f.file }), el("td", { class: "num", text: bytes(f.size) }), el("td", { text: when(f.modified) })))))];
}

function ondiskSection(actor) {
  const data = ondiskState.byActor.get(actor.id);
  if (data === undefined) {
    ondiskState.byActor.set(actor.id, null);
    loadOndisk(actor);
  }
  const card = el("div", { class: "card" }, el("h2", { text: "What it keeps on disk to send" }));
  if (!data) { card.append(el("div", { class: "sub", text: "Reading the app's folders…" })); return card; }
  if (data.error) { card.append(el("div", { class: "none", text: data.error })); return card; }
  if (data.system) { card.append(el("div", { class: "sub", text: "Part of Windows; see the Windows telemetry page." })); return card; }
  if (!data.sources.length) {
    card.append(el("div", { class: "sub", text: data.roots.length
      ? "No crash reporter or report queue was found in the app's folders."
      : "No data folder of this app was found." }));
    return card;
  }
  card.append(el("div", { class: "sub", text: "Read from the app's own folders on this PC. Nothing here was decrypted or sent anywhere. "
    + "Values that identify you are hidden until you click them." }));
  for (const source of data.sources) {
    const key = `${actor.id}|${source.path}`;
    const body = source.error ? [el("div", { class: "none", text: source.error })]
      : source.kind === "sentry" || source.kind === "sentry-native" ? sentryView(source, key)
        : source.kind === "crashpad" ? crashpadView(source, key) : source.facts ? factsView(source, key) : genericView(source, key);
    card.append(el("div", { class: "row" }, el("div", { class: "grow" },
      el("div", { class: "name", text: source.title }), el("div", { class: "sub mono", text: source.path }), body)));
  }
  return card;
}

// --- how to stop its reporting: one method per destination ---------------------------------------

const stopPlans = { byActor: new Map() };
const METHOD_LABEL = {
  switch: ["private", "Use a setting"], stop_program: ["partly", "Stop the program that reports"],
  address_block: ["partly", "Block it for this program"], name_block: ["partly", "Block the name on this PC"],
  nothing_safe: ["na", "Nothing safe"],
};

async function loadStopPlan(actorId) {
  const response = await fetch(`/api/stop-plan?actor=${encodeURIComponent(actorId)}`);
  stopPlans.byActor.set(actorId, response.ok ? await response.json() : { error: "Could not work out how to stop it." });
  renderLive();
  if (typeof renderCases === "function" && casesState.data) renderCases();
}

// For each reporting destination: the least damaging method, why, and exactly what it would change.
function stopPlanView(actorId, key) {
  const data = stopPlans.byActor.get(actorId);
  if (data === undefined) {
    stopPlans.byActor.set(actorId, null);
    loadStopPlan(actorId);
  }
  let body;
  if (!data) body = el("div", { class: "sub", text: "Working out the safest way…" });
  else if (data.error) body = el("div", { class: "none", text: data.error });
  else if (!data.plans.length) body = el("div", { class: "sub", text: "Nothing it sends goes to a reporting or advertising service." });
  else {
    body = data.plans.map((plan) => {
      const [kind, label] = METHOD_LABEL[plan.method] || ["na", plan.method];
      const action = plan.method === "switch" ? el("div", { class: "sub", text: `Use the setting "${plan.title}" above.` })
        : plan.method === "stop_program" ? el("div", { class: "sub", text: `Use "Network block" for ${plan.sender} further down; it only reports.` })
          : (plan.method === "address_block" || plan.method === "name_block")
            ? el("div", {}, el("pre", { class: "plan", text: plan.preview }),
              el("button", { type: "button", class: "small", disabled: "", title: "Real blocking is switched off in this version",
                text: data.real_enabled ? "Apply" : "Apply (switched off in this version)" }))
            : null;
      return el("div", { class: "row" }, el("div", { class: "grow" },
        el("div", { class: "mono", text: `${plan.sender} → ${plan.destination}` }),
        el("div", { class: "sub", text: `${plan.company || "Unknown company"} · sent ${bytes(plan.sent)}` }),
        el("ul", { class: "facts" }, plan.reasons.map((reason) => el("li", { text: reason }))), action),
      el("span", { class: `state ${kind}`, text: label }));
    });
  }
  return fold(key, "How to stop each destination without breaking the app", body);
}

// --- inspect this app: run it with its own network log ---------------------------------------------

const inspectState = { byActor: new Map(), reports: new Map(), choice: new Map(), message: new Map(), busy: false };

async function loadInspect(actor) {
  const response = await fetch(`/api/inspect?actor=${encodeURIComponent(actor.id)}`);
  const body = await response.json();
  inspectState.byActor.set(actor.id, response.ok ? body : { error: body.detail || "Could not read this app's programs." });
  const live_ = (body.sessions || []).find((s) => s.status === "running");
  if (live_) inspectState.reports.set(live_.id, await (await fetch(`/api/inspect/${live_.id}`)).json());
  const reading = (body.sessions || []).find((s) => s.status === "reading");
  renderLive();
  if ((live_ || reading) && live.open === actor.id) setTimeout(() => { if (live.open === actor.id) loadInspect(actor); }, live_ ? 5000 : 2000);
  if (!live_ && !reading) {                       // a report that finished reading while it was open: refresh it
    for (const session of body.sessions || []) {
      const shown = inspectState.reports.get(session.id);
      if (shown && shown.status === "reading") inspectState.reports.set(session.id, await (await fetch(`/api/inspect/${session.id}`)).json());
    }
    renderLive();
  }
}

async function openInspection(id) {
  if (inspectState.reports.has(id)) { inspectState.reports.delete(id); renderLive(); return; }
  inspectState.reports.set(id, { loading: true });
  renderLive();
  inspectState.reports.set(id, await (await fetch(`/api/inspect/${id}`)).json());
  renderLive();
}

function button(text, handler, kind = "small") {
  const node = el("button", { type: "button", class: kind, text });
  node.addEventListener("click", async (event) => {
    event.stopPropagation();
    if (inspectState.busy) return;
    inspectState.busy = true;
    node.disabled = true;
    try { await handler(); } finally { inspectState.busy = false; }
  });
  return node;
}

function requestView(item, key) {
  const summary = item.summary || {};
  const facts = [item.status ? `answer ${item.status}` : "no answer recorded", item.body_size ? `sent ${bytes(item.body_size)}` : "no body",
    summary.records ? `${plural(summary.records, "record")}` : null, summary.format && summary.format !== "json" ? summary.format : null,
    item.body_note || null].filter(Boolean);
  const identifying = Object.entries(summary.identifying || {});
  return fold(`${key}|${item.time}|${item.url}`, el("span", { class: "mono", text: `${item.method} ${item.url}` }),
    el("div", { class: "sub", text: `${new Date(Number(item.time)).toLocaleTimeString()} · ${facts.join(" · ")}` }),
    summary.event_names && summary.event_names.length ? el("div", {}, el("strong", { text: "Events in it: " }),
      summary.event_names.map(([name, count]) => el("span", { class: "chip tag", text: count > 1 ? `${name} ×${count}` : name }))) : null,
    identifying.length ? el("div", {}, el("strong", { text: "Fields that identify you or this PC" }),
      kv(identifying.map(([field, value]) => [field, secret(value)]))) : null,
    summary.fields && summary.fields.length ? fold(`${key}|${item.time}|fields`, `All ${summary.fields.length} fields`,
      el("div", { class: "mono sub", text: summary.fields.join(", ") })) : null,
    item.request_headers ? fold(`${key}|${item.time}|headers`, "Request headers", el("pre", { class: "plan", text: item.request_headers })) : null,
    item.body ? fold(`${key}|${item.time}|body`, `The body as sent${item.body_truncated ? " (first 60,000 characters)" : ""}`,
      el("pre", { class: "plan", text: item.body })) : null);
}

function inspectionReport(actor, data) {
  if (data.loading) return el("div", { class: "sub", text: "Loading…" });
  if (data.status === "reading") return el("div", { class: "sub", text: "Reading the log… This can take a minute for a long session." });
  if (!data.report) return el("div", { class: "none", text: "No report was saved." });
  const report = data.report;
  if (report.error) return el("div", { class: "none", text: report.error });
  if (!report.requests.length) return el("div", { class: "sub", text: "The app wrote no requests to its log. Either it sent nothing while it ran, "
    + "or it does not support the network log (it may not be built on Chromium, or it may have restarted itself without the setting)." });
  const key = `${actor.id}|inspect|${data.id}`;
  const remove = button("Delete this inspection", async () => { await post(`/api/inspect/${data.id}/delete`); inspectState.reports.delete(data.id);
    await loadInspect(actor); });
  return el("div", {},
    el("div", { class: "sub", text: `${plural(report.requests.length, "request")} to ${plural(report.hosts.length, "destination")}. `
      + "Cookies, sign-in tokens and passwords were replaced; the raw log was deleted." }),
    smallTable(["Destination", "Requests", "Sent", "Events", "Identifying fields"], report.hosts.map((h) => el("tr", {},
      el("td", { class: "mono", text: h.host }), el("td", { class: "num", text: h.requests }), el("td", { class: "num", text: bytes(h.sent) }),
      el("td", {}, h.event_names.slice(0, 6).map(([name, count]) => el("span", { class: "chip tag", text: `${name} ×${count}` }))),
      el("td", { class: "sub mono", text: h.identifying.join(", ") })))),
    fold(`${key}|all`, `Every request (${report.requests.length})`, report.requests.map((item) => requestView(item, key))),
    el("div", { class: "actions" }, remove));
}

function inspectSection(actor) {
  const data = inspectState.byActor.get(actor.id);
  if (data === undefined) {
    inspectState.byActor.set(actor.id, null);
    loadInspect(actor);
  }
  const card = el("div", { class: "card" }, el("h2", { text: "Inspect this app" }));
  if (!data) { card.append(el("div", { class: "sub", text: "Looking at its programs…" })); return card; }
  if (data.error) { card.append(el("div", { class: "none", text: data.error })); return card; }
  if (!data.programs.length) {
    card.append(el("div", { class: "sub", text: "Part of Windows or no program file of its own, so it cannot be inspected this way." }));
    return card;
  }
  card.append(el("div", { class: "sub", text: "Runs the app with its own network log switched on, so you can see every request it makes while you use it, "
    + "with what is inside. Works for apps built on Chromium or Electron, and for Firefox (addresses and headers). Nothing is intercepted: the app writes the log itself, for this run only. "
    + "The log holds cookies and sign-in tokens, so it is deleted once it has been read; what is kept has secrets replaced." }));
  const message = inspectState.message.get(actor.id);
  if (message) card.append(el("div", { class: "notice", text: message }));
  const current = data.sessions.find((s) => s.status === "running");
  if (current) {
    const status = inspectState.reports.get(current.id) || current;
    card.append(kv([["program", status.exe], ["started", new Date(status.started * 1000).toLocaleString()],
      ["app open", status.app_running ? "yes" : "no, it was closed"],
      ["requests logged so far", status.requests_so_far ?? "…"], ["log size", bytes(status.log_bytes || 0)]]));
    if (status.no_log) card.append(el("div", { class: "warn", text: "No log has appeared after 30 seconds. This program probably does not support it, "
      + "or it handed over to another program and closed." }));
    if (status.large) card.append(el("div", { class: "warn", text: "The log is over 2 GB: it also records everything the app downloads. "
      + "End the inspection soon; at 4 GB it is ended automatically." }));
    card.append(el("div", { class: "actions" },
      button(status.app_running ? "End: close the app and show what it sent" : "Show what it sent", async () => {
        await post(`/api/inspect/${current.id}/finish`, { close_app: true });
        inspectState.message.delete(actor.id);
        await loadInspect(actor);
        await openInspection(current.id);
      }, "primary small")));
    return card;
  }
  const choice = inspectState.choice.get(actor.id) || data.programs[0].exe;
  const program = data.programs.find((p) => p.exe === choice) || data.programs[0];
  const select = el("select", {}, data.programs.map((p) => {
    const option = el("option", { value: p.exe, text: `${p.name}${p.main ? "" : " (helper)"}${p.engine ? "" : " (no network log)"}` });
    if (p.exe === program.exe) option.selected = true;
    return option;
  }));
  select.addEventListener("click", (event) => event.stopPropagation());
  select.addEventListener("change", () => { inspectState.choice.set(actor.id, select.value); renderLive(); });
  const controls = [data.programs.length > 1 ? select : el("span", { class: "mono", text: program.name })];
  if (program.engine === "firefox") card.append(el("div", { class: "sub", text: "Firefox writes its own HTTP log: every address it contacts "
    + "and the headers it sends. Its log does not hold request bodies." }));
  else if (!program.engine) card.append(el("div", { class: "warn", text: "This program is not built on Chromium or Firefox, so it probably cannot write "
    + "a network log (most games and native apps cannot). You can still try." }));
  if (program.running.length) {
    card.append(el("div", { class: "warn", text: `${program.name} is running (${plural(program.running.length, "process", "processes")}). `
      + "It has to be closed first, so it can be started again with its log on. Close it yourself, or let this tool close it "
      + "(anything unsaved in it may be lost)." }));
    controls.push(button("Close it for me", async () => {
      const response = await post("/api/inspect/close-app", { actor: actor.id, exe: program.exe });
      const body = await response.json();
      inspectState.message.set(actor.id, response.ok ? (body.still_running ? "Some of its processes did not close." : `${program.name} was closed.`) : body.detail);
      await loadInspect(actor);
    }), button("I closed it", async () => { await loadInspect(actor); }));
  } else {
    controls.push(button("Start the app with its network log", async () => {
      const response = await post("/api/inspect/start", { actor: actor.id, exe: program.exe });
      const body = await response.json();
      inspectState.message.set(actor.id, response.ok ? `${program.name} started. Use it as you normally would, then end the inspection here.` : body.detail);
      await loadInspect(actor);
    }, "primary small"));
  }
  card.append(el("div", { class: "actions" }, controls));
  const past = data.sessions.filter((s) => s.status !== "running");
  if (past.some((s) => s.status === "reading")) card.append(el("div", { class: "notice", text: "Reading the app's log and then deleting it…" }));
  if (past.length) {
    card.append(el("h3", { text: "Earlier inspections" }), ...past.map((s) => {
      const open = inspectState.reports.get(s.id);
      return el("div", { class: "row" }, el("div", { class: "grow" },
        el("div", { text: `${new Date(s.started * 1000).toLocaleString()} · ${Math.max(1, Math.round(((s.ended || s.started) - s.started) / 60))} min · `
          + (s.status === "reading" ? "reading…" : `${plural(s.requests || 0, "request")} to ${plural(s.hosts || 0, "destination")}`) }),
        s.note ? el("div", { class: "sub", text: s.note }) : null,
        open ? inspectionReport(actor, open) : null),
      button(open ? "Hide" : "Show", () => openInspection(s.id)));
    }));
  }
  return card;
}

// What the app sent, when request content recording is on. Only possible for programs that use
// Windows' own web library; the others encrypt inside the app (see "Inspect this app").
function contentFold(actor, data, key, encrypted) {
  const recording = inside.helper && inside.helper.content;
  const watching = inside.helper && inside.helper.running;
  let body;
  if (data.payloads.length) {
    body = [el("div", { class: "sub", text: `The newest ${data.payloads.length} recorded requests. Cookies, sign-in tokens and passwords were replaced before saving.` }),
      ...data.payloads.map(payloadView)];
  } else if (encrypted) {
    body = el("div", { class: "sub", text: "This app encrypts its traffic itself, so its requests cannot be recorded by the watcher. "
      + "\"Inspect this app\" can show them by running the app with its own network log switched on." });
  } else if (!watching) {
    body = el("div", { class: "sub", text: "Start watching first: the watcher records request content." });
  } else if (recording) {
    body = el("div", { class: "sub", text: "Recording is on. Requests this app makes from now on will appear here." });
  } else {
    const button = el("button", { type: "button", class: "small", text: "Record what it sends" });
    button.addEventListener("click", async (event) => { event.stopPropagation(); button.disabled = true; await setContent(true, false);
      details.byActor.delete(actor.id); renderLive(); });
    body = [el("div", { class: "sub", text: "This app uses Windows' own web library, so the watcher can record the headers and the first "
      + "4,000 characters of each request it sends. Cookies, sign-in tokens and passwords are replaced before saving; recordings "
      + "stay on this PC for seven days. This turns recording on for every program that uses that library." }),
    el("div", { class: "actions" }, button)];
  }
  return fold(key, `What it sent (${data.payloads.length} recorded)`, body);
}

function recordsSection(actor) {
  const data = details.byActor.get(actor.id);
  if (data === undefined) {
    details.byActor.set(actor.id, null);
    loadDetails(actor);
  }
  const card = el("div", { class: "card" }, el("h2", { text: "Everything recorded (last 7 days)" }));
  if (!data) { card.append(el("div", { class: "sub", text: "Gathering…" })); return card; }
  if (data.error || !data.available) { card.append(el("div", { class: "none", text: data.error || "Nothing recorded yet." })); return card; }
  const k = (name) => `${actor.id}|${name}`;
  const encrypted = !data.requests.length;
  card.append(contentFold(actor, data, k("content"), encrypted),
    fold(k("timeline"), `When it sends (${data.timeline.length} hours with traffic)`, timelineView(data.timeline)),
    fold(k("destinations"), `All ${data.destinations.length} destinations`, smallTable(
      ["Destination", "Company", "Kind", "Sent", "Received", "Contacts", "First", "Last", "Programs"],
      data.destinations.map((d) => el("tr", {},
        el("td", {}, el("div", { class: "mono", text: d.name || d.addresses[0] }),
          el("div", { class: "sub", text: [d.addresses.join(", "), d.ports.join(", "), d.country].filter(Boolean).join(" · ") })),
        el("td", { text: d.company || "Unknown" }), el("td", { text: d.purpose || d.category || "Not identified" }),
        el("td", { class: "num", text: bytes(d.sent) }), el("td", { class: "num", text: bytes(d.received) }),
        el("td", { class: "num", text: d.contacts }), el("td", { text: since(d.first) }), el("td", { text: since(d.last) }),
        el("td", { class: "sub", text: d.programs.join(", ") }))))),
    fold(k("requests"), `Request addresses (${data.requests.length})`,
      encrypted ? el("div", { class: "sub", text: "None recorded. This app does its own encryption, so only the destination, size and time "
        + "of its traffic are visible. \"Inspect this app\" below can show its requests." })
        : smallTable(["Request", "Times", "Last", "Program"], data.requests.map((r) => el("tr", {},
          el("td", { class: "mono", text: `${r.method} ${r.url}` }), el("td", { class: "num", text: r.count }),
          el("td", { text: since(r.last) }), el("td", { class: "sub", text: r.programs.join(", ") }))))),
    fold(k("lookups"), `Names it looked up (${data.lookups.length})`, data.lookups.length
      ? smallTable(["Name", "Times", "Last", "Program"], data.lookups.map((l) => el("tr", {},
        el("td", { class: "mono", text: l.name }), el("td", { class: "num", text: l.count }), el("td", { text: since(l.last) }),
        el("td", { class: "sub", text: l.programs.join(", ") }))))
      : el("div", { class: "sub", text: "None through Windows' resolver. Apps built on Chromium look names up themselves." })),
    fold(k("programs"), `Programs and how they started (${data.programs.length})`, programsView(data.programs)),
    fold(k("history"), `60-day history from Windows (${data.history.length} days)`, historyView(data.history)),
    fold(k("inventory"), "Installed app: startup, sensors, last opened", inventoryView(data.inventory)));
  return card;
}
