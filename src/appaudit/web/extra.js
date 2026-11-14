"use strict";

// Proof, Windows telemetry, and "Who is listening".

const VERDICTS = {
  off_but_active: ["exposed", "Off, but still active"], on_and_active: ["exposed", "On and in use"],
  on_but_quiet: ["na", "On, nothing seen"], off_and_quiet: ["private", "Off and quiet"],
  waiting: ["na", "Still observing"], stopped: ["private", "Stopped"], reduced: ["private", "Reduced"],
  unchanged: ["exposed", "Did not stop"], nothing_seen: ["na", "Nothing seen either side"],
};

function verdictBadge(code) {
  const [kind, label] = VERDICTS[code] || ["na", code];
  return el("span", { class: `state ${kind}`, text: label });
}

function footprintText(mark) {
  const parts = [];
  const runs = Object.entries(mark.run_names || {}).map(([name, count]) => `${name} ran ${count} time${count === 1 ? "" : "s"}`);
  if (runs.length) parts.push(runs.join(", "));
  if (mark.sent || mark.received) parts.push(`${bytes(mark.sent)} sent, ${bytes(mark.received)} received`);
  if (mark.destinations && mark.destinations.length) parts.push(`to ${mark.destinations.slice(0, 3).map((d) => d[0]).join(", ")}`);
  if (mark.senders && mark.senders.length) parts.push(`by ${mark.senders.slice(0, 3).map((s) => s[0]).join(", ")}`);
  return parts.length ? parts.join(" · ") : "Nothing seen";
}

async function loadProof() {
  const page = $("#page-proof");
  const data = await (await fetch("/api/proof?hours=24")).json();
  const blocks = [el("p", { class: "lead", text: "For each switch that names what it should silence, this page compares the "
    + "setting with what the watcher actually saw in the last 24 hours. After you switch something off here, it also "
    + "compares the day before with the time since." })];
  if (!data.watching) blocks.push(el("p", { class: "empty", text: "Start watching to collect evidence." }));
  const counts = {};
  for (const item of data.items) counts[item.verdict] = (counts[item.verdict] || 0) + 1;
  blocks.push(el("section", { class: "tiles" }, [
    ["hot", counts.off_but_active || 0, "switched off but still active"],
    ["", counts.on_and_active || 0, "on and in use"],
    ["", counts.off_and_quiet || 0, "off and confirmed quiet"],
    ["", data.items.filter((item) => item.change).length, "changed through this tool"],
  ].map(([kind, value, label]) => el("div", { class: `tile ${kind}` }, el("strong", { text: value }), el("span", { text: label })))));
  if (data.counters && data.counters.last_upload) {
    blocks.push(el("div", { class: "card" }, el("h2", { text: "Windows' own record" }),
      el("div", { text: `Windows says its last successful diagnostic-data upload was ${new Date(data.counters.last_upload * 1000).toLocaleString()}, `
        + `after ${Number(data.counters.uploads || 0).toLocaleString()} uploads in total.` })));
  }
  const rows = data.items.map((item) => {
    const change = item.change ? el("div", { class: "card", style: "margin-top:8px" },
      el("div", {}, verdictBadge(item.change.verdict), ` since you switched it off on ${new Date(item.change.applied * 1000).toLocaleString()}`),
      el("div", { class: "sub", text: item.change.text }),
      el("div", { class: "sub", text: `Day before: ${footprintText(item.change.before)}` }),
      el("div", { class: "sub", text: `Since: ${footprintText(item.change.after)}` })) : null;
    return el("div", { class: "row" },
      el("div", { class: "grow" }, el("div", { class: "name", text: item.title }),
        el("div", { class: "sub", text: item.group }), el("div", { text: footprintText(item.window) }),
        el("div", { class: "sub", text: item.text }), change),
      el("div", { style: "text-align:right; display:flex; flex-direction:column; gap:6px; align-items:flex-end" },
        verdictBadge(item.verdict), el("span", { class: "sub", text: `setting: ${item.state === "private" ? "off" : "on"}` })));
  });
  blocks.push(el("div", { class: "card" }, rows.length ? rows : el("p", { class: "empty", text: "No evidence yet." })));
  page.replaceChildren(...blocks);
}
pageLoaders.proof = loadProof;

// --- Windows telemetry ------------------------------------------------------------------------

async function loadWindowsTelemetry() {
  const page = $("#page-windows");
  const data = await (await fetch("/api/windows-telemetry")).json();
  const blocks = [el("p", { class: "lead", text: "What Windows itself is set up to collect and send, read from Windows' own files and counters." })];
  if (data.counters) {
    const last = data.counters.last_upload ? new Date(data.counters.last_upload * 1000).toLocaleString() : "never recorded";
    blocks.push(el("section", { class: "tiles" },
      el("div", { class: "tile" }, el("strong", { text: Number(data.counters.uploads || 0).toLocaleString() }), el("span", { text: "diagnostic uploads since Windows was installed" })),
      el("div", { class: "tile" }, el("strong", { text: last }), el("span", { text: "last successful upload" })),
      el("div", { class: "tile" }, el("strong", { text: Number(data.counters.triggers || 0).toLocaleString() }), el("span", { text: "upload triggers counted by Windows" }))));
  }
  blocks.push(el("div", { class: "card" }, el("h2", { text: "The services that collect" }), data.services.map((service) => {
    const [kind, label] = STATE_LABEL[service.state] || ["na", service.state];
    return el("div", { class: "row" }, el("div", { class: "grow" }, el("div", { class: "name", text: service.title }),
      el("div", { text: service.explain })), el("span", { class: `state ${kind}`, text: label }));
  })));
  const details = data.details;
  if (!details.available) {
    blocks.push(el("p", { class: "empty", text: details.reason }));
  } else {
    const rules = details.rules;
    blocks.push(el("div", { class: "card" }, el("h2", { text: "Collection rules downloaded from Microsoft" }),
      el("div", { text: `Windows keeps ${rules.files.length} rule files that Microsoft can change at any time. `
        + `They define ${rules.providers.toLocaleString()} event sources.`
        + (rules.refreshed ? ` Last refreshed ${new Date(rules.refreshed * 1000).toLocaleDateString()}.` : "") }),
      rules.endpoints.length ? el("div", { class: "sub", text: `Upload addresses named in the rules: ${rules.endpoints.slice(0, 14).join(", ")}` }) : null,
      el("details", {}, el("summary", { class: "sub", text: "Rule files" }),
        el("pre", { class: "plan", text: rules.files.map((f) => `${new Date(f.modified * 1000).toLocaleDateString().padEnd(12)} ${String(f.bytes).padStart(9)}  ${f.name}`).join("\n") }))));
    const facts = [];
    if (details.autologger) facts.push(`The boot-time telemetry trace is ${details.autologger.start ? "set to start" : "not set to start"} with ${details.autologger.providers} event sources.`);
    if (details.event_store) facts.push(`Windows' diagnosis folder holds ${bytes(details.event_store.bytes)} in ${details.event_store.files} files, last written ${details.event_store.newest ? new Date(details.event_store.newest * 1000).toLocaleString() : "unknown"}.`);
    if (details.usage_insights) facts.push(`"Usage and Quality Insights" logs: ${bytes(details.usage_insights.bytes)} in ${details.usage_insights.files} files, last written ${details.usage_insights.newest ? new Date(details.usage_insights.newest * 1000).toLocaleString() : "unknown"}.`);
    const transcript = details.transcript;
    facts.push(transcript.present
      ? `Windows is keeping a readable copy of what it sends (${transcript.total.toLocaleString()} events).`
      : "Windows is not keeping a readable copy of what it sends. Turn on \"View diagnostic data\" in Settings > Privacy & security > Diagnostics & feedback to make it keep one; this page will then show the events.");
    blocks.push(el("div", { class: "card" }, el("h2", { text: "On this PC right now" }), el("ul", { class: "facts" }, facts.map((text) => el("li", { text })))));
    if (transcript.present && transcript.by_name.length) {
      blocks.push(el("div", { class: "card" }, el("h2", { text: "Events Windows recorded for upload" }),
        el("pre", { class: "plan", text: transcript.by_name.map((e) => `${String(e.count).padStart(7)}  ${e.name}`).join("\n") })));
    }
  }
  page.replaceChildren(...blocks);
}
pageLoaders.windows = loadWindowsTelemetry;

// --- who is listening --------------------------------------------------------------------------

const SESSION_KINDS = { telemetry: "Usage reporting", vendor: "Other software", security: "Security", windows: "Windows diagnostics",
  update: "Updates", "this-tool": "This tool", unknown: "Not identified" };

async function loadListeners() {
  const page = $("#page-listeners");
  page.replaceChildren(el("p", { class: "empty", text: "Reading the trace sessions…" }));
  const data = await (await fetch("/api/listeners")).json();
  const blocks = [el("p", { class: "lead", text: "Windows lets programs subscribe to streams of system events. "
    + "These are the subscriptions running now, and what each one can see." })];
  if (!data.available) { page.replaceChildren(...blocks, el("p", { class: "empty", text: data.reason })); return; }
  const order = ["telemetry", "vendor", "unknown", "security", "update", "windows", "this-tool"];
  const sessions = data.sessions.slice().sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind) || b.sees.length - a.sees.length);
  const watchers = sessions.filter((s) => s.sees.length && s.kind !== "this-tool" && s.kind !== "windows").length;
  blocks.push(el("section", { class: "tiles" },
    el("div", { class: "tile" }, el("strong", { text: sessions.length }), el("span", { text: "trace sessions running" })),
    el("div", { class: "tile hot" }, el("strong", { text: watchers }), el("span", { text: "can see what your programs do, outside Windows' own diagnostics" })),
    el("div", { class: "tile" }, el("strong", { text: sessions.filter((s) => s.kind === "unknown").length }), el("span", { text: "not identified" }))));
  blocks.push(el("div", { class: "card" }, sessions.map((session) => el("div", { class: "row" },
    el("div", { class: "grow" }, el("div", { class: "name", text: session.name }),
      el("div", { class: "sub", text: `${session.owner} · ${session.provider_count} event source${session.provider_count === 1 ? "" : "s"}`
        + (session.output ? ` · writes to ${session.output}` : " · read live") }),
      el("div", { text: session.what }),
      session.sees.length ? el("div", { class: "sub warn", text: `Can see: ${session.sees.join("; ")}` }) : null,
      session.providers.length ? el("details", {}, el("summary", { class: "sub", text: "Event sources" }),
        el("pre", { class: "plan", text: session.providers.join("\n") + (session.unnamed_providers ? `\n(+${session.unnamed_providers} unnamed)` : "") })) : null),
    el("span", { class: `state ${session.kind === "telemetry" || session.kind === "vendor" ? "exposed" : "na"}`, text: SESSION_KINDS[session.kind] || session.kind })))));
  page.replaceChildren(...blocks);
}
pageLoaders.listeners = loadListeners;

// --- summary -------------------------------------------------------------------------------------

function finding(title, lines, kind) {
  return el("div", { class: "card" }, el("h2", { text: title }),
    lines.length ? el("ul", { class: "facts" }, lines) : el("div", { class: kind === "good" ? "sub" : "none", text: "Nothing in this window." }));
}

async function loadSummary() {
  const page = $("#page-summary");
  if (!page.dataset.hours) page.dataset.hours = "12";
  const hours = Number(page.dataset.hours);
  const data = await (await fetch(`/api/digest?hours=${hours}`)).json();
  const picker = el("div", { class: "tabs" }, [[1, "Last hour"], [12, "Last 12 hours"], [24, "Last 24 hours"], [168, "Last 7 days"]].map(([value, label]) => {
    const button = el("button", { type: "button", class: value === hours ? "active" : "", text: label });
    button.addEventListener("click", () => { page.dataset.hours = String(value); loadSummary(); });
    return button;
  }));
  const totals = data.totals || {};
  const blocks = [el("section", { class: "toolbar", style: "margin-top:16px" }, picker,
    el("span", { class: "muted", text: data.watching.running ? "" : "The watcher is not running, so this shows only what was recorded earlier." }))];
  blocks.push(el("section", { class: "tiles" }, [
    ["", totals.actors || 0, "apps and components used the network"],
    ["hot", bytes(totals.reporting_sent || 0), "sent to usage-reporting or ad services"],
    ["hot", data.contradictions.length, "settings that are off but still active"],
    ["", data.idle_but_active.length, "apps active that you rarely or never open"],
  ].map(([kind, value, label]) => el("div", { class: `tile ${kind}` }, el("strong", { text: value }), el("span", { text: label })))));

  blocks.push(finding("Switched off, but still active", data.contradictions.map((item) =>
    el("li", {}, el("strong", { text: item.title }), `: ${footprintText(item.seen)}`))));
  blocks.push(finding("Sent data to usage-reporting or advertising services", data.reporters.map((item) =>
    el("li", {}, el("strong", { text: item.name }), ` sent ${bytes(item.sent)} to ${item.to.join(", ")}`))));
  blocks.push(finding("Active, though you rarely or never open them", data.idle_but_active.map((item) =>
    el("li", {}, el("strong", { text: item.name }),
      ` ${item.never_recorded ? "has no record of you opening it" : `was last opened ${item.days_unused} days ago`}`
      + `${item.starts_itself ? ", starts by itself" : ""}, and sent ${bytes(item.sent)}`
      + (item.companies.length ? ` to ${item.companies.join(", ")}` : "")))));
  blocks.push(finding("Windows reporting programs that ran", data.reporting_runs.map((item) =>
    el("li", {}, el("strong", { text: item.process }), ` ran ${item.runs} time${item.runs === 1 ? "" : "s"}`
      + (item.task ? ` (task ${item.task})` : ""), item.what ? el("div", { class: "sub", text: item.what }) : null))));
  blocks.push(finding("Where the data went", data.companies.map((item) =>
    el("li", {}, el("strong", { text: item.company }), ` received ${bytes(item.sent)} from ${item.actors.join(", ")}`))));
  if (data.counters && data.counters.last_upload) {
    blocks.push(el("div", { class: "card" }, el("h2", { text: "Windows' own record" }),
      el("div", { text: `Last successful diagnostic-data upload: ${new Date(data.counters.last_upload * 1000).toLocaleString()} `
        + `(${Number(data.counters.uploads || 0).toLocaleString()} uploads in total).` })));
  }
  page.replaceChildren(...blocks);
}
pageLoaders.summary = loadSummary;
