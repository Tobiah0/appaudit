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
  return el("div", { class: "row" }, el("div", { class: "grow" },
    el("div", { class: "mono", text: `${item.method || ""} ${item.url || item.host}` }),
    el("div", { class: "sub", text: `${item.program} · ${new Date(item.at * 1000).toLocaleString()} · body ${bytes(item.body_size || 0)}` }),
    item.request_headers ? el("pre", { class: "plan", text: item.request_headers }) : null,
    item.body ? el("pre", { class: "plan", text: item.body }) : null));
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
        : source.kind === "crashpad" ? crashpadView(source, key) : genericView(source, key);
    card.append(el("div", { class: "row" }, el("div", { class: "grow" },
      el("div", { class: "name", text: source.title }), el("div", { class: "sub mono", text: source.path }), body)));
  }
  return card;
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
  card.append(
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
