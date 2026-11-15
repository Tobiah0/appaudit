# App Audit

See what your Windows PC does, switch it off, and check that it stopped.

Windows 11 has hundreds of privacy settings spread over many places, and every vendor adds its
own. Tools exist that flip those settings, and tools exist that show network traffic. This one
does both and then compares them: for each setting it shows whether the activity it is supposed
to stop is still happening.

Everything runs on the PC. The tool makes no network connections of its own apart from an optional
one-time download of public reference lists, and it appears in its own results.

## What you get

| Page | What it shows |
|---|---|
| Summary | The findings for a time window: settings that are off but still active, apps that sent data to reporting or ad services, apps active though you never open them |
| Activity | Every app and Windows component that used the network, where it sent data, and what each destination is for |
| Companies | Which companies received data, and from which of your apps |
| Background runs | Programs that started by themselves, what each one is, and which scheduled task started it |
| 60-day history | Windows' own record of per-app network use from before the watcher ran |
| Apps | The inventory: what starts by itself, what uses camera, mic and location, when you last opened it |
| Switches | 120 privacy switches for Windows, Edge, Office, other vendors and developer tools, with their current state, apply and undo |
| Proof | Each switch against the evidence: "off and quiet", "off but still active", and before/after once you change one here |
| Windows telemetry | Windows' own upload counters, its collection services, and the rule files it downloads from Microsoft |
| Who is listening | Every event-trace subscription running on the PC and what it can see |
| Data requests | Drafts a letter asking a company what it holds about you, quoting what this PC observed, and tracks when the answer is due. Nothing is sent by the tool |

Opening an app on the Activity page also shows:

- **Turn off its reporting**: the switches that concern this app (settings, policies, config files, steps), each with the exact change shown before it is made.
- **What it keeps on disk to send**: read from the app's own folders. Crash reporters' state (Sentry: the user record, device description and recent-activity log attached to error reports, plus reports waiting to be sent), Crashpad crash dumps and whether they are uploaded. Identifying values are hidden until clicked.
- **Inspect this app**: for apps built on Chromium or Electron, starts the app with its own network log switched on, then shows every request it made with its content: event names, fields that identify you, headers and body. The raw log is deleted once read.
- **Everything recorded**: all destinations, an hourly timeline, request addresses, DNS lookups, programs and how they started, the 60-day Windows history and the inventory record, in collapsed sections.
- **Built into this app**: reporting components (Sentry, Datadog, Segment and about 30 others) found by reading the app's own files. This shows what the app is built to do, not what it sent.
- **What a message looks like**: select a destination to see a real captured request, when "Request content" is switched on, or an illustration built from the vendor's published format. The two are labelled differently.
- **Request content** (off by default, button at the top): records headers and the start of the body for requests made through Windows' own web library. Cookies, tokens and passwords are replaced before saving.

## Run it

Needs Windows 11 and [uv](https://docs.astral.sh/uv/).

```
uv sync
uv run python -m appaudit.naming.reference    # optional: download public reference lists
uv run appaudit                               # opens the dashboard at http://127.0.0.1:8756
```

Press **Start watching** in the dashboard. Windows asks for administrator rights for the watcher
(the "helper"); the dashboard itself never runs elevated. Without the watcher the Apps and Switches
pages still work.

```
uv run pytest        # 40 tests; none of them changes the PC
```

## How it works

```
helper (elevated)      one event-trace session: network per process, DNS, program starts,
                       request URLs of Windows' own HTTP libraries; DNS packets through the
                       built-in Packet Monitor; a fixed list of typed commands on a named pipe
dashboard (your user)  reads the helper's database; app inventory; switch catalogue; proof
```

- No driver is installed. Capture uses tracing that is built into Windows.
- The helper accepts only named commands. It cannot be asked to run a program or write an
  arbitrary registry path: switches and their values come from the catalogue on the helper's side.
- The pipe accepts only the signed-in user. The dashboard refuses requests from other websites
  and requires a session token for anything that changes the PC.
- Every change is journaled with the previous value and can be undone. Network blocks are ordinary
  Windows Firewall rules in the group "App Audit".
- Request addresses are stored without their query strings. Request headers and bodies are only
  recorded when you switch on Request content or run an inspection, with secrets replaced.

## Limits

- Programs with their own encryption code (browsers, most third-party apps) reveal the destination
  and volume, not the content. Encrypted DNS hides names; the owner of the address is still shown.
- On Windows Home, "diagnostic data off" is not available as a setting. The catalogue says so and
  offers the service switch instead.
- Proof needs observation time: the watcher only sees what happens while it runs.
- The switch catalogue was checked read-only on one PC (Windows 11 Home 25H2). Apply and undo were
  tested against a sandbox, not against real settings.

## Data and licences of reference lists

Downloaded to `data/reference` and not redistributed: address owners from iptoasn.com (public
domain), tracker lists from hagezi/dns-blocklists (GPL-3.0). See [RESEARCH.md](RESEARCH.md) for
sources and measurements, and [PLAN.md](PLAN.md) for status.
