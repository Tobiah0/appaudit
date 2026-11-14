# Research: from app audit to device control

Date: 2026-11-13. Dev PC: Windows 11 Home 25H2 (build 26200), Python 3.14, 24 logical CPUs, 31 GB RAM.

"Tested" means it was run on the dev PC by a script in `scripts/`; the summaries are in
`.spike/etw/` (git-ignored). Everything else comes from the sources at the end and says so.

## Summary

The bigger product can be built without writing or installing a kernel driver. With administrator
rights, tracing that is built into Windows gives a live record of network activity per process. For
software that uses Windows' own HTTP libraries it also gives URLs, headers and request bodies before
they are encrypted.

The hard parts are naming destinations for software with its own DNS or TLS code, blocking by domain
name, and proving over time that a switch worked.

This research found no tool that checks whether a privacy switch actually stopped the traffic. That
check is the proposed centre of the product.

## The product as one loop

1. **See.** Every process: what started it, what it connects to, how much it sends, which sensors
   it used, and whether you use it.
2. **Explain.** Turn `svchost.exe`, task names and service names into plain language: what it is,
   who made it, whether it is needed, what breaks without it.
3. **Switch off.** One catalogue of the real off switches (Windows, vendors, developer tools), plus
   per-app network blocking. Every change is recorded and reversible.
4. **Prove.** Measure the same traffic before and after a switch and report whether it stopped.
5. **Keep.** Re-check after updates and report anything that was switched back on.

Day 1 already built the inventory half of step 1.

## What was tested

| Question | Result | Needs |
|---|---|---|
| Live network activity per process | Works. A 20,000,000-byte test download was measured as 20,033,671 bytes for the right process; the extra is protocol overhead. 8,876 events, none lost. | Admin |
| Cost of reading events in Python | About 1.3 microseconds per event for a minimal handler, using `ctypes` and no extra packages. | |
| DNS names per process | Works for software that uses the Windows resolver. The event carries the calling process. | Admin |
| URLs, headers, bodies | Works for WinHTTP and WinINet. A test POST's URL, custom header and body were all recovered in clear text. Not available for software with its own TLS code: a Python `urllib` request showed no URL. | Admin |
| Packet contents without a driver | Works through the built-in Packet Monitor. A hand-made DNS packet (invisible to the resolver events) and a TLS server name were both read live. | Admin |
| Process starts and stops | Works, with parent process, image path and package name. Stop events carry CPU and I/O totals. | Admin |
| Tracing without admin | Refused (error 5). | |
| Naming remote addresses in a 30-second window | Poor: 4 of 41 public addresses were named from DNS events, 6 with the DNS cache. Most connections were opened before the window started. | |
| History already on disk | SRUM holds about 60 days (tested on day 1). BAM holds 64 entries for the user. Prefetch is not parsed yet. | Admin |
| Windows' own upload counters | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack` holds the last upload time and an upload count. | None |

Not tested: changing any setting, adding firewall rules, WinDivert, mitmproxy, the Diagnostic Data
Viewer database, anything running as SYSTEM.

## What the dev PC showed

The PC had already been hardened: the telemetry service (DiagTrack) is disabled, diagnostic data,
advertising ID, Bing search, activity history, Recall and Copilot are off by policy. Windows' own
counter says the last successful telemetry upload was 2026-08-01 11:43 UTC, after 23,097 uploads.

Things that still run on it:

- 166 of 194 scheduled tasks are enabled. Nine Windows usage-reporting tasks ran on the day of the
  probe: Device Census (two tasks), the Customer Experience "Consolidator", the feedback client
  (`DmClient`), four feature-usage tasks under `Flighting\FeatureConfig`, and the error-report queue.
  Whether they still send anything is unknown; answering that is what the product is for.
- A trace session named `UQI_local_trace` was writing a log that day into a `UsageAndQualityInsights`
  folder. It probably belongs to the "Windows Health and Optimized Experiences" service (`whesvc`),
  which is running. Press coverage in mid-2026 disputed whether that service uploads data. The link
  and the upload behaviour are both unconfirmed here.
- 37 trace sessions were running. One belongs to Steam and subscribes to the Windows process
  provider. Another (`WINNETESP`) already consumes the same WinINet and WebIO events this product
  would use.
- The boot-time `Diagtrack-Listener` trace is still configured with 228 providers, although the
  session was not running.
- The telemetry rule files that Windows downloads from Microsoft define 1,220 providers
  (`utc.app.json`, last refreshed 2026-07-30).

Other counts: 260 processes, 87 of them `svchost.exe`. All 87 were mapped to a named service without
admin. Windows tracks 37 permission categories per app, including screen capture, passkeys and
on-device AI models.

## Access levels

| Level | What it unlocks | Status |
|---|---|---|
| Standard user | Inventory: startup entries, tasks, services, permission history, launch history, service names behind `svchost.exe`, Windows' telemetry upload counters | Tested |
| Administrator | Everything in "What was tested", plus SRUM, BAM, the DNS cache, every process's path and command line, firewall rules, policy registry keys, services and tasks, the telemetry folder | Tested (read-only) |
| SYSTEM service | Start before logon, keep running across logoff, change a few protected tasks | Not tested, not needed for the core |
| Signed third-party driver (WinDivert) | Hold and modify packets: per-app domain blocking, TLS interception through mitmproxy's local mode | Not tested. `pydivert` and `mitmproxy` install on Python 3.14. Memory integrity is on. |
| Our own kernel driver | Tamper resistance | Not possible in days: needs paid signing through Microsoft |

Administrator is the right level for this product. It is a lot of access, and admin still cannot do
three things: read URLs of software with its own TLS code, change settings that Defender tamper
protection guards, or turn off Required diagnostic data on Home by policy.

### What the access obliges us to do

- Split the app: a small elevated helper with a fixed list of typed commands, and an unprivileged
  dashboard. No "run this command" or "write this registry path" endpoint.
- Lock the local interface. A dashboard served on localhost by an elevated process can be called by
  any web page the user visits unless it checks a secret token and the `Host` and `Origin` headers.
  A named pipe restricted to the user is safer than HTTP for the helper.
- Address the user's registry hive by SID, not through `HKCU`. Windows 11 is rolling out
  Administrator Protection, where elevation runs under a separate system-managed account, so
  `HKCU` in the elevated helper would be the wrong user (reported by BleepingComputer and call4cloud).
- Keep the tool's own data honest: local only, a retention limit, a wipe button, and the tool listed
  in its own results with zero connections.
- Never lower security to gain privacy: no touching Defender, Windows Update or the firewall's
  on/off state.

## How each part can be built

### See

One real-time trace session in the elevated helper, consumed with `ctypes`:

- `Microsoft-Windows-Kernel-Network`: bytes, addresses and ports per process, TCP and UDP.
- `Microsoft-Windows-Kernel-Process`: starts and stops, which catches short-lived processes.
- `Microsoft-Windows-DNS-Client`: lookups per process.
- `Microsoft-Windows-WebIO` and `Microsoft-Windows-WinINet`: URLs for the Windows HTTP stacks.
  Header and body events are tagged as containing personal data and should be off by default.

History comes from SRUM (hourly bytes and CPU per app, about 60 days), Prefetch and BAM.
A trace-session inventory ("who else is listening on this PC") is nearly free and unusual.

### Name the destination

In order of reliability: URL events for the Windows stacks; DNS events; DNS packets read through
Packet Monitor with a port-53 filter, which covers browsers that resolve names themselves; the DNS
cache at startup; TLS server names from packets; and the owner of the address from a bundled
IP-to-network table (iptoasn.com, public domain), which always works.

Blind spots: DNS over HTTPS hides the lookup, and Encrypted Client Hello hides the server name.
Reading every port-443 packet for server names is costly during large downloads, so it should be
an optional mode.

Destinations are then labelled with a purpose: Microsoft's published endpoint list (about 100 host
names with what breaks if each is blocked), tracker lists, and a hand-written map for common vendors.

### Explain

Facts first, all local: signer, version info, parent chain, the service behind each `svchost.exe`,
the task or startup entry that launched it, the service description Windows ships, and what it has
connected to. A written knowledge base covers the few hundred most common Windows and vendor
components. A language model is optional for the long tail and for questions in plain English; it
would receive process names, signers and domain names, so it must be opt-in and show what it sends.

### Switch off

Four mechanisms, safest first:

1. **Official switches.** Registry and policy values, service start types, scheduled tasks,
   environment variables, app config files. A declarative catalogue: how to detect the software, how
   to read the current state, how to apply, how to undo, what breaks, and the source.
2. **Per-app network block.** A Windows Firewall outbound rule per program. Built in, visible in
   Windows' own firewall console, reversible. Not tested in this research.
3. **Block by domain.** Weak without a driver. Hosts-file entries for Microsoft domains are flagged
   by Defender as `HostsFileHijack` and Windows reportedly ignores the file for some of its own
   servers (reports from 2020; current behaviour unchecked). The firewall's by-name rules need
   Defender Network Protection, which Microsoft lists for Pro and Enterprise only, and need DNS over
   HTTPS off. What remains is a local DNS filter (a system DNS change) or name policy rules.
4. **Driver-based interception.** WinDivert through `pydivert` or mitmproxy. Optional, later.

On Home, "Diagnostic data off" is not available: Microsoft documents it for Server, Enterprise and
Education only. On Home the options are disabling the service or blocking at the network level, and
Microsoft says update-failure information is then not sent.

### Prove

For each switch, record the traffic it is supposed to stop (process, destination, bytes, runs) for a
window before and after, and report one of: stopped, reduced, unchanged, not enough data. Windows'
own upload counters are a second witness for Microsoft telemetry. This needs hours of real time.

### Keep

Store the intended state of every switch. Re-read on a schedule and after each Windows update, and
report what was reverted. Compare task, service and startup inventories between scans.

## Directions

All five share the engine above. The choice is which one leads and how deep the others go.

| Direction | What the user gets | Cost and risk |
|---|---|---|
| A. Proof | Every off switch checked against real traffic; "your settings say off, here is what still runs" | Needs observation time; the idea found nowhere else in this research |
| B. Watchtower | Live and historical view of who talks to whom, grouped by company | Overlaps Portmaster, GlassWire, Packetly; naming is the hard part |
| C. Translator | Every process, task, service and trace session explained in plain language | Knowledge base is large; AI raises a privacy question |
| D. Telemetry X-ray | The content Windows sends: the Diagnostic Data Viewer database, the rule files, request bodies of Windows components | Most striking, most fragile; little to show on a PC with telemetry disabled |
| E. Firewall | Default-deny per app, domain blocking | Highest chance of breaking things; simplewall and Portmaster already do it |

Recommended: A leads, B is built because A needs it, C makes both readable. D is added as a
showpiece if time allows. E is limited to the per-app block.

## Proposed architecture

```
helper (elevated)      trace session, Packet Monitor, SRUM/Prefetch readers,
                       typed actions: policy value, service, task, firewall rule
core (unprivileged)    day-1 collectors, identity, attribution, naming, catalogue engine,
                       proof runs, drift checks, SQLite store, API
web                    dashboard: live feed, companies, switchboard, proof, explanations
catalogue/             one YAML file per switch: detect, read, apply, undo, breaks, source
knowledge/             endpoint purposes, component descriptions, vendor map
```

Tables to add: process runs, flows (process, address, port, bytes, first and last seen), names
(address, name, source), requests (process, method, URL), switch states over time, action journal,
proof runs.

Stay in Python. The measured event cost leaves a wide margin, and a native sidecar can replace the
consumer later without changing anything else. The .NET 9 SDK and Node are installed if needed;
Rust and Go are not.

## Build order

Each step is about one working session.

1. Helper and live capture; attribution to apps, services and tasks; store.
2. Naming and labelling: DNS events, Packet Monitor DNS, cache, address owners, endpoint purposes.
3. Live dashboard: feed, per-app history, per-company view, trace-session inventory.
4. Catalogue engine with state detection, apply, undo and journal; first 100 or so switches;
   per-app block.
5. Proof runs and drift checks.
6. Explanations: knowledge base, optional AI, "what breaks" notes.
7. Telemetry X-ray if time allows; then demo mode, README, rehearsal.

## Risks and limits

- **Observation takes real time.** Live capture only sees what happens while it runs, and proof
  needs before and after windows. SRUM softens this with 60 days of hourly history.
- **Testing switches on the only PC.** The engine will be tested against a sandbox registry key and
  dry runs. Real switches are flipped by the user in the dashboard, not by Claude.
- **A hardened dev PC is a poor "before" picture.** A default Windows install in a virtual machine,
  or vendor telemetry that is still on, gives a clearer demonstration.
- **Catalogue accuracy.** A switch that is wrong for this Windows build does harm. Each entry needs
  a state check that was actually run, so 100 checked entries beat 400 copied ones.
- **Packet Monitor details.** Wi-Fi frames arrive as raw 802.11, not Ethernet. Filters are global to
  the machine, so the helper must not disturb a capture someone else is running.
- **Security products and games.** Tools that edit the hosts file or load WinDivert are sometimes
  flagged, and kernel anti-cheat may object to packet drivers. The driverless design avoids both.
- **Distribution.** An unsigned program that asks for admin shows an "unknown publisher" warning.
  Running from source avoids this for the hackathon.

## Open decisions

1. Which direction leads (recommended: A, with B and C).
2. AI explanations: none, a local model, or an opt-in cloud model that needs an API key.
3. Blocking depth: driverless only (recommended), or an optional WinDivert mode.
4. A virtual machine with default Windows for testing and for the demo.
5. Project licence. GPL-3 or AGPL allows reuse of the largest catalogues.
6. Product name.

## Knowledge that can be reused

| Source | Content | Licence |
|---|---|---|
| privacy.sexy | Hundreds of reversible Windows privacy scripts in YAML | AGPL-3.0 |
| ChrisTitusTech/winutil | Tweaks with registry values, services, tasks and undo data | MIT |
| beatcracker/toptout | Telemetry opt-outs for developer tools, machine-readable | MIT |
| hagezi/dns-blocklists | "Native tracker" domain lists per vendor, including Windows and Office | GPL-3.0 |
| crazy-max/WindowsSpyBlocker | Windows telemetry host and address lists | MIT |
| duckduckgo/tracker-radar | Tracker domains with owning company | CC BY-NC-SA 4.0 (non-commercial) |
| iptoasn.com | Address ranges to network owner, updated hourly | Public domain (PDDL) |
| Microsoft endpoint list | About 100 host names by component, with what breaks if blocked | Documentation |
| BSI SiSyPHuS | Telemetry internals, endpoint lists, a guide to disabling | Government study |

Existing tools: O&O ShutUp10++ (closed) and the catalogues above flip switches; Portmaster (kernel
driver), simplewall (Windows Filtering Platform, by address and app) and Packetly (tracing-based
monitor) cover the network side.

## Implementation notes

- Provider GUIDs: Kernel-Network `7dd42a49-5329-4832-8dfd-43d979153a88`, Kernel-Process
  `22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716`, DNS-Client `1c95126e-7eea-49a9-a3fe-a378b03ddb4d`,
  WebIO `50b3e73c-9370-461d-bb9f-26f32d68887d`, WinINet `43d1a55c-76d6-4f7e-995c-64c711e5cafe`,
  PktMon `4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac`.
- Kernel-Network payloads are fixed layouts starting `PID:u32, size:u32, daddr, saddr, dport:u16,
  sport:u16`. Send IDs 10, 26, 42, 58; receive IDs 11, 27, 43, 59; connect 12 and 28; accept 15
  and 31; disconnect 13 and 29. The event header's process is often 4 (System), so use the payload
  PID. Decide which address is remote by comparing with local interface addresses.
- DNS-Client: 3006 query, 3008 completed with results, 3020 response. Attribution came from the
  event header; the `ClientPID` field was not populated in this capture.
- WebIO: 17 method and URL, 100 request headers, 101 response headers, 111 request body, 205 and
  700 host name. WinINet: 102 URL, 103 server, 104 verb and path.
- Kernel-Process: 1 start (parent, image, package), 2 stop (CPU cycles, I/O counts). Keyword `0x10`.
- Packet Monitor: run `pktmon filter add <name> -p 53`, then `pktmon start --capture --comp nics`,
  and enable the PktMon provider in our own session. Event 160 has a 34-byte header, then the frame.
  Parsed headers arrive as events 120 (IPv4) and 130 (IPv6).
- `ctypes` structure sizes on x64, confirmed working: `EVENT_TRACE_PROPERTIES` 120,
  `EVENT_TRACE_LOGFILEW` 448, `EVENT_RECORD` 112. See `scripts/etw_spike.py`.
- The built-in `tracerpt` decodes a 6.5 MB trace file to XML in 0.3 seconds, which is useful in tests.
- Chrome and Edge resolve names with their own code on Windows; Electron apps use the system
  resolver by default (Chromium and Electron documentation).
- Scripts: `scripts/etw_spike.py`, `scripts/pktmon_spike.py`, `scripts/telemetry_config_peek.py`,
  `scripts/srum_spike.py`. All need an elevated run and change nothing.

## Sources

- Microsoft: [Configure Windows diagnostic data](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization),
  [Connection endpoints for Windows 11 Enterprise](https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints),
  [Firewall dynamic keywords](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/dynamic-keywords),
  [Network protection](https://learn.microsoft.com/en-us/defender-endpoint/network-protection),
  [Add-DnsClientNrptRule](https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule),
  [Pktmon syntax](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon-syntax)
- Telemetry research: [BSI SiSyPHuS Win10 telemetry](https://www.bsi.bund.de/dok/12818674),
  [TROOPERS19 "The Anatomy of Windows Telemetry"](https://troopers.de/downloads/troopers19/TROOPERS19_DM_Telemetry.pdf),
  [Kroll on EventTranscript.db](https://www.kroll.com/en/publications/cyber/forensically-unpacking-eventtranscript),
  [EventTranscript.db research](https://www.github.com/AndrewRathbun/EventTranscript.db-Research)
- Packet Monitor internals: [Gary Nebbett, "In Detail: PktMon"](https://gary-nebbett.blogspot.com/2021/05/pktmon.html)
- Hosts file and Defender: [Winhelponline](https://www.winhelponline.com/blog/windows-defender-hostsfilehijack-alert-telemetry-block/),
  [Winaero](https://winaero.com/microsoft-now-flags-hosts-files-that-block-windows-10-telemetry)
- Administrator Protection: [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/windows-11-kb5067036-update-rolls-out-administrator-protection-feature/amp/),
  [call4cloud](https://call4cloud.nl/administrator-protection-windows-25h2/)
- `whesvc`: [Neowin](https://www.neowin.net/reports/what-is-the-viral-whesvc-service-and-should-you-disable-it/)
- Browser DNS: [Chromium host resolution](https://chromium.googlesource.com/chromium/src/+/main/net/dns/README.md),
  [dns0.eu known issues](https://docs.dns0.eu/known-issues)
- Interception: [mitmproxy local capture on Windows](https://mitmproxy.org/posts/local-capture/windows/)
- Catalogues and lists: [privacy.sexy](https://github.com/undergroundwires/privacy.sexy),
  [winutil](https://github.com/ChrisTitusTech/winutil), [toptout](https://github.com/beatcracker/toptout),
  [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists),
  [WindowsSpyBlocker](https://github.com/crazy-max/WindowsSpyBlocker),
  [tracker-radar](https://github.com/duckduckgo/tracker-radar), [iptoasn.com](https://iptoasn.com/)
- Existing tools: [Portmaster](https://safing.io/), [simplewall](https://github.com/henrypp/simplewall),
  [Packetly](https://github.com/robinix/Packetly)
