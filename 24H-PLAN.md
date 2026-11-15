# 24-hour autonomous phase

Started 2026-11-14, evening. Tobiah is away; Claude works through this list without instruction,
one item per cycle, and logs each result at the bottom. Background: [PRODUCT.md](PRODUCT.md),
[STOPPING.md](STOPPING.md), [BLOCKING-RESEARCH.md](BLOCKING-RESEARCH.md), [PLAN.md](PLAN.md).

## Goal

By the end, a person opening App Audit should get a short list of plain cases, each with an
action that does not break the app, and evidence they can check. Accuracy first, then actions,
then depth.

## Ground rules while Tobiah is away

- **Never change the PC's real settings.** No real switch apply, firewall rule, hosts file, NRPT
  rule, service or task change. New change mechanisms are built and tested against sandbox
  backends only; real use waits for Tobiah.
- **No elevation.** Do not start anything as administrator (elevation is silent on this PC). The
  helper that is already running may be used through its existing read commands.
- **Do not touch Tobiah's running apps.** Never close one. Tests that launch apps use temporary
  profiles and headless modes, and clean up after themselves.
- **No pushes, no pull requests, nothing sent anywhere.** Public downloads of reference data and
  web research are fine.
- **Commit after every item** on `device-control`, with tests passing. Never commit with failing
  tests.
- **Verify** every visible change in the dashboard (browser pane) and every data change on the
  real capture, not only in unit tests.
- **Stuck for more than one cycle on an item:** write down why under the log and move on.
- **Delete anything sensitive** a test produces (network logs, captured tokens).

## Phase R: research (first, short)

- [x] R1. Where other reporting SDKs keep their queues on disk on Windows: Bugsnag, Datadog RUM,
      App Center, Firebase, Amplitude, Segment, Mixpanel, Raygun, Unity, Unreal crash reporter.
      Output: a table in BLOCKING-RESEARCH.md and the readers to add in R-build items below.
- [x] R2. Inspecting what Chromium's log misses: Firefox (MOZ_LOG HTTP logging), Node.js requests
      inside Electron apps (--tls-keylog, NODE_OPTIONS and Electron fuses). Feasibility only.
- [x] R3. Server names from encrypted traffic: reading the name from the TLS ClientHello (SNI) in
      Packet Monitor captures, and what Encrypted Client Hello hides. Goal: name the ~30% of
      bytes that go to addresses with no name today.

## Phase 1: accuracy (the critique's open items)

- [x] 1.1 Knowledge fixes: `spclient.wg.spotify.com` is Spotify's API, `lcs-*.adobe.io` is Adobe
      licensing, `docs.*`/documentation hosts are not reporting. Add `blockable: yes|no|careful`
      and reasons to domains.yaml; a test that every reporting entry has the field.
- [x] 1.2 Browsers: traffic from browsers to trackers is "websites you visit", shown apart from
      the browser's own reporting (Firefox/Chrome/Edge telemetry hosts). Summary and app view.
- [x] 1.3 Leave out App Audit itself and development tools it runs (its own Python, uv) from
      findings, or label them; same for Claude Code's own processes where identifiable.
- [x] 1.4 Unresolved "pid NNNN" actors under System: attribute or group them honestly.
- [x] 1.5 Proof for imported switches: give toptout switches an `expect` from the app's own
      programs and known telemetry hosts where safe; otherwise mark "no proof available".

## Phase 2: cases (PRODUCT.md)

- [x] 2.1 Findings engine: rules turn evidence into cases with a stable id, severity, one-sentence
      statement of what was observed (never intent), evidence links, actions and a state
      (open, fixed with proof, accepted, testing). Dismissals move into it.
- [x] 2.2 Contrasts: says against does (switch off, still active, using the fixed proof), used
      against active (never opened, still sends), first party against third party (app sends
      to a company other than its maker), new company for an app.
- [x] 2.3 Cases home page: open cases ranked, accepted and fixed behind a filter; each case links
      to the app view sections and its actions. Target: about 10 open cases on this PC, each
      readable in one sentence.
- [x] 2.4 Presence: per-minute "at the keyboard" from the input-time data Windows already keeps
      (SRUM input seconds, and the watcher if feasible without new elevation); split traffic into
      "while you were there" and "while you were away".

## Phase 3: stopping reporting without breaking the app (STOPPING.md)

- [x] 3.1 Shared-address check from the names table, by time.
- [x] 3.2 Never-block list (Adobe licensing, Microsoft sign-in/time/licensing/Defender, Pi-hole
      breakage knowledge) as data, with tests.
- [x] 3.3 Method chooser: (sender, destination) to switch / stop program / address block / name
      block / nothing safe, with reasons; tests from the table in STOPPING.md.
- [x] 3.4 Address-block and name-block backends with sandbox implementations, journal and undo,
      and helper commands that take ids only. Real backends written but not run.
- [x] 3.5 "Stop it" in each case and app view: preview of what stops and what might break;
      apply disabled for real backends until Tobiah enables them.
- [x] 3.6 Startup control: "stop it starting by itself" for apps never opened (Dropbox, Zoom,
      Logi Options+...), as switches on the inventory's startup entries, sandbox-tested.

## Phase 4: depth

- [x] 4.1 More on-disk readers from R1 (Bugsnag, App Center, Unity, Unreal, and whatever R1 finds
      on this PC).
- [x] 4.2 Inspection improvements from R2 (Firefox headers via MOZ_LOG if feasible).
- [x] 4.3 Names from TLS ClientHello (R3) in the capture pipeline, with tests on recorded packets.
- [ ] 4.4 Inspection results feed proof: an inspection after a switch counts as before/after
      evidence for that switch.

## Phase 5: robustness and safety

- [ ] 5.1 Undo journal: values written as administrator must not come from a file the user's
      programs can edit (sign or keep a copy on the helper's side); tests.
- [ ] 5.2 Pipe: the helper accepts commands only from the dashboard (check the client process
      and a shared secret); tests.
- [ ] 5.3 Stale docs: README, PLAN.md status, RESEARCH.md; one place that says what is verified
      and what is not.
- [ ] 5.4 Test coverage for attribution, labels, digest; a fixture database from today's capture
      with personal data removed.

## Phase 6: worth keeping

- [ ] 6.1 Weekly recap page: what changed, what was fixed and stayed fixed, what came back.
- [ ] 6.2 Privacy report export (one HTML file) of cases and evidence.
- [ ] 6.3 Morning summary for Tobiah: what was done in this phase, what to look at first, what
      needs his decision (real applies, VM tests).

## Progress log

Newest first. Each entry: item, what changed, how it was verified, commit.

- **4.3** (done, not activated): `packets.HelloAssembler` joins the first segments of each TLS connection (Chrome's ~1,800-byte ClientHello puts the name in segment two) and skips Encrypted Client Hello cover names (counted as hidden). The helper gains `sample_tls()`: a 90 s window with Packet Monitor also passing TCP 443 at 2,048 bytes per packet, then the DNS-only filter is restored; helper command `tls_sample`; periodic windows off (`TLS_SAMPLE_EVERY = None`). Tested with synthetic frames (split hello, interleaved connections, ECH) and with Packet Monitor commands recorded, not run. Activating it needs a helper restart, which is elevated, so it waits for Tobiah. 201 tests.
- **4.2** (done): Firefox-family programs (firefox, librewolf, waterfox, floorp, zen, thunderbird) are inspected with their own HTTP log (MOZ_LOG nsHttp:3): every request's address and headers, secrets replaced, no bodies; logs from all Firefox processes are read and then deleted. `mozlog.py` parses the request blocks; netlog's per-destination overview is shared. Parser checked on a fresh headless Firefox log (394 requests to 8 hosts in 12 s, incl. Mozilla's location lookup and remote settings). A real inspection of Tobiah's Firefox was not run: it is open (30 processes) and inspections never close a running app; the refusal was verified on the real process list. 196 tests.
- **4.1** (done): new on-disk readers, found through the same folder matching (now also LocalLow for Unity games): Bugsnag store (device ID, waiting events/sessions), Unreal `Saved\Crashes` CrashContext (game, engine, error, and identifying login ID, Epic account ID, machine ID, Windows user name), Unity `Player.log` (analytics SDKs started and events logged), Electron Local Storage analytics IDs (Datadog, Statsig, Segment, Amplitude, Mixpanel, GA, Intercom, PostHog, LaunchDarkly, Sentry). Real files: Docker Desktop Bugsnag device ID; Witchfire's 2 crash reports carry login and Epic account IDs; RACCOIN logged 92 GameAnalytics events; Riot Client stores a Datadog session and Statsig experiments. Not seen in the browser because none of these apps ran this week (the view only lists active apps); checked through tests. 194 tests.
- **3.6** (done): `switches/startup.py` generates "X starting by itself" switches from the inventory for apps it marks as starting while unused: Run keys/Startup folder via Task Manager's StartupApproved flag (new check type `startup_approved`), services to manual, scheduled tasks disabled. Left out: updaters, anything in the Windows or Store app folders, never-stop programs, Microsoft/Xbox services and hardware helpers (audio, Bluetooth, display...). Services are checked against the real system before use, because the inventory file is user-writable. Journal entries now keep each check's definition; undo uses it only for user-level changes when the switch has left the catalogue, never for administrator changes. On the dev PC: 8 startup switches (NVIDIA Container, Adobe CCX, MSI Afterburner, OneDrive, AORUS, GBTEC; MathWorks and Dropbox already off). Sandbox apply/undo tested. 190 tests.
- **3.5** (done): `/api/stop-plan` and a "How to stop each destination" section in every app's "Turn off its reporting" and in third-party cases: method, reasons, the exact firewall rule or hosts line it would add, and Apply visibly disabled while real stops are off. Found on the way: Claude's 12.5 MB to Datadog comes from **Claude Code** (bundled at Roaming\Claude\claude-code), much of it probably this session's own work; the dev.claude-code switch now detects that copy, adds DISABLE_ERROR_REPORTING and covers it, while Intercom (the desktop app's help chat) correctly stays an address block. The chooser now tells senders apart by program file, not name. Fixed a broken f-string that stopped the dashboard starting (tests import api but had not run since). Verified in the browser on Claude's case. 187 tests.
- **3.4** (done): `stops.py`: address block (one firewall rule: program + addresses taken from this PC's DNS data, refreshed as the name moves) and name block (a marked section of the hosts file; Microsoft names refused), each with real and sandbox backends, a journal (`stops` table) and undo. Every add re-checks on the helper side: program exists and is not protected, host was seen, not never-block, addresses clean. Helper commands `stop_address_add/stop_name_add/stop_remove/stop_refresh` take only a program path and host name. Real backends are written but `REAL_ENABLED = False`, so the helper refuses; only the sandbox ran. Sandbox tests: hosts edits keep every other line (CRLF, foreign entries) and undo restores the file byte for byte. 186 tests.
- **3.3** (done): `stopping.py` chooses switch / stop_program / address_block / name_block / nothing_safe per (sending program, destination), with reasons. Programs never stopped are data in neverblock.yaml (Defender and other security software, core Windows hosts). Careful destinations carry their warning. Real data: Claude to Datadog and Intercom: address block (Intercom: help chat stops); Spotify and Steam to Google Analytics: name block (addresses shared with Safe Browsing); Firefox and Adobe: their switches; Notion to Splunk/Sentry: address block; Chrome to clientservices: nothing safe (Google's own, shared); Defender: left alone. 176 tests.
- **3.1 + 3.2** (done): `blocking.py`: `shared()` finds a name's addresses and the other names they carried at overlapping times (aliases from the same DNS answer and the same site are not counted), and lists which of those must not break; `never_block()` reads knowledge/neverblock.yaml (sign-in, time, Store licensing, Windows Update, Defender/SmartScreen, certificate revocation, Safe Browsing, updaters, Adobe licensing, Spotify API, with sources) plus domains marked blockable "no". Real data: Google Analytics addresses would also block Safe Browsing and Google's updater; Datadog, Adobe analytics, Sentry, Mozilla telemetry and Microsoft's collector are clean. 167 tests.
- **2.4** (done): `presence.py`: the dashboard records one bit per minute (keyboard or mouse used in the last 2 minutes, via GetLastInputInfo, no elevation, nothing else stored, kept 30 days). Traffic is split into while present / while away / unknown (minutes without a record are unknown, never away). Third-party and unused-app cases add "N% of it went out while nobody was at the keyboard" once at least half the bytes fall in recorded minutes; evidence shows the split. Sampler verified recording (first minute: away, Tobiah is out). The sentence itself needs a few hours of samples; re-check in 6.3. SRUM's per-day input time is not used for minutes (too coarse). 158 tests.
- **2.3** (done): Cases is the first page and the default. Open / Marked fine / Fixed tabs, 24 h or 7 days; each case shows its sentence, evidence (collapsed), switch previews inline, "Look at the app" (opens its Activity view), and "It's fine" / "Show it again". Verified in the browser on the real capture: 14 open cases; Firefox's switch preview opens in its case; marking Steam fine hid it and showing it again restored the count; Look at the app opens Claude's view. 154 tests.
- **2.1 + 2.2** (done): `cases.py` builds cases with stable ids, severity, one-sentence statements of what was observed, evidence, actions (the app's switches) and states (open, accepted, testing; fixed when a says-vs-does case disappears). Accepted cases reopen when their fingerprint changes (new company, 4x more data). Dismissed apps count as accepted. Contrasts: says vs does, can be switched off, third party (destination company is not the app's maker), unused vs active (updaters excluded, small ones grouped), new company. On the real capture: 14 open cases (from 25 before grouping), e.g. "Claude sent 11.8 MB to Datadog, Intercom, not to Anthropic PBC." API `/api/cases`, `/api/cases/decide`. Build takes ~9 s, cached 60 s; to speed up later. 154 tests.
- **1.5** (done): new proof rule `reporting_from`: a product's own programs sending to destinations the knowledge base calls reporting. 74 of 183 imported switches now have proof (the rest are steps-only or share a program with another product). Runs with their own profile (`--user-data-dir`) are not counted, because the user's settings do not govern them. Real result: Tobiah's VS Code telemetry switch shows **off and quiet**; without the profile rule Claude's blank-profile test would have made it look "off but still active". 144 tests.
- **1.4** (done): processes known only by id borrow the program of an overlapping record with the same id; any left over go into one group, "Programs that ended before they could be identified". On the real capture all 106 were resolved; no `pid NNNN` rows remain and System lists only System. 143 tests.
- **1.3** (done): interpreters (Python, Node, Java...) are attributed to what they run: App Audit itself (kept out of findings), scripts run by Claude Code, a `-m` module or a project found by its venv or project files. Real data: the 23.7 MB "Python" traffic was Tobiah's own project `novel_ultimate (backend)`; the 68 destinations incl. Facebook/Mixpanel were Claude's research scripts. Python and dev tools no longer appear as "active though never opened". 141 tests.
- **1.2** (done): knowledge/browsers.yaml lists each browser's programs and its own reporting hosts; anything else reporting-shaped from a browser is "trackers on websites you visited", counted apart (`website_tracking_sent`) and shown as its own Summary finding and in the app view. Real data (24h): Firefox's own reporting is 791 KB to incoming.telemetry.mozilla.org; website trackers 812 KB (Firefox) and 952 KB (Chrome) no longer inflate the reporting total (18.0 to 16.5 MB). Checked on the Summary page. 134 tests.
- **1.1** (done): Spotify `spclient` moved to its main API (blockable no); Adobe licensing and Genuine hosts in their own entry (no); Firefox Remote Settings is security (no); Meta split into tracking pixel vs Facebook/Instagram themselves; Intel no longer telemetry; documentation sites and analytics vendors' own websites are not reporting. Every reporting entry has `blockable` yes/careful (7 careful, with what breaks). On the real capture, 24h reporting total went from 21.1 to 18.0 MB; Spotify's 3 MB is no longer counted. Note: 3.4 MB of VS Code telemetry in the capture came from Claude's blank-profile test. 132 tests.
- **R3** (done): measured 92% of TCP 443 bytes and 77% of QUIC bytes unnamed. The ClientHello parser exists but the Packet Monitor filter is DNS-only. Capturing all of port 443 is too heavy; chose short sampling windows with two-segment reassembly for 4.3, QUIC later, ECH labelled. Activation needs a helper restart, so it waits for Tobiah.
- **R2** (done): Firefox HTTP logging (MOZ_LOG) gives addresses and headers, no bodies; tested headless with a temporary profile. Firefox uses encrypted DNS via Cloudflare here, explaining unnamed Firefox traffic. Node.js requests in Electron apps are reachable only where the NodeOptions fuse is on (VS Code, Discord; not Claude), by an opt-in in-app logger. Written up in BLOCKING-RESEARCH.md; 4.2 will add Firefox headers.
- **R1** (done): web docs were thin, so the dev PC was surveyed. New sources for 4.1: Bugsnag folders (Docker Desktop), Unreal `Saved\Crashes` with CrashContext XML (4 games), Unity `Player.log` with analytics SDK lines (RACCOIN: 717 GameAnalytics lines), analytics IDs in Electron Local Storage (Riot: Datadog, Statsig). Table added to BLOCKING-RESEARCH.md.
