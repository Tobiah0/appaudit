# Status: what is verified and what is not

Updated 2026-11-15, during the 24-hour autonomous phase ([24H-PLAN.md](24H-PLAN.md) has the item-by-item
log). This is the one place that says how far each part has been checked. "Verified on the dev
PC" means it ran against the real capture or real files of Tobiah's PC (Windows 11 Home 25H2,
build 26200) and the result was looked at; "sandbox" means the change path ran against an
in-memory backend; "not run" means the code exists and its unit tests pass, nothing more.

## Watching and explaining

| Part | Status |
|---|---|
| Live capture (network per process, DNS, program starts, request addresses) | Verified on the dev PC since 2026-11-14 11:58 |
| Attribution of processes to apps, scripts and services; App Audit itself left out | Verified on the dev PC |
| Destination labels, `blockable` field, documentation and vendor websites not counted as reporting | Verified on the dev PC (reporting total 21.1 to 16.5 MB after the fixes) |
| Browsers: own reporting versus trackers of visited websites | Verified on the dev PC |
| Cases home page (contrasts, decisions, reopening) | Verified on the dev PC: 14 open cases; accept and reopen tried |
| Presence (one bit per minute) | Recording verified; the "while nobody was at the keyboard" sentence needs hours of samples |
| What apps keep on disk (Sentry, Crashpad, Bugsnag, Unreal, Unity, Local Storage) | Verified on real files of the dev PC |
| Request content recording (Windows web library apps) | Verified: 40 requests captured (Adobe, NVIDIA) |
| Inspect this app, Chromium and Electron | Verified with VS Code (real profile and blank profile) |
| Inspect this app, Firefox | Parser verified on a headless Firefox log; a real inspection needs Firefox closed |
| Server names from TLS handshakes (reassembly, ECH) | Tested with synthetic packets; sampling not switched on (needs a helper restart) |
| Windows' Diagnostic Data Viewer reader | Not testable here: the telemetry service is disabled on the dev PC |

## Changing things

| Part | Status |
|---|---|
| Switches: registry, environment, config files | Verified for real by Tobiah's own clicks: Start suggestions (HKCU), VS Code telemetry (config file); proof shows VS Code quiet afterwards |
| Switches: services and scheduled tasks (administrator) | Sandbox only |
| Imported switches (toptout) and startup switches | Sandbox only |
| Undo, including the helper's protected record in %ProgramData%\AppAudit | Sandbox only; the folder lock-down needs an elevated run |
| Per-program network block (Windows Firewall) | Sandbox only |
| Address and name blocks (stops.py) | Sandbox only; real use is switched off in code (`REAL_ENABLED = False`) |
| Helper accepts changes only from the dashboard | Unit tests and the real process list; takes effect at the next helper start |

## Proof

| Part | Status |
|---|---|
| Proof matched to the switch's own programs and senders | Verified on the dev PC |
| Proof for imported switches (`reporting_from`), runs with separate profiles ignored | Verified on the dev PC |
| Inspections as proof | Verified: VS Code's telemetry switch has an inspection after the change with 0 of 68 requests to reporting destinations |
| A full apply, observe, undo cycle on real Windows settings | Not done. Needs the virtual machine or Tobiah |

## Needs Tobiah

- Restart the helper (elevated) to pick up 5.1, 5.2 and the TLS sampling code; then try one
  administrator switch and its undo, and check the protected folder's permissions.
- Decide whether to turn on real address and name blocks (`stops.REAL_ENABLED`) and TLS sampling
  (`TLS_SAMPLE_EVERY`).
- Run Inspect this app on Firefox, Discord or Spotify (they have to be closed first).
- The virtual machine for the switch-results table.
