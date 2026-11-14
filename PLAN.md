# Device control for Windows 11: build plan

Solo hackathon. Claude builds, Tobiah steers. Background and measurements: [RESEARCH.md](RESEARCH.md).

## What it is

A local tool that shows what every process on the PC does, explains it in plain language, switches
off what the user does not want, and then proves from real traffic that the switch worked.

Five directions share one engine: **A Proof**, **B Watchtower**, **C Translator**,
**D Telemetry X-ray**, **E Firewall**.

## Rules for the build

- The elevated helper only reads and records. Real switches and firewall rules are applied when
  Tobiah clicks them in the dashboard; Claude tests them against a sandbox.
- A local commit after each phase, no push.
- No kernel driver. No change to Defender, Windows Update or the firewall's on/off state.
- All data stays on the PC.

## Layout

```
src/appaudit/
  etw.py            trace sessions through ctypes
  capture/          event decoders, flow aggregation, packet parsing
  helper/           the elevated process: capture, history readers, typed actions
  collectors/       day-1 inventory (startup, tasks, services, permissions, launches)
  identity.py       executables to apps
  attribution.py    process to app, service, task
  naming/           address to name, owner and purpose
  switches/         catalogue engine: read, apply, undo, journal, sandbox
  proof.py drift.py before/after verdicts; what changed
  explain/          fact sheets and the knowledge base
  xray/             Windows telemetry rule files, counters, Diagnostic Data Viewer reader
  api.py web/       dashboard
catalogue/          one YAML file per group of switches
knowledge/          endpoint purposes, component descriptions, vendor map
tests/
```

The helper writes to `data/live.db`; the unprivileged dashboard reads it. Commands to the helper go
over a named pipe limited to the signed-in user.

## Phases

Engine
1. Foundations: this plan, tests, a way to replay recorded events without admin.
2. Elevated helper and live capture.
3. Attribution: process to app, service, task.
4. Naming and labelling of destinations.
5. History backfill from SRUM, Prefetch and BAM.

B Watchtower
6. Live dashboard: feed, per-app timeline, per-company view, who else is tracing.

A Proof and E Firewall
7. Switch engine with sandbox mode, journal and undo.
8. Catalogue content: 120 to 150 switches.
9. Firewall: per-app block, "quiet this app", DNS filter prototype.
10. Proof engine, tested with our own beacon program.
11. Drift: intended state against actual state; what changed between scans.

C Translator
12. Fact sheets, knowledge base, plain-English search, AI hook (off by default).

D Telemetry X-ray
13. Rule-file reader, upload counters, Diagnostic Data Viewer reader, opt-in request content.

Quality on real overnight data
14. Replay the night's capture, measure coverage, fix the biggest gaps.
15. "While you slept" digest.
16. Findings engine, second version.
17. Knowledge base second pass: everything seen on this PC.
18. Catalogue second pass: toward 250 switches.

Deeper features
19. Server names from encrypted traffic and QUIC.
20. Sensor and sensitive-folder watch.
21. Profiles and bulk actions.
22. Privacy report.
23. Background mode: tray, notifications.

Robustness
24. Soak and stress.
25. Attack our own code.
26. Tests and packaging.

Pitch
27. Demo material.
28. Hardening, demo mode, morning report.

Cut order if short: catalogue breadth, knowledge-base size, DNS filter prototype.
Phases 2 to 7 and 10 are never cut.

## Left for Tobiah

- Clicking real switches and firewall rules, then the first real proof run.
- A virtual machine with default Windows; an AI key if wanted.
- Enabling the Diagnostic Data Viewer to test its reader on live data.

## Status

Updated at the end of each phase.

- 2026-11-13: day-1 app audit built (inventory, grouping, dashboard). Research done.
- Phases 1-2 done: tracing module, decoders, live database, elevated helper with a user-only command pipe, 9 tests. The helper is started with `uv run python -m appaudit.helper --launch` and stopped with the `stop` pipe command.
- Phase 3: in progress.
