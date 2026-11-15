# What others have done to stop telemetry

Date: 2026-11-14. Background for [STOPPING.md](STOPPING.md). It covers what exists, what it
teaches, and what to reuse. Checks against the dev PC use its capture in `data/live.db`.

## Summary

Many people have worked on this, and their work falls into four kinds: setting catalogues, host
lists, SDK signature databases, and per-app filtering tools. None of them publishes what this
project can: per-app results checked against the PC's own traffic, with breakage recorded.

Three lessons repeat across all of them:

1. **Lists go stale.** WindowsSpyBlocker's hosts were last updated in May 2022, and on the dev PC
   its "spy" list matched none of the Microsoft hosts in use. Users report that HaGeZi's
   Windows/Office list has not been updated in about three years.
2. **Knowing what breaks is as valuable as knowing what to block.** The Pi-hole community keeps a
   "commonly whitelisted domains" thread. pihole-antitelemetry moves hosts known to break things
   into a separate "borked" file. Adobe publishes the hosts its licensing needs.
3. **A lot of telemetry shares a host with the app's real work.** A web study (TrackerSift) found
   48% of hostnames that carry tracking also serve functionality. Discord sends analytics to
   `discord.com/api/.../science`, and Spotify needs `spclient.wg.spotify.com` to work at all. Only
   path-level filtering separates these, which means HTTPS inspection or modified clients.

## Setting catalogues: change the app's own setting

| Source | What it is | Reuse |
|---|---|---|
| [toptout](https://github.com/beatcracker/toptout) | 163 products, each with its opt-out as JSON against a schema. Methods: environment variable, registry, INI file, JSON file, plain-text file, command. Also served by an API | **High.** Its methods match the catalogue's check types almost one to one. Licence still to check |
| [privacy.sexy](https://github.com/undergroundwires/privacy.sexy) | Open scripts for Windows and per-app telemetry (VS Code, Office, NVIDIA, Visual Studio, browsers) | Medium. Already cited by the catalogue; review its scripts per entry. Licence still to check |
| Vendor policy templates (ADMX) | Chrome, Edge, Firefox, Office and others publish their policies in a machine-readable format | High for those vendors: a script can extract telemetry policies for review |
| [Microsoft: Manage connections from Windows components](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services) | Microsoft's own table of every Windows connection and the setting that controls it, plus the Restricted Traffic baseline | High for Windows switches. Written for Enterprise; each setting must be checked on Home |
| [BSI SiSyPHuS](https://www.bsi.bund.de/dok/12818674) | German security agency's analysis of Windows telemetry, with instructions and an endpoint list | Already the source for the DiagTrack switch. It confirms that Office and other apps send telemetry without the central service |

Matched against the dev PC's 195 inventory apps, toptout covers about 8 things here:
VS Code, .NET, NVIDIA drivers, Windows, Firefox, Docker Desktop, Windows Terminal and Calculator.
It is strong on developer tools and has nothing for Spotify, Discord, Adobe, Zoom or Steam.
Setting catalogues will always leave a long tail of uncovered apps.

## Host lists: block names

| Source | Notes |
|---|---|
| [WindowsSpyBlocker](https://crazymax.dev/WindowsSpyBlocker/blocking-rules/) | MIT licence. Hosts and firewall rules for Windows in three lists: spy, extra and update. Built from captured traffic, but last updated 2022-05-16 |
| [HaGeZi native trackers](https://github.com/hagezi/dns-blocklists) | Vendor lists (`native.winoffice` and others). The tool already downloads them |
| [pihole-antitelemetry](https://awesome.ecosyste.ms/projects/github.com%2Fmoralcode%2Fpihole-antitelemetry) | Keeps known-breaking hosts in a separate "borked" file, so breakage is a choice |
| [Pi-hole: commonly whitelisted domains](https://discourse.pi-hole.net/t/commonly-whitelisted-domains/212) | What people had to unblock: Windows Update and Store hosts, Office, Spotify's `spclient` and `apresolve` |

Checked on the dev PC, WindowsSpyBlocker's **extra** list matches 16 hosts in use. These include
Microsoft sign-in (`login.live.com`, `login.microsoftonline.com`), Store licensing
(`licensing.mp.microsoft.com`), clock sync (`time.windows.com`) and Defender's cloud protection
(`wdcp.microsoft.com`). Applying that list wholesale would break sign-in and weaken Defender. Host
lists are a source of candidates, not something to apply.

## SDK signature databases: find reporting code inside apps

| Source | Notes |
|---|---|
| [Exodus Privacy ETIP](https://exodus-privacy.eu.org/en/post/tracking-trackers) | The reference database for Android trackers. Each tracker has code signatures and domains, checked by at least two people against how many known apps a pattern matches. F-Droid and Guardian Project use it |
| [DuckDuckGo Tracker Radar](https://github.com/duckduckgo/tracker-radar) | Domain → company → category for web trackers. Sources disagree on whether the licence is NC-SA or NC-ND; both are non-commercial |

Exodus is the model for `knowledge/sdks.yaml`: the same idea (strings plus domains per SDK) and
the same review rule (a signature must not match apps that do not contain the SDK). Many of its
SDKs (Sentry, Firebase, Amplitude, Segment) ship in desktop Electron apps too, so its domain lists
carry over. Its code signatures are Java package names and do not carry over.

## Tools that filter per app

| Tool | How it works | Lesson |
|---|---|---|
| [Portmaster](https://safing.io/blog/2021/03/23/attributing-dns-requests-on-windows/) | Own DNS resolver plus a driver; per-app filter lists | It cannot see which app made a query that goes through Windows' DNS Client, and at first switched that client off, which caused problems. App Audit's helper reads the DNS Client's own event (3008), which names the requesting process |
| [simplewall](https://github.com/henrypp/simplewall) | Configures Windows Filtering Platform rules; ships WindowsSpyBlocker's rules | Its filters stay in place after the app is uninstalled. Anything App Audit adds must be removable and clearly named |
| [AdGuard for Windows](https://adguard.com/en/blog/how-desktop-apps-watch-you-research.html) | HTTPS inspection with path-level rules; by default only for browsers | Its own study: over 20% of tested desktop apps send telemetry on timers with no user action, and DNS blocking is too coarse when tracking shares a domain with content. AdGuard is a filtering vendor, so this is self-reported |

## Recipes for specific apps

| App | What the community found |
|---|---|
| Discord | Analytics go to `/api/v*/science` on the main domain. They can only be stopped with a path filter in a browser, or a modified client (Vencord NoTrack, CutTheCord). Discord may treat client modification as a terms violation. **For the desktop app: nothing safe** apart from Discord's own privacy setting |
| Spotify | `spclient.wg.spotify.com` and `apresolve.spotify.com` are required. Community block lists for Spotify cause breakage as Spotify moves endpoints. **Nothing safe by host**; App Audit's label on `spclient` is wrong |
| Adobe Acrobat | Adobe's documented licensing hosts: `lcs-cops`, `lcs-robs`, `lcs-ulecs` (all `.adobe.io`) and `ims-na1.adobelogin.com`. These go on a never-block list. `cc-api-data.adobe.io` is not documented as licensing |
| NVIDIA | The separate telemetry service was removed; telemetry now runs inside `NVDisplay.Container.exe`, which the driver needs. Disabling the scheduled tasks is what remains. No verified opt-out in the current NVIDIA App |
| Windows | Microsoft's "Manage connections" table and the BSI instructions are the authoritative sources. Both note side effects (Get Help and Feedback stop working; updates can be affected) |

## What this changes in the plan

1. **Ship a never-block list alongside the block knowledge.** Sources: vendor allowlists (Adobe
   licensing; Microsoft sign-in, time, licensing and Defender), the Pi-hole whitelist thread, and
   pihole-antitelemetry's "borked" file. In `domains.yaml` this is `blockable: no` with a reason.
   It also fixes the Spotify label.
2. **Import toptout into the catalogue.** Write an importer that turns its JSON into switch
   candidates with the source recorded. Each candidate is reviewed before it ships, and added only
   if the product is detected on the PC. Do the same for policy templates (ADMX) from Chrome, Edge,
   Firefox and Office. This replaces writing vendor switches by hand.
3. **Treat host lists as candidates, verified per PC.** Use WindowsSpyBlocker, HaGeZi and Tracker
   Radar to suggest what might be reporting. Block only what this PC's traffic shows coming from
   the expected sender, and only after the shared-address and never-block checks.
4. **Line SDK signatures up with Exodus**, and reuse its domain lists for SDKs that also ship on
   desktop.
5. **Say "nothing safe" for in-band telemetry** (Discord, Spotify), and point to the vendor's own
   setting or a data request. App Audit will not modify clients or inspect HTTPS.
6. **Keep the verified results.** I found no published table of per-app blocking results with
   breakage. Every published list here is either a list of names or a script, never "applied
   on this Windows build, this stopped and nothing broke". The proof engine can produce that,
   and it is the part nobody else offers.

## Sources

- [toptout](https://github.com/beatcracker/toptout)
- [telemetry.how](https://www.github.com/yeskunall/telemetry.how)
- [privacy.sexy releases](https://github.com/undergroundwires/privacy.sexy/releases/)
- [Microsoft: Manage connections from Windows components to Microsoft services](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)
- [Microsoft: Windows 11 connection endpoints for non-Enterprise editions](https://learn.microsoft.com/windows/privacy/windows-11-endpoints-non-enterprise-editions)
- [BSI: SiSyPHuS Win10, Telemetry in Windows 10](https://www.bsi.bund.de/dok/12818674)
- [WindowsSpyBlocker blocking rules](https://crazymax.dev/WindowsSpyBlocker/blocking-rules/)
- [HaGeZi DNS blocklists](https://github.com/hagezi/dns-blocklists)
- [Privacy Guides: Windows Spyblocker still good in 2025?](https://discuss.privacyguides.net/t/windows-spyblocker-still-good-in-2025/32656)
- [Pi-hole: Commonly whitelisted domains](https://discourse.pi-hole.net/t/commonly-whitelisted-domains/212)
- [pihole-antitelemetry](https://awesome.ecosyste.ms/projects/github.com%2Fmoralcode%2Fpihole-antitelemetry)
- [Exodus Privacy: Tracking trackers](https://exodus-privacy.eu.org/en/post/tracking-trackers)
- [Guardian Project: Exodus ETIP](https://guardianproject.info/2020/12/11/%CE%B5xodus-etip-the-canonical-database-for-tracking-trackers/)
- [DuckDuckGo Tracker Radar data model](https://github.com/duckduckgo/tracker-radar/blob/main/docs/DATA_MODEL.md)
- [Safing: Attributing DNS requests on Windows](https://safing.io/blog/2021/03/23/attributing-dns-requests-on-windows/)
- [simplewall](https://github.com/henrypp/simplewall)
- [AdGuard: How desktop apps watch you](https://adguard.com/en/blog/how-desktop-apps-watch-you-research.html)
- [Reddit (mirror): uMatrix setup for Discord, path filter for /api/science](https://axebps-redlib.hf.space/r/uMatrix/comments/197xhlm/best_umatrix_setup_for_discord)
- [Vencord NoTrack plugin](https://gitdab.com/profxadke/Vencord/src/branch/main/src/plugins/noTrack.ts)
- [Discord support: Adblocker + /api/science = client modification?](https://support.discord.com/hc/de/community/posts/1500000832822-Adblocker-api-science-client-modification)
- [Pi-hole: Spotify not connecting](https://discourse.pi-hole.net/t/spotify-not-connecting-whats-the-latest-news/26613)
- [Adobe community: firewall details for Acrobat licensing](https://community.adobe.com/questions-617/firewall-details-for-adobe-acrobat-pro-subscription-for-activate-license-554572)
- [Disable NVIDIA telemetry (gHacks)](https://www.ghacks.net/?p=126026)
- [TrackerSift (IMC 2021)](https://arxiv.org/pdf/2108.13923.pdf)
- [Duumviri: detecting trackers with a breakage detector](https://arxiv.org/pdf/2402.08031)

## Where reporting SDKs keep data on disk (checked on the dev PC, 2026-11-14)

Web documentation on this is thin, so the table comes mostly from what is actually on the dev PC.
App Audit reads the first three already; the rest are item 4.1 of [24H-PLAN.md](24H-PLAN.md).

| SDK | Location | What is there | On the dev PC |
|---|---|---|---|
| Sentry (JavaScript, Electron) | `<app data>\sentry\` | `scope_v3.json` (user record, device sections, activity log), `session.json`, `queue\` envelopes | Claude, Discord, Riot Client, two games |
| sentry-native | `<app data>\.sentry-native\` | `*.run\` session folders, `*.envelope` | RSDragonwilds |
| Crashpad (Chromium) | `<app data>\Crashpad\` | `settings.dat` (uploads on/off, install ID), dumps in `reports\`/`pending\`/`completed\` | about 20 apps |
| Bugsnag (Electron) | `<app data>\bugsnag\<key hash>\` | `device.json`, `events\`, `sessions\`, `runinfo\`, `last-run-info.json` | Docker Desktop |
| Unreal Engine crash reporter | `%LOCALAPPDATA%\<Game>\Saved\Crashes\<id>\` | `CrashContext.runtime-xml` (machine, account and user fields, GPU, engine version), `CrashReportClient.ini`, `UE4Minidump.dmp` | Witchfire (2), Half Sword, Discovery |
| Unity player | `%USERPROFILE%\AppData\LocalLow\<Company>\<Product>\Player.log` | The game's log; analytics SDKs write to it (GameAnalytics: design events, error events, queue activity) | 15 games; RACCOIN has 717 GameAnalytics lines |
| Browser-style SDKs in Electron apps (Datadog RUM, Statsig, Segment, Amplitude, Mixpanel, LaunchDarkly, PostHog) | `<app data>\Local Storage\leveldb\` | Session and anonymous IDs, cached experiment assignments, under well-known keys (`_dd_s`, `statsig.*`, `ajs_anonymous_id`, `AMP_*`, `mp_*_mixpanel`) | Riot Client: Datadog session, Statsig evaluations |
| App Center, Amplitude and Firebase desktop SDKs | not found | no documentation found and nothing on this PC | not checked further |

Sources: [Unity CrashReporting.crashReportFolder](https://docs.unity3d.com/ScriptReference/Windows.CrashReporting-crashReportFolder.html),
[@bugsnag/electron-filestore](https://socket.dev/npm/package/@bugsnag/electron-filestore),
[Sentry Electron offline support](https://docs.sentry.io/platforms/javascript/guides/electron/features/offline-support).

## What "Inspect this app" can and cannot reach (R2, tested 2026-11-14)

| Traffic | How it can be read | Tested |
|---|---|---|
| Chromium and Electron apps, browser side | `--log-net-log` with capture mode Everything: addresses, headers, bodies | Yes: Chrome, VS Code |
| Firefox | `MOZ_LOG=timestamp,nsHttp:3` with `MOZ_LOG_FILE`: address and headers of every request, no bodies. Needs Firefox closed (or a separate profile) | Yes: 398 requests logged in 15 seconds by a headless temporary profile |
| Firefox name lookups | Firefox sends them encrypted to `mozilla.cloudflare-dns.com` (DNS over HTTPS), which is why the watcher has no names for much of Firefox's traffic | Seen in the same log |
| Node.js requests inside Electron apps (main process, `https` module) | Not in Chromium's log. Reachable only where the app leaves Electron's `NodeOptionsEnvironmentVariable` fuse on: `NODE_OPTIONS=--require <logger>` can record each request from inside the app | Fuses read from the program files: VS Code and Discord on; Claude off |

The Node.js route runs code inside the app, so if it is built it must be opt-in per app and say so.
