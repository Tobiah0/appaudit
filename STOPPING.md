# Stopping reporting without breaking the app

Date: 2026-11-14. Follows [PRODUCT.md](PRODUCT.md). Prior art and what to reuse:
[BLOCKING-RESEARCH.md](BLOCKING-RESEARCH.md). Measurements are from the dev PC's capture
(about 17 hours on Windows 11 Home 25H2, build 26200) unless a source is given.

## The problem

Today the only action for an app is "block its network". That stops the reporting, but it stops the
app too, so for most apps nobody will press it. A person wants to keep using Spotify, Acrobat or
Claude and stop only the part that reports on them.

Reporting is almost never all of an app's traffic. On the dev PC:

| Program | To reporting services | Everything else | Where the reporting goes |
|---|---|---|---|
| claude.exe | 5.6 MB | 44.8 MB | Datadog log intake, Intercom |
| Spotify.exe | 2.4 MB | 3.5 MB | `spclient.wg.spotify.com` (see below), Google Analytics |
| firefox.exe | 1.3 MB | 51.3 MB | Mozilla telemetry, and Google Analytics from web pages |
| chrome.exe | 550 KB | 5.2 MB | Google Analytics from web pages, Bugsnag, `clientservices.googleapis.com` |
| AdobeCollabSync.exe | 238 KB | 799 KB | `cc-api-data.adobe.io` |
| acrotray.exe | 189 KB | 1.1 MB | `cc-api-data.adobe.io`, `lcs-cops.adobe.io` |
| MpDefenderCoreService.exe | 152 KB | 0 | Office config, Microsoft's shared event collector |
| taskhostw.exe | 100 KB | 2 KB | Windows remote configuration (OneSettings) |
| Notion.exe | 12 KB | 3.5 MB | Splunk, Sentry |

So the unit of action must be smaller than an app: one destination of one app, or one program
inside an app.

## Five ways to stop it, most precise first

| | Method | Stops | Risk | Works without the helper running |
|---|---|---|---|---|
| 1 | **Vendor setting** (policy, registry, config file, environment variable) | Exactly what the vendor says it stops | Lowest; supported by the vendor | Yes |
| 2 | **Stop the reporting program** (block or disable one helper program, task or service) | Everything that program does | Low when the program only reports | Yes |
| 3 | **Block the address for this app only** (firewall rule: this program, these addresses) | This app's traffic to that host | Shared addresses break other features of the same app | Yes, but addresses go stale |
| 4 | **Block the name for the whole PC** (DNS level) | Every program's lookups of that name | The name might be needed by something else | Depends on the variant |
| 5 | Block the app (exists today) | Everything | The app stops working | Yes |

There is also an honest sixth outcome: **nothing safe can stop this**. The case then says so,
and offers what is left: a data request, or "it's fine".

### 1. Vendor settings

The catalogue already has 120. Each one has a `breaks` text and an `expect` block for proof. To
cover the apps people actually run, the catalogue needs two new check types:

- **Config file values**: JSON or INI settings that apps keep in their own folders, for example
  VS Code's `telemetry.telemetryLevel`. The value is read and written the same way as a registry
  value, and journaled for undo.
- **Account settings**: some opt-outs exist only on the vendor's website (Discord's "use my data
  to improve Discord", Spotify's tailored ads). The tool cannot change these. It can open the right
  page and then show with proof whether anything changed.

### 2. Stopping one program inside an app

Many vendors put reporting in a separate executable, scheduled task or service. Blocking that one
program leaves the app working. Examples from the dev PC and the catalogue:
- Adobe: `acrotray.exe`, `LogTransport2.exe`, and `AdobeCollabSync.exe`.
- Mozilla: `default-browser-agent.exe` and `pingsender.exe`.
- NVIDIA: `NvTelemetryContainer.exe`.
- Microsoft: `wsqmcons.exe` (the CEIP task).

The tool knows which executable sent what, so it can say "this program sends only to reporting
services" (MpDefenderCoreService.exe above: 152 KB to reporting, nothing else). The existing
per-program firewall block already does this. What is missing is offering it per component
instead of per app, and the rule that a program qualifies only when almost all its traffic is
reporting.

Disabling the program's scheduled task or startup entry is often better than a firewall block,
because the program then does not run at all. Both are already supported by the switch engine
(task and service checks) and the inventory (startup entries).

### 3. Per-app address block

This is a Windows Firewall rule limited to one program and a list of remote addresses. Windows
Firewall cannot match host names, so the tool must supply the addresses and keep them current.

**Dynamic keywords** make this practical. A rule refers to a keyword object, and the tool updates
the object's address list (`Update-NetFirewallDynamicKeywordAddress`) without recreating the rule.
Both cmdlets exist on the dev PC. Windows can resolve keyword names itself (`AutoResolve`), but that
depends on Defender's Network Protection, which is off on the dev PC and which the project rules
say not to change. So the helper fills the lists itself from the DNS answers it already captures.
That works for Chromium apps too, because the helper reads DNS packets as well as Windows' DNS
client.

What decides whether this is safe is whether the addresses are shared. The tool can measure that:
an address that has resolved to other names, or that this app used for other names, is shared.
On the dev PC:

| App and destination | Addresses | Shared with |
|---|---|---|
| claude.exe → Datadog, Intercom | 20 | nothing |
| Adobe helpers → `cc-api-data.adobe.io`, `lcs-cops.adobe.io` | 12 | nothing |
| Notion → Splunk, Sentry | 2 | nothing |
| chrome.exe → Google Analytics and others | 7 | 4 shared with `update.googleapis.com`, `safebrowsing.google.com`, `takeout.google.com` |
| firefox.exe → Mozilla telemetry | 1 of 8 | `aus5.mozilla.org` (Firefox updates) |
| Spotify.exe, Steam → Google Analytics | 1 | `update.googleapis.com` |

So this method suits vendors that run their own collection endpoints (Datadog, Sentry, Adobe,
Splunk), and must never be used on Google's shared front ends. There, blocking the Analytics address
for Chrome would also block Safe Browsing.

Two weaknesses:
- **The first connection to a new address gets through.** It happens before the helper sees the
  DNS answer and updates the list. Collection hosts change addresses rarely, and most reporting
  retries, so this costs a little, not everything.
- **Some apps queue reports and send them later.** Undoing the block can release the backlog.
  The undo dialog should say so.

### 4. Name block for the whole PC

This is the method ad blockers use. It matches names instead of addresses, so shared addresses
stop mattering. The trade-off is that it applies to every program. That is fine for third-party
trackers (Google Analytics, Bugsnag, Splunk inputs), which nobody needs. It is not fine for
first-party names.

Chromium decides which variant to use. On the dev PC, chrome.exe made **zero** lookups through
Windows' DNS resolver while it contacted 55 destinations. Steam's web helper made none either, and
Spotify, Discord and Notion made only one or two. Chromium and Electron apps use Chromium's own
resolver. That resolver reads the hosts file itself, but it does not ask Windows' DNS client.

Two variants:
- **A marked section in the hosts file.** This reaches Chromium apps. It cannot match wildcards,
  so Sentry's per-customer names (`o324374.ingest.sentry.io`) need an entry each, added as the tool
  sees them. Defender flags hosts entries that block Microsoft names and can reset the file
  (`SettingsModifier:Win32/PossibleHostsFileHijack`), so Microsoft names never go in. Those are
  handled by switches. The dev PC's hosts file already has 49 lines from other software, so the
  tool edits only its own marked section.
- **Name Resolution Policy Table (NRPT) rules plus a small resolver in the helper.** These match
  suffixes like `.ingest.sentry.io`, do not touch the hosts file, and do not trigger Defender.
  Chromium checks whether NRPT rules exist. A Microsoft forum answer suggests Chromium then falls
  back to Windows' resolver, which would make this reach Chromium apps too. That needs testing
  before it is relied on. Another unknown is how lookups of those names behave when the helper is
  stopped (probably timeouts).

Encrypted DNS in a browser bypasses both variants. The catalogue should get switches for Firefox's
and Chrome's DNS-over-HTTPS policies. The tool can also detect the bypass: an app that contacts
addresses for which no DNS answer was ever seen is resolving names some other way.

## Which method, decided by evidence

Each reporting destination in a case gets one recommended method, chosen in this order:

1. A catalogue switch whose `expect` covers this sender and destination → **the switch**.
2. The sender is a program whose traffic is at least about 90% reporting → **stop that program**:
   disable its task or startup entry if it has one, otherwise block it.
3. The destination's addresses are not shared, by observation over at least a day → **per-app
   address block**.
4. The destination is a third-party tracker, not the app's own company and not Microsoft →
   **name block**.
5. Otherwise → **nothing safe**. The case says why, for example "this address also serves Chrome's
   Safe Browsing".

Applied to the dev PC:

| Case | Method | Note |
|---|---|---|
| Claude → Datadog log intake | Address block for claude.exe | Clean addresses. Also stops error logs the developer uses for support |
| Claude → Intercom | Address block | Breaks the in-app support chat; the case says so |
| Spotify → `spclient.wg.spotify.com` | **None. Fix the label** | This is Spotify's main client API, not only logging. Blocking it breaks Spotify |
| Spotify, Steam → Google Analytics | Name block | Address shared with Google's updater |
| Firefox → Mozilla telemetry | Switch `firefox.telemetry` (exists) | Address shared with Firefox updates |
| Chrome → `clientservices.googleapis.com` | Switch `chrome.metrics` (exists) | Shared Google front end |
| Firefox, Chrome → Google Analytics | Name block, offered as "block trackers on websites" | This is the pages you visit, not the browser. Treat it separately |
| Acrobat helpers → `cc-api-data.adobe.io` | Switch `adobe.acrobat-usage`, then address block if proof shows it continues | `lcs-cops.adobe.io` is licensing: never block |
| Notion → Splunk, Sentry | Address block | Clean addresses, small volume |
| Defender → Office config, event collector | None | Project rule: no changes to Defender |
| Windows tasks → OneSettings | Switch `win.onesettings` (exists) | Microsoft name: not in the hosts file |

## The "Stop it" flow

1. **The case shows one button** with the chosen method in plain words: "Stop Claude sending logs
   to Datadog (blocks 2 addresses for Claude only)". Other methods sit behind "other ways".
2. **Preview** before applying: what stops (names and bytes from the last week), what might
   break (from the knowledge base's `breaks` and from the shared-address check), how to undo it.
3. **Apply** through the helper, journaled like switches. Every firewall rule goes in group
   "App Audit", every hosts line in the marked section, and every NRPT rule has a recognisable
   name.
4. **Test** with the proof engine the commit before this one fixed: the destination should go
   quiet for that sender.
5. **Watch for breakage.** If the app's other traffic drops sharply after the change, the case
   asks "Is Claude still working?" and offers undo. No silent automatic undo, since the person
   may simply have closed the app.
6. **Keep the result.** Each method, app and destination with its verdict feeds the "does it work"
   table from PRODUCT.md, now covering blocks as well as switches.

## What has to change in the code

1. **Knowledge base.** Add `blockable: yes | no | careful` and a `breaks` text to domain entries.
   Fix known wrong labels: `spclient.wg.spotify.com` is Spotify's API; `lcs-cops.adobe.io` is
   licensing. Mark documentation hosts (`docs.*`) as not reporting.
2. **Shared-address check.** For a destination, list the other names its addresses carried, from
   the `names` table, by time.
3. **Method chooser.** A function from (sender, destination) to a method and its reasons, with
   tests from the table above.
4. **Helper commands.** Add `address_block_add` / `address_block_remove`, using a keyword and a
   rule per app and destination group; `name_block_add` / `name_block_remove`; and refreshing the
   keyword address lists from captured DNS answers. These take ids from the knowledge base and
   observed names, never free text. That keeps the rule that the helper does not take arbitrary
   values.
5. **Catalogue.** Add config-file and account-setting check types; DNS-over-HTTPS policies for
   Firefox and Chrome; component programs for the vendors above.
6. **Dashboard.** Add the Stop it flow to cases and the app page.
7. **Tests in the VM.** For each method, apply it, check proof, check the app still works, then
   undo. The NRPT variant and the hosts file under Defender are tested here first.

## Open questions

- Does Chromium fall back to Windows' resolver when NRPT rules exist, and do Electron apps
  behave the same? Testing settles this quickly.
- How do apps behave when collection is blocked: retry storms, growing queues, error dialogs?
  Measure with the beacon program and two or three real apps.
- How many reporting destinations on a typical PC land in "nothing safe"? If it is many, the
  product's promise needs rewording.

## Sources

- [Windows Firewall dynamic keywords (Microsoft Learn)](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/dynamic-keywords)
- [Update-NetFirewallDynamicKeywordAddress (Microsoft Learn)](https://learn.microsoft.com/ja-jp/powershell/module/netsecurity/update-netfirewalldynamickeywordaddress)
- [Chrome host resolution, net/dns README (Chromium)](https://chromium.googlesource.com/chromium/src/+/main/net/dns/README.md)
- [Chromium Windows DNS system settings, NRPT check](https://chromium.googlesource.com/chromium/src.git/+/lkgr-android-internal/net/dns/public/win_dns_system_settings.h)
- [Edge Insider forum: NRPT support](https://techcommunity.microsoft.com/discussions/edgeinsiderdiscussions/name-resolution-policy-table-nrpt-support/664177/replies/673542)
- [Hosts file is detected as malware in Windows Defender (Microsoft Support)](https://support.microsoft.com/en-us/servicing/os/windows/2017/01/hosts-file-is-detected-as-malware-in-windows-defender)
- [Windows Defender HostsFileHijack alert when telemetry is blocked (Winhelponline)](https://www.winhelponline.com/blog/windows-defender-hostsfilehijack-alert-telemetry-block/)
