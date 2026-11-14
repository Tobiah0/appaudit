# Product direction: from a mix of data to a short list of cases

Date: 2026-11-14. Follows [RESEARCH.md](RESEARCH.md) (what is technically possible) and the build
recorded in [PLAN.md](PLAN.md). This document is about what the product should be.

## The problem with what we built

The dashboard has eleven pages and, on the dev PC today, about 570 rows: 33 apps, 120 switches,
130 background programs, 246 history rows, 37 trace sessions. Behind those rows there are roughly
25 things a person would actually want to know. The tool makes the user find them.

Two more weaknesses showed up in the same check:

- Half of the destinations have no purpose label (89 of 175). An unlabelled address is noise.
- 122 addresses were "first seen" in three hours, so novelty by address is useless. Novelty only
  means something at the level of a company or an app.

The user's own reactions pointed the same way: collapse repeats, hide plumbing, let me dismiss
things, and "Steam received 160 MB?" was a question the tool should have answered by itself.

## What research says about tools like this

- **Lists of domains do not help people.** A 2025 study of Apple's App Privacy Report found users
  "confused about how and why network activities occurred, overwhelmed by the number of domains",
  and unsure what they could do. The sensor section worked better because it was concrete. The
  authors' advice: interpret the data for the user.
- **Seeing data rarely leads to action.** In a study of Google's My Activity, only 25% of people
  said they would change a setting afterwards. A study of Facebook's off-site activity tool
  asked for "easily actionable privacy controls" next to the data.
- **Asking about everything fails too.** Little Snitch moved from an alert per connection to a
  silent mode that records first and lets the user decide in batches.

So the product must do three things the current build does not: interpret, lead to an action, and
stay quiet about what is normal.

## The idea

The unit of the product is a **case**, not a row.

A case is one sentence a person can agree or disagree with, the evidence for it, and what can be
done about it:

> Adobe Acrobat sent 95 KB to Adobe's usage-measurement service while you were away.
> You last opened Acrobat 3 days ago. One switch stops this. [Switch off] [Test it] [It's fine]

Cases come from four contrasts. Each one compares two things the tool already measures, and no
existing tool compares them:

| Contrast | Example |
|---|---|
| Says against does | Telemetry is switched off, yet two Windows components still sent data to telemetry addresses |
| Used against active | Dropbox was last opened 92 days ago and still runs and sends |
| Present against away | 80% of what Spotify sent went out while nobody was at the keyboard |
| Before against now | Notion started sending to a company it had not contacted before; a switch you turned off is on again |

A fifth lens makes cases fairer: **first party against third party**. Spotify talking to Spotify is
expected. Notion sending logs to Splunk is a third party. Only the second is worth a case.

Every case ends in one of four states: fixed (and confirmed by proof), accepted ("it's fine"),
being tested, or open. The home page shows open cases only, most important first. The goal the
user can feel is an empty list.

## What makes it interesting, not only useful

**The test.** "Test it" runs an experiment: record a baseline, flip the switch, watch, give a
verdict. Each result is kept. Over time the tool builds a table nobody has published: which
Windows privacy switches actually stop what they claim to, on this build of Windows. That table is
the thing to show an audience.

**The recap.** Once a week, one screen: what changed, what was fixed and stayed fixed, what came
back. This is the reason to keep the tool installed after the first cleanup.

**The question box (optional).** "Why did Steam receive 160 MB?" answered from the evidence. It
needs a language model, so it stays opt-in.

## Shape of the product

Eleven pages become four.

| Page | Content |
|---|---|
| Cases | Open cases, ranked. Resolved and accepted cases behind a filter. The weekly recap. |
| Apps | One page per app: a verdict line, a label (who it talks to, when, whether you use it, what starts it, sensors), and its actions |
| Switches and tests | The catalogue, experiments, and the "does it work" table |
| Evidence | Everything built so far (activity, companies, background runs, history, listeners, Windows telemetry) as drill-down |

## Build plan

1. **Findings engine.** Rules turn evidence into cases with a stable identity, a severity, links
   to evidence, available actions and a state. Dismissal moves into this. A fixed case closes only
   when proof agrees.
2. **Presence.** The helper records whether someone is at the keyboard. Every flow is split into
   "while you were there" and "while you were away". SRUM input time gives the same for history.
3. **Baselines and change.** Per app: usual volume, usual companies, usual schedule. Cases for a
   new company, a volume far above the app's own normal, a new startup entry, a reverted switch.
4. **First party and coverage.** Match destination company to app publisher. Raise purpose labels
   from 49% to above 85% with company-level fallbacks and more knowledge entries.
5. **New home, app page, four-page navigation.** Old pages move under Evidence.
6. **Experiment runner** and the switch results table. Needs the virtual machine to run for real.
7. **Weekly recap and notifications** for new cases only.
8. **Question box**, opt-in.

Steps 1 to 5 change what the product is. Steps 6 and 7 make it worth showing and worth keeping.

## How we will know it worked

- The home page on the dev PC shows at most about 10 open cases, each readable in one sentence.
- Every case offers at least one action or says plainly that nothing can be done.
- Nothing appears on the home page that the user has accepted, unless it changes.
- A person who has never seen the tool can say what to do next within a minute. This needs a real
  person; it has not been tested.

## Risks

- **Wrong accusations.** A case states what was observed ("sent 95 KB to X"), never intent. Severity
  rules need review against real data before they are trusted.
- **Too few cases is as bad as too many.** Thresholds must be tuned on more than one PC.
- **Experiments take hours** and are only safe in the virtual machine.
- **Presence tracking is itself sensitive.** It stores only "active or not" per minute, locally.
- This direction rests on published studies and on one user's reactions, not on user testing.

## Sources

- [Transparency or Information Overload? Evaluating Users' Comprehension and Perceptions of the iOS App Privacy Report (NDSS 2025)](https://ndss-symposium.org/ndss-paper/transparency-or-information-overload-evaluating-users-comprehension-and-perceptions-of-the-ios-app-privacy-report)
- [Are Privacy Dashboards Good for End Users? Google's My Activity (USENIX Security 2021)](https://www.usenix.org/conference/usenixsecurity21/presentation/farke)
- ['Surprised, Shocked, Worried': User Reactions to Facebook Data Collection from Third Parties](https://ar5iv.labs.arxiv.org/html/2209.08048)
- [About App Privacy Report (Apple)](https://support.apple.com/102188)
- [Little Snitch operation modes](https://help.obdev.at/littlesnitch6/concepts-opmodes)
- [How The Markup built Blacklight](https://themarkup.org/blacklight/2020/09/22/how-we-built-a-real-time-privacy-inspector)
