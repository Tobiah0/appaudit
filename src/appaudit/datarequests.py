"""Ask a company what it holds about you.

The dashboard prepares everything it can: who to ask, a letter that quotes what was observed on
this PC, and a record of when the answer is due. It never sends anything. Sending a letter, or
pressing a company's own "download my data" button, is done by the person at the PC.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

import yaml

from .store import data_dir

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"

# days: how long the law gives the company to answer. None means no deadline is set by a law we name.
LAWS = {
    "gdpr": {"title": "European Union (GDPR)", "days": 31,
             "basis": "Article 15 of the General Data Protection Regulation (GDPR)",
             "deadline": "Article 12(3) of the GDPR requires an answer within one month of receiving this request."},
    "uk": {"title": "United Kingdom (UK GDPR)", "days": 31,
           "basis": "Article 15 of the UK General Data Protection Regulation and the Data Protection Act 2018",
           "deadline": "The law requires an answer within one month of receiving this request."},
    "ccpa": {"title": "California (CCPA)", "days": 45,
             "basis": "the California Consumer Privacy Act (California Civil Code sections 1798.100 and 1798.110)",
             "deadline": "The law requires an answer within 45 days of receiving this request."},
    "other": {"title": "Somewhere else", "days": 30,
              "basis": "the data protection law that applies to me and your own privacy policy",
              "deadline": "Please answer within 30 days."},
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS data_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT, company TEXT NOT NULL, law TEXT NOT NULL, created REAL NOT NULL,
    sent REAL, due REAL, answered REAL, subject TEXT NOT NULL, body TEXT NOT NULL, about TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
"""
PROFILE_KEYS = ("name", "email", "law", "account")


@contextmanager
def _db(file: Path | None = None):
    conn = sqlite3.connect(file or (data_dir() / "appaudit.db"), timeout=10)
    try:
        conn.executescript(SCHEMA)
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    finally:
        conn.close()


# --- who to ask ---------------------------------------------------------------------------------

@lru_cache(maxsize=1)
def directory() -> dict[str, dict]:
    entries = yaml.safe_load((KNOWLEDGE / "companies.yaml").read_text(encoding="utf-8"))
    return {entry["company"].lower(): entry for entry in entries}


_SUFFIXES = re.compile(r"[,.]|\b(inc|llc|ltd|pbc|ab|corp|corporation|gmbh|labs|communications|limited|co)\b", re.IGNORECASE)


def company_for(publisher: str | None) -> str | None:
    """'Anthropic PBC' -> 'Anthropic'. Falls back to the publisher's own name, tidied."""
    if not publisher:
        return None
    lowered = publisher.lower()
    for key, entry in directory().items():
        if lowered == key or lowered.startswith(key + " ") or lowered.startswith(key + ","):
            return entry["company"]
    return " ".join(_SUFFIXES.sub(" ", publisher).split()) or publisher


def contact(company: str) -> dict:
    entry = directory().get((company or "").lower())
    if entry is None:
        return {"company": company, "role": "unknown", "known": False}
    return {"known": True, **{key: entry.get(key) for key in ("company", "role", "export", "request", "policy", "how",
                                                              "unchecked")}}


# --- the person asking --------------------------------------------------------------------------

def profile(file: Path | None = None) -> dict:
    with _db(file) as conn:
        stored = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM settings")}
    return {key: stored.get(f"profile.{key}", "other" if key == "law" else "") for key in PROFILE_KEYS}


def save_profile(values: dict, file: Path | None = None) -> dict:
    clean = {key: str(values.get(key, "") or "")[:200] for key in PROFILE_KEYS}
    if clean["law"] not in LAWS:
        clean["law"] = "other"
    with _db(file) as conn:
        conn.executemany("INSERT OR REPLACE INTO settings VALUES (?, ?)",
                         [(f"profile.{key}", value) for key, value in clean.items()])
    return clean


# --- the letter ---------------------------------------------------------------------------------

def _size(value: int) -> str:
    if value < 1024:
        return f"{value} bytes"
    if value < 1048576:
        return f"{value / 1024:.0f} KB"
    return f"{value / 1048576:.1f} MB"


def _day(when: float) -> str:
    return time.strftime("%d %B %Y", time.localtime(when)).lstrip("0")


def evidence_from(actors: list[dict], company: str) -> list[dict]:
    """What this PC observed that concerns `company`: its own apps, and other apps that sent data to it."""
    wanted = company.lower()
    found = []
    for actor in actors:
        own = (company_for(actor.get("publisher")) or "").lower() == wanted
        hosts = [item for item in actor["destinations"]
                 if own or (item.get("company") or "").lower() == wanted]
        hosts = [item for item in hosts if item.get("category") != "local" and item.get("name")]
        if not hosts:
            continue
        found.append({
            "app": actor["name"], "publisher": actor.get("publisher"), "own": own,
            "first": actor["first"], "last": actor["last"],
            "hosts": [{"name": item["name"], "company": item.get("company"), "category": item.get("category"),
                       "sent": item["sent"]} for item in sorted(hosts, key=lambda item: -item["sent"])[:12]]})
    return found


def draft(company: str, evidence: list[dict], who: dict, law: str | None = None, now: float | None = None) -> dict:
    """The letter, as text. Nothing is stored or sent."""
    law = law if law in LAWS else (who.get("law") if who.get("law") in LAWS else "other")
    rules = LAWS[law]
    now = now or time.time()
    name = who.get("name") or "[your name]"
    processors = {key for key, entry in directory().items() if entry.get("role") == "processor"}
    lines = [
        "To the privacy team,", "",
        f"I am writing to ask for a copy of the personal data you hold about me, under {rules['basis']}.", "",
        "Please send me:",
        "  1. A copy of all personal data you hold about me, including data collected automatically by your "
        "software (usage data, diagnostic data, logs, device and advertising identifiers).",
        "  2. The purposes for which you use it.",
        "  3. Every recipient you have shared it with, including service providers that process it for you.",
        "  4. How long you keep it.",
        "  5. Where you obtained any data that did not come from me.", "",
    ]
    if evidence:
        lines.append("To help you find the data: software on my Windows PC was observed sending data as follows.")
        for item in evidence:
            span = _day(item["first"]) if _day(item["first"]) == _day(item["last"]) \
                else f"{_day(item['first'])} to {_day(item['last'])}"
            lines.append(f"  - {item['app']}" + (f" (published by {item['publisher']})" if item.get("publisher") else "")
                         + f", observed {span}:")
            for host in item["hosts"]:
                # Only name another company where we know it stores data for app makers. The owner of
                # an address (a hosting or delivery network) is not evidence of who holds the data.
                other = (host.get("company") or "").lower() in processors and host["company"].lower() != company.lower()
                owner = f", operated by {host['company']}" if other else ""
                lines.append(f"      {host['name']}{owner} ({_size(host['sent'])} sent)")
        third = sorted({host["company"] for item in evidence for host in item["hosts"] if item["own"]
                        and (host.get("company") or "").lower() in processors
                        and host["company"].lower() != company.lower()})
        if third:
            lines += ["", "Your software sent data to these other companies. Please include what they hold on your "
                          "behalf: " + ", ".join(third) + "."]
        lines.append("")
    lines.append("You can identify me by:")
    lines.append(f"  Name: {name}")
    lines.append(f"  Email address on the account: {who.get('email') or '[the email address you use with them]'}")
    if who.get("account"):
        lines.append(f"  Other identifier: {who['account']}")
    lines += ["", rules["deadline"],
              "If you need more information to confirm who I am, please tell me what you need.",
              "If you hold no data about me, please confirm that in writing.", "", "Thank you,", name]
    return {"company": company, "law": law, "law_title": rules["title"], "days": rules["days"],
            "subject": f"Request for a copy of my personal data ({company})", "body": "\n".join(lines),
            "contact": contact(company)}


def reminder(request: dict, who: dict, now: float | None = None) -> dict:
    """A follow-up for a request that has had no answer by its due date."""
    name = who.get("name") or "[your name]"
    rules = LAWS.get(request["law"], LAWS["other"])
    body = "\n".join([
        "To the privacy team,", "",
        f"On {_day(request['sent'])} I sent you a request for a copy of my personal data under {rules['basis']}. "
        f"An answer was due by {_day(request['due'])} and I have not received one.", "",
        "Please send the data, or tell me when I will receive it and the reason for the delay.",
        "If I do not hear from you, I will raise the matter with the data protection authority.", "",
        "My original request follows.", "", "-----", request["body"], "-----", "", "Thank you,", name])
    return {"subject": f"Reminder: {request['subject']}", "body": body}


# --- the record ---------------------------------------------------------------------------------

def _row(row: sqlite3.Row, now: float) -> dict:
    item = dict(row)
    item["about"] = json.loads(item["about"])
    if item["answered"]:
        item["state"] = "answered"
    elif not item["sent"]:
        item["state"] = "draft"
    elif item["due"] and now > item["due"]:
        item["state"] = "overdue"
    else:
        item["state"] = "waiting"
    item["days_left"] = round((item["due"] - now) / 86400) if item["sent"] and item["due"] and not item["answered"] else None
    item["contact"] = contact(item["company"])
    return item


def listing(file: Path | None = None, now: float | None = None) -> list[dict]:
    now = now or time.time()
    with _db(file) as conn:
        return [_row(row, now) for row in conn.execute("SELECT * FROM data_requests ORDER BY created DESC")]


def save(letter: dict, apps: list[str], file: Path | None = None, now: float | None = None) -> int:
    with _db(file) as conn:
        cursor = conn.execute(
            "INSERT INTO data_requests (company, law, created, subject, body, about) VALUES (?,?,?,?,?,?)",
            (letter["company"], letter["law"], now or time.time(), letter["subject"], letter["body"], json.dumps(apps)))
        return cursor.lastrowid


def update(request_id: int, action: str, file: Path | None = None, now: float | None = None) -> None:
    now = now or time.time()
    with _db(file) as conn:
        row = conn.execute("SELECT * FROM data_requests WHERE id = ?", (request_id,)).fetchone()
        if row is None:
            raise KeyError("unknown request")
        if action == "sent":
            days = LAWS.get(row["law"], LAWS["other"])["days"]
            conn.execute("UPDATE data_requests SET sent = ?, due = ?, answered = NULL WHERE id = ?",
                         (now, now + days * 86400, request_id))
        elif action == "answered":
            conn.execute("UPDATE data_requests SET answered = ? WHERE id = ?", (now, request_id))
        elif action == "reopen":
            conn.execute("UPDATE data_requests SET answered = NULL WHERE id = ?", (request_id,))
        elif action == "delete":
            conn.execute("DELETE FROM data_requests WHERE id = ?", (request_id,))
        else:
            raise ValueError("unknown action")
