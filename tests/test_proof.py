"""Proof verdicts against a synthetic live database: a pretend telemetry process that is
active before a switch is applied and silent, quieter or unchanged afterwards."""

import time

from appaudit import livestore, proof, switches
from appaudit.switches.backends import SandboxBackend

EXPECT = {"processes": ["beacon.exe"], "domains": ["collect.example.com"]}
HOUR = 3600


def make_db(tmp_path, runs_before, runs_after, changed, bytes_per_run=5000, other_traffic_after=True):
    conn = livestore.connect(file=tmp_path / "live.db")
    conn.execute("INSERT INTO names VALUES ('203.0.113.50', 'collect.example.com', 'dns', ?, ?)",
                 (changed - 30 * HOUR, time.time()))
    proc_id = 0

    def run(name, when, remote, sent):
        nonlocal proc_id
        proc_id += 1
        conn.execute("INSERT INTO procs (id, pid, started, ended, exe, name, seen_start) VALUES (?,?,?,?,?,?,1)",
                     (proc_id, 1000 + proc_id, when, when + 20, f"C:\\x\\{name}", name))
        conn.execute("INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (proc_id, remote, 443, "tcp", int(when // HOUR) * HOUR, sent, sent * 2, 4, when, when + 5))

    for index in range(6):                               # background noise so every hour counts as observed
        run("browser.exe", changed - (index + 1) * HOUR + 60, "198.51.100.7", 100)
        if other_traffic_after:
            run("browser.exe", changed + index * HOUR + 60, "198.51.100.7", 100)
    for index in range(runs_before):
        run("beacon.exe", changed - (index + 1) * HOUR + 600, "203.0.113.50", bytes_per_run)
    for index in range(runs_after):
        run("beacon.exe", changed + index * HOUR + 600, "203.0.113.50", bytes_per_run)
    conn.commit()
    return conn


def verdict(tmp_path, runs_before, runs_after, **kwargs):
    changed = time.time() - 6 * HOUR
    conn = make_db(tmp_path, runs_before, runs_after, changed, **kwargs)
    before = proof.footprint(conn, EXPECT, changed - 24 * HOUR, changed)
    after = proof.footprint(conn, EXPECT, changed, time.time())
    return before, after, proof.compare(before, after)


def test_footprint_counts_runs_bytes_and_destinations(tmp_path):
    before, _after, _ = verdict(tmp_path, 5, 0)
    assert before["runs"] == 5 and before["sent"] == 25000
    assert before["destinations"][0][0] == "collect.example.com"
    assert before["hours_observed"] >= 5


def test_stopped(tmp_path):
    assert verdict(tmp_path, 5, 0)[2]["verdict"] == "stopped"


def test_reduced(tmp_path):
    assert verdict(tmp_path, 6, 1)[2]["verdict"] == "reduced"


def test_unchanged(tmp_path):
    assert verdict(tmp_path, 5, 5)[2]["verdict"] == "unchanged"


def test_waiting_without_observation_after(tmp_path):
    assert verdict(tmp_path, 5, 0, other_traffic_after=False)[2]["verdict"] == "waiting"


def test_nothing_seen(tmp_path):
    assert verdict(tmp_path, 0, 0)[2]["verdict"] == "nothing_seen"


def add_flow(conn, proc_id, name, remote, sent, when, services=None):
    conn.execute("INSERT INTO procs (id, pid, started, exe, name, services, seen_start) VALUES (?,?,?,?,?,?,1)",
                 (proc_id, proc_id, when, f"C:\\x\\{name}", name, services))
    conn.execute("INSERT INTO flows VALUES (?,?,443,'tcp',?,?,0,1,?,?)",
                 (proc_id, remote, int(when // HOUR) * HOUR, sent, when, when))


def test_shared_endpoint_does_not_count_other_programs(tmp_path):
    """Defender and OneDrive use the same Microsoft collection address as the telemetry service.
    Their traffic is not evidence that the telemetry service is still active."""
    conn = make_db(tmp_path, 0, 0, time.time() - 6 * HOUR)
    when = time.time() - 2 * HOUR
    add_flow(conn, 900, "MpDefenderCoreService.exe", "203.0.113.50", 777, when)
    expect = {"services": ["DiagTrack"]}
    mark = proof.footprint(conn, expect, time.time() - 5 * HOUR, time.time())
    assert mark["sent"] == 0 and not mark["active"]
    mark = proof.footprint(conn, EXPECT, time.time() - 5 * HOUR, time.time())
    assert "MpDefenderCoreService.exe" not in dict(mark["senders"])


def test_senders_count_only_traffic_to_listed_domains(tmp_path):
    conn = make_db(tmp_path, 0, 0, time.time() - 6 * HOUR)
    when = time.time() - 2 * HOUR
    add_flow(conn, 900, "msedge.exe", "203.0.113.50", 500, when)        # to collect.example.com
    add_flow(conn, 901, "msedge.exe", "198.51.100.7", 9000, when)       # an ordinary web page
    add_flow(conn, 902, "chrome.exe", "203.0.113.50", 300, when)        # not a named sender
    expect = {"domains": ["collect.example.com"], "senders": {"processes": ["msedge.exe"]}}
    mark = proof.footprint(conn, expect, time.time() - 5 * HOUR, time.time())
    assert mark["sent"] == 500
    assert mark["runs"] == 0                                            # a sender starting is not evidence
    assert mark["destinations"][0][0] == "collect.example.com"


def test_stale_name_is_not_the_destination(tmp_path):
    """A CDN address that resolved to a collection host days ago may serve anything today."""
    conn = make_db(tmp_path, 0, 0, time.time() - 6 * HOUR)
    long_ago = time.time() - 5 * 24 * HOUR
    conn.execute("INSERT INTO names VALUES ('192.0.2.9', 'collect.example.com', 'dns', ?, ?)", (long_ago, long_ago))
    add_flow(conn, 900, "msedge.exe", "192.0.2.9", 400, time.time() - 2 * HOUR)
    expect = {"domains": ["collect.example.com"], "senders": {"processes": ["msedge.exe"]}}
    assert proof.footprint(conn, expect, time.time() - 5 * HOUR, time.time())["sent"] == 0


def test_expect_without_senders_is_refused():
    import pytest

    with pytest.raises(ValueError, match="domains need"):
        proof.validate_expect({"domains": ["bing.com"]}, "x")
    with pytest.raises(ValueError, match="unknown expect keys"):
        proof.validate_expect({"processes": ["a.exe"], "process_domains": ["b.com"]}, "x")
    proof.validate_expect({"domains": ["bing.com"], "senders": {"processes": ["SearchHost.exe"]}}, "x")


def test_catalogue_expect_blocks_are_valid():
    switches.load_catalogue.cache_clear()
    catalogue = switches.load_catalogue()
    assert sum(1 for item in catalogue.values() if item.expect) >= 20


def test_now_verdicts():
    quiet = {"hours_observed": 5, "active": False}
    busy = {"hours_observed": 5, "active": True}
    assert proof.now_verdict("private", busy)["verdict"] == "off_but_active"
    assert proof.now_verdict("private", quiet)["verdict"] == "off_and_quiet"
    assert proof.now_verdict("exposed", busy)["verdict"] == "on_and_active"
    assert proof.now_verdict("exposed", {"hours_observed": 0, "active": False})["verdict"] == "waiting"


def test_report_uses_journal_for_before_and_after(tmp_path):
    changed = time.time() - 6 * HOUR
    conn = make_db(tmp_path, 4, 0, changed)
    backend = SandboxBackend()
    switch = switches.load_catalogue()["svc.wer"]
    # Reuse a real catalogue entry: pretend its service is our beacon.
    conn.execute("UPDATE procs SET services = 'WerSvc' WHERE name = 'beacon.exe'")
    conn.commit()
    switches.write_check(switch.checks[0], "manual", backend)
    result = switches.apply(switch, backend, tmp_path / "journal.db")
    import sqlite3
    journal = sqlite3.connect(tmp_path / "journal.db")
    journal.execute("UPDATE switch_journal SET applied = ? WHERE id = ?", (changed, result["journal_id"]))
    journal.commit()
    journal.close()
    report = proof.report(24, conn=conn, backend=backend, journal_file=tmp_path / "journal.db")
    item = next(entry for entry in report["items"] if entry["id"] == "svc.wer")
    assert item["state"] == "private"
    assert item["change"]["verdict"] == "stopped"
    assert item["change"]["before"]["runs"] == 4
