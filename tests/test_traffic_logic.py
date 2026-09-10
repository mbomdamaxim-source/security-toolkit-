"""Tests for Traffic Dashboard logic: snapshots, rates and analysis."""
import json

import pytest

from modules.traffic.logic import (
    SCAN_SCRIPT,
    AdapterRate,
    TrafficError,
    analyze_connections,
    compute_rates,
    encode_powershell_command,
    format_bits_per_second,
    is_public_remote,
    is_suspicious_path,
    parse_snapshot,
    run_snapshot,
    summarize,
    top_talkers,
)

SAMPLE = {
    "adapters": [
        {"Name": "Ethernet0", "Status": "Up", "LinkSpeed": "1 Gbps",
         "ReceivedBytes": 1_000_000_000, "SentBytes": 500_000_000},
        {"Name": "Wi-Fi", "Status": "Up", "LinkSpeed": "866 Mbps",
         "ReceivedBytes": 200_000_000, "SentBytes": 300_000_000},
    ],
    "connections": [
        {"LocalAddress": "192.168.1.10", "LocalPort": 51234, "RemoteAddress": "8.8.8.8",
         "RemotePort": 443, "ProcessId": 7001, "ProcessName": "chrome",
         "ProcessPath": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
        {"LocalAddress": "192.168.1.10", "LocalPort": 50001, "RemoteAddress": "198.51.100.23",
         "RemotePort": 8888, "ProcessId": 7111, "ProcessName": "updater",
         "ProcessPath": "C:\\Users\\Maxim\\AppData\\Local\\Temp\\updater.exe"},
        {"LocalAddress": "192.168.1.10", "LocalPort": 50002, "RemoteAddress": "192.168.1.1",
         "RemotePort": 53, "ProcessId": 7002, "ProcessName": "dns",
         "ProcessPath": "C:\\Windows\\System32\\svchost.exe"},
        {"LocalAddress": "192.168.1.10", "LocalPort": 50003, "RemoteAddress": "142.250.10.5",
         "RemotePort": 443, "ProcessId": 7001, "ProcessName": "chrome",
         "ProcessPath": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
    ],
    "time": 1_700_000_000,
}


def test_script_uses_structured_cmdlets():
    for token in ("Get-NetAdapter", "Get-NetAdapterStatistics",
                  "Get-NetTCPConnection", "ConvertTo-Json"):
        assert token in SCAN_SCRIPT
    assert "netstat" not in SCAN_SCRIPT.lower()


def test_encode_command_utf16le():
    encoded = encode_powershell_command("Write-Output 'x'")
    assert encoded == __import__("base64").b64encode(
        "Write-Output 'x'".encode("utf-16-le")
    ).decode()


def test_parse_snapshot():
    snapshot = parse_snapshot(SAMPLE)
    assert len(snapshot.adapters) == 2
    assert len(snapshot.connections) == 4
    assert snapshot.adapters[0].name == "Ethernet0"
    assert snapshot.taken_at


def test_parse_snapshot_single_object_tolerance():
    single = {"adapters": {"Name": "Ethernet0", "Status": "Up", "LinkSpeed": "1 Gbps",
                           "ReceivedBytes": 10, "SentBytes": 5},
              "connections": []}
    snapshot = parse_snapshot(single)
    assert len(snapshot.adapters) == 1


def test_compute_rates_known_delta():
    previous = parse_snapshot(SAMPLE)
    later_payload = json.loads(json.dumps(SAMPLE))
    later_payload["adapters"][0]["ReceivedBytes"] = 1_000_000_000 + 1_000_000  # +1 MB
    later_payload["adapters"][0]["SentBytes"] = 500_000_000 + 500_000          # +500 KB
    current = parse_snapshot(later_payload)
    rates = compute_rates(previous, current, interval_hint=10.0)
    ethernet = next(r for r in rates if r.name == "Ethernet0")
    assert isinstance(ethernet, AdapterRate)
    assert ethernet.down_bps == pytest.approx(1_000_000 * 8 / 10.0)
    assert ethernet.up_bps == pytest.approx(500_000 * 8 / 10.0)
    assert ethernet.seconds == 10.0


def test_compute_rates_ignores_new_adapters_and_counter_reset():
    previous = parse_snapshot(SAMPLE)
    later_payload = json.loads(json.dumps(SAMPLE))
    later_payload["adapters"][0]["ReceivedBytes"] = 10  # counter reset -> diff clamps to 0
    later_payload["adapters"].append({"Name": "NewIf", "Status": "Up", "LinkSpeed": "100 Mbps",
                                      "ReceivedBytes": 99, "SentBytes": 99})
    current = parse_snapshot(later_payload)
    rates = compute_rates(previous, current, interval_hint=5.0)
    assert all(r.name != "NewIf" for r in rates)
    ethernet = next(r for r in rates if r.name == "Ethernet0")
    assert ethernet.down_bps == 0.0  # clamped, not negative


def test_format_bits_per_second():
    assert format_bits_per_second(500) == "500 bps"
    assert format_bits_per_second(5_000) == "5.0 Kbps"
    assert format_bits_per_second(2_000_000) == "2.00 Mbps"
    assert format_bits_per_second(1_500_000_000) == "1.50 Gbps"


def test_is_public_remote():
    assert is_public_remote("8.8.8.8")
    assert not is_public_remote("192.168.1.10")
    assert not is_public_remote("10.0.0.5")
    assert not is_public_remote("172.16.0.5")
    assert is_public_remote("172.32.0.5")
    assert not is_public_remote("127.0.0.1")
    assert not is_public_remote("")


def test_is_suspicious_path():
    assert is_suspicious_path("C:\\Users\\x\\AppData\\Local\\Temp\\a.exe")
    assert is_suspicious_path("C:\\Users\\x\\Downloads\\a.exe")
    assert not is_suspicious_path("C:\\Windows\\System32\\svchost.exe")
    assert not is_suspicious_path("C:\\Program Files\\App\\app.exe")


def test_top_talkers_groups_by_process():
    snapshot = parse_snapshot(SAMPLE)
    talkers = top_talkers(snapshot.connections)
    chrome = next(t for t in talkers if t.process == "chrome")
    assert chrome.connections == 2 and chrome.distinct_remotes == 2


def test_analyze_connections_heuristics():
    snapshot = parse_snapshot(SAMPLE)
    findings = analyze_connections(snapshot.connections)
    high = [f for f in findings if f.severity == "high"]
    assert len(high) == 1 and "updater" in high[0].title
    # chrome on 443 public, dns to private gateway -> no finding
    assert not any("chrome" in f.title for f in findings)
    assert not any("dns" in f.title for f in findings)


def test_summarize_counts():
    snapshot = parse_snapshot(SAMPLE)
    summary = summarize(snapshot)
    assert summary["adapters"] == 2
    assert summary["connections"] == 4
    assert summary["public"] == 3
    assert summary["private"] == 1
    assert summary["anomalies"] >= 1
    assert summary["top"][0].process == "chrome"


def test_run_snapshot_success(monkeypatch):
    class FakeCompleted:
        returncode = 0
        stdout = json.dumps(SAMPLE)
        stderr = ""

    monkeypatch.setattr("modules.traffic.logic.subprocess.run",
                        lambda *a, **k: FakeCompleted())
    payload = run_snapshot()
    assert len(payload["adapters"]) == 2


def test_run_snapshot_failures(monkeypatch):
    class Failed:
        returncode = 1
        stdout = ""
        stderr = ""

    monkeypatch.setattr("modules.traffic.logic.subprocess.run",
                        lambda *a, **k: Failed())
    with pytest.raises(TrafficError, match="failed"):
        run_snapshot()

    def missing(*a, **k):
        raise FileNotFoundError("powershell.exe")

    monkeypatch.setattr("modules.traffic.logic.subprocess.run", missing)
    with pytest.raises(TrafficError, match="Windows only"):
        run_snapshot()


def test_diff_connections_detects_new_and_closed():
    from modules.traffic.logic import diff_connections
    prev = parse_snapshot(SAMPLE)
    changed = json.loads(json.dumps(SAMPLE))
    # drop chrome's second connection, add a brand new one
    changed["connections"] = [c for c in changed["connections"]
                              if not (c["ProcessId"] == 7001 and c["RemotePort"] == 443 and c["RemoteAddress"] != "8.8.8.8")]
    changed["connections"].append(
        {"LocalAddress": "192.168.1.10", "LocalPort": 50099, "RemoteAddress": "203.0.113.5",
         "RemotePort": 8443, "ProcessId": 7777, "ProcessName": "newtool",
         "ProcessPath": "C:\\Tools\\newtool.exe"})
    curr = parse_snapshot(changed)
    diffs = diff_connections(prev, curr)
    kinds = {d.kind for d in diffs}
    assert "new" in kinds and "closed" in kinds
    assert diff_connections(None, curr) == ()


def test_new_process_alerts_flags_suspicious_and_normal():
    from modules.traffic.logic import new_process_alerts
    prev = parse_snapshot(SAMPLE)
    changed = json.loads(json.dumps(SAMPLE))
    changed["connections"] = [c for c in changed["connections"] if c["ProcessId"] != 7111]
    changed["connections"].append(
        {"LocalAddress": "192.168.1.10", "LocalPort": 50001, "RemoteAddress": "198.51.100.23",
         "RemotePort": 8888, "ProcessId": 8888, "ProcessName": "strange",
         "ProcessPath": "C:\\Users\\Maxim\\AppData\\Local\\Temp\\strange.exe"})
    changed["connections"].append(
        {"LocalAddress": "192.168.1.10", "LocalPort": 50002, "RemoteAddress": "203.0.113.9",
         "RemotePort": 443, "ProcessId": 9999, "ProcessName": "notepad",
         "ProcessPath": "C:\\Windows\\System32\\notepad.exe"})
    curr = parse_snapshot(changed)
    alerts = new_process_alerts(prev, curr)
    high = [a for a in alerts if a.severity == "high"]
    low = [a for a in alerts if a.severity == "low"]
    assert any("strange" in a.title for a in high)
    assert any("notepad" in a.title for a in low)
    assert new_process_alerts(None, curr) == ()


def _snapshot_with_connections(payload, time_offset):
    p = json.loads(json.dumps(payload))
    base = p.get("_t", 1_752_000_000)
    p["_t"] = base + time_offset
    snap = parse_snapshot(p)
    return snap


def test_beacon_detector_finds_regular_rhythm():
    from modules.traffic.logic import detect_beacons, beacon_anomalies
    # build 4 snapshots where "agent" appears every ~10s to the same remote
    samples = []
    for i in range(4):
        p = json.loads(json.dumps(SAMPLE))
        conns = [c for c in p["connections"] if c["ProcessName"] != "updater"]
        if i % 1 == 0:
            conns.append(
                {"LocalAddress": "192.168.1.10", "LocalPort": 50000 + i, "RemoteAddress": "203.0.113.77",
                 "RemotePort": 4444, "ProcessId": 6000 + i, "ProcessName": "agent",
                 "ProcessPath": "C:\\Windows\\agent.exe"})
        p["connections"] = conns
        p["time"] = 1_752_000_000 + i * 10
        samples.append(parse_snapshot(p))
    candidates = detect_beacons(samples, min_samples=3)
    agent = [c for c in candidates if c.process == "agent" and c.remote == "203.0.113.77"]
    assert agent, "agent beacon not detected"
    assert agent[0].jitter < 0.05 and agent[0].median_interval == 10.0
    anomalies = beacon_anomalies(agent)
    assert anomalies and anomalies[0].severity == "high"
    # The sample's static connections are also regular, so they are flagged too;
    # a tight threshold must not remove the true beacons.
    flagged = beacon_anomalies(candidates, jitter_threshold=0.05)
    assert any("agent" in finding.title for finding in flagged)
    # A threshold below zero excludes every candidate (all jitters are >= 0).
    assert beacon_anomalies(candidates, jitter_threshold=-0.01) == ()


def test_detect_beacons_needs_min_samples():
    from modules.traffic.logic import detect_beacons
    assert detect_beacons([parse_snapshot(SAMPLE)]) == ()
    assert detect_beacons([]) == ()


def test_export_snapshot_csv(tmp_path):
    from modules.traffic.report import export_snapshot_csv
    snapshot = parse_snapshot(SAMPLE)
    path = export_snapshot_csv(tmp_path / "traffic.csv", snapshot)
    assert path.exists() and path.stat().st_size > 0
    text = path.read_text(encoding="utf-8")
    assert "Connections" in text and "chrome" in text and "Findings" in text
    import pytest as _pytest
    with _pytest.raises(ValueError):
        export_snapshot_csv(tmp_path / "traffic.txt", snapshot)
