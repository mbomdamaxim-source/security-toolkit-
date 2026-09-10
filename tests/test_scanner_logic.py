"""Tests for Scan Reports logic: parsing, analysis, drift and PowerShell invocation."""
from datetime import date, timedelta
import json

import pytest

from modules.scanner.logic import (
    SCAN_SCRIPT,
    ScanError,
    analyze_connections,
    analyze_patches,
    analyze_ports,
    build_report,
    diff_reports,
    encode_powershell_command,
    is_suspicious_path,
    load_allowlist,
    months_since,
    parse_connections,
    parse_firewall,
    parse_patches,
    parse_ports,
    parse_services,
    run_local_scan,
    save_allowlist,
)

SAMPLE_PAYLOAD = {
    "ports": [
        {"Protocol": "TCP", "LocalAddress": "127.0.0.1", "LocalPort": 135,
         "ProcessId": 4, "ProcessName": "System", "ProcessPath": "C:\\Windows\\System32\\", "Allowed": None},
        {"Protocol": "TCP", "LocalAddress": "0.0.0.0", "LocalPort": 3389,
         "ProcessId": 1234, "ProcessName": "svchost", "ProcessPath": "C:\\Windows\\System32\\svchost.exe",
         "ServiceName": "TermService", "Allowed": True},
        {"Protocol": "TCP", "LocalAddress": "0.0.0.0", "LocalPort": 445,
         "ProcessId": 4, "ProcessName": "System", "ProcessPath": "C:\\Windows\\System32\\", "Allowed": True},
        {"Protocol": "TCP", "LocalAddress": "0.0.0.0", "LocalPort": 22,
         "ProcessId": 99, "ProcessName": "sshd", "ProcessPath": "C:\\Windows\\System32\\OpenSSH\\sshd.exe",
         "Allowed": False},
        {"Protocol": "TCP", "LocalAddress": "127.0.0.1", "LocalPort": 54321,
         "ProcessId": 4321, "ProcessName": "myapp", "ProcessPath": "C:\\Program Files\\myapp\\", "Allowed": None},
    ],
    "udp_ports": [
        {"Protocol": "UDP", "LocalAddress": "0.0.0.0", "LocalPort": 5353,
         "ProcessId": 4, "ProcessName": "System", "ProcessPath": "", "Allowed": None},
    ],
    "connections": [
        {"LocalAddress": "192.168.1.5", "LocalPort": 51234, "RemoteAddress": "8.8.8.8",
         "RemotePort": 443, "ProcessId": 900, "ProcessName": "chrome",
         "ProcessPath": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
        {"LocalAddress": "192.168.1.5", "LocalPort": 50000, "RemoteAddress": "45.33.10.5",
         "RemotePort": 8888, "ProcessId": 1111, "ProcessName": "updater",
         "ProcessPath": "C:\\Users\\x\\AppData\\Local\\Temp\\updater.exe"},
    ],
    "firewall": {"Available": True, "Enabled": True, "EnabledProfileCount": 2,
                 "DefaultInbound": "Block", "DefaultOutbound": "Allow"},
    "services": [
        {"Name": "WinDefend", "DisplayName": "Windows Defender Antivirus",
         "Status": "Running", "StartType": "Automatic"},
        {"Name": "wscsvc", "DisplayName": "Security Center",
         "Status": "Stopped", "StartType": "Manual"},
    ],
    "patches": [
        {"HotFixId": "KB5000001", "Description": "Security Update", "InstalledOn": "2026-07-01"},
    ],
}


def test_script_uses_structured_cmdlets_not_text_parsing():
    for token in ("Get-NetTCPConnection", "Get-NetUDPEndpoint", "Get-NetFirewallRule",
                  "Get-NetFirewallProfile", "Get-CimInstance", "Get-Service", "Get-HotFix",
                  "ConvertTo-Json"):
        assert token in SCAN_SCRIPT
    assert "netstat" not in SCAN_SCRIPT.lower()


def test_encode_command_is_utf16le_base64():
    encoded = encode_powershell_command("Write-Output 'ok'")
    assert encoded == __import__("base64").b64encode("Write-Output 'ok'".encode("utf-16-le")).decode()


def test_parse_ports_merges_tcp_and_udp():
    ports = parse_ports(SAMPLE_PAYLOAD)
    by_key = {(p.protocol, p.local_port): p for p in ports}
    assert ("TCP", 3389) in by_key and by_key[("TCP", 3389)].allowed is True
    assert by_key[("TCP", 3389)].service_name == "TermService"
    assert ("UDP", 5353) in by_key
    assert by_key[("TCP", 22)].allowed is False


def test_parse_services_patches_firewall():
    assert [s.name for s in parse_services(SAMPLE_PAYLOAD)] == ["WinDefend", "wscsvc"]
    assert parse_patches(SAMPLE_PAYLOAD)[0].hotfix_id == "KB5000001"
    fw = parse_firewall(SAMPLE_PAYLOAD)
    assert fw.enabled and fw.default_inbound == "Block" and fw.enabled_profile_count == 2


def test_analyze_ports_firewall_truth():
    ports = parse_ports(SAMPLE_PAYLOAD)
    fw = parse_firewall(SAMPLE_PAYLOAD)
    findings = analyze_ports(ports, firewall=fw)
    titles = [f.title for f in findings]
    # RDP allowed through -> high
    assert any("3389" in t and "reachable" in t for t in titles)
    assert any(f.severity == "high" for f in findings if "3389" in f.title)
    # SMB allowed -> medium
    assert any(f.severity == "medium" for f in findings if "445" in f.title)
    # SSH blocked by the firewall -> downgraded to info, not medium/high
    ssh = [f for f in findings if "22" in f.title]
    assert ssh and ssh[0].severity == "info" and "firewall blocks it" in ssh[0].title
    # Loopback listener -> no finding
    assert not any("54321" in t for t in titles)


def test_analyze_ports_allowlist_suppresses_findings():
    ports = parse_ports(SAMPLE_PAYLOAD)
    fw = parse_firewall(SAMPLE_PAYLOAD)
    allow = {("TCP", 3389), ("TCP", 445)}
    titles = [f.title for f in analyze_ports(ports, firewall=fw, allowlist=allow)]
    assert not any("3389" in t or "445" in t for t in titles)
    assert any("22" in t for t in titles)


def test_analyze_connections_heuristics():
    conns = parse_connections(SAMPLE_PAYLOAD)
    findings = analyze_connections(conns)
    # chrome -> 8.8.8.8:443 is normal -> no finding
    assert not any("chrome" in f.title for f in findings)
    # updater.exe from AppData/Temp -> 45.33.10.5:8888 -> high
    updater = [f for f in findings if "updater" in f.title]
    assert updater and updater[0].severity == "high"


def test_is_suspicious_path():
    assert is_suspicious_path("C:\\Users\\me\\AppData\\Local\\Temp\\x.exe")
    assert is_suspicious_path("C:\\Users\\me\\Downloads\\x.exe")
    assert not is_suspicious_path("C:\\Windows\\System32\\svchost.exe")
    assert not is_suspicious_path("C:\\Program Files\\App\\app.exe")


def test_months_since():
    assert months_since((date.today()).isoformat(), today=date.today()) == 0
    assert months_since("2025-03-15", today=date(2026, 9, 2)) == 17
    assert months_since("not-a-date", today=date(2026, 9, 2)) == 0


def test_analyze_patches_recency():
    recent = (date.today() - timedelta(days=3)).isoformat()
    assert analyze_patches(parse_patches({"patches": [{"HotFixId": "KB1", "Description": "", "InstalledOn": recent}]}))[0].severity == "info"
    assert analyze_patches(parse_patches({"patches": [{"HotFixId": "KB1", "Description": "", "InstalledOn": "2024-01-01"}]}))[0].severity == "high"
    assert analyze_patches(())[0].severity == "medium"


def test_build_report_full_pipeline():
    report = build_report(SAMPLE_PAYLOAD, scanned_at="2026-09-02T10:00:00+00:00")
    assert len(report.ports) == 6  # 5 TCP + 1 UDP
    assert len(report.connections) == 2
    assert report.firewall.enabled
    assert any(finding.severity == "high" for finding in report.findings)
    assert any("updater" in finding.title for finding in report.findings)


def test_firewall_disabled_is_high_finding():
    payload = json.loads(json.dumps(SAMPLE_PAYLOAD))
    payload["firewall"] = {"Available": True, "Enabled": False, "EnabledProfileCount": 0,
                           "DefaultInbound": "Block", "DefaultOutbound": "Allow"}
    report = build_report(payload)
    assert any("not enabled" in f.title for f in report.findings)
    assert any(f.severity == "high" and "not enabled" in f.title for f in report.findings)


def test_diff_reports_detects_changes():
    previous = build_report(SAMPLE_PAYLOAD, scanned_at="2026-09-01T10:00:00+00:00")
    changed = json.loads(json.dumps(SAMPLE_PAYLOAD))
    # add a new listener + stop WinDefend
    changed["ports"].append({"Protocol": "TCP", "LocalAddress": "0.0.0.0", "LocalPort": 8080,
                             "ProcessId": 777, "ProcessName": "webserver",
                             "ProcessPath": "C:\\app\\webserver.exe", "Allowed": True})
    changed["services"][0]["Status"] = "Stopped"
    current = build_report(changed, scanned_at="2026-09-02T10:00:00+00:00")
    drift = diff_reports(previous, current)
    kinds = [d.kind for d in drift]
    assert "added_listener" in kinds and "service_status" in kinds
    added = [d for d in drift if d.kind == "added_listener"]
    assert any("8080" in d.title for d in added)
    assert diff_reports(None, current) == ()


def test_allowlist_round_trip(tmp_path):
    path = tmp_path / "allowlist.json"
    assert load_allowlist(path) == set()
    save_allowlist(path, {("TCP", 3389), ("UDP", 5353)})
    assert load_allowlist(path) == {("TCP", 3389), ("UDP", 5353)}
    path.write_text("{broken", encoding="utf-8")
    assert load_allowlist(path) == set()


def test_run_local_scan_success(monkeypatch):
    class FakeCompleted:
        returncode = 0
        stdout = json.dumps(SAMPLE_PAYLOAD)
        stderr = ""

    def fake_run(*args, **kwargs):
        return FakeCompleted()

    monkeypatch.setattr("modules.scanner.logic.subprocess.run", fake_run)
    payload = run_local_scan()
    assert payload["ports"][0]["LocalPort"] == 135


def test_run_local_scan_failures(monkeypatch):
    class Failed:
        returncode = 1
        stdout = ""
        stderr = "Access denied"

    def fake_run_fail(*args, **kwargs):
        return Failed()

    monkeypatch.setattr("modules.scanner.logic.subprocess.run", fake_run_fail)
    with pytest.raises(ScanError, match="failed"):
        run_local_scan()

    def fake_run_missing(*args, **kwargs):
        raise FileNotFoundError("powershell.exe")

    monkeypatch.setattr("modules.scanner.logic.subprocess.run", fake_run_missing)
    with pytest.raises(ScanError, match="Windows only"):
        run_local_scan()

    class BadJson:
        returncode = 0
        stdout = "not json"
        stderr = ""

    def fake_run_bad(*args, **kwargs):
        return BadJson()

    monkeypatch.setattr("modules.scanner.logic.subprocess.run", fake_run_bad)
    with pytest.raises(ScanError, match="unreadable"):
        run_local_scan()


def test_scan_docx_export(tmp_path):
    from modules.scanner.report import export_scan_docx

    report = build_report(SAMPLE_PAYLOAD, scanned_at="2026-09-02T10:00:00+00:00")
    path = export_scan_docx(tmp_path / "scan.docx", report)
    assert path.exists() and path.stat().st_size > 0

    import pytest as _pytest
    with _pytest.raises(ValueError):
        export_scan_docx(tmp_path / "scan.txt", report)


def test_exposure_summary_math_and_posture():
    from datetime import timedelta as _td
    from modules.scanner.logic import exposure_summary

    payload = json.loads(json.dumps(SAMPLE_PAYLOAD))
    # Pin the patch date so recency is deterministic regardless of run date.
    payload["patches"][0]["InstalledOn"] = (date.today() - _td(days=3)).isoformat()
    report = build_report(payload, scanned_at="2026-09-02T10:00:00+00:00")
    summary = exposure_summary(report)
    # The fixture lists only WinDefend + wscsvc, so SecurityHealthService, wuauserv
    # and BITS are flagged as not running too:
    #   high=3 (RDP, updater, SecurityHealthService)
    #   medium=3 (SMB, Security Center, Windows Update)
    #   low=2 (UDP 5353, BITS)
    #   info=2 (SSH blocked by firewall, recent hotfix)
    # Score = 100 - 3*20 - 3*10 - 2*4 = 2.
    assert summary["counts"] == {"critical": 0, "high": 3, "medium": 3, "low": 2, "info": 2}
    assert summary["score"] == 2
    assert summary["posture"] == "Needs attention" and summary["tone"] == "danger"


def test_exposure_summary_clean_posture():
    from modules.scanner.logic import exposure_summary
    clean = {
        "ports": [{"Protocol": "TCP", "LocalAddress": "127.0.0.1", "LocalPort": 135,
                   "ProcessId": 4, "ProcessName": "System", "ProcessPath": "",
                   "ServiceName": "", "Allowed": None}],
        "firewall": {"Available": True, "Enabled": True, "EnabledProfileCount": 3,
                     "DefaultInbound": "Block", "DefaultOutbound": "Allow"},
        "services": [
            {"Name": "WinDefend", "DisplayName": "Defender", "Status": "Running", "StartType": "Automatic"},
            {"Name": "SecurityHealthService", "DisplayName": "Health", "Status": "Running", "StartType": "Automatic"},
            {"Name": "wscsvc", "DisplayName": "Center", "Status": "Running", "StartType": "Automatic"},
            {"Name": "wuauserv", "DisplayName": "Update", "Status": "Running", "StartType": "Automatic"},
            {"Name": "BITS", "DisplayName": "BITS", "Status": "Running", "StartType": "Automatic"},
        ],
        "patches": [{"HotFixId": "KB1", "Description": "", "InstalledOn": (date.today() - timedelta(days=3)).isoformat()}],
    }
    report = build_report(clean, scanned_at="2026-09-02T10:00:00+00:00")
    summary = exposure_summary(report)
    assert summary["counts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1}
    assert summary["score"] == 100
    assert summary["posture"] == "Good posture" and summary["tone"] == "success"


def test_assess_baseline_flags_exposed_smb_rdp_and_disabled_firewall():
    from modules.scanner.logic import assess_baseline
    payload = json.loads(json.dumps(SAMPLE_PAYLOAD))
    payload["firewall"] = {"Available": True, "Enabled": False, "EnabledProfileCount": 0,
                           "DefaultInbound": "Block", "DefaultOutbound": "Allow"}
    report = build_report(payload)
    baseline = assess_baseline(report)
    assert baseline["smb445"]["status"] == "fail"
    assert baseline["rdp3389"]["status"] == "fail"
    assert baseline["firewall"]["status"] == "fail"
    assert baseline["updates"]["status"] in ("pass", "fail", "unknown")
    # registry-only checks stay unknown + honest
    assert baseline["smbv1"]["status"] == "unknown"
    assert baseline["rdp_nla"]["status"] == "unknown"


def test_assess_baseline_clean_machine_passes_visible_checks():
    from modules.scanner.logic import assess_baseline
    clean = {
        "ports": [
            {"Protocol": "TCP", "LocalAddress": "127.0.0.1", "LocalPort": 445,
             "ProcessId": 4, "ProcessName": "System", "ProcessPath": "",
             "ServiceName": "", "Allowed": None},
            {"Protocol": "TCP", "LocalAddress": "0.0.0.0", "LocalPort": 3389,
             "ProcessId": 4, "ProcessName": "System", "ProcessPath": "",
             "ServiceName": "", "Allowed": False},
        ],
        "firewall": {"Available": True, "Enabled": True, "EnabledProfileCount": 3,
                     "DefaultInbound": "Block", "DefaultOutbound": "Allow"},
        "services": [
            {"Name": "WinDefend", "DisplayName": "Defender", "Status": "Running", "StartType": "Automatic"},
        ],
        "patches": [{"HotFixId": "KB1", "Description": "", "InstalledOn": (date.today() - timedelta(days=2)).isoformat()}],
    }
    report = build_report(clean)
    baseline = assess_baseline(report)
    assert baseline["smb445"]["status"] == "pass"
    assert baseline["rdp3389"]["status"] == "pass"
    assert baseline["firewall"]["status"] == "pass"
    assert baseline["defender"]["status"] == "pass"
    assert baseline["updates"]["status"] == "pass"


def test_hardening_history_round_trip_and_cap(tmp_path):
    from modules.scanner.logic import append_hardening_score, load_hardening_history
    path = tmp_path / "hardening.json"
    assert load_hardening_history(path) == []
    for score in range(0, 35):
        append_hardening_score(path, score, when=f"2026-09-{(score % 28) + 1:02d}T10:00:00")
    entries = load_hardening_history(path)
    assert len(entries) == 30 and entries[-1]["hardening"] == 34
    with pytest.raises(ValueError):
        append_hardening_score(path, 101)
    path.write_text("{broken", encoding="utf-8")
    assert load_hardening_history(path) == []
