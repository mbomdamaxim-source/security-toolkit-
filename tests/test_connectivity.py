"""Tests for internet-connectivity probing (no network required)."""
from core.connectivity import (
    ProbeResult,
    check_connectivity,
    evaluate,
    probe_host,
)


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_evaluate_online_when_any_probe_succeeds():
    report = evaluate([
        ProbeResult(host="1.1.1.1", port=443, ok=False, latency_ms=None, error="timeout"),
        ProbeResult(host="8.8.8.8", port=53, ok=True, latency_ms=12.0),
    ])
    assert report.online is True
    assert report.latency_ms == 12.0
    assert "Online" in report.detail


def test_evaluate_offline_when_all_fail():
    report = evaluate([
        ProbeResult(host="1.1.1.1", port=443, ok=False, latency_ms=None, error="timeout"),
        ProbeResult(host="8.8.8.8", port=53, ok=False, latency_ms=None, error="refused"),
    ])
    assert report.online is False
    assert "Offline" in report.detail
    assert report.latency_ms is None


def test_evaluate_empty_is_offline():
    report = evaluate([])
    assert report.online is False


def test_probe_host_success_uses_injected_connect():
    calls = []

    def fake_connect(target, timeout):
        calls.append((target, timeout))
        return FakeSocket()

    result = probe_host("example.com", 443, timeout=1.5, connect=fake_connect)
    assert result.ok is True and result.latency_ms is not None
    assert calls == [(("example.com", 443), 1.5)]


def test_probe_host_failure_reports_error():
    def broken_connect(target, timeout):
        raise ConnectionRefusedError("no route")

    result = probe_host("1.1.1.1", 443, connect=broken_connect)
    assert result.ok is False and result.error


def test_check_connectivity_stops_after_first_success():
    def fake_connect(target, timeout):
        host = target[0]
        if host == "1.1.1.1":
            raise ConnectionRefusedError("down")
        return FakeSocket()

    report = check_connectivity(
        hosts=[("1.1.1.1", 443), ("8.8.8.8", 53), ("example.com", 443)],
        connect=fake_connect,
    )
    assert report.online is True
    assert len(report.probes) == 2  # stopped after 8.8.8.8 succeeded


def test_check_connectivity_all_down():
    def fake_connect(target, timeout):
        raise OSError("offline")

    report = check_connectivity(connect=fake_connect)
    assert report.online is False
    # every host was tried, none succeeded
    assert len(report.probes) == 3
    assert all(not probe.ok for probe in report.probes)
