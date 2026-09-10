"""Internet-connectivity probing for Bastion.

Rules:
* Read-only and privacy-first: a probe is a plain TCP connect to a public
  endpoint - no data is sent, nothing is uploaded.
* Short timeouts so a probe never blocks the interface (callers run it on a
  worker thread in the UI).
* The verdict logic is pure and fully testable; socket I/O is isolated in
  probe_host so tests can inject fakes.
"""
from dataclasses import dataclass
import socket
import time

# Well-known public endpoints used for the probes. 1.1.1.1/8.8.8.8 are IPs so
# the probe still works when DNS itself is broken; example.com adds a
# DNS + 443 path.
DEFAULT_PROBE_HOSTS = (
    ("1.1.1.1", 443),   # Cloudflare DNS over HTTPS port
    ("8.8.8.8", 53),    # Google DNS (UDP service, TCP connect still validates route)
    ("example.com", 443),
)
PROBE_TIMEOUT_SECONDS = 3.0


@dataclass(frozen=True)
class ProbeResult:
    host: str
    port: int
    ok: bool
    latency_ms: float | None
    error: str = ""


@dataclass(frozen=True)
class ConnectivityReport:
    online: bool
    probes: tuple[ProbeResult, ...]
    detail: str

    @property
    def latency_ms(self) -> float | None:
        for probe in self.probes:
            if probe.ok and probe.latency_ms is not None:
                return probe.latency_ms
        return None


def probe_host(host: str, port: int, timeout: float = PROBE_TIMEOUT_SECONDS,
               connect=None) -> ProbeResult:
    """Attempt one TCP connect and measure latency.

    connect is injectable for tests (defaults to socket.create_connection).
    """
    connect = connect or socket.create_connection
    started = time.monotonic()
    try:
        with connect((host, port), timeout=timeout):
            latency = (time.monotonic() - started) * 1000.0
            return ProbeResult(host=host, port=port, ok=True,
                               latency_ms=round(latency, 1))
    except OSError as error:
        return ProbeResult(host=host, port=port, ok=False,
                           latency_ms=None, error=str(error))


def evaluate(probes) -> ConnectivityReport:
    """Pure verdict from probe results: online if at least one connected."""
    probes = tuple(probes)
    online = any(probe.ok for probe in probes)
    if online:
        latency = next((probe.latency_ms for probe in probes if probe.ok), None)
        detail = "Online" if latency is None else f"Online ({latency:.0f} ms via a public endpoint)"
    else:
        detail = "Offline - no public endpoint responded"
    return ConnectivityReport(online=online, probes=probes, detail=detail)


def check_connectivity(hosts=DEFAULT_PROBE_HOSTS,
                       timeout: float = PROBE_TIMEOUT_SECONDS,
                       connect=None) -> ConnectivityReport:
    """Probe each public endpoint until one connects, then report."""
    results = []
    for host, port in hosts:
        result = probe_host(host, port, timeout=timeout, connect=connect)
        results.append(result)
        if result.ok:
            break  # first success is enough - the rest would be redundant
    return evaluate(results)
