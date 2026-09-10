"""Traffic Dashboard logic: observe this device's network activity.

Design rules:
* Read-only PowerShell snapshots only (Get-NetAdapterStatistics for byte
  counters, Get-NetTCPConnection -State Established for live connections),
  returned as structured JSON - never parsed localized text.
* No packet capture: throughput is derived from adapter byte counters
  sampled twice, so the dashboard stays lightweight and permission-light.
* Pure analysis functions are fully testable without Windows.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import subprocess

# --------------------------------------------------------------------------
# PowerShell payload (Windows PowerShell 5.1 compatible).
# Emits one JSON object: {adapters: [...], connections: [...], time: epoch}.
# --------------------------------------------------------------------------
SCAN_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'

$adapters = @()
foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
    $stats = $a | Get-NetAdapterStatistics -ErrorAction SilentlyContinue
    $rx = 0L
    $tx = 0L
    if ($null -ne $stats) {
        $rx = [long]$stats.ReceivedBytes
        $tx = [long]$stats.SentBytes
    }
    $adapters += [PSCustomObject]@{
        Name         = [string]$a.Name
        Status       = [string]$a.Status
        LinkSpeed    = [string]$a.LinkSpeed
        ReceivedBytes = $rx
        SentBytes    = $tx
    }
}

$procs = @{}
foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
    $procs[[int]$p.Id] = [PSCustomObject]@{ Name = [string]$p.ProcessName; Path = [string]$p.Path }
}
function Get-ProcessInfo([int]$id) {
    $info = $procs[[int]$id]
    if ($null -eq $info) { return [PSCustomObject]@{ Name = ''; Path = '' } }
    return $info
}

$connections = @()
foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
    $info = Get-ProcessInfo ([int]$c.OwningProcess)
    $connections += [PSCustomObject]@{
        LocalAddress  = [string]$c.LocalAddress
        LocalPort     = [int]$c.LocalPort
        RemoteAddress = [string]$c.RemoteAddress
        RemotePort    = [int]$c.RemotePort
        ProcessId     = [int]$c.OwningProcess
        ProcessName   = [string]$info.Name
        ProcessPath   = [string]$info.Path
    }
}

$out = [ordered]@{
    adapters    = $adapters
    connections = $connections
    time        = [long][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
}
ConvertTo-Json -InputObject $out -Compress -Depth 4
"""

# Ports that legitimate software commonly dials OUT to.
COMMON_OUTBOUND_PORTS = {
    21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 8080, 8443,
}

SUSPICIOUS_PATH_MARKERS = (
    "\\appdata\\",
    "\\temp\\",
    "\\downloads\\",
    "\\public\\",
    "\\desktop\\",
)


class TrafficError(RuntimeError):
    """Raised when a local snapshot cannot be taken or parsed."""


@dataclass(frozen=True)
class AdapterSample:
    name: str
    status: str
    link_speed: str
    received_bytes: int
    sent_bytes: int


@dataclass(frozen=True)
class ConnectionRecord:
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    process_id: int
    process_name: str
    process_path: str


@dataclass(frozen=True)
class TrafficSnapshot:
    taken_at: str                 # ISO timestamp
    adapters: tuple[AdapterSample, ...]
    connections: tuple[ConnectionRecord, ...]


@dataclass(frozen=True)
class AdapterRate:
    """Throughput measured between two snapshots for one adapter."""
    name: str
    status: str
    link_speed: str
    seconds: float
    down_bps: float               # bytes/sec *8
    up_bps: float
    received_bytes: int
    sent_bytes: int


@dataclass(frozen=True)
class Anomaly:
    severity: str                 # info | low | medium | high
    title: str
    detail: str


@dataclass(frozen=True)
class Talker:
    process: str
    connections: int
    distinct_remotes: int
    path: str = ""


# --------------------------------------------------------------------------
# Invocation + parsing (pure parts testable)
# --------------------------------------------------------------------------
def encode_powershell_command(script: str) -> str:
    import base64
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def run_snapshot(powershell: str = "powershell.exe", timeout: int = 60) -> dict:
    try:
        completed = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
             "Bypass", "-EncodedCommand", encode_powershell_command(SCAN_SCRIPT)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as error:
        raise TrafficError(
            f"PowerShell ({powershell}) was not found. Traffic Dashboard runs on Windows only."
        ) from error
    except subprocess.TimeoutExpired as error:
        raise TrafficError("The traffic snapshot timed out.") from error
    if completed.returncode != 0:
        raise TrafficError("The traffic snapshot failed.")
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as error:
        raise TrafficError("The snapshot returned unreadable output.") from error
    if not isinstance(payload, dict):
        raise TrafficError("The snapshot returned an unexpected structure.")
    return payload


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _text(value) -> str:
    return "" if value is None else str(value)


def _int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_snapshot(payload: dict) -> TrafficSnapshot:
    adapters = []
    for row in _as_list(payload.get("adapters")):
        if not isinstance(row, dict):
            continue
        adapters.append(AdapterSample(
            name=_text(row.get("Name")),
            status=_text(row.get("Status")),
            link_speed=_text(row.get("LinkSpeed")),
            received_bytes=_int(row.get("ReceivedBytes")),
            sent_bytes=_int(row.get("SentBytes")),
        ))
    connections = []
    for row in _as_list(payload.get("connections")):
        if not isinstance(row, dict):
            continue
        connections.append(ConnectionRecord(
            local_address=_text(row.get("LocalAddress")),
            local_port=_int(row.get("LocalPort")),
            remote_address=_text(row.get("RemoteAddress")),
            remote_port=_int(row.get("RemotePort")),
            process_id=_int(row.get("ProcessId")),
            process_name=_text(row.get("ProcessName")),
            process_path=_text(row.get("ProcessPath")),
        ))
    epoch = payload.get("time")
    if isinstance(epoch, (int, float)) and epoch > 0:
        taken_at = datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat(timespec="seconds")
    else:
        taken_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return TrafficSnapshot(
        taken_at=taken_at,
        adapters=tuple(adapters),
        connections=tuple(connections),
    )


def snapshot_now(powershell: str = "powershell.exe", timeout: int = 60) -> TrafficSnapshot:
    return parse_snapshot(run_snapshot(powershell=powershell, timeout=timeout))


# --------------------------------------------------------------------------
# Throughput between two snapshots
# --------------------------------------------------------------------------
def _diff(previous: int, current: int) -> int:
    return max(0, current - previous)


def compute_rates(previous: TrafficSnapshot, current: TrafficSnapshot,
                  interval_hint: float | None = None) -> tuple[AdapterRate, ...]:
    """Compute per-adapter throughput from two byte-counter snapshots."""
    seconds = interval_hint
    if seconds is None:
        try:
            previous_time = datetime.fromisoformat(previous.taken_at)
            current_time = datetime.fromisoformat(current.taken_at)
            seconds = max(0.1, (current_time - previous_time).total_seconds())
        except (ValueError, TypeError):
            seconds = 1.0
    by_name = {adapter.name: adapter for adapter in previous.adapters}
    rates = []
    for adapter in current.adapters:
        previous_adapter = by_name.get(adapter.name)
        if previous_adapter is None:
            continue
        down_bytes = _diff(previous_adapter.received_bytes, adapter.received_bytes)
        up_bytes = _diff(previous_adapter.sent_bytes, adapter.sent_bytes)
        rates.append(AdapterRate(
            name=adapter.name,
            status=adapter.status,
            link_speed=adapter.link_speed,
            seconds=round(seconds, 1),
            down_bps=down_bytes * 8 / seconds,
            up_bps=up_bytes * 8 / seconds,
            received_bytes=adapter.received_bytes,
            sent_bytes=adapter.sent_bytes,
        ))
    return tuple(rates)


def format_bits_per_second(value: float) -> str:
    """Human-readable throughput: bps / Kbps / Mbps / Gbps."""
    if value < 1_000:
        return f"{value:.0f} bps"
    if value < 1_000_000:
        return f"{value / 1_000:.1f} Kbps"
    if value < 1_000_000_000:
        return f"{value / 1_000_000:.2f} Mbps"
    return f"{value / 1_000_000_000:.2f} Gbps"


# --------------------------------------------------------------------------
# Connection analysis
# --------------------------------------------------------------------------
def is_public_remote(address: str) -> bool:
    if not address:
        return False
    if address in ("127.0.0.1", "::1", "0.0.0.0", "::"):
        return False
    lowered = address.casefold()
    if lowered.startswith("fe80:") or lowered.startswith("fc") or lowered.startswith("fd"):
        return False
    if address.startswith("10.") or address.startswith("192.168."):
        return False
    if address.startswith("172."):
        try:
            second = int(address.split(".")[1])
            if 16 <= second <= 31:
                return False
        except (IndexError, ValueError):
            pass
    if lowered == "localhost":
        return False
    return True


def is_suspicious_path(path: str) -> bool:
    lowered = path.casefold()
    return any(marker in lowered for marker in SUSPICIOUS_PATH_MARKERS)


def top_talkers(connections: tuple[ConnectionRecord, ...], limit: int = 8) -> tuple[Talker, ...]:
    """Group established connections by process."""
    grouped: dict[str, dict] = {}
    for connection in connections:
        key = connection.process_name or str(connection.process_id)
        entry = grouped.setdefault(key, {"count": 0, "remotes": set(), "path": connection.process_path})
        entry["count"] += 1
        entry["remotes"].add(connection.remote_address)
    ordered = sorted(grouped.items(), key=lambda item: item[1]["count"], reverse=True)
    return tuple(
        Talker(process=key, connections=data["count"],
               distinct_remotes=len(data["remotes"]), path=data["path"])
        for key, data in ordered[:limit]
    )


def analyze_connections(connections: tuple[ConnectionRecord, ...]) -> tuple[Anomaly, ...]:
    """Heuristic findings for established outbound connections."""
    findings: list[Anomaly] = []
    for connection in connections:
        if not is_public_remote(connection.remote_address):
            continue
        standard_port = connection.remote_port in COMMON_OUTBOUND_PORTS
        suspicious_path = is_suspicious_path(connection.process_path)
        if suspicious_path and not standard_port:
            findings.append(Anomaly(
                severity="high",
                title=f"{connection.process_name or connection.process_id} talks to "
                      f"{connection.remote_address}:{connection.remote_port} from a suspicious location",
                detail=f"The process runs from {connection.process_path or 'an unknown path'} and uses a "
                       "non-standard port. Check the executable's publisher and whether you recognise the remote address.",
            ))
        elif suspicious_path:
            findings.append(Anomaly(
                severity="medium",
                title=f"{connection.process_name or connection.process_id} runs from a user-writable folder",
                detail=f"The process at {connection.process_path} has an established connection. Software in "
                       "AppData/Temp is often dropped by installers - or by malware.",
            ))
        elif not standard_port:
            findings.append(Anomaly(
                severity="low",
                title=f"Outbound connection to {connection.remote_address} on port {connection.remote_port}",
                detail="The remote port is not one of the most common service ports. This can be legitimate "
                       "(updates, games, P2P) - note it so you recognise it in later snapshots.",
            ))
    return tuple(findings)


def summarize(snapshot: TrafficSnapshot) -> dict:
    """Compact dashboard summary used by the UI."""
    public = [c for c in snapshot.connections if is_public_remote(c.remote_address)]
    private = [c for c in snapshot.connections if not is_public_remote(c.remote_address)]
    return {
        "adapters": len(snapshot.adapters),
        "connections": len(snapshot.connections),
        "public": len(public),
        "private": len(private),
        "anomalies": len(analyze_connections(snapshot.connections)),
        "top": top_talkers(snapshot.connections),
    }


# --------------------------------------------------------------------------
# Change detection between snapshots (TCPView-style highlighting)
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class ConnectionChange:
    kind: str          # new | closed | endpoint_changed
    process: str
    remote: str
    remote_port: int
    detail: str = ""


def _connection_key(connection: ConnectionRecord) -> tuple:
    return (
        connection.process_name or str(connection.process_id),
        connection.remote_address,
        connection.remote_port,
    )


def diff_connections(previous: TrafficSnapshot | None,
                     current: TrafficSnapshot) -> tuple[ConnectionChange, ...]:
    """Compare connection sets and describe what changed between snapshots."""
    if previous is None:
        return ()
    before = {_connection_key(c) for c in previous.connections}
    after = {_connection_key(c) for c in current.connections}
    changes: list[ConnectionChange] = []
    for key in sorted(after - before):
        process, remote, port = key
        changes.append(ConnectionChange(
            kind="new",
            process=process,
            remote=remote,
            remote_port=port,
            detail=f"{process} opened a new connection to {remote}:{port}.",
        ))
    for key in sorted(before - after):
        process, remote, port = key
        changes.append(ConnectionChange(
            kind="closed",
            process=process,
            remote=remote,
            remote_port=port,
            detail=f"{process} closed its connection to {remote}:{port}.",
        ))
    return tuple(changes)


def new_process_alerts(previous: TrafficSnapshot | None,
                       current: TrafficSnapshot) -> tuple[Anomaly, ...]:
    """Flag processes that were not talking before and appeared with
    outbound connections (especially from user-writable folders)."""
    if previous is None:
        return ()
    before_processes = {
        (c.process_name or str(c.process_id)) for c in previous.connections
    }
    alerts: list[Anomaly] = []
    for connection in current.connections:
        process = connection.process_name or str(connection.process_id)
        if process in before_processes:
            continue
        if not is_public_remote(connection.remote_address):
            continue
        if is_suspicious_path(connection.process_path):
            alerts.append(Anomaly(
                severity="high",
                title=f"New process '{process}' just started talking to "
                      f"{connection.remote_address}:{connection.remote_port}",
                detail=f"'{process}' was not communicating in the previous sample and now has an "
                       f"outbound connection. It runs from {connection.process_path or 'an unknown path'} "
                       "- a user-writable location. Verify what started it.",
            ))
        else:
            alerts.append(Anomaly(
                severity="low",
                title=f"New process '{process}' started talking to "
                      f"{connection.remote_address}:{connection.remote_port}",
                detail=f"'{process}' was not communicating in the previous sample. If you did not just "
                       "start it, investigate.",
            ))
    return tuple(alerts)


# --------------------------------------------------------------------------
# Beaconing detector (simplified RITA-style interval analysis)
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class BeaconCandidate:
    process: str
    remote: str
    remote_port: int
    samples: int
    median_interval: float   # seconds
    jitter: float            # 0..1 - low jitter means very regular timing


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def detect_beacons(samples: list[TrafficSnapshot], min_samples: int = 3) -> tuple[BeaconCandidate, ...]:
    """Detect connections that reappear at suspiciously regular intervals.

    For each (process, remote, port) seen in at least `min_samples` snapshots,
    compute the gap between successive appearances. When the gaps are
    consistent (low jitter), the pattern resembles the beaconing used by C2
    software (and also by legitimate update checkers - the UI labels it as a
    candidate, not a verdict).
    """
    if len(samples) < min_samples:
        return ()
    appearances: dict[tuple, list[float]] = {}
    timestamps: list[float] = []
    for snapshot in samples:
        try:
            timestamps.append(datetime.fromisoformat(snapshot.taken_at).timestamp())
        except (ValueError, TypeError):
            return ()
        seen = set()
        for connection in snapshot.connections:
            key = (
                connection.process_name or str(connection.process_id),
                connection.remote_address,
                connection.remote_port,
            )
            if not is_public_remote(connection.remote_address):
                continue
            if key in seen:
                continue
            seen.add(key)
            appearances.setdefault(key, []).append(timestamps[-1])
    candidates: list[BeaconCandidate] = []
    for (process, remote, port), times in appearances.items():
        if len(times) < min_samples:
            continue
        gaps = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        gaps = [gap for gap in gaps if gap > 0]
        if len(gaps) < min_samples - 1:
            continue
        median = _median(gaps)
        if median <= 0:
            continue
        jitter = _median([abs(gap - median) / median for gap in gaps])
        candidates.append(BeaconCandidate(
            process=process,
            remote=remote,
            remote_port=port,
            samples=len(times),
            median_interval=median,
            jitter=jitter,
        ))
    return tuple(sorted(candidates, key=lambda c: (c.jitter, -c.samples)))


def beacon_anomalies(candidates: tuple[BeaconCandidate, ...], jitter_threshold: float = 0.35) -> tuple[Anomaly, ...]:
    """Turn low-jitter beacon candidates into dashboard findings."""
    findings: list[Anomaly] = []
    for candidate in candidates:
        if candidate.jitter > jitter_threshold:
            continue
        severity = "high" if candidate.jitter < 0.15 else "medium"
        findings.append(Anomaly(
            severity=severity,
            title=f"Possible beaconing: {candidate.process} contacts "
                  f"{candidate.remote}:{candidate.remote_port} on a regular rhythm",
            detail=(
                f"Seen in {candidate.samples} samples with a median interval of "
                f"{candidate.median_interval:.1f} seconds and {candidate.jitter * 100:.0f}% jitter. "
                "Very regular timing to one remote resembles command-and-control beaconing - but also "
                "matches update checkers. Verify the process path and whether you recognise the remote."
            ),
        ))
    return tuple(findings)
