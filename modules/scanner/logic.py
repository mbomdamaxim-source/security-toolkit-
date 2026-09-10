"""Scan Reports logic: map this Windows device's exposure.

Design rules:
* We never parse localized text output. Every system query uses a
  PowerShell cmdlet (Get-NetTCPConnection, Get-Service, Get-HotFix) and
  the results are returned as structured JSON.
* The scan is read-only: it queries local state and never changes it.
* Analysis (port exposure, critical-service checks, patch recency) is pure
  Python, fully testable without Windows.
"""
from dataclasses import dataclass
from datetime import date, datetime, timezone
import json
from pathlib import Path
import subprocess

# --------------------------------------------------------------------------
# PowerShell payload (Windows PowerShell 5.1 compatible). Runs read-only
# cmdlets and emits one JSON object: {ports: [], services: [], patches: []}.
# An empty array is guaranteed for every section even when nothing is found.
# --------------------------------------------------------------------------
SCAN_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'

# --- process map (name + executable path) ---
$procs = @{}
foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
    $procs[[int]$p.Id] = [PSCustomObject]@{ Name = [string]$p.ProcessName; Path = [string]$p.Path }
}
function Get-ProcessInfo([int]$id) {
    $info = $procs[[int]$id]
    if ($null -eq $info) { return [PSCustomObject]@{ Name = ''; Path = '' } }
    return $info
}

# --- listening TCP ports ---
$tcpPorts = @()
foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
    $info = Get-ProcessInfo ([int]$c.OwningProcess)
    $tcpPorts += [PSCustomObject]@{
        Protocol = 'TCP'
        LocalAddress = [string]$c.LocalAddress
        LocalPort = [int]$c.LocalPort
        ProcessId = [int]$c.OwningProcess
        ProcessName = [string]$info.Name
        ProcessPath = [string]$info.Path
        ServiceName = ''
        Allowed = $null
    }
}

# --- UDP endpoints ---
$udpPorts = @()
foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
    $info = Get-ProcessInfo ([int]$u.OwningProcess)
    $udpPorts += [PSCustomObject]@{
        Protocol = 'UDP'
        LocalAddress = [string]$u.LocalAddress
        LocalPort = [int]$u.LocalPort
        ProcessId = [int]$u.OwningProcess
        ProcessName = [string]$info.Name
        ProcessPath = [string]$info.Path
        ServiceName = ''
        Allowed = $null
    }
}

# --- service owner for svchost listeners (cheap per-PID CIM query) ---
foreach ($row in @($tcpPorts + $udpPorts)) {
    if ($row.ProcessName -eq 'svchost') {
        $svc = Get-CimInstance Win32_Service -Filter "ProcessId=$($row.ProcessId)" -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $svc) { $row.ServiceName = [string]$svc.Name }
    }
}

# --- established outbound connections ---
$conns = @()
foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
    $info = Get-ProcessInfo ([int]$c.OwningProcess)
    $conns += [PSCustomObject]@{
        LocalAddress = [string]$c.LocalAddress
        LocalPort = [int]$c.LocalPort
        RemoteAddress = [string]$c.RemoteAddress
        RemotePort = [int]$c.RemotePort
        ProcessId = [int]$c.OwningProcess
        ProcessName = [string]$info.Name
        ProcessPath = [string]$info.Path
    }
}

# --- firewall state (values from cmdlets are NOT localized: True/False, Block/Allow) ---
$fw = [ordered]@{
    Available = $false
    Enabled = $false
    EnabledProfileCount = 0
    DefaultInbound = ''
    DefaultOutbound = ''
    AllowRules = @{}
}
$profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
if ($profiles.Count -gt 0) {
    $fw.Available = $true
    $enabledProfiles = @($profiles | Where-Object { $_.Enabled -eq 'True' })
    $fw.EnabledProfileCount = $enabledProfiles.Count
    $fw.Enabled = ($enabledProfiles.Count -gt 0)
    $inboundActions = @($enabledProfiles | Select-Object -ExpandProperty DefaultInboundAction -ErrorAction SilentlyContinue)
    $outboundActions = @($enabledProfiles | Select-Object -ExpandProperty DefaultOutboundAction -ErrorAction SilentlyContinue)
    $fw.DefaultInbound = if ($inboundActions -contains 'Allow') { 'Allow' } elseif ($inboundActions -contains 'Block') { 'Block' } else { '' }
    $fw.DefaultOutbound = if ($outboundActions -contains 'Allow') { 'Allow' } elseif ($outboundActions -contains 'Block') { 'Block' } else { '' }

    # --- single pass over enabled inbound Allow rules -> "PROTO-PORT" -> display name ---
    $allRules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)
    if ($allRules.Count -le 3000) {
        foreach ($rule in $allRules) {
            $pf = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            if ($null -eq $pf) { continue }
            $protocol = [string]$pf.Protocol
            $localPorts = $pf.LocalPort
            if ($localPorts -is [array]) {
                foreach ($p in $localPorts) {
                    if ($p -match '^\d+$') { $fw.AllowRules["$protocol-$p"] = [string]$rule.DisplayName }
                }
            } elseif ($localPorts -match '^\d+$') {
                $fw.AllowRules["$protocol-$localPorts"] = [string]$rule.DisplayName
            }
        }
        # tag each listener with its firewall truth
        foreach ($row in @($tcpPorts + $udpPorts)) {
            $key = "$($row.Protocol)-$($row.LocalPort)"
            if ($fw.AllowRules.Contains($key)) {
                $row.Allowed = $true
            } elseif ($fw.Enabled -and $fw.DefaultInbound -eq 'Block') {
                $row.Allowed = $false
            } else {
                $row.Allowed = $null
            }
        }
    }
}

$services = @()
foreach ($s in @(Get-Service -ErrorAction SilentlyContinue)) {
    $services += [PSCustomObject]@{
        Name = [string]$s.Name
        DisplayName = [string]$s.DisplayName
        Status = [string]$s.Status
        StartType = [string]$s.StartType
    }
}

$patches = @()
foreach ($h in @(Get-HotFix -ErrorAction SilentlyContinue)) {
    $installed = ''
    if ($null -ne $h.InstalledOn) {
        $installed = $h.InstalledOn.ToString('yyyy-MM-dd')
    }
    $patches += [PSCustomObject]@{
        HotFixId = [string]$h.HotFixID
        Description = [string]$h.Description
        InstalledOn = $installed
    }
}

$out = [ordered]@{
    ports = $tcpPorts
    udp_ports = $udpPorts
    connections = $conns
    firewall = $fw
    services = $services
    patches = $patches
}
ConvertTo-Json -InputObject $out -Compress -Depth 5
"""


_WILDCARD_ADDRESSES = {"0.0.0.0", "::"}

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "SMTP submission", 993: "IMAPS", 995: "POP3S",
    1433: "Microsoft SQL Server", 1521: "Oracle Database", 2049: "NFS",
    2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP (alternative)", 8443: "HTTPS (alternative)",
    9200: "Elasticsearch", 27017: "MongoDB",
}
UDP_PORT_SERVICES = {
    53: "DNS", 67: "DHCP server", 68: "DHCP client", 123: "NTP", 137: "NetBIOS",
    138: "NetBIOS", 161: "SNMP", 500: "IPsec IKE", 1900: "SSDP", 3702: "WS-Discovery",
    5353: "mDNS", 5355: "LLMNR",
}

# Severity when a wildcard listener is actually allowed through the firewall.
RISKY_WILDCARD_PORTS = {
    21: "medium", 23: "high", 25: "low", 135: "medium", 137: "medium",
    138: "medium", 139: "medium", 389: "low", 445: "medium", 2375: "high",
    1433: "medium", 1521: "medium", 3306: "medium", 3389: "high",
    5432: "medium", 5900: "medium", 6379: "medium", 9200: "medium",
    27017: "medium",
}

# Ports that legitimate software commonly dials OUT to. Others are worth a look.
COMMON_OUTBOUND_PORTS = {
    21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 8080, 8443,
}

# Path fragments that strongly suggest a user-writable, high-risk location.
SUSPICIOUS_PATH_MARKERS = (
    "\\appdata\\",
    "\\temp\\",
    "\\downloads\\",
    "\\public\\",
    "\\desktop\\",
)

CRITICAL_SERVICES = {
    "WinDefend": ("high", "Windows Defender Antivirus is not running"),
    "SecurityHealthService": ("high", "Windows Security health service is not running"),
    "wscsvc": ("medium", "Windows Security Center is not running"),
    "wuauserv": ("medium", "Windows Update service is not running"),
    "BITS": ("low", "Background Intelligent Transfer (BITS) is not running"),
}


class ScanError(RuntimeError):
    """Raised when the local scan cannot be performed or parsed."""


@dataclass(frozen=True)
class PortRecord:
    protocol: str          # TCP | UDP
    local_address: str
    local_port: int
    process_id: int
    process_name: str
    process_path: str
    service_name: str      # hosting service when the process is svchost
    allowed: bool | None   # True=explicit inbound Allow, False=blocked by default, None=unknown


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
class ServiceRecord:
    name: str
    display_name: str
    status: str
    start_type: str


@dataclass(frozen=True)
class PatchRecord:
    hotfix_id: str
    description: str
    installed_on: str  # ISO date (yyyy-mm-dd) or empty when unknown


@dataclass(frozen=True)
class FirewallState:
    available: bool
    enabled: bool
    enabled_profile_count: int
    default_inbound: str
    default_outbound: str


@dataclass(frozen=True)
class Finding:
    severity: str  # info | low | medium | high | critical (matches SeverityBadge)
    title: str
    detail: str


@dataclass(frozen=True)
class ScanReport:
    scanned_at: str
    ports: tuple[PortRecord, ...]
    connections: tuple[ConnectionRecord, ...]
    firewall: FirewallState
    services: tuple[ServiceRecord, ...]
    patches: tuple[PatchRecord, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class DriftChange:
    kind: str  # added_listener | removed_listener | service_status
    severity: str
    title: str
    detail: str


# --------------------------------------------------------------------------
# PowerShell invocation
# --------------------------------------------------------------------------
def encode_powershell_command(script: str) -> str:
    """UTF-16LE base64 encoding used by powershell -EncodedCommand."""
    import base64
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def run_local_scan(powershell: str = "powershell.exe", timeout: int = 90) -> dict:
    """Run the read-only PowerShell scan and return the raw JSON structure.

    Raises ScanError when PowerShell is unavailable, times out, or returns
    malformed output. Never raises on a partially empty scan: missing
    sections become empty lists.
    """
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
        raise ScanError(
            f"PowerShell ({powershell}) was not found. Scan Reports runs on "
            "Windows only."
        ) from error
    except subprocess.TimeoutExpired as error:
        raise ScanError("The local scan timed out.") from error

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise ScanError(
            "The local scan failed. " + (detail[-400:] if detail else "")
        )
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as error:
        raise ScanError("The scan returned unreadable output.") from error
    if not isinstance(payload, dict):
        raise ScanError("The scan returned an unexpected structure.")
    return payload


# --------------------------------------------------------------------------
# Parsing (pure, testable)
# --------------------------------------------------------------------------
def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _text(value) -> str:
    return "" if value is None else str(value)


def _as_bool(value) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "1"):
        return True
    if text in ("false", "0"):
        return False
    return None


def _as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_ports(payload: dict) -> tuple[PortRecord, ...]:
    records = []
    for row in _as_list(payload.get("ports")):
        if not isinstance(row, dict):
            continue
        records.append(PortRecord(
            protocol=_text(row.get("Protocol")) or "TCP",
            local_address=_text(row.get("LocalAddress")),
            local_port=_as_int(row.get("LocalPort")),
            process_id=_as_int(row.get("ProcessId")),
            process_name=_text(row.get("ProcessName")),
            process_path=_text(row.get("ProcessPath")),
            service_name=_text(row.get("ServiceName")),
            allowed=_as_bool(row.get("Allowed")),
        ))
    for row in _as_list(payload.get("udp_ports")):
        if not isinstance(row, dict):
            continue
        records.append(PortRecord(
            protocol=_text(row.get("Protocol")) or "UDP",
            local_address=_text(row.get("LocalAddress")),
            local_port=_as_int(row.get("LocalPort")),
            process_id=_as_int(row.get("ProcessId")),
            process_name=_text(row.get("ProcessName")),
            process_path=_text(row.get("ProcessPath")),
            service_name=_text(row.get("ServiceName")),
            allowed=_as_bool(row.get("Allowed")),
        ))
    return tuple(sorted(records, key=lambda record: (record.protocol, record.local_port)))


def parse_connections(payload: dict) -> tuple[ConnectionRecord, ...]:
    records = []
    for row in _as_list(payload.get("connections")):
        if not isinstance(row, dict):
            continue
        records.append(ConnectionRecord(
            local_address=_text(row.get("LocalAddress")),
            local_port=_as_int(row.get("LocalPort")),
            remote_address=_text(row.get("RemoteAddress")),
            remote_port=_as_int(row.get("RemotePort")),
            process_id=_as_int(row.get("ProcessId")),
            process_name=_text(row.get("ProcessName")),
            process_path=_text(row.get("ProcessPath")),
        ))
    return tuple(records)


def parse_firewall(payload: dict) -> FirewallState:
    row = payload.get("firewall")
    if not isinstance(row, dict):
        return FirewallState(False, False, 0, "", "")
    return FirewallState(
        available=bool(row.get("Available")),
        enabled=bool(row.get("Enabled")),
        enabled_profile_count=_as_int(row.get("EnabledProfileCount")),
        default_inbound=_text(row.get("DefaultInbound")),
        default_outbound=_text(row.get("DefaultOutbound")),
    )


def parse_services(payload: dict) -> tuple[ServiceRecord, ...]:
    records = []
    for row in _as_list(payload.get("services")):
        if not isinstance(row, dict):
            continue
        records.append(ServiceRecord(
            name=_text(row.get("Name")),
            display_name=_text(row.get("DisplayName")),
            status=_text(row.get("Status")),
            start_type=_text(row.get("StartType")),
        ))
    return tuple(sorted(records, key=lambda record: record.name.casefold()))


def parse_patches(payload: dict) -> tuple[PatchRecord, ...]:
    records = []
    for row in _as_list(payload.get("patches")):
        if not isinstance(row, dict):
            continue
        records.append(PatchRecord(
            hotfix_id=_text(row.get("HotFixId")),
            description=_text(row.get("Description")),
            installed_on=_text(row.get("InstalledOn")),
        ))
    return tuple(sorted(records, key=lambda record: record.installed_on or "0000-00-00", reverse=True))


# --------------------------------------------------------------------------
# Allowlist ("known-good" listeners the user has confirmed)
# --------------------------------------------------------------------------
def load_allowlist(path) -> set:
    """Load {(protocol, port)} pairs the user marked as expected."""
    import json as _json
    try:
        raw = _json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if not isinstance(raw, list):
        return set()
    result = set()
    for entry in raw:
        if isinstance(entry, dict) and isinstance(entry.get("port"), int):
            result.add((str(entry.get("protocol", "TCP")).upper(), entry["port"]))
    return result


def save_allowlist(path, allowlist) -> None:
    import json as _json
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        _json.dumps(
            [{"protocol": protocol, "port": port} for protocol, port in sorted(allowlist)],
            indent=2,
        ),
        encoding="utf-8",
    )


# --------------------------------------------------------------------------
# Analysis (pure, testable)
# --------------------------------------------------------------------------
def is_suspicious_path(path: str) -> bool:
    lowered = path.casefold()
    return any(marker in lowered for marker in SUSPICIOUS_PATH_MARKERS)


def _is_public_remote(address: str) -> bool:
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


def analyze_ports(records: tuple[PortRecord, ...], firewall: FirewallState | None = None,
                  allowlist: set | None = None) -> tuple[Finding, ...]:
    """Exposure findings for listening TCP/UDP ports, firewall-aware."""
    allowlist = allowlist or set()
    findings = []
    for record in records:
        if (record.protocol.upper(), record.local_port) in allowlist:
            continue  # user-confirmed expected listener
        service_table = UDP_PORT_SERVICES if record.protocol.upper() == "UDP" else PORT_SERVICES
        service = service_table.get(record.local_port, "")
        wildcard = record.local_address in _WILDCARD_ADDRESSES
        blocked = record.allowed is False and firewall is not None and firewall.enabled

        if not wildcard:
            continue  # loopback-only listeners are not reachable from the network
        if blocked:
            findings.append(Finding(
                severity="info",
                title=f"Port {record.local_port} ({service or 'unknown service'}) listens on every "
                      "interface but the firewall blocks it",
                detail=(
                    f"{service or 'An unrecognised service'} (process {record.process_name or record.process_id}) "
                    "binds to 0.0.0.0 but no inbound allow rule exists and the firewall's default "
                    "inbound action is Block. It is NOT reachable from the network - still consider "
                    "binding it to 127.0.0.1 to shrink the attack surface."
                ),
            ))
            continue

        base = (
            f"{service or 'An unrecognised service'} (process {record.process_name or record.process_id}"
            + (f", service {record.service_name}" if record.service_name else "")
            + f") listens on {record.local_address}:{record.local_port} "
        )
        if record.allowed is True and record.local_port in RISKY_WILDCARD_PORTS:
            severity = RISKY_WILDCARD_PORTS[record.local_port]
            findings.append(Finding(
                severity=severity,
                title=f"Port {record.local_port} ({service or 'unknown service'}) is reachable on every "
                      "interface - the firewall allows it",
                detail=(
                    base + "and an enabled inbound firewall rule allows the traffic. Any device on the "
                    "network can reach it. If the service is not required on the network, bind it to "
                    "127.0.0.1 or remove the firewall rule."
                ),
            ))
        elif record.allowed is True and service:
            findings.append(Finding(
                severity="low",
                title=f"Port {record.local_port} ({service}) listens on every interface and is allowed",
                detail=base + "accepts connections from the whole network (inbound allow rule present). "
                "Confirm this is intentional and protected by authentication."
            ))
        elif record.allowed is True:
            findings.append(Finding(
                severity="low",
                title=f"Unrecognised listener on port {record.local_port} is firewall-allowed",
                detail=base + "with an enabled inbound allow rule. Identify the software and decide "
                "whether it should be reachable from the network."
            ))
        elif record.allowed is None:
            findings.append(Finding(
                severity="low",
                title=f"Port {record.local_port} ({service or 'unknown service'}) listens on every "
                      "interface - firewall state unknown",
                detail=base + "but the firewall could not be checked (no rule data or restricted "
                "permissions). Open Windows Defender Firewall and confirm whether the port is allowed."
            ))
    return tuple(findings)


def analyze_connections(records: tuple[ConnectionRecord, ...]) -> tuple[Finding, ...]:
    """Heuristic findings for established outbound connections."""
    findings = []
    for record in records:
        if not _is_public_remote(record.remote_address):
            continue
        standard_port = record.remote_port in COMMON_OUTBOUND_PORTS
        suspicious_path = is_suspicious_path(record.process_path)
        if suspicious_path and not standard_port:
            severity = "high"
            title = (f"{record.process_name or record.process_id} connects to {record.remote_address}:"
                     f"{record.remote_port} from a suspicious location")
            detail = (
                f"Process {record.process_name or record.process_id} running from "
                f"{record.process_path or 'an unknown path'} has an active connection to a public "
                "address on a non-standard port. This pattern is worth investigating: check the "
                "executable's publisher and whether you recognise the remote address."
            )
        elif suspicious_path:
            severity = "medium"
            title = f"{record.process_name or record.process_id} runs from a user-writable folder and is online"
            detail = (
                f"The process runs from {record.process_path} and has an established connection to "
                f"{record.remote_address}:{record.remote_port}. Software running from AppData/Temp is "
                "often dropped there by installers - or by malware."
            )
        elif not standard_port:
            severity = "low"
            title = f"Outbound connection to {record.remote_address} on port {record.remote_port}"
            detail = (
                f"{record.process_name or record.process_id} connects to a public address on port "
                f"{record.remote_port}, which is not one of the most common service ports. This can be "
                "legitimate (updates, games, P2P) - note it so you recognise it in later scans."
            )
        else:
            continue
        findings.append(Finding(severity=severity, title=title, detail=detail))
    return tuple(findings)


def analyze_services(records: tuple[ServiceRecord, ...]) -> tuple[Finding, ...]:
    """Findings for critical Windows services that are not running."""
    findings = []
    running = {record.name.casefold() for record in records if record.status.casefold() == "running"}
    for name, (severity, title) in CRITICAL_SERVICES.items():
        if name.casefold() not in running:
            findings.append(Finding(
                severity=severity,
                title=title,
                detail=(
                    f"The service '{name}' is not currently running. This weakens the device's built-in "
                    "defences. Check the Services console (services.msc) for its startup type and last error."
                ),
            ))
    return tuple(findings)


def months_since(iso_date: str, today=None) -> int:
    """Whole calendar months between an ISO date and today (minimum 0)."""
    today = today or date.today()
    try:
        installed = datetime.strptime(iso_date[:10], "%Y-%m-%d").date()
    except ValueError:
        return 0
    months = (today.year - installed.year) * 12 + today.month - installed.month
    if today.day < installed.day:
        months -= 1
    return max(0, months)


def analyze_patches(records: tuple[PatchRecord, ...]) -> tuple[Finding, ...]:
    """Recency findings for installed updates."""
    if not records:
        return (Finding(
            severity="medium",
            title="No update records were found",
            detail=(
                "Get-HotFix reported no installed updates. Some servicing channels (for example "
                "Windows Update on newer Windows versions) are not fully listed there. Open Windows "
                "Update and confirm the device is up to date."
            ),
        ),)
    latest = records[0]
    months = months_since(latest.installed_on) if latest.installed_on else 0
    if months >= 12:
        severity = "high"
    elif months >= 6:
        severity = "medium"
    elif months >= 1:
        severity = "low"
    else:
        severity = "info"
    title = (
        f"{len(records)} hotfixes installed; the newest is {latest.hotfix_id or 'unknown'} from "
        f"{latest.installed_on or 'an unknown date'}"
    )
    detail = (
        f"The most recent recorded update is {months} month(s) old. Get-HotFix only lists quick-fix "
        "engineering updates; compare this against Windows Update for cumulative and driver updates, "
        "and enable automatic updates."
    )
    return (Finding(severity=severity, title=title, detail=detail),)


def _firewall_finding(firewall: FirewallState) -> tuple[Finding, ...]:
    if not firewall.available:
        return (Finding(
            severity="info",
            title="Firewall state could not be read",
            detail="The scan could not query Windows Defender Firewall. Firewall-aware exposure "
            "classification is unavailable for this scan.",
        ),)
    if not firewall.enabled:
        return (Finding(
            severity="high",
            title="Windows Defender Firewall is not enabled",
            detail=f"None of the {max(firewall.enabled_profile_count, 1)} network profile(s) has the "
            "firewall enabled. Every listening port on 0.0.0.0 is reachable from the network. Enable "
            "the firewall for all profiles.",
        ),)
    return ()


def build_report(payload: dict, scanned_at: str | None = None,
                 allowlist: set | None = None) -> ScanReport:
    """Parse raw PowerShell JSON into a fully analysed report.

    allowlist is an optional set of (protocol, port) pairs the user marked
    as expected; those listeners are excluded from the exposure findings.
    """
    ports = parse_ports(payload)
    connections = parse_connections(payload)
    firewall = parse_firewall(payload)
    services = parse_services(payload)
    patches = parse_patches(payload)
    findings = (
        _firewall_finding(firewall)
        + analyze_ports(ports, firewall=firewall, allowlist=allowlist)
        + analyze_connections(connections)
        + analyze_services(services)
        + analyze_patches(patches)
    )
    return ScanReport(
        scanned_at=scanned_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        ports=ports,
        connections=connections,
        firewall=firewall,
        services=services,
        patches=patches,
        findings=tuple(findings),
    )


# --------------------------------------------------------------------------
# Drift detection: what changed since the last scan
# --------------------------------------------------------------------------
def baseline_summary(baseline: dict) -> dict:
    """Summarise an assess_baseline result into pass/fail/unknown counts and a
    hardening percentage (passes over the checks that could be determined)."""
    counts = {"pass": 0, "fail": 0, "unknown": 0}
    for result in baseline.values():
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    determinable = counts["pass"] + counts["fail"]
    hardening = round(counts["pass"] / determinable * 100) if determinable else 0
    return {"counts": counts, "hardening": hardening}


def _scan_signature(report: ScanReport) -> dict:
    listeners = {
        (record.protocol.upper(), record.local_port, record.process_name or str(record.process_id))
        for record in report.ports
    }
    service_status = {record.name.casefold(): record.status.casefold() for record in report.services}
    return {"listeners": listeners, "services": service_status}


def diff_reports(previous: ScanReport, current: ScanReport) -> tuple[DriftChange, ...]:
    """Compare two reports and describe what changed on the device."""
    if previous is None:
        return ()
    before = _scan_signature(previous)
    after = _scan_signature(current)
    changes = []
    for listener in sorted(after["listeners"] - before["listeners"]):
        protocol, port, process = listener
        changes.append(DriftChange(
            kind="added_listener",
            severity="medium",
            title=f"New listener: {protocol} port {port} ({process})",
            detail=f"Port {port} ({protocol}) is now listening (process {process}) and was not "
            "listening during the previous scan. A new listener can mean a newly installed service - "
            "or an unauthorised change. Verify what opened it.",
        ))
    for listener in sorted(before["listeners"] - after["listeners"]):
        protocol, port, process = listener
        changes.append(DriftChange(
            kind="removed_listener",
            severity="info",
            title=f"Listener gone: {protocol} port {port} ({process})",
            detail=f"Port {port} ({protocol}) is no longer listening. If you did not stop the service, "
            "check whether it failed to start.",
        ))
    for name in sorted(before["services"] | after["services"]):
        previous_status = before["services"].get(name)
        current_status = after["services"].get(name)
        if previous_status != current_status and current_status is not None:
            changes.append(DriftChange(
                kind="service_status",
                severity="medium" if current_status != "running" else "info",
                title=f"Service '{name}' changed from {previous_status or 'unknown'} to {current_status}",
                detail=f"Service {name} is now {current_status} (was {previous_status or 'unknown'}). "
                "Stopped security services (Defender, Windows Update) deserve immediate attention.",
            ))
    return tuple(changes)


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


# --------------------------------------------------------------------------
# CIS Level-1 style baseline checks (mini hardening assessment)
# --------------------------------------------------------------------------
# Each check maps to a hardening control; state comes from the snapshot.
BASELINE_CHECKS = (
    {
        "key": "smbv1",
        "title": "SMBv1 protocol disabled",
        "why": "SMBv1 powered EternalBlue (MS17-010) - the WannaCry/NotPetya vector. "
               "Modern Windows disables it by default; re-enabling it reopens the hole.",
    },
    {
        "key": "rdp_nla",
        "title": "RDP Network Level Authentication (NLA) enforced",
        "why": "Without NLA an unauthenticated attacker can reach the RDP pre-auth attack "
               "surface (BlueKeep, CVE-2019-0708) and brute force more easily.",
    },
    {
        "key": "print_spooler",
        "title": "Print Spooler not exposed (or disabled)",
        "why": "PrintNightmare (CVE-2021-34527) allowed remote code execution through the "
               "spooler. Home PCs rarely need inbound spooler access.",
    },
    {
        "key": "firewall",
        "title": "Windows Firewall enabled on all profiles",
        "why": "A disabled firewall makes every wildcard listener reachable from the network.",
    },
    {
        "key": "defender",
        "title": "Windows Defender running",
        "why": "Real-time antivirus is the baseline protection layer on every Windows device.",
    },
    {
        "key": "updates",
        "title": "Recent updates installed",
        "why": "Most exploits target known, already-patched vulnerabilities (73% of Windows "
               "exploits hit misconfigurations or defaults).",
    },
    {
        "key": "smb445",
        "title": "No wildcard SMB listener (445)",
        "why": "Inbound SMB on 0.0.0.0 with an allow rule is reachable from the whole network.",
    },
    {
        "key": "rdp3389",
        "title": "No wildcard RDP listener (3389)",
        "why": "RDP exposed on every interface is a top ransomware entry point.",
    },
)


def assess_baseline(report) -> dict:
    """Assess CIS Level-1 style checks against a scan report.

    Returns {check_key: {"title", "status": "pass"|"fail"|"unknown",
                          "note", "why", "severity"}}.
    Statuses are best-effort from what the snapshot can see; items the scan
    cannot inspect are reported as unknown with an honest note.
    """
    ports_by_key = {(p.protocol.upper(), p.local_port): p for p in report.ports}
    firewall = report.firewall
    services = {s.name.casefold(): s for s in report.services}
    results = {}

    def add(key, status, note, severity="medium"):
        check = next(c for c in BASELINE_CHECKS if c["key"] == key)
        results[key] = {"title": check["title"], "why": check["why"],
                        "status": status, "note": note, "severity": severity}

    smb = ports_by_key.get(("TCP", 445))
    rdp = ports_by_key.get(("TCP", 3389))
    smb_exposed = smb is not None and smb.local_address in _WILDCARD_ADDRESSES and smb.allowed is not False
    rdp_exposed = rdp is not None and rdp.local_address in _WILDCARD_ADDRESSES and rdp.allowed is not False
    add("smb445",
        "fail" if smb_exposed else "pass",
        "SMB listens on every interface and is firewall-allowed - reachable from the network."
        if smb_exposed else "No wildcard-allowed SMB listener found.",
        severity="high" if smb_exposed else "info")
    add("rdp3389",
        "fail" if rdp_exposed else "pass",
        "RDP listens on every interface and is firewall-allowed - reachable from the network."
        if rdp_exposed else "No wildcard-allowed RDP listener found.",
        severity="high" if rdp_exposed else "info")

    if not firewall.available:
        add("firewall", "unknown", "Firewall state could not be queried.")
    elif firewall.enabled:
        add("firewall", "pass", f"{firewall.enabled_profile_count} profile(s) enabled.")
    else:
        add("firewall", "fail", "Firewall is disabled on all profiles.", severity="high")

    running_defender = services.get("windefend")
    if running_defender is None:
        add("defender", "unknown", "Windows Defender status could not be queried.")
    elif running_defender.status.casefold() == "running":
        add("defender", "pass", "Windows Defender is running.")
    else:
        add("defender", "fail", "Windows Defender is not running.", severity="high")

    if not report.patches:
        add("updates", "unknown", "Get-HotFix returned no records; check Windows Update.")
    else:
        latest = report.patches[0]
        months = months_since(latest.installed_on)
        if latest.installed_on and months <= 1:
            add("updates", "pass", f"Newest hotfix {latest.hotfix_id} is {months} month(s) old.")
        else:
            add("updates", "fail",
                f"Newest hotfix is {months} month(s) old - check Windows Update.",
                severity="medium" if months < 6 else "high")

    for key in ("smbv1", "rdp_nla", "print_spooler"):
        add(key, "unknown",
            "This snapshot cannot read the registry/service state for this control; "
            "verify it manually (see the reference).",
            severity="info")
    return results


def exposure_summary(report: ScanReport) -> dict:
    """Derive severity counts, an exposure score (0-100) and a posture verdict.

    Score model (mirrors the browser preview):
      100 - 35 per critical - 20 per high - 10 per medium - 4 per low.
    """
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in report.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    score = max(
        0,
        100
        - counts["critical"] * 35
        - counts["high"] * 20
        - counts["medium"] * 10
        - counts["low"] * 4,
    )
    if counts["critical"] or counts["high"]:
        posture, tone = "Needs attention", "danger"
    elif counts["medium"] or counts["low"]:
        posture, tone = "Acceptable - review the medium and low findings", "warning"
    else:
        posture, tone = "Good posture", "success"
    return {"counts": counts, "score": score, "posture": posture, "tone": tone}


def scan_now(powershell: str = "powershell.exe", timeout: int = 90) -> ScanReport:
    """Convenience wrapper: run the local scan and return the analysed report."""
    return build_report(run_local_scan(powershell=powershell, timeout=timeout))


def load_hardening_history(path) -> list:
    """Load recorded hardening scores (oldest first) from a JSON file."""
    try:
        entries = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(entries, list):
        return []
    return [
        entry for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("hardening"), int)
        and isinstance(entry.get("date"), str)
    ][-30:]


def append_hardening_score(path, hardening: int, when: str | None = None) -> list:
    """Record one hardening score, keep the newest 30, never raise."""
    if not isinstance(hardening, int) or not 0 <= hardening <= 100:
        raise ValueError("Hardening score must be a whole number from 0 to 100.")
    from datetime import datetime as _dt
    entry = {"date": when or _dt.now().isoformat(timespec="seconds"), "hardening": hardening}
    entries = load_hardening_history(path) + [entry]
    entries = entries[-30:]
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(entries, indent=2), encoding="utf-8")
    except OSError:
        pass
    return entries
