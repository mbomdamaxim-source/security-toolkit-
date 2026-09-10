"""Firewall Builder logic: validated rule construction for three targets.

Targets
-------
* Windows Defender Firewall  -> PowerShell New-NetFirewallRule (cmdlets only,
  never netsh: netsh output is localized and its vocabulary differs).
* MikroTik RouterOS          -> /ip firewall filter commands.
* Cisco IOS                  -> named extended ACL + ip access-group.

Rules enforced here
-------------------
* Vocabulary is validated before any command is built: Windows action is
  allow|block, direction is in|out (mapped to Allow|Block, Inbound|Outbound
  only at render time); Cisco keeps its native permit|deny.
* Every user-supplied value is validated (ports, addresses, wildcards,
  interfaces, comments); invalid input raises ValueError with a clear message.
* Rules are only rendered as text commands. Applying them to a live system
  happens in the UI layer, guarded by an administrator check.
"""
from dataclasses import dataclass
import ipaddress
import json
import re
import subprocess

# ---------------------------------------------------------------------------
# Shared validation helpers
# ---------------------------------------------------------------------------
_PORT_RE = re.compile(r"^\d{1,5}$")


def validate_port(port: int | str, label: str = "Port") -> int:
    try:
        value = int(str(port).strip())
    except ValueError:
        raise ValueError(f"{label} must be a whole number from 1 to 65535.") from None
    if not 1 <= value <= 65535:
        raise ValueError(f"{label} must be a whole number from 1 to 65535.")
    return value


def validate_port_list(ports: str, label: str = "Ports") -> str:
    """Accept '443', '443,445' or '443-445'. Returns the trimmed spec."""
    spec = str(ports).strip().replace(" ", "")
    if not spec:
        raise ValueError(f"{label} cannot be empty.")
    for chunk in spec.split(","):
        if "-" in chunk:
            low, _, high = chunk.partition("-")
            low_i = validate_port(low, label)
            high_i = validate_port(high, label)
            if low_i > high_i:
                raise ValueError(f"{label} range start is larger than its end.")
        else:
            validate_port(chunk, label)
    return spec


def validate_ip_or_host(address: str, label: str = "Address") -> str:
    value = str(address).strip()
    if value.casefold() in ("any", "host"):
        raise ValueError(f"{label} must be an IPv4 address (or use the any/host keyword).")
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ValueError(f"{label} must be a valid IPv4 address.") from None
    return value


def is_contiguous_wildcard(wildcard: str) -> bool:
    """A wildcard is valid when its own bits are contiguous ones from the
    bottom (the complement of a contiguous netmask): 0.0.0.255, 0.0.255.255,
    0.255.255.255, 255.255.255.255, and 0.0.0.0 (a single host)."""
    try:
        bits = int(ipaddress.IPv4Address(wildcard))
    except ipaddress.AddressValueError:
        return False
    return (bits & (bits + 1)) == 0


def validate_comment(comment: str, label: str = "Comment", limit: int = 80) -> str:
    value = str(comment).strip()
    if not value:
        raise ValueError(f"{label} cannot be empty.")
    if len(value) > limit:
        raise ValueError(f"{label} must be at most {limit} characters.")
    return value


def _quote_powershell(value: str) -> str:
    """Single-quote a PowerShell string argument, doubling embedded quotes."""
    return "'" + str(value).replace("'", "''") + "'"


# ---------------------------------------------------------------------------
# Windows Defender Firewall
# ---------------------------------------------------------------------------
WINDOWS_ACTIONS = ("allow", "block")
WINDOWS_DIRECTIONS = ("in", "out")
WINDOWS_PROTOCOLS = ("TCP", "UDP", "ICMPv4", "Any")
WINDOWS_PROFILES = ("Any", "Domain", "Private", "Public")

_WINDOWS_ACTION_MAP = {"allow": "Allow", "block": "Block"}
_WINDOWS_DIRECTION_MAP = {"in": "Inbound", "out": "Outbound"}


@dataclass(frozen=True)
class WindowsRuleSpec:
    """A validated, render-ready Windows Defender firewall rule."""

    name: str
    action: str            # allow | block
    direction: str         # in | out
    protocol: str          # TCP | UDP | ICMPv4 | Any
    local_port: str = ""   # validated spec (single/list/range) - TCP/UDP only
    remote_address: str = ""  # validated IPv4, an address range keyword, or empty
    program: str = ""      # optional full path to an executable
    profile: str = "Any"   # Any | Domain | Private | Public
    description: str = ""

    @property
    def elevation_required(self) -> bool:
        return True  # New-NetFirewallRule always needs an administrator

    def to_powershell(self) -> str:
        """Render the rule as one PowerShell New-NetFirewallRule command."""
        parts = [
            "New-NetFirewallRule",
            f"-DisplayName {_quote_powershell(self.name)}",
            f"-Direction {_WINDOWS_DIRECTION_MAP[self.direction]}",
            f"-Action {_WINDOWS_ACTION_MAP[self.action]}",
            f"-Profile {_quote_powershell(self.profile)}",
        ]
        if self.protocol != "Any":
            parts.append(f"-Protocol {self.protocol}")
            if self.protocol in ("TCP", "UDP") and self.local_port:
                parts.append(f"-LocalPort {_quote_powershell(self.local_port)}")
        if self.remote_address:
            parts.append(f"-RemoteAddress {_quote_powershell(self.remote_address)}")
        if self.program:
            parts.append(f"-Program {_quote_powershell(self.program)}")
        if self.description:
            parts.append(f"-Description {_quote_powershell(self.description)}")
        return " ".join(parts)


def build_windows_rule(
    name: str,
    action: str,
    direction: str,
    protocol: str = "TCP",
    local_port: str = "",
    remote_address: str = "",
    program: str = "",
    profile: str = "Any",
    description: str = "",
) -> WindowsRuleSpec:
    """Validate inputs and return a Windows firewall rule spec."""
    clean_name = validate_comment(name, "Rule name", limit=120)
    action = str(action).strip().casefold()
    if action not in WINDOWS_ACTIONS:
        raise ValueError("Windows rule action must be 'allow' or 'block'.")
    direction = str(direction).strip().casefold()
    if direction not in WINDOWS_DIRECTIONS:
        raise ValueError("Windows rule direction must be 'in' or 'out'.")
    protocol = str(protocol).strip().upper()
    if protocol not in WINDOWS_PROTOCOLS:
        raise ValueError("Protocol must be TCP, UDP, ICMPv4 or Any.")
    profile = str(profile).strip()
    if profile not in WINDOWS_PROFILES:
        raise ValueError("Profile must be Any, Domain, Private or Public.")
    if protocol in ("TCP", "UDP"):
        if not local_port.strip():
            raise ValueError(f"A local port is required for protocol {protocol}.")
        local_port = validate_port_list(local_port, "Local port")
    if remote_address.strip():
        first = remote_address.strip().split(",")[0]
        if not (first.casefold() in ("any", "localsubnet", "dns", "dhcp", "wins", "defaultgateway")
                or _is_valid_ip(first)):
            raise ValueError("Remote address must be an IPv4 address or a supported keyword.")
        remote_address = remote_address.strip().replace(" ", "")
    if program.strip() and not program.strip().lower().endswith(".exe"):
        raise ValueError("Program must be the full path to an .exe file.")
    if description:
        validate_comment(description, "Description", limit=200)
    return WindowsRuleSpec(
        name=clean_name,
        action=action,
        direction=direction,
        protocol=protocol,
        local_port=local_port,
        remote_address=remote_address,
        program=program.strip(),
        profile=profile,
        description=description.strip(),
    )


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


# Parsing support for listing existing rules (Get-NetFirewallRule JSON).
@dataclass(frozen=True)
class ExistingRule:
    name: str
    display_name: str
    direction: str       # Inbound | Outbound
    action: str          # Allow | Block
    enabled: bool
    profile: str


def parse_windows_rules(payload: dict) -> tuple[ExistingRule, ...]:
    """Parse a {rules: [...]} payload (from Get-NetFirewallRule JSON)."""
    rows = payload.get("rules") or []
    if not isinstance(rows, list):
        rows = [rows]
    records = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        records.append(ExistingRule(
            name=str(row.get("Name") or ""),
            display_name=str(row.get("DisplayName") or ""),
            direction=str(row.get("Direction") or ""),
            action=str(row.get("Action") or ""),
            enabled=str(row.get("Enabled") or "").casefold() in ("true", "1"),
            profile=str(row.get("Profile") or ""),
        ))
    return tuple(records)


# ---------------------------------------------------------------------------
# Listing existing Windows rules (audit view)
# ---------------------------------------------------------------------------
FIREWALL_RULES_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'

$rules = @()
foreach ($r in @(Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
    $rules += [PSCustomObject]@{
        Name        = [string]$r.Name
        DisplayName = [string]$r.DisplayName
        Direction   = [string]$r.Direction
        Action      = [string]$r.Action
        Enabled     = [string]$r.Enabled
        Profile     = [string]$r.Profile
    }
}

ConvertTo-Json -InputObject @{ rules = $rules } -Compress -Depth 4
"""


def read_firewall_rules(powershell: str = "powershell.exe", timeout: int = 90) -> dict:
    """Run the read-only Get-NetFirewallRule query and return parsed JSON."""
    try:
        completed = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
             "Bypass", "-EncodedCommand",
             __import__("base64").b64encode(FIREWALL_RULES_SCRIPT.encode("utf-16-le")).decode("ascii")],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("PowerShell was not found. Rule audit runs on Windows only.") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError("Reading firewall rules timed out.") from None
    if completed.returncode != 0:
        raise RuntimeError("Reading firewall rules failed.")
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        raise RuntimeError("The firewall query returned unreadable output.") from None
    if not isinstance(payload, dict):
        raise RuntimeError("The firewall query returned an unexpected structure.")
    return payload


# ---------------------------------------------------------------------------
# MikroTik RouterOS
# ---------------------------------------------------------------------------
MIKROTIK_ACTIONS = ("accept", "drop")
MIKROTIK_CHAINS = ("input", "output", "forward")
MIKROTIK_PROTOCOLS = ("tcp", "udp", "icmp", "any")


def _quote_routeros(comment: str) -> str:
    return '"' + str(comment).replace('"', '\\"') + '"'


def validate_interface(name: str) -> str:
    value = str(name).strip()
    if not value:
        raise ValueError("Interface cannot be empty.")
    if not re.match(r"^[A-Za-z0-9._-]+$", value):
        raise ValueError(
            "Interface names may contain only letters, digits, dot, dash and underscore."
        )
    return value


@dataclass(frozen=True)
class MikroTikRule:
    """One validated /ip firewall filter rule."""

    chain: str
    action: str
    protocol: str = "any"
    dst_port: str = ""
    src_address: str = ""
    dst_address: str = ""
    in_interface: str = ""
    out_interface: str = ""
    connection_state: str = ""
    comment: str = ""

    def to_routeros(self) -> str:
        parts = ["/ip firewall filter add", f"chain={self.chain}", f"action={self.action}"]
        if self.protocol != "any":
            parts.append(f"protocol={self.protocol}")
        if self.dst_port:
            parts.append(f"dst-port={self.dst_port}")
        if self.src_address:
            parts.append(f"src-address={self.src_address}")
        if self.dst_address:
            parts.append(f"dst-address={self.dst_address}")
        if self.in_interface:
            parts.append(f"in-interface={self.in_interface}")
        if self.out_interface:
            parts.append(f"out-interface={self.out_interface}")
        if self.connection_state:
            parts.append(f"connection-state={self.connection_state}")
        if self.comment:
            parts.append(f"comment={_quote_routeros(self.comment)}")
        return " ".join(parts)


def build_mikrotik_rule(
    chain: str,
    action: str,
    protocol: str = "any",
    dst_port: str = "",
    src_address: str = "",
    dst_address: str = "",
    in_interface: str = "",
    out_interface: str = "",
    connection_state: str = "",
    comment: str = "",
) -> MikroTikRule:
    """Validate inputs and return a MikroTik filter rule."""
    chain = str(chain).strip().casefold()
    if chain not in MIKROTIK_CHAINS:
        raise ValueError("MikroTik chain must be input, output or forward.")
    action = str(action).strip().casefold()
    if action not in MIKROTIK_ACTIONS:
        raise ValueError("MikroTik action must be accept or drop.")
    protocol = str(protocol).strip().casefold()
    if protocol not in MIKROTIK_PROTOCOLS:
        raise ValueError("Protocol must be tcp, udp, icmp or any.")
    if dst_port:
        dst_port = validate_port_list(dst_port, "Destination port")
        if protocol not in ("tcp", "udp"):
            raise ValueError("Destination ports are only valid for tcp or udp.")
    if src_address:
        src_address = str(src_address).strip()
        if not _valid_mikrotik_address(src_address):
            raise ValueError("Source address must be an IPv4 address or CIDR block.")
    if dst_address:
        dst_address = str(dst_address).strip()
        if not _valid_mikrotik_address(dst_address):
            raise ValueError("Destination address must be an IPv4 address or CIDR block.")
    if in_interface:
        in_interface = validate_interface(in_interface)
    if out_interface:
        out_interface = validate_interface(out_interface)
    allowed_states = {"", "established", "new", "related", "invalid", "established,related", "established,related,new"}
    connection_state = str(connection_state).strip().casefold()
    if connection_state and connection_state not in allowed_states:
        raise ValueError("Connection state must be established, new, related, invalid or a comma list.")
    if comment:
        comment = validate_comment(comment, "Comment", limit=60)
    return MikroTikRule(
        chain=chain,
        action=action,
        protocol=protocol,
        dst_port=dst_port,
        src_address=src_address,
        dst_address=dst_address,
        in_interface=in_interface,
        out_interface=out_interface,
        connection_state=connection_state,
        comment=comment,
    )


def _valid_mikrotik_address(value: str) -> bool:
    value = value.strip()
    if "/" in value:
        host, _, prefix = value.partition("/")
        try:
            ipaddress.IPv4Address(host)
            return 0 <= int(prefix) <= 32
        except (ipaddress.AddressValueError, ValueError):
            return False
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def mikrotik_wan_hardening(wan_interface: str, allow_ping: bool = False) -> list[MikroTikRule]:
    """A readable WAN hardening recipe for teaching: a sequence of validated
    rules that protect the router's own input chain from the WAN."""
    wan = validate_interface(wan_interface)
    rules = [
        build_mikrotik_rule(
            "input", "accept", connection_state="established,related",
            in_interface=wan,
            comment=f"Allow established/related traffic from {wan}",
        ),
        build_mikrotik_rule(
            "input", "drop", connection_state="invalid",
            in_interface=wan,
            comment="Drop invalid packets from the WAN",
        ),
    ]
    if allow_ping:
        rules.append(build_mikrotik_rule(
            "input", "accept", protocol="icmp", in_interface=wan,
            comment="Allow ICMP (ping) from the WAN",
        ))
    else:
        rules.append(build_mikrotik_rule(
            "input", "drop", protocol="icmp", in_interface=wan,
            comment="Drop ICMP (ping) from the WAN",
        ))
    # block well-known dangerous inbound ports
    for port in (23, 445, 3389, 5900):
        rules.append(build_mikrotik_rule(
            "input", "drop", protocol="tcp", dst_port=str(port),
            in_interface=wan, comment=f"Block inbound TCP port {port} from {wan}",
        ))
    return rules


# ---------------------------------------------------------------------------
# Cisco IOS named extended ACL
# ---------------------------------------------------------------------------
CISCO_ACTIONS = ("permit", "deny")
CISCO_PROTOCOLS = ("ip", "tcp", "udp", "icmp")
_CISCO_SOURCE_KEYWORDS = ("any", "host")


def _parse_address_arg(value: str, label: str) -> str:
    """Parse an address argument into IOS form: any | host x | x wc."""
    value = str(value).strip()
    if not value:
        raise ValueError(f"{label} cannot be empty.")
    tokens = value.split()
    if value.casefold() == "any":
        return "any"
    if len(tokens) == 2 and tokens[0].casefold() == "host":
        ip = validate_ip_or_host(tokens[1], label)
        return f"host {ip}"
    if len(tokens) == 2:
        net, wildcard = tokens
        if not _is_valid_ip(net):
            raise ValueError(f"{label} network must be a valid IPv4 address.")
        if not is_contiguous_wildcard(wildcard):
            raise ValueError(f"{label} wildcard is invalid (must complement a contiguous mask).")
        return f"{net} {wildcard}"
    if len(tokens) == 1 and _is_valid_ip(tokens[0]):
        return f"{tokens[0]} 0.0.0.0"
    raise ValueError(
        f"{label} must be 'any', 'host <ip>', '<ip> <wildcard>' or a plain IPv4 address."
    )


def _validate_port_operator(protocol: str, operator: str, port_value: str) -> str:
    if operator == "":
        return ""
    if protocol not in ("tcp", "udp"):
        raise ValueError("Port operators are only valid for tcp or udp.")
    operator = str(operator).strip().casefold()
    allowed = ("eq", "neq", "gt", "lt") if protocol == "tcp" else ("eq", "neq")
    if operator not in allowed:
        raise ValueError(f"Port operator must be one of: {', '.join(allowed)}.")
    if operator == "range":
        raise ValueError("Use 'range low high' for ranges on Cisco ACLs.")
    validate_port(port_value, "Port")
    return f"{operator} {int(port_value)}"


@dataclass(frozen=True)
class CiscoAce:
    """One validated access-control entry."""

    action: str            # permit | deny
    protocol: str          # ip | tcp | udp | icmp
    source: str
    destination: str
    operator: str = ""     # eq <port> | neq <port> | gt <port> | lt <port> | range a b
    log: bool = False

    def to_ios(self) -> str:
        parts = [self.action, self.protocol, self.source, self.destination]
        if self.operator:
            parts.append(self.operator)
        if self.log and self.protocol != "ip":
            parts.append("log")
        return " ".join(parts)


def build_cisco_ace(
    action: str,
    protocol: str,
    source: str,
    destination: str,
    port_operator: str = "",
    port_value: str = "",
    log: bool = False,
) -> CiscoAce:
    action = str(action).strip().casefold()
    if action not in CISCO_ACTIONS:
        raise ValueError("Cisco action must be permit or deny.")
    protocol = str(protocol).strip().casefold()
    if protocol not in CISCO_PROTOCOLS:
        raise ValueError("Protocol must be ip, tcp, udp or icmp.")
    source = _parse_address_arg(source, "Source")
    destination = _parse_address_arg(destination, "Destination")
    operator = _validate_port_operator(protocol, port_operator, port_value)
    return CiscoAce(action, protocol, source, destination, operator, bool(log))


@dataclass(frozen=True)
class CiscoAcl:
    """A named extended ACL plus an optional interface binding."""

    name: str
    entries: tuple[CiscoAce, ...]
    interface: str = ""
    direction: str = "in"

    def to_ios(self) -> str:
        lines = [f"ip access-list extended {self.name}"]
        for entry in self.entries:
            lines.append(f" {entry.to_ios()}")
        if self.interface:
            lines.append("!")
            lines.append(f"interface {self.interface}")
            lines.append(f" ip access-group {self.name} {self.direction}")
        return "\n".join(lines)


def validate_cisco_interface(name: str) -> str:
    """Cisco interfaces may contain letters, digits and / : . _ - (no spaces)."""
    value = str(name).strip()
    if not value:
        raise ValueError("Interface cannot be empty.")
    if not re.match(r"^[A-Za-z0-9/.:_ -]+$", value) or " " in value:
        raise ValueError(
            "Interface names may contain only letters, digits and / : . _ - (no spaces)."
        )
    return value


def build_cisco_acl(
    name: str,
    entries: list[CiscoAce],
    interface: str = "",
    direction: str = "in",
) -> CiscoAcl:
    name = str(name).strip()
    if not name or not re.match(r"^[A-Za-z][A-Za-z0-9._-]{0,30}$", name):
        raise ValueError("ACL name must start with a letter and use letters, digits, . _ - only.")
    if not entries:
        raise ValueError("An ACL needs at least one entry.")
    if direction not in ("in", "out"):
        raise ValueError("Access-group direction must be in or out.")
    if interface:
        interface = validate_cisco_interface(interface)
    return CiscoAcl(name=name, entries=tuple(entries), interface=interface, direction=direction)


# ---------------------------------------------------------------------------
# ACL first-match simulator (teaches top-down evaluation)
# ---------------------------------------------------------------------------
def _ip_to_int(address: str) -> int:
    parts = [int(part) for part in str(address).strip().split(".")]
    value = 0
    for part in parts:
        value = value * 256 + part
    return value


def address_matches(spec: str, address: str) -> bool:
    """Does an ACE address spec ('any' | 'host x' | 'net wildcard') match?"""
    spec = str(spec).strip()
    if spec.casefold() == "any":
        return True
    tokens = spec.split()
    target = _ip_to_int(address)
    if len(tokens) == 2 and tokens[0].casefold() == "host":
        return _ip_to_int(tokens[1]) == target
    if len(tokens) == 2 and _is_valid_ip(tokens[0]) and _is_valid_ip(tokens[1]):
        network = _ip_to_int(tokens[0])
        wildcard = _ip_to_int(tokens[1])
        inverse = (~wildcard) & 0xFFFFFFFF
        return (target & inverse) == (network & inverse)
    if len(tokens) == 1 and _is_valid_ip(tokens[0]):
        return _ip_to_int(tokens[0]) == target
    return False


def simulate_acl(entries, protocol: str, source: str, destination: str,
                 port: int | None = None):
    """Walk the ACEs top-down and report the first match.

    Returns (verdict, matched_index, steps) where verdict is 'permit', 'deny'
    or None (implicit deny at the end), matched_index is 1-based or None, and
    steps is a list of (index, entry_text, matched) for display.
    """
    protocol = str(protocol).strip().casefold()
    steps = []
    for index, entry in enumerate(entries, start=1):
        matched = True
        if entry.protocol != "ip" and entry.protocol != protocol:
            matched = False
        if matched and not address_matches(entry.source, source):
            matched = False
        if matched and not address_matches(entry.destination, destination):
            matched = False
        if matched and port is not None and entry.operator and entry.protocol in ("tcp", "udp"):
            matched = _port_matches(entry.operator, port)
        steps.append((index, entry.to_ios(), matched))
        if matched:
            return entry.action, index, steps
    return None, None, steps


def _port_matches(operator: str, port: int) -> bool:
    """operator is a rendered string such as 'eq 443'."""
    tokens = str(operator).split()
    if len(tokens) != 2:
        return False
    op, value = tokens[0], int(tokens[1])
    if op == "eq":
        return port == value
    if op == "neq":
        return port != value
    if op == "gt":
        return port > value
    if op == "lt":
        return port < value
    return False


def cisco_block_inbound_template(interface: str = "") -> CiscoAcl:
    """Teaching template: block common risky inbound services, allow the rest."""
    entries = [
        build_cisco_ace("deny", "tcp", "any", "any", "eq", "445", log=True),
        build_cisco_ace("deny", "tcp", "any", "any", "eq", "3389", log=True),
        build_cisco_ace("deny", "tcp", "any", "any", "eq", "23", log=True),
        build_cisco_ace("permit", "tcp", "any", "any", "eq", "443"),
        build_cisco_ace("permit", "tcp", "any", "any", "eq", "80"),
        build_cisco_ace("permit", "ip", "any", "any"),
    ]
    return build_cisco_acl("BLOCK_RISKY", entries, interface=interface)


def cisco_allow_management_template(management_ip: str, interface: str = "") -> CiscoAcl:
    """Teaching template: allow SSH only from one management host, deny the rest."""
    entries = [
        build_cisco_ace("permit", "tcp", f"host {validate_ip_or_host(management_ip, 'Management IP')}", "any", "eq", "22"),
        build_cisco_ace("deny", "tcp", "any", "any", "eq", "22", log=True),
        build_cisco_ace("permit", "ip", "any", "any"),
    ]
    return build_cisco_acl("MGMT_SSH", entries, interface=interface)
