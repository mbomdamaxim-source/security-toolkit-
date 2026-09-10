"""Tests for the Firewall Builder logic: validation and command rendering."""
import pytest

from modules.firewall.logic import (
    build_cisco_ace,
    build_cisco_acl,
    build_mikrotik_rule,
    build_windows_rule,
    cisco_allow_management_template,
    cisco_block_inbound_template,
    is_contiguous_wildcard,
    mikrotik_wan_hardening,
    parse_windows_rules,
    validate_port_list,
)


# --------------------------------------------------------------------------
# Windows Defender Firewall
# --------------------------------------------------------------------------
def test_windows_rule_allow_inbound_renders_correctly():
    rule = build_windows_rule("Allow HTTPS", "allow", "in", "TCP", "443")
    command = rule.to_powershell()
    assert command.startswith("New-NetFirewallRule")
    assert "-DisplayName 'Allow HTTPS'" in command
    assert "-Direction Inbound" in command
    assert "-Action Allow" in command
    assert "-Protocol TCP" in command
    assert "-LocalPort '443'" in command
    assert "-Profile 'Any'" in command


def test_windows_rule_block_outbound_uses_block_not_deny():
    rule = build_windows_rule("Block exfil port", "block", "out", "TCP", "8080")
    command = rule.to_powershell()
    assert "-Direction Outbound" in command
    assert "-Action Block" in command
    assert "deny" not in command.casefold()


def test_windows_rule_rejects_bad_vocabulary():
    with pytest.raises(ValueError, match="action must be 'allow' or 'block'"):
        build_windows_rule("x", "deny", "in", "TCP", "80")  # not allow|block
    with pytest.raises(ValueError, match="direction must be 'in' or 'out'"):
        build_windows_rule("x", "allow", "inbound", "TCP", "80")
    with pytest.raises(ValueError, match="required for protocol"):
        build_windows_rule("x", "allow", "in", "TCP", "")
    with pytest.raises(ValueError, match="whole number"):
        build_windows_rule("x", "allow", "in", "TCP", "70000")
    with pytest.raises(ValueError, match="Ports cannot be empty"):
        validate_port_list("")
    with pytest.raises(ValueError, match="range start is larger"):
        build_windows_rule("x", "allow", "in", "TCP", "500-100")


def test_windows_rule_port_list_and_range_ok():
    assert build_windows_rule("a", "allow", "in", "TCP", "80,443").local_port == "80,443"
    assert build_windows_rule("b", "allow", "in", "UDP", "137-139").local_port == "137-139"


def test_windows_rule_program_and_remote_address():
    rule = build_windows_rule(
        "Block app", "block", "out", "TCP", "443",
        remote_address="10.0.0.0/8" if False else "192.168.1.5",
        program="C:\\Windows\\evil.exe",
    )
    command = rule.to_powershell()
    assert "-RemoteAddress '192.168.1.5'" in command
    assert "-Program" in command
    with pytest.raises(ValueError, match=".exe"):
        build_windows_rule("x", "block", "out", "TCP", "443", program="not-a-program")


def test_parse_windows_rules_single_and_list():
    payload = {"rules": {"Name": "r1", "DisplayName": "R1", "Direction": "Inbound",
                         "Action": "Allow", "Enabled": "True", "Profile": "Any"}}
    rules = parse_windows_rules(payload)
    assert len(rules) == 1 and rules[0].name == "r1" and rules[0].enabled
    payload2 = {"rules": [
        {"Name": "a", "DisplayName": "A", "Direction": "Inbound", "Action": "Block",
         "Enabled": "False", "Profile": "Public"},
        {"Name": "b", "DisplayName": "B", "Direction": "Outbound", "Action": "Allow",
         "Enabled": "True", "Profile": "Any"},
    ]}
    assert len(parse_windows_rules(payload2)) == 2


# --------------------------------------------------------------------------
# MikroTik
# --------------------------------------------------------------------------
def test_mikrotik_rule_basic_and_quoted_comment():
    rule = build_mikrotik_rule("input", "drop", protocol="tcp", dst_port="445",
                               in_interface="ether1-WAN", comment="Block SMB")
    command = rule.to_routeros()
    assert command.startswith("/ip firewall filter add chain=input action=drop")
    assert "protocol=tcp" in command and "dst-port=445" in command
    assert 'comment="Block SMB"' in command


def test_mikrotik_rule_validates():
    with pytest.raises(ValueError, match="chain must be input"):
        build_mikrotik_rule("bogus", "drop")
    with pytest.raises(ValueError, match="action must be accept or drop"):
        build_mikrotik_rule("input", "reject")
    with pytest.raises(ValueError, match="only valid for tcp or udp"):
        build_mikrotik_rule("input", "drop", protocol="icmp", dst_port="80")
    with pytest.raises(ValueError, match="Interface names"):
        build_mikrotik_rule("input", "drop", in_interface="bad interface!")
    with pytest.raises(ValueError, match="Source address"):
        build_mikrotik_rule("input", "drop", src_address="999.1.1.1")


def test_mikrotik_wan_hardening_template():
    rules = mikrotik_wan_hardening("ether1-WAN", allow_ping=False)
    assert len(rules) == 7
    assert all(rule.in_interface == "ether1-WAN" for rule in rules)
    assert rules[0].action == "accept" and "established" in rules[0].connection_state
    assert rules[1].action == "drop" and rules[1].connection_state == "invalid"
    # ping blocked when allow_ping=False, allowed when True
    assert rules[2].action == "drop" and rules[2].protocol == "icmp"
    ping_ok = mikrotik_wan_hardening("ether1", allow_ping=True)
    assert ping_ok[2].action == "accept"
    # dangerous ports blocked
    assert any(rule.dst_port == "3389" and rule.action == "drop" for rule in rules)


# --------------------------------------------------------------------------
# Cisco IOS
# --------------------------------------------------------------------------
def test_cisco_ace_and_acl_render():
    ace = build_cisco_ace("deny", "tcp", "any", "any", "eq", "445")
    acl = build_cisco_acl("BLOCK", [ace], interface="GigabitEthernet0/1", direction="in")
    text = acl.to_ios()
    assert text.startswith("ip access-list extended BLOCK")
    assert " deny tcp any any eq 445" in text
    assert "interface GigabitEthernet0/1" in text
    assert " ip access-group BLOCK in" in text


def test_cisco_address_forms():
    assert build_cisco_ace("permit", "tcp", "any", "host 192.168.1.10", "eq", "80").to_ios() == \
        "permit tcp any host 192.168.1.10 eq 80"
    assert build_cisco_ace("permit", "ip", "10.0.0.0 0.0.0.255", "any").to_ios() == \
        "permit ip 10.0.0.0 0.0.0.255 any"


def test_cisco_rejects_bad_wildcard_and_vocabulary():
    with pytest.raises(ValueError, match="wildcard is invalid"):
        build_cisco_ace("permit", "ip", "10.0.0.0 0.0.1.1", "any")
    with pytest.raises(ValueError, match="action must be permit or deny"):
        build_cisco_ace("allow", "ip", "any", "any")
    with pytest.raises(ValueError, match="Port operators are only valid"):
        build_cisco_ace("permit", "icmp", "any", "any", "eq", "80")


def test_cisco_templates():
    block = cisco_block_inbound_template(interface="GigabitEthernet0/1")
    assert any("eq 3389" in e.to_ios() and e.action == "deny" for e in block.entries)
    assert any(e.action == "permit" and e.protocol == "ip" for e in block.entries)
    mgmt = cisco_allow_management_template("192.168.1.10")
    assert any("host 192.168.1.10" in e.source and e.protocol == "tcp" for e in mgmt.entries)
    with pytest.raises(ValueError):
        cisco_allow_management_template("not-an-ip")


def test_wildcard_helper():
    assert is_contiguous_wildcard("0.0.0.255")
    assert is_contiguous_wildcard("0.0.255.255")
    assert is_contiguous_wildcard("0.0.0.0")
    assert is_contiguous_wildcard("255.255.255.255")
    assert not is_contiguous_wildcard("0.0.1.1")


def test_rules_script_uses_cmdlet_and_json():
    from modules.firewall.logic import FIREWALL_RULES_SCRIPT
    assert "Get-NetFirewallRule" in FIREWALL_RULES_SCRIPT
    assert "ConvertTo-Json" in FIREWALL_RULES_SCRIPT
    assert "netsh" not in FIREWALL_RULES_SCRIPT.lower()


def test_read_firewall_rules_success(monkeypatch):
    from modules.firewall.logic import read_firewall_rules
    payload = {"rules": [{"Name": "r1", "DisplayName": "R1", "Direction": "Inbound",
                          "Action": "Allow", "Enabled": "True", "Profile": "Any"}]}

    class FakeCompleted:
        returncode = 0
        stdout = __import__("json").dumps(payload)
        stderr = ""

    monkeypatch.setattr("modules.firewall.logic.subprocess.run",
                        lambda *a, **k: FakeCompleted())
    parsed = read_firewall_rules()
    assert parsed["rules"][0]["Name"] == "r1"


def test_read_firewall_rules_failures(monkeypatch):
    from modules.firewall.logic import read_firewall_rules

    class Failed:
        returncode = 1
        stdout = ""
        stderr = ""

    monkeypatch.setattr("modules.firewall.logic.subprocess.run",
                        lambda *a, **k: Failed())
    try:
        read_firewall_rules()
        raise AssertionError("should raise")
    except RuntimeError as error:
        assert "failed" in str(error)

    def missing(*a, **k):
        raise FileNotFoundError("powershell.exe")

    monkeypatch.setattr("modules.firewall.logic.subprocess.run", missing)
    try:
        read_firewall_rules()
        raise AssertionError("should raise")
    except RuntimeError as error:
        assert "Windows only" in str(error)


def test_acl_simulator_first_match_wins():
    from modules.firewall.logic import simulate_acl
    aces = [
        build_cisco_ace("deny", "tcp", "any", "any", "eq", "445"),
        build_cisco_ace("permit", "tcp", "any", "any", "eq", "443"),
        build_cisco_ace("permit", "ip", "any", "any"),
    ]
    verdict, index, steps = simulate_acl(aces, "tcp", "192.168.1.50", "8.8.8.8", 445)
    assert verdict == "deny" and index == 1 and steps[0][2] is True

    verdict, index, _ = simulate_acl(aces, "tcp", "192.168.1.50", "8.8.8.8", 443)
    assert verdict == "permit" and index == 2

    verdict, index, _ = simulate_acl(aces, "udp", "192.168.1.50", "8.8.8.8", 53)
    assert verdict == "permit" and index == 3


def test_acl_simulator_implicit_deny_and_host_matching():
    from modules.firewall.logic import simulate_acl
    aces = [build_cisco_ace("permit", "tcp", "host 192.168.1.10", "any", "eq", "22")]
    verdict, index, _ = simulate_acl(aces, "tcp", "192.168.1.10", "8.8.8.8", 22)
    assert verdict == "permit" and index == 1
    verdict, index, steps = simulate_acl(aces, "tcp", "192.168.1.11", "8.8.8.8", 22)
    assert verdict is None and index is None  # implicit deny
    assert steps and steps[0][2] is False


def test_address_matches_wildcard():
    from modules.firewall.logic import address_matches
    assert address_matches("any", "1.2.3.4")
    assert address_matches("10.0.0.0 0.0.0.255", "10.0.0.5")
    assert not address_matches("10.0.0.0 0.0.0.255", "10.0.1.5")
    assert address_matches("host 192.168.1.10", "192.168.1.10")
