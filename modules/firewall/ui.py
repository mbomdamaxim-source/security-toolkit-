"""Native PySide6 Firewall Builder: validated rule construction for three
targets (Windows Defender, MikroTik RouterOS, Cisco IOS), a learning dialog,
and a port/attack reference.

Generate + copy only: applying rules to a live system is a separate,
administrator-gated action that belongs to the UI layer and is not offered
for network devices (RouterOS/Cisco) from this workstation.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QTabWidget, QVBoxLayout, QWidget,
)

from core import theme
from core.context import AppContext
from core.status_widgets import ModuleHeader
from modules.firewall.learn import FirewallLearnDialog
from modules.firewall.logic import (
    build_cisco_ace,
    build_cisco_acl,
    build_mikrotik_rule,
    build_windows_rule,
    mikrotik_wan_hardening,
    parse_windows_rules,
    read_firewall_rules,
    simulate_acl,
)

_PORT_INCIDENTS = [
    ("21", "TCP", "FTP", "Passwords and files sent in clear text; anonymous uploads",
     "FTP credential sniffing; malware planted via anonymous write", "Use SFTP/FTPS and block inbound FTP unless truly needed"),
    ("22", "TCP", "SSH", "Brute force when weak passwords are used",
     "Continuous SSH brute-force campaigns against exposed servers", "Allow only from management hosts; use key authentication"),
    ("23", "TCP", "Telnet", "No encryption at all; easy to sniff and hijack",
     "Mirai botnet enslaved routers via Telnet defaults", "Block it; use SSH instead"),
    ("25", "TCP", "SMTP", "Open relays send spam; spoofed mail",
     "Spam relays abused for phishing campaigns", "Only mail servers need it; never expose it on workstations"),
    ("53", "UDP/TCP", "DNS", "Amplification if open to the internet; cache poisoning",
     "DNS amplification DDoS attacks", "Only run a DNS server if you host domains"),
    ("135", "TCP", "RPC", "Remote code execution when vulnerable",
     "Multiple Windows RCE exploits (e.g. CVE-2017-0145 chain)", "Not needed on modern networks - block inbound"),
    ("139/445", "TCP", "NetBIOS / SMB", "File-sharing protocol with a history of critical RCE",
     "EternalBlue (MS17-010) -> WannaCry and NotPetya ransomware", "Block inbound SMB on the internet boundary; keep SMBv1 disabled"),
    ("3389", "TCP", "RDP", "Brute force and pre-auth RCE when exposed",
     "BlueKeep (CVE-2019-0708); ransomware groups buy RDP access", "Never expose RDP to the internet; use a VPN or allowlist"),
    ("5900", "TCP", "VNC", "Often unprotected or weak password; full screen control",
     "VNC exposures probed and taken over by bots", "Use a VPN; never expose VNC directly"),
    ("2375", "TCP", "Docker API", "Unauthenticated remote API = full container control",
     "Cryptojacking via exposed Docker daemons", "Bind to localhost only; never 0.0.0.0"),
    ("3306/5432/27017", "TCP", "MySQL / PostgreSQL / MongoDB",
     "Databases exposed to brute force and ransomware",
     "MongoDB ransom attacks; database credential stuffing", "Databases belong on private networks, not the internet"),
    ("8080/8443", "TCP", "Web (alt)", "Dev consoles and admin panels on non-standard ports",
     "Jenkins / admin panels brute-forced when exposed", "Verify what listens here; bind admin panels to localhost"),
]


class FirewallRulesWorker(QThread):
    """Reads existing Windows firewall rules off the UI thread."""

    succeeded = Signal(object)  # tuple[ExistingRule, ...]
    failed = Signal(str)

    def run(self):
        try:
            payload = read_firewall_rules()
            self.succeeded.emit(parse_windows_rules(payload))
        except RuntimeError as error:
            self.failed.emit(str(error))


class FirewallModule(QWidget):
    """Three validated rule builders with copyable output."""

    def __init__(self, context: AppContext):
        super().__init__()
        self.context = context

        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL)
        layout.setSpacing(theme.SPACE_MD)

        header = QHBoxLayout()
        header.setSpacing(theme.SPACE_MD)
        header.addWidget(ModuleHeader(
            "Firewall Builder",
            "Create validated firewall rules for Windows Defender Firewall, "
            "MikroTik RouterOS and Cisco IOS ACLs - with plain-language explanations.",
        ), 1)
        self.learn_button = QPushButton("Practice & Quiz")
        self.learn_button.setAccessibleName("Open firewall practice labs and concepts quiz")
        self.learn_button.clicked.connect(self._open_learn)
        header.addWidget(self.learn_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)

        note = QLabel(
            "<b>Generate, do not apply:</b> this module builds and copies commands only - nothing "
            "is changed on any system. Windows rules must be run in an elevated PowerShell on the "
            "target; RouterOS and IOS commands run on their respective devices. Input is validated "
            "before a command is produced."
        )
        note.setWordWrap(True)
        note.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE};"
            f" border-left: 4px solid {theme.COLOR_INFO};"
            f" border-radius: {theme.RADIUS_SM}px;"
            f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
            f" color: {theme.COLOR_TEXT_SECONDARY};"
        )
        layout.addWidget(note)

        self._cis_row_data = []

        self._audit_rules = []
        self._audit_worker = None

        tabs = QTabWidget()
        tabs.addTab(self._windows_tab(), "Windows Defender")
        tabs.addTab(self._mikrotik_tab(), "MikroTik RouterOS")
        tabs.addTab(self._cisco_tab(), "Cisco IOS ACL")
        tabs.addTab(self._audit_tab(), "Rule audit")
        layout.addWidget(tabs, 1)

        reference = self._reference_widget()
        layout.addWidget(reference)

    # ------------------------------------------------------------- learning
    def _open_learn(self):
        dialog = FirewallLearnDialog(self)
        window = self.window()
        if window is not None:
            dialog.move(window.geometry().center() - dialog.rect().center())
        dialog.exec()
        dialog.deleteLater()

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _form_row(label_text, widget) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(theme.SPACE_MD)
        label = QLabel(label_text)
        label.setFixedWidth(150)
        label.setWordWrap(True)
        layout.addWidget(label)
        layout.addWidget(widget, 1)
        return row

    def _output_panel(self, title: str) -> tuple[QFrame, QLineEdit]:
        panel = QFrame()
        panel.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE};"
            f" border: 1px solid {theme.COLOR_BORDER};"
            f" border-radius: {theme.RADIUS_MD}px;"
        )
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(theme.SPACE_MD, theme.SPACE_MD, theme.SPACE_MD, theme.SPACE_MD)
        layout.setSpacing(theme.SPACE_SM)
        label = QLabel(title)
        label.setStyleSheet("font-weight: 600;")
        output = QLineEdit()
        output.setReadOnly(True)
        output.setPlaceholderText("The generated command appears here.")
        output.setAccessibleName(title)
        font = output.font()
        font.setFamily("Consolas")
        font.setPointSize(9)
        output.setFont(font)
        layout.addWidget(label)
        layout.addWidget(output)
        return panel, output

    @staticmethod
    def _explain_label(text: str) -> QLabel:
        label = QLabel(text)
        label.setWordWrap(True)
        label.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE_RAISED};"
            f" border-left: 3px solid {theme.COLOR_ACCENT};"
            f" border-radius: {theme.RADIUS_SM}px;"
            f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
            f" color: {theme.COLOR_TEXT_SECONDARY};"
        )
        return label

    @staticmethod
    def _template_button(text: str, callback) -> QPushButton:
        button = QPushButton(text)
        button.setStyleSheet(
            f"QPushButton {{ background-color: {theme.COLOR_SURFACE_RAISED};"
            f" color: {theme.COLOR_TEXT_PRIMARY};"
            f" border: 1px solid {theme.COLOR_BORDER};"
            f" border-radius: {theme.RADIUS_SM}px; padding: 6px 10px; }}"
            f"QPushButton:hover {{ border-color: {theme.COLOR_ACCENT}; }}"
        )
        button.clicked.connect(callback)
        return button

    # ------------------------------------------------------------- windows
    def _windows_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(theme.SPACE_MD)

        grid = QGridLayout()
        grid.setHorizontalSpacing(theme.SPACE_MD)
        grid.setVerticalSpacing(theme.SPACE_SM)

        self.win_name = QLineEdit()
        self.win_name.setPlaceholderText("e.g. Allow HTTPS inbound 443")
        grid.addWidget(QLabel("Rule name"), 0, 0)
        grid.addWidget(self.win_name, 0, 1)

        self.win_action = QComboBox()
        self.win_action.addItems(["allow", "block"])
        grid.addWidget(QLabel("Action"), 1, 0)
        grid.addWidget(self.win_action, 1, 1)

        self.win_direction = QComboBox()
        self.win_direction.addItems(["in", "out"])
        grid.addWidget(QLabel("Direction"), 2, 0)
        grid.addWidget(self.win_direction, 2, 1)

        self.win_protocol = QComboBox()
        self.win_protocol.addItems(["TCP", "UDP", "ICMPv4", "Any"])
        grid.addWidget(QLabel("Protocol"), 3, 0)
        grid.addWidget(self.win_protocol, 3, 1)

        self.win_port = QLineEdit()
        self.win_port.setPlaceholderText("443 or 80,443 or 137-139")
        grid.addWidget(QLabel("Local port (TCP/UDP)"), 4, 0)
        grid.addWidget(self.win_port, 4, 1)

        self.win_profile = QComboBox()
        self.win_profile.addItems(["Any", "Domain", "Private", "Public"])
        grid.addWidget(QLabel("Profile"), 5, 0)
        grid.addWidget(self.win_profile, 5, 1)

        self.win_remote = QLineEdit()
        self.win_remote.setPlaceholderText("Any, LocalSubnet or a single IPv4")
        grid.addWidget(QLabel("Remote address"), 6, 0)
        grid.addWidget(self.win_remote, 6, 1)

        self.win_program = QLineEdit()
        self.win_program.setPlaceholderText("Full path to an .exe")
        grid.addWidget(QLabel("Program"), 7, 0)
        grid.addWidget(self.win_program, 7, 1)

        self.win_desc = QLineEdit()
        self.win_desc.setPlaceholderText("Why this rule exists")
        grid.addWidget(QLabel("Description"), 8, 0)
        grid.addWidget(self.win_desc, 8, 1)
        layout.addLayout(grid)

        templates = QHBoxLayout()
        templates.setSpacing(theme.SPACE_SM)
        templates.addWidget(QLabel("Templates:"))
        templates.addWidget(self._template_button("Allow HTTPS (443) inbound", self._win_tpl_web))
        templates.addWidget(self._template_button("Block RDP (3389) inbound", self._win_tpl_rdp))
        templates.addWidget(self._template_button("Block SMB (445) outbound", self._win_tpl_smb))
        templates.addStretch(1)
        layout.addLayout(templates)

        controls = QHBoxLayout()
        self.win_copy = QPushButton("Copy command")
        self.win_copy.clicked.connect(self._win_copy_command)
        self.win_status = QLabel("")
        self.win_status.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        controls.addWidget(self.win_copy)
        controls.addWidget(self.win_status, 1)
        layout.addLayout(controls)

        _, self.win_output = self._output_panel("Generated PowerShell command")
        layout.addWidget(self.win_output)
        self.win_explain = self._explain_label(
            "Fill the form to generate a New-NetFirewallRule command. Vocabulary: "
            "Allow / Block (not \"deny\") and Inbound / Outbound directions."
        )
        layout.addWidget(self.win_explain)

        for widget in (self.win_name, self.win_port, self.win_remote, self.win_program, self.win_desc):
            widget.textChanged.connect(self._win_refresh)
        for widget in (self.win_action, self.win_direction, self.win_protocol, self.win_profile):
            widget.currentIndexChanged.connect(self._win_refresh)
        layout.addStretch(1)
        return tab

    def _win_opts(self) -> dict:
        return {
            "name": self.win_name.text(),
            "action": self.win_action.currentText(),
            "direction": self.win_direction.currentText(),
            "protocol": self.win_protocol.currentText(),
            "local_port": self.win_port.text(),
            "remote_address": self.win_remote.text(),
            "program": self.win_program.text(),
            "profile": self.win_profile.currentText(),
            "description": self.win_desc.text(),
        }

    def _win_refresh(self):
        try:
            spec = build_windows_rule(**self._win_opts())
            self.win_output.setText(spec.to_powershell())
            self._explain_windows(spec)
        except ValueError as error:
            self.win_output.setText("")
            self.win_explain.setText(str(error))
            self.win_explain.setStyleSheet(
                f"background-color: {theme.COLOR_SURFACE_RAISED};"
                f" border-left: 3px solid {theme.COLOR_DANGER};"
                f" border-radius: {theme.RADIUS_SM}px;"
                f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
                f" color: {theme.COLOR_DANGER};"
            )

    def _explain_windows(self, spec):
        direction = "Inbound" if spec.direction == "in" else "Outbound"
        lines = [
            f"Name: names the rule \"{spec.name}\" so you can manage it later in Windows Defender Firewall.",
            f"Direction {direction}: governs connections that {'arrive from other hosts' if spec.direction == 'in' else 'this computer initiates'}.",
            f"Action {spec.action.title()}: {'permits' if spec.action == 'allow' else 'drops'} matching traffic. A Block rule wins over Allow rules.",
            f"Profile {spec.profile}: applies when Windows classifies the network as {spec.profile}.",
        ]
        if spec.protocol != "Any":
            lines.append(f"Protocol {spec.protocol}: only {spec.protocol} packets are matched.")
            if spec.local_port:
                lines.append(f"LocalPort {spec.local_port}: matches local port(s) {spec.local_port}.")
        if spec.remote_address:
            lines.append(f"RemoteAddress {spec.remote_address}: limits the rule to that remote address.")
        if spec.program:
            lines.append(f"Program {spec.program}: restricts the rule to that executable only.")
        if spec.description:
            lines.append(f"Description: {spec.description}.")
        lines.append("Run the command in an ELEVATED PowerShell - it changes the firewall immediately.")
        self.win_explain.setText("\n".join(lines))
        self.win_explain.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE_RAISED};"
            f" border-left: 3px solid {theme.COLOR_ACCENT};"
            f" border-radius: {theme.RADIUS_SM}px;"
            f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
            f" color: {theme.COLOR_TEXT_SECONDARY};"
        )

    def _win_apply_template(self, name, action, direction, protocol, port):
        self.win_name.setText(name)
        self.win_action.setCurrentText(action)
        self.win_direction.setCurrentText(direction)
        self.win_protocol.setCurrentText(protocol)
        self.win_port.setText(port)
        self.win_remote.setText("")
        self.win_program.setText("")
        self.win_desc.setText("")
        self._win_refresh()

    def _win_tpl_web(self):
        self._win_apply_template("Allow HTTPS inbound", "allow", "in", "TCP", "443")

    def _win_tpl_rdp(self):
        self._win_apply_template("Block RDP inbound", "block", "in", "TCP", "3389")

    def _win_tpl_smb(self):
        self._win_apply_template("Block SMB outbound", "block", "out", "TCP", "445")

    def _win_copy_command(self):
        command = self.win_output.text()
        if not command:
            return
        QApplication.clipboard().setText(command)
        self.win_status.setText("Copied to clipboard.")

    # ------------------------------------------------------------- mikrotik
    def _mikrotik_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(theme.SPACE_MD)

        grid = QGridLayout()
        grid.setHorizontalSpacing(theme.SPACE_MD)
        grid.setVerticalSpacing(theme.SPACE_SM)

        self.mik_chain = QComboBox()
        self.mik_chain.addItems(["input", "output", "forward"])
        grid.addWidget(QLabel("Chain"), 0, 0)
        grid.addWidget(self.mik_chain, 0, 1)

        self.mik_action = QComboBox()
        self.mik_action.addItems(["accept", "drop"])
        grid.addWidget(QLabel("Action"), 0, 2)
        grid.addWidget(self.mik_action, 0, 3)

        self.mik_protocol = QComboBox()
        self.mik_protocol.addItems(["any", "tcp", "udp", "icmp"])
        grid.addWidget(QLabel("Protocol"), 1, 0)
        grid.addWidget(self.mik_protocol, 1, 1)

        self.mik_dstport = QLineEdit()
        self.mik_dstport.setPlaceholderText("e.g. 3389 or 80,443 or 137-139")
        grid.addWidget(QLabel("Dst port (tcp/udp)"), 1, 2)
        grid.addWidget(self.mik_dstport, 1, 3)

        self.mik_src = QLineEdit()
        self.mik_src.setPlaceholderText("IPv4 or CIDR - empty for any")
        grid.addWidget(QLabel("Source address"), 2, 0)
        grid.addWidget(self.mik_src, 2, 1)

        self.mik_dst = QLineEdit()
        self.mik_dst.setPlaceholderText("IPv4 or CIDR - empty for any")
        grid.addWidget(QLabel("Dest address"), 2, 2)
        grid.addWidget(self.mik_dst, 2, 3)

        self.mik_inif = QLineEdit()
        self.mik_inif.setPlaceholderText("e.g. ether1-WAN")
        grid.addWidget(QLabel("In interface"), 3, 0)
        grid.addWidget(self.mik_inif, 3, 1)

        self.mik_outif = QLineEdit()
        self.mik_outif.setPlaceholderText("e.g. ether2-LAN")
        grid.addWidget(QLabel("Out interface"), 3, 2)
        grid.addWidget(self.mik_outif, 3, 3)

        self.mik_state = QComboBox()
        self.mik_state.addItems(["", "established", "new", "related", "invalid",
                                 "established,related", "established,related,new"])
        grid.addWidget(QLabel("Connection state"), 4, 0)
        grid.addWidget(self.mik_state, 4, 1)

        self.mik_comment = QLineEdit()
        self.mik_comment.setPlaceholderText("Short description (max 60 chars)")
        grid.addWidget(QLabel("Comment"), 4, 2)
        grid.addWidget(self.mik_comment, 4, 3)
        layout.addLayout(grid)

        recipe = QHBoxLayout()
        recipe.setSpacing(theme.SPACE_SM)
        recipe.addWidget(QLabel("WAN hardening recipe"))
        self.mik_wan = QLineEdit("ether1-WAN")
        self.mik_wan.setMaximumWidth(150)
        recipe.addWidget(self.mik_wan)
        run_recipe = self._template_button("Generate WAN hardening recipe (7 rules)", self._mik_recipe)
        recipe.addWidget(run_recipe)
        recipe.addStretch(1)
        layout.addLayout(recipe)

        controls = QHBoxLayout()
        self.mik_copy = QPushButton("Copy rule")
        self.mik_copy.clicked.connect(self._mik_copy_command)
        self.mik_status = QLabel("")
        self.mik_status.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        controls.addWidget(self.mik_copy)
        controls.addWidget(self.mik_status, 1)
        layout.addLayout(controls)

        self.mik_output = QLineEdit()
        self.mik_output.setReadOnly(True)
        self.mik_output.setAccessibleName("Generated RouterOS command")
        font = self.mik_output.font()
        font.setFamily("Consolas")
        font.setPointSize(9)
        self.mik_output.setFont(font)
        layout.addWidget(self.mik_output)
        self.mik_explain = self._explain_label(
            "Fill the form to generate an /ip firewall filter command. Rules are evaluated "
            "top-down in the chain: the first match decides."
        )
        layout.addWidget(self.mik_explain)
        layout.addStretch(1)

        for widget in (self.mik_dstport, self.mik_src, self.mik_dst, self.mik_inif,
                       self.mik_outif, self.mik_comment):
            widget.textChanged.connect(self._mik_refresh)
        for widget in (self.mik_chain, self.mik_action, self.mik_protocol, self.mik_state):
            widget.currentIndexChanged.connect(self._mik_refresh)
        return tab

    def _mik_opts(self) -> dict:
        return {
            "chain": self.mik_chain.currentText(),
            "action": self.mik_action.currentText(),
            "protocol": self.mik_protocol.currentText(),
            "dst_port": self.mik_dstport.text(),
            "src_address": self.mik_src.text(),
            "dst_address": self.mik_dst.text(),
            "in_interface": self.mik_inif.text(),
            "out_interface": self.mik_outif.text(),
            "connection_state": self.mik_state.currentText(),
            "comment": self.mik_comment.text(),
        }

    def _mik_refresh(self):
        try:
            rule = build_mikrotik_rule(**self._mik_opts())
            self.mik_output.setText(rule.to_routeros())
            self._explain_mikrotik(rule)
        except ValueError as error:
            self.mik_output.setText("")
            self.mik_explain.setText(str(error))
            self.mik_explain.setStyleSheet(
                f"background-color: {theme.COLOR_SURFACE_RAISED};"
                f" border-left: 3px solid {theme.COLOR_DANGER};"
                f" border-radius: {theme.RADIUS_SM}px;"
                f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
                f" color: {theme.COLOR_DANGER};"
            )

    def _explain_mikrotik(self, rule):
        if rule.chain == "input":
            chain_text = "packets destined to the router itself - protects the router"
        elif rule.chain == "output":
            chain_text = "packets the router itself sends out"
        else:
            chain_text = "packets routed through the router (LAN to WAN)"
        lines = [
            f"chain={rule.chain}: applies to {chain_text}.",
            f"action={rule.action}: {'the packet passes and evaluation continues' if rule.action == 'accept' else 'the packet is silently discarded - no reply is sent'}.",
        ]
        if rule.protocol != "any":
            lines.append(f"protocol={rule.protocol}: matches only {rule.protocol.upper()} packets.")
        if rule.dst_port:
            lines.append(f"dst-port={rule.dst_port}: matches destination port(s) {rule.dst_port}.")
        if rule.src_address:
            lines.append(f"src-address={rule.src_address}: the source must be inside that network.")
        if rule.dst_address:
            lines.append(f"dst-address={rule.dst_address}: the destination must be inside that network.")
        if rule.in_interface:
            lines.append(f"in-interface={rule.in_interface}: the packet must arrive on that interface (usually your WAN side).")
        if rule.out_interface:
            lines.append(f"out-interface={rule.out_interface}: the packet must leave through that interface.")
        if rule.connection_state:
            lines.append(f"connection-state={rule.connection_state}: RouterOS stateful filtering - accepting 'established,related' lets replies to your own traffic through automatically.")
        if rule.comment:
            lines.append(f"comment: documents the purpose - {rule.comment}.")
        lines.append("Rules are evaluated from the top of the chain down; the first match decides.")
        self.mik_explain.setText("\n".join(lines))
        self.mik_explain.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE_RAISED};"
            f" border-left: 3px solid {theme.COLOR_ACCENT};"
            f" border-radius: {theme.RADIUS_SM}px;"
            f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
            f" color: {theme.COLOR_TEXT_SECONDARY};"
        )

    def _mik_recipe(self):
        try:
            rules = mikrotik_wan_hardening(self.mik_wan.text(), allow_ping=False)
        except ValueError as error:
            self.mik_output.setText("")
            self.mik_explain.setText(str(error))
            return
        text = "\n".join(rule.to_routeros() for rule in rules)
        self.mik_output.setText(text)
        self.mik_output.setCursorPosition(0)
        explanations = []
        for index, rule in enumerate(rules, start=1):
            purpose = rule.comment or rule.to_routeros()
            explanations.append(f"Rule {index}: {purpose}")
        self.mik_explain.setText("\n".join(explanations))
        self.mik_explain.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE_RAISED};"
            f" border-left: 3px solid {theme.COLOR_ACCENT};"
            f" border-radius: {theme.RADIUS_SM}px;"
            f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
            f" color: {theme.COLOR_TEXT_SECONDARY};"
        )

    def _mik_copy_command(self):
        command = self.mik_output.text()
        if not command:
            return
        QApplication.clipboard().setText(command)
        self.mik_status.setText("Copied to clipboard.")

    # ------------------------------------------------------------- cisco
    def _cisco_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(theme.SPACE_MD)

        grid = QGridLayout()
        grid.setHorizontalSpacing(theme.SPACE_MD)
        grid.setVerticalSpacing(theme.SPACE_SM)
        self.cis_name = QLineEdit("BLOCK_RISKY")
        grid.addWidget(QLabel("ACL name"), 0, 0)
        grid.addWidget(self.cis_name, 0, 1)
        self.cis_iface = QLineEdit()
        self.cis_iface.setPlaceholderText("e.g. GigabitEthernet0/1")
        grid.addWidget(QLabel("Interface"), 0, 2)
        grid.addWidget(self.cis_iface, 0, 3)
        self.cis_dir = QComboBox()
        self.cis_dir.addItems(["in", "out"])
        grid.addWidget(QLabel("Direction"), 1, 0)
        grid.addWidget(self.cis_dir, 1, 1)
        layout.addLayout(grid)

        header_row = QHBoxLayout()
        header_row.addWidget(QLabel("Access-control entries"))
        add_entry = QPushButton("Add entry")
        add_entry.clicked.connect(self._cis_add_row)
        header_row.addWidget(add_entry)
        header_row.addStretch(1)
        layout.addLayout(header_row)
        self.cis_rows = QVBoxLayout()
        self.cis_rows.setSpacing(theme.SPACE_XS)
        layout.addLayout(self.cis_rows)

        templates = QHBoxLayout()
        templates.setSpacing(theme.SPACE_SM)
        templates.addWidget(QLabel("Templates:"))
        templates.addWidget(self._template_button("Block risky inbound (445/3389/23)", self._cis_tpl_block))
        templates.addWidget(QLabel("Mgmt host"))
        self.cis_mgmt = QLineEdit("192.168.1.10")
        self.cis_mgmt.setMaximumWidth(130)
        templates.addWidget(self.cis_mgmt)
        templates.addWidget(self._template_button("SSH from mgmt host only", self._cis_tpl_mgmt))
        templates.addStretch(1)
        layout.addLayout(templates)

        controls = QHBoxLayout()
        self.cis_copy = QPushButton("Copy ACL")
        self.cis_copy.clicked.connect(self._cis_copy_command)
        self.cis_status = QLabel("")
        self.cis_status.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        controls.addWidget(self.cis_copy)
        controls.addWidget(self.cis_status, 1)
        layout.addLayout(controls)

        self.cis_output = QLineEdit()
        self.cis_output.setReadOnly(True)
        self.cis_output.setAccessibleName("Generated Cisco IOS ACL")
        font = self.cis_output.font()
        font.setFamily("Consolas")
        font.setPointSize(9)
        self.cis_output.setFont(font)
        layout.addWidget(self.cis_output)
        self.cis_explain = self._explain_label(
            "Named extended ACLs are evaluated top-down, first match wins, and every denied "
            "packet can be logged. An implicit deny drops anything unmatched."
        )
        layout.addWidget(self.cis_explain)

        # ---- first-match simulator ----
        sim_heading = QLabel("ACL first-match simulator")
        sim_heading.setStyleSheet(f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 700;")
        layout.addWidget(sim_heading)
        sim_note = QLabel(
            "Send a test packet through the ACL above and watch which entry decides - "
            "this is how top-down, first-match evaluation really works."
        )
        sim_note.setWordWrap(True)
        sim_note.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        layout.addWidget(sim_note)

        sim_grid = QGridLayout()
        sim_grid.setHorizontalSpacing(theme.SPACE_MD)
        sim_grid.setVerticalSpacing(theme.SPACE_SM)
        self.sim_protocol = QComboBox()
        self.sim_protocol.addItems(["tcp", "udp", "icmp"])
        self.sim_source = QLineEdit("192.168.1.50")
        self.sim_destination = QLineEdit("8.8.8.8")
        self.sim_port = QLineEdit("445")
        sim_grid.addWidget(QLabel("Protocol"), 0, 0)
        sim_grid.addWidget(self.sim_protocol, 0, 1)
        sim_grid.addWidget(QLabel("Source IP"), 0, 2)
        sim_grid.addWidget(self.sim_source, 0, 3)
        sim_grid.addWidget(QLabel("Dest IP"), 1, 0)
        sim_grid.addWidget(self.sim_destination, 1, 1)
        sim_grid.addWidget(QLabel("Dest port"), 1, 2)
        sim_grid.addWidget(self.sim_port, 1, 3)
        layout.addLayout(sim_grid)

        sim_buttons = QHBoxLayout()
        run_sim = QPushButton("Run packet")
        run_sim.clicked.connect(self._run_simulation)
        sim_buttons.addWidget(run_sim)
        for label, proto, src, dst, port in (
            ("TCP 445 -> internet", "tcp", "192.168.1.50", "8.8.8.8", "445"),
            ("TCP 443 -> internet", "tcp", "192.168.1.50", "8.8.8.8", "443"),
            ("TCP 3389 inbound", "tcp", "203.0.113.9", "192.168.1.1", "3389"),
            ("UDP 53 (DNS)", "udp", "192.168.1.50", "8.8.8.8", "53"),
        ):
            button = self._template_button(label, lambda checked=False, p=proto, s=src, d=dst, po=port: self._sample_packet(p, s, d, po))
            sim_buttons.addWidget(button)
        sim_buttons.addStretch(1)
        layout.addLayout(sim_buttons)

        self.sim_output = QLabel("Press 'Run packet' to simulate.")
        self.sim_output.setWordWrap(True)
        self.sim_output.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.sim_output.setStyleSheet(
            f"background-color: {theme.COLOR_BACKGROUND};"
            f" color: {theme.COLOR_TEXT_PRIMARY};"
            f" border: 1px solid {theme.COLOR_BORDER};"
            f" border-radius: {theme.RADIUS_SM}px;"
            f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
            f" font-family: Consolas;"
        )
        layout.addWidget(self.sim_output)
        layout.addStretch(1)

        self.cis_name.textChanged.connect(self._cis_refresh)
        self.cis_iface.textChanged.connect(self._cis_refresh)
        self.cis_dir.currentIndexChanged.connect(self._cis_refresh)
        self._cis_tpl_block()
        return tab

    def _cis_add_row(self, spec=None):
        spec = spec or {"action": "permit", "protocol": "ip", "source": "any",
                        "destination": "any", "operator": "", "port": "", "log": False}
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(theme.SPACE_XS)
        action = QComboBox()
        action.addItems(["permit", "deny"])
        action.setCurrentText(spec["action"])
        protocol = QComboBox()
        protocol.addItems(["ip", "tcp", "udp", "icmp"])
        protocol.setCurrentText(spec["protocol"])
        source = QLineEdit(spec["source"])
        destination = QLineEdit(spec["destination"])
        operator = QComboBox()
        operator.addItems(["", "eq", "neq", "gt", "lt"])
        operator.setCurrentText(spec["operator"])
        port = QLineEdit(spec["port"])
        port.setMaximumWidth(70)
        log = QPushButton("log")
        log.setCheckable(True)
        log.setChecked(spec["log"])
        remove = QPushButton("Remove")
        remove.setStyleSheet(
            f"QPushButton {{ background-color: transparent; color: {theme.COLOR_DANGER};"
            f" border: 1px solid {theme.COLOR_BORDER}; border-radius: {theme.RADIUS_SM}px;"
            f" padding: 4px 8px; }}"
        )
        for w in (action, protocol):
            w.setMaximumWidth(90)
        source.setPlaceholderText("any / host x / net wildcard")
        destination.setPlaceholderText("any / host x / net wildcard")
        port.setPlaceholderText("port")

        def refresh():
            self._cis_refresh()

        for w in (action, protocol, operator):
            w.currentIndexChanged.connect(refresh)
        for w in (source, destination, port):
            w.textChanged.connect(refresh)
        log.toggled.connect(refresh)
        remove.clicked.connect(lambda checked=False, r=row: self._remove_cis_row(r))

        row_layout.addWidget(action)
        row_layout.addWidget(protocol)
        row_layout.addWidget(source, 1)
        row_layout.addWidget(destination, 1)
        row_layout.addWidget(operator)
        row_layout.addWidget(port)
        row_layout.addWidget(log)
        row_layout.addWidget(remove)
        self.cis_rows.addWidget(row)
        self._cis_row_data.append(row)

    def _remove_cis_row(self, row):
        if row in self._cis_row_data:
            self._cis_row_data.remove(row)
        row.deleteLater()
        self._cis_refresh()

    def _read_cis_entries(self):
        entries = []
        for row in self._cis_row_data:
            action = protocol = operator = None
            source = destination = port = None
            for widget in row.findChildren(QComboBox):
                if widget.currentIndex() >= 0 and widget.count() >= 5 and widget.itemText(0) in ("permit", "deny"):
                    action = widget.currentText()
                elif widget.itemText(0) == "ip":
                    protocol = widget.currentText()
                elif widget.itemText(0) in ("", "eq", "neq", "gt", "lt"):
                    operator = widget.currentText()
            for widget in row.findChildren(QLineEdit):
                if widget.placeholderText().startswith("any / host"):
                    if source is None:
                        source = widget.text()
                    else:
                        destination = widget.text()
                else:
                    port = widget.text()
            log_button = None
            for button in row.findChildren(QPushButton):
                if button.text() == "log":
                    log_button = button
            if action is None:
                action = "permit"
            if protocol is None:
                protocol = "ip"
            if operator is None:
                operator = ""
            if source is None:
                source = "any"
            if destination is None:
                destination = "any"
            if port is None:
                port = ""
            entries.append({
                "action": action, "protocol": protocol, "source": source,
                "destination": destination, "operator": operator, "port": port,
                "log": bool(log_button and log_button.isChecked()),
            })
        return entries

    def _cis_refresh(self):
        try:
            aces = []
            descriptions = []
            for spec in self._read_cis_entries():
                ace = build_cisco_ace(
                    spec["action"], spec["protocol"], spec["source"], spec["destination"],
                    spec["operator"], spec["port"], spec["log"],
                )
                aces.append(ace)
                op = f" when the destination port is {spec['operator']} {spec['port']}" if spec["operator"] else ""
                descriptions.append(
                    f"{spec['action'].title()} {spec['protocol'].upper()} from {spec['source']} "
                    f"to {spec['destination']}{op}{' (logged)' if spec['log'] else ''}."
                )
            acl = build_cisco_acl(self.cis_name.text(), aces, interface=self.cis_iface.text(), direction=self.cis_dir.currentText())
            self.cis_output.setText(acl.to_ios())
            self.cis_output.setCursorPosition(0)
            lines = [
                f"ACL {acl.name}: named EXTENDED ACL - evaluated top-down, first match decides; "
                "an implicit deny drops anything unmatched.",
            ]
            for index, description in enumerate(descriptions, start=1):
                lines.append(f"ACE {index}: {description}")
            if acl.interface:
                lines.append(f"Applied {acl.direction} on interface {acl.interface}.")
            self.cis_explain.setText("\n".join(lines))
            self.cis_explain.setStyleSheet(
                f"background-color: {theme.COLOR_SURFACE_RAISED};"
                f" border-left: 3px solid {theme.COLOR_ACCENT};"
                f" border-radius: {theme.RADIUS_SM}px;"
                f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
                f" color: {theme.COLOR_TEXT_SECONDARY};"
            )
        except ValueError as error:
            self.cis_output.setText("")
            self.cis_explain.setText(str(error))
            self.cis_explain.setStyleSheet(
                f"background-color: {theme.COLOR_SURFACE_RAISED};"
                f" border-left: 3px solid {theme.COLOR_DANGER};"
                f" border-radius: {theme.RADIUS_SM}px;"
                f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
                f" color: {theme.COLOR_DANGER};"
            )

    def _cis_tpl_block(self):
        self.cis_name.setText("BLOCK_RISKY")
        self.cis_iface.setText("")
        for row in list(self._cis_row_data):
            self._remove_cis_row(row)
        for spec in [
            {"action": "deny", "protocol": "tcp", "source": "any", "destination": "any",
             "operator": "eq", "port": "445", "log": True},
            {"action": "deny", "protocol": "tcp", "source": "any", "destination": "any",
             "operator": "eq", "port": "3389", "log": True},
            {"action": "deny", "protocol": "tcp", "source": "any", "destination": "any",
             "operator": "eq", "port": "23", "log": True},
            {"action": "permit", "protocol": "tcp", "source": "any", "destination": "any",
             "operator": "eq", "port": "443", "log": False},
            {"action": "permit", "protocol": "tcp", "source": "any", "destination": "any",
             "operator": "eq", "port": "80", "log": False},
            {"action": "permit", "protocol": "ip", "source": "any", "destination": "any",
             "operator": "", "port": "", "log": False},
        ]:
            self._cis_add_row(spec)
        self._cis_refresh()

    def _cis_tpl_mgmt(self):
        mgmt = self.cis_mgmt.text().strip()
        if not mgmt:
            self.cis_explain.setText("Enter the management host IP first.")
            return
        self.cis_name.setText("MGMT_SSH")
        self.cis_iface.setText("")
        for row in list(self._cis_row_data):
            self._remove_cis_row(row)
        for spec in [
            {"action": "permit", "protocol": "tcp", "source": f"host {mgmt}", "destination": "any",
             "operator": "eq", "port": "22", "log": False},
            {"action": "deny", "protocol": "tcp", "source": "any", "destination": "any",
             "operator": "eq", "port": "22", "log": True},
            {"action": "permit", "protocol": "ip", "source": "any", "destination": "any",
             "operator": "", "port": "", "log": False},
        ]:
            self._cis_add_row(spec)
        self._cis_refresh()

    def _sample_packet(self, protocol, source, destination, port):
        self.sim_protocol.setCurrentText(protocol)
        self.sim_source.setText(source)
        self.sim_destination.setText(destination)
        self.sim_port.setText(port)
        self._run_simulation()

    def _run_simulation(self):
        try:
            specs = self._read_cis_entries()
            aces = [
                build_cisco_ace(spec["action"], spec["protocol"], spec["source"],
                                spec["destination"], spec["operator"], spec["port"], spec["log"])
                for spec in specs
            ]
            if not aces:
                raise ValueError("Add at least one ACE to simulate.")
            protocol = self.sim_protocol.currentText()
            source = self.sim_source.text().strip()
            destination = self.sim_destination.text().strip()
            port_text = self.sim_port.text().strip()
            for label, value in (("Source IP", source), ("Dest IP", destination)):
                try:
                    import ipaddress as _ip
                    _ip.IPv4Address(value)
                except Exception:
                    raise ValueError(f"{label} must be a valid IPv4 address.") from None
            port = None
            if protocol in ("tcp", "udp"):
                try:
                    port = int(port_text)
                except ValueError:
                    raise ValueError("Dest port must be a number for tcp/udp packets.") from None
                if not 1 <= port <= 65535:
                    raise ValueError("Dest port must be from 1 to 65535.")
            verdict, index, steps = simulate_acl(aces, protocol, source, destination, port)
        except ValueError as error:
            self.sim_output.setText(str(error))
            self.sim_output.setStyleSheet(
                f"background-color: {theme.COLOR_BACKGROUND}; color: {theme.COLOR_DANGER};"
                f" border: 1px solid {theme.COLOR_DANGER}; border-radius: {theme.RADIUS_SM}px;"
                f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px; font-family: Consolas;"
            )
            return
        lines = [f"Packet: {protocol} {source} -> {destination}" + (f" port {port}" if port else ""), ""]
        for number, text, matched in steps:
            if matched:
                lines.append(f"ACE {number} MATCHED -> {text.split()[0].upper()} (first match wins; evaluation stops)")
            else:
                lines.append(f"ACE {number}: {text} -> no match (continue)")
        lines.append("")
        if verdict:
            lines.append(f"VERDICT: packet is {verdict.upper()} by ACE {index}.")
        else:
            lines.append("VERDICT: no entry matched - implicit deny drops the packet.")
        self.sim_output.setText("\n".join(lines))
        self.sim_output.setStyleSheet(
            f"background-color: {theme.COLOR_BACKGROUND}; color: {theme.COLOR_TEXT_PRIMARY};"
            f" border: 1px solid {theme.COLOR_BORDER}; border-radius: {theme.RADIUS_SM}px;"
            f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px; font-family: Consolas;"
        )

    def _cis_copy_command(self):
        command = self.cis_output.text()
        if not command:
            return
        QApplication.clipboard().setText(command)
        self.cis_status.setText("Copied to clipboard.")

    # ------------------------------------------------------------- audit
    def _audit_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(theme.SPACE_MD)

        note = QLabel(
            "Existing Windows firewall rules are read live with Get-NetFirewallRule "
            "(read-only, no elevation needed). Auditing regularly is best practice: "
            "prefer program-bound rules over wildcard ports and review enabled "
            "Inbound/Allow rules on the Public profile."
        )
        note.setWordWrap(True)
        note.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE};"
            f" border-left: 4px solid {theme.COLOR_INFO};"
            f" border-radius: {theme.RADIUS_SM}px;"
            f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
            f" color: {theme.COLOR_TEXT_SECONDARY};"
        )
        layout.addWidget(note)

        controls = QHBoxLayout()
        controls.setSpacing(theme.SPACE_SM)
        self.audit_load = QPushButton("Load rules")
        self.audit_load.clicked.connect(self._audit_load_rules)
        controls.addWidget(self.audit_load)
        self.audit_status = QLabel("")
        self.audit_status.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        controls.addWidget(self.audit_status, 1)
        layout.addLayout(controls)

        filters = QHBoxLayout()
        filters.setSpacing(theme.SPACE_SM)
        filters.addWidget(QLabel("Search"))
        self.audit_search = QLineEdit()
        self.audit_search.setPlaceholderText("rule name / profile keyword")
        self.audit_search.setClearButtonEnabled(True)
        self.audit_search.textChanged.connect(self._audit_apply_filters)
        filters.addWidget(self.audit_search, 1)
        filters.addWidget(QLabel("Direction"))
        self.audit_direction = QComboBox()
        self.audit_direction.addItems(["All", "Inbound", "Outbound"])
        self.audit_direction.currentIndexChanged.connect(self._audit_apply_filters)
        filters.addWidget(self.audit_direction)
        filters.addWidget(QLabel("Action"))
        self.audit_action = QComboBox()
        self.audit_action.addItems(["All", "Allow", "Block"])
        self.audit_action.currentIndexChanged.connect(self._audit_apply_filters)
        filters.addWidget(self.audit_action)
        filters.addWidget(QLabel("State"))
        self.audit_state = QComboBox()
        self.audit_state.addItems(["All", "Enabled", "Disabled"])
        self.audit_state.currentIndexChanged.connect(self._audit_apply_filters)
        filters.addWidget(self.audit_state)
        layout.addLayout(filters)

        self.audit_table = QTableWidget(0, 5)
        self.audit_table.setHorizontalHeaderLabels(("Rule name", "Direction", "Action", "State", "Profile"))
        self.audit_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.audit_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.audit_table.verticalHeader().setVisible(False)
        self.audit_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.audit_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.audit_table, 1)

        tips = QLabel(
            "<b>Operational tips</b>\n"
            "\u2022 Verify: after changing a rule, test from another host with "
            "Test-NetConnection TARGET -Port PORT - a rule that is not tested is a guess.\n"
            "\u2022 Logging: enable firewall logging (wf.msc > properties > logging) so "
            "blocked and allowed traffic leaves an audit trail.\n"
            "\u2022 Least exposure: review Inbound + Allow + Public rules first - those are "
            "reachable from the internet. Prefer program-bound rules over wildcard ports."
        )
        tips.setWordWrap(True)
        tips.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE_RAISED};"
            f" border-left: 3px solid {theme.COLOR_ACCENT};"
            f" border-radius: {theme.RADIUS_SM}px;"
            f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
            f" color: {theme.COLOR_TEXT_SECONDARY};"
        )
        layout.addWidget(tips)
        return tab

    def _audit_load_rules(self):
        if self._audit_worker is not None and self._audit_worker.isRunning():
            return
        self.audit_load.setEnabled(False)
        self.audit_status.setText("Reading firewall rules...")
        self._audit_worker = FirewallRulesWorker(parent=self)
        self._audit_worker.succeeded.connect(self._audit_on_rules)
        self._audit_worker.failed.connect(self._audit_on_error)
        self._audit_worker.finished.connect(lambda: self.audit_load.setEnabled(True))
        self._audit_worker.start()

    def _audit_on_error(self, message: str):
        self.audit_status.setText(message)
        self.audit_status.setStyleSheet(f"color: {theme.COLOR_DANGER};")

    def _audit_on_rules(self, rules):
        self._audit_rules = rules
        self.audit_status.setText(f"{len(rules)} rule(s) loaded.")
        self.audit_status.setStyleSheet(f"color: {theme.COLOR_SUCCESS};")
        self._audit_apply_filters()

    def _audit_apply_filters(self):
        query = self.audit_search.text().strip().casefold()
        direction = self.audit_direction.currentText()
        action = self.audit_action.currentText()
        state = self.audit_state.currentText()
        rows = []
        for rule in self._audit_rules:
            if direction != "All" and rule.direction != direction:
                continue
            if action != "All" and rule.action != action:
                continue
            label_state = "Enabled" if rule.enabled else "Disabled"
            if state != "All" and label_state != state:
                continue
            haystack = (rule.display_name + " " + rule.name + " " + rule.profile).casefold()
            if query and query not in haystack:
                continue
            rows.append(rule)
        self.audit_table.setRowCount(len(rows))
        for row, rule in enumerate(rows):
            self.audit_table.setItem(row, 0, QTableWidgetItem(rule.display_name or rule.name))
            self.audit_table.setItem(row, 1, QTableWidgetItem(rule.direction))
            action_item = QTableWidgetItem(rule.action)
            action_item.setForeground(QBrush(QColor(
                theme.COLOR_SUCCESS if rule.action == "Allow" else theme.COLOR_DANGER)))
            self.audit_table.setItem(row, 2, action_item)
            state_item = QTableWidgetItem("Enabled" if rule.enabled else "Disabled")
            state_item.setForeground(QBrush(QColor(
                theme.COLOR_SUCCESS if rule.enabled else theme.COLOR_TEXT_SECONDARY)))
            self.audit_table.setItem(row, 3, state_item)
            self.audit_table.setItem(row, 4, QTableWidgetItem(rule.profile))

    # ------------------------------------------------------------- reference
    def _reference_widget(self) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE};"
            f" border: 1px solid {theme.COLOR_BORDER};"
            f" border-radius: {theme.RADIUS_MD}px;"
        )
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(theme.SPACE_MD, theme.SPACE_MD, theme.SPACE_MD, theme.SPACE_MD)
        layout.setSpacing(theme.SPACE_SM)
        title = QLabel("Port and attack reference - why these rules exist")
        title.setStyleSheet("font-weight: 700;")
        layout.addWidget(title)
        for port, proto, service, threat, incidents, advice in _PORT_INCIDENTS:
            line = QLabel(
                f"{port} ({proto}) {service}: {threat}. Known: {incidents}. Advice: {advice}"
            )
            line.setWordWrap(True)
            line.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY}; font-size: 9pt;")
            layout.addWidget(line)
        return frame
