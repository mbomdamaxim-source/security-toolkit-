"""Native PySide6 learning dialog for the Firewall Builder: practice labs
and a concepts quiz, shown from the module's upper-right button."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup, QDialog, QFrame, QHBoxLayout, QLabel,
    QPushButton, QScrollArea, QTabWidget, QVBoxLayout, QWidget,
)

from core import theme

_LAB_QUIZ = [
    {
        "title": "Lab 1: Secure a home Windows PC",
        "desc": "A Windows 10 PC at home is used for online work and has Windows "
                "Defender Firewall enabled with default-inbound block. Build the "
                "rules a careful user should add.",
        "steps": [
            ("Remote Desktop (RDP, TCP 3389) should NOT be reachable from the internet. What rule do you create?",
             ["Allow inbound TCP 3389", "Block inbound TCP 3389", "Block outbound TCP 3389", "Allow outbound TCP 443"],
             1,
             "RDP on 0.0.0.0 is a top ransomware entry point (BlueKeep, brute force). Block inbound 3389 so the listening service cannot be reached from the network."),
            ("SMB file sharing (TCP 445) is not needed at home. What should you do?",
             ["Block inbound TCP 445", "Allow inbound TCP 445 from Any", "Enable SMBv1", "Block outbound TCP 53"],
             0,
             "Inbound SMB exposure was the WannaCry/EternalBlue vector. Block inbound 445 - your own outbound file access is unaffected."),
            ("You suspect an app tries to phone home on port 8080. Which direction blocks traffic THIS PC starts?",
             ["Inbound", "Outbound", "Forward", "ICMPv4"],
             1,
             "Outbound rules govern connections your computer initiates. To stop data leaving, you block outbound."),
            ("Which profile should a rule apply to when you want it active on every network?",
             ["Domain", "Private", "Public", "Any"],
             3,
             "Profile 'Any' (the default) applies the rule regardless of how Windows classifies the network."),
            ("Which PowerShell cmdlet creates the rule?",
             ["netsh firewall add", "New-NetFirewallRule", "Add-FirewallPort", "Set-NetTCPConnection"],
             1,
             "New-NetFirewallRule is the structured cmdlet. Avoid netsh: its output is localized and its vocabulary is legacy."),
        ],
    },
    {
        "title": "Lab 2: Harden a MikroTik home router (WAN)",
        "desc": "A MikroTik router connects a home LAN to the internet on ether1-WAN. "
                "Your goal: protect the router itself from the internet.",
        "steps": [
            ("Which chain protects the router itself from packets arriving from the internet?",
             ["forward", "output", "input", "prerouting"],
             2,
             "The input chain applies to packets destined TO the router. Forward handles traffic passing through to the LAN."),
            ("What is the FIRST rule you should add for the WAN interface?",
             ["accept established,related", "drop invalid", "accept icmp", "drop tcp 3389"],
             0,
             "First accept replies to your own connections (established,related); otherwise stateful replies would be blocked later. Order matters - rules run top-down."),
            ("How should invalid connection-tracking packets be treated?",
             ["accept", "drop", "mark", "log only"],
             1,
             "Invalid packets are either broken or crafted attacks - silently drop them."),
            ("Which port does Windows Remote Desktop use and should be blocked from the WAN?",
             ["22", "445", "3389", "8080"],
             2,
             "TCP 3389 (RDP) is a common brute-force target. Blocking inbound 3389 on the WAN protects any PC behind the router."),
            ("Where must the WAN-block rules be placed relative to an allow-all input rule?",
             ["After it", "Before it", "Anywhere", "It does not matter"],
             1,
             "First match wins: a broad accept rule earlier would let the blocked traffic through. Put specific blocks before any permissive rule."),
        ],
    },
    {
        "title": "Lab 3: Cisco ACL for router management",
        "desc": "A Cisco router's SSH (port 22) must be reachable only from the network "
                "administrator's PC at 192.168.1.10.",
        "steps": [
            ("Which keyword matches exactly ONE host in an extended ACL?",
             ["any", "host", "net", "range"],
             1,
             "'host x.x.x.x' matches a single address; 'any' matches everything; a network needs 'address wildcard'."),
            ("What wildcard mask represents the subnet mask 255.255.255.0 (a /24)?",
             ["0.0.0.255", "255.255.255.0", "0.0.255.0", "255.0.0.0"],
             0,
             "Wildcard = inverse of the mask: 255.255.255.0 inverted is 0.0.0.255. Getting this backwards is a classic ACL bug."),
            ("To allow the admin and block everyone else on SSH, which ORDER of entries is correct?",
             ["deny any first, then permit host", "permit host first, then deny any", "Only a deny rule", "Order does not matter"],
             1,
             "ACLs are first-match: the specific permit for the admin must appear BEFORE the deny-any entry."),
            ("What happens to a packet that matches no entry of an extended ACL?",
             ["Allowed", "Dropped (implicit deny)", "Logged and allowed", "Forwarded anyway"],
             1,
             "Extended ACLs end with an implicit deny - unmatched traffic is dropped. Never rely on it silently; end with an explicit permit if you intend to allow the rest."),
            ("Which protocol and port pair does SSH use?",
             ["tcp/22", "udp/22", "tcp/443", "icmp/22"],
             0,
             "SSH uses TCP port 22. Matching 'tcp eq 22' is what the ACL needs - udp/icmp would never match."),
        ],
    },
]

_QUIZ_BANK = [
    ("Which action value stops matching traffic in a Windows Defender Firewall rule?",
     ["Allow", "Block", "Deny", "Reject"], 1,
     "PowerShell firewall cmdlets speak Allow and Block. 'Deny' is Cisco vocabulary - using it in a Windows rule is the classic cross-vendor mistake."),
    ("An Inbound rule governs traffic that ...",
     ["This PC sends to other hosts", "Arrives from other hosts to this PC", "Passes through this PC to another network", "Is generated by Windows Update"], 1,
     "Inbound = connections arriving towards your computer. Outbound = connections your computer initiates."),
    ("Which cmdlet creates a firewall rule on Windows?",
     ["Add-FirewallRule", "New-NetFirewallRule", "Grant-NetFirewallAccess", "Set-NetTCPConnection"], 1,
     "New-NetFirewallRule from the NetSecurity module. Prefer it over netsh: structured, not localized, cmdlet-native."),
    ("Why avoid netsh for firewall management?",
     ["It is deprecated on all Windows versions", "Its output is localized and hard to parse; cmdlets are structured", "It cannot block ports", "It requires Linux"], 1,
     "netsh output depends on the OS language, which breaks automation. Get-NetFirewallRule / New-NetFirewallRule return objects."),
    ("ACL and filter entries are evaluated in which order?",
     ["Random", "Top-down, first match wins", "Bottom-up", "Longest-prefix first"], 1,
     "Windows rules, MikroTik chains and Cisco ACLs all evaluate top-down and stop at the first match."),
    ("The Cisco wildcard mask for network 192.168.1.0/24 is ...",
     ["255.255.255.0", "0.0.0.255", "0.0.255.255", "255.0.0.0"], 1,
     "Wildcard masks invert the subnet mask: /24 (255.255.255.0) becomes 0.0.0.255."),
    ("Which keyword matches a single specific host in a Cisco ACL?",
     ["any", "host", "net", "all"], 1,
     "'host 192.168.1.10' matches exactly that address - ideal for management allowlists."),
    ("On MikroTik, which chain protects the router itself?",
     ["forward", "output", "input", "srcnat"], 2,
     "input = packets destined to the router; forward = packets routed through it."),
    ("Which MikroTik rule should come FIRST on the WAN input chain?",
     ["drop invalid", "accept established,related", "drop tcp 3389", "drop icmp"], 1,
     "Accept replies to your own traffic first; only then drop the unwanted NEW inbound packets."),
    ("Which of these protocols sends passwords in clear text?",
     ["SSH", "Telnet", "HTTPS", "SFTP"], 1,
     "Telnet has no encryption - that is why port 23 should be blocked and SSH (22) used instead."),
    ("Port 445 (SMB) is famous because of ...",
     ["The Mirai botnet", "EternalBlue and the WannaCry ransomware", "BlueKeep", "DNS amplification"], 1,
     "EternalBlue (MS17-010) exploited SMBv1 on 445 and powered WannaCry/NotPetya."),
    ("What is the best practice for a service you do not need to receive inbound?",
     ["Block it (or remove its allow rule)", "Leave it and add a log-only rule", "Allow it from the Public profile", "Set its profile to Domain only"], 0,
     "Attack surface is a budget: close what you do not use. Log-only rules still leave the door open."),
]


class FirewallLearnDialog(QDialog):
    """Small overlay dialog: practice labs + concepts quiz."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Firewall practice")
        self.resize(760, 700)
        self.setWindowModality(Qt.WindowModality.WindowModal)

        root = QVBoxLayout(self)
        root.setContentsMargins(theme.SPACE_LG, theme.SPACE_LG, theme.SPACE_LG, theme.SPACE_LG)
        root.setSpacing(theme.SPACE_MD)
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Firewall practice")
        title.setStyleSheet(f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 700;")
        subtitle = QLabel("Hands-on labs and concept questions with explanations.")
        subtitle.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box, 1)
        close_button = QPushButton("\u2715 Close")
        close_button.clicked.connect(self.reject)
        header.addWidget(close_button, 0, Qt.AlignmentFlag.AlignTop)
        root.addLayout(header)

        self.tabs = QTabWidget()
        lab_tab = QWidget()
        self.lab_layout = QVBoxLayout(lab_tab)
        self.lab_layout.setContentsMargins(0, 0, 0, 0)
        quiz_tab = QWidget()
        self.quiz_layout = QVBoxLayout(quiz_tab)
        self.quiz_layout.setContentsMargins(0, 0, 0, 0)
        self.tabs.addTab(lab_tab, "Practice labs")
        self.tabs.addTab(quiz_tab, "Concepts quiz")
        root.addWidget(self.tabs, 1)

        self._lab_host = self._make_scroll(self.lab_layout)
        self._quiz_host = self._make_scroll(self.quiz_layout)
        self._show_lab_list()

    def _make_scroll(self, layout) -> QWidget:
        host = QWidget()
        inner = QVBoxLayout(host)
        inner.setContentsMargins(theme.SPACE_SM, theme.SPACE_SM, theme.SPACE_SM, theme.SPACE_SM)
        inner.setSpacing(theme.SPACE_SM)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(host)
        layout.addWidget(scroll)
        return host

    def _clear(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _card(self, title_text, description="") -> tuple[QFrame, QVBoxLayout]:
        card = QFrame()
        card.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE};"
            f" border: 1px solid {theme.COLOR_BORDER};"
            f" border-radius: {theme.RADIUS_MD}px;"
        )
        layout = QVBoxLayout(card)
        layout.setContentsMargins(theme.SPACE_MD, theme.SPACE_MD, theme.SPACE_MD, theme.SPACE_MD)
        layout.setSpacing(theme.SPACE_SM)
        if title_text:
            label = QLabel(title_text)
            label.setStyleSheet("font-weight: 600; font-size: 11pt;")
            label.setWordWrap(True)
            layout.addWidget(label)
        if description:
            desc = QLabel(description)
            desc.setWordWrap(True)
            desc.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
            layout.addWidget(desc)
        return card, layout

    def _note(self, text: str, success: bool) -> QLabel:
        note = QLabel(text)
        note.setWordWrap(True)
        note.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE_RAISED};"
            f" border-left: 4px solid {theme.COLOR_SUCCESS if success else theme.COLOR_DANGER};"
            f" border-radius: {theme.RADIUS_SM}px;"
            f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
            f" color: {theme.COLOR_TEXT_SECONDARY};"
        )
        return note

    # ------------------------------------------------------------------ labs
    def _show_lab_list(self):
        self._clear(self.lab_layout)
        self._lab_state = None
        for index, lab in enumerate(_LAB_QUIZ):
            card, layout = self._card(lab["title"], lab["desc"])
            meta = QLabel(f"{len(lab['steps'])} steps")
            meta.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
            layout.addWidget(meta)
            start = QPushButton("Start lab")
            start.clicked.connect(lambda checked=False, i=index: self._run_lab(i))
            layout.addWidget(start, alignment=Qt.AlignmentFlag.AlignLeft)
            self.lab_layout.addWidget(card)
        self.lab_layout.addStretch(1)

    def _run_lab(self, lab_index: int):
        lab = _LAB_QUIZ[lab_index]
        self._clear(self.lab_layout)
        self._lab_state = {"index": lab_index, "step": 0, "score": 0, "title": lab["title"], "steps": lab["steps"]}
        self._render_lab_step()

    def _render_lab_step(self):
        state = self._lab_state
        self._clear(self.lab_layout)
        if state is None:
            return
        steps = state["steps"]
        if state["step"] >= len(steps):
            card, layout = self._card("Lab complete")
            total = QLabel(f"You answered {state['score']} of {len(steps)} steps correctly.")
            layout.addWidget(total)
            if state["score"] == len(steps):
                advice = QLabel("Excellent - you reason like a firewall engineer. Try the other labs or the Concepts quiz.")
            else:
                advice = QLabel("Review the explanations you missed, then run the lab again.")
            advice.setWordWrap(True)
            advice.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
            layout.addWidget(advice)
            buttons = QHBoxLayout()
            again = QPushButton("Restart lab")
            again.clicked.connect(lambda: self._run_lab(state["index"]))
            back = QPushButton("All labs")
            back.clicked.connect(self._show_lab_list)
            buttons.addWidget(again)
            buttons.addWidget(back)
            buttons.addStretch(1)
            layout.addLayout(buttons)
            self.lab_layout.addWidget(card)
            self.lab_layout.addStretch(1)
            return
        question, options, answer, why = steps[state["step"]]
        card, layout = self._card(
            f"Step {state['step'] + 1} of {len(steps)} - {state['title']}", question
        )
        group = QButtonGroup(self)
        for index, option in enumerate(options):
            button = QPushButton(f"{chr(65 + index)}. {option}")
            button.setCheckable(True)
            button.setStyleSheet(_option_style())
            group.addButton(button)
            layout.addWidget(button)
        feedback = QLabel("")
        feedback.setWordWrap(True)
        feedback.hide()
        next_button = QPushButton("Check answer")
        next_button.setEnabled(False)

        def check():
            selected = group.checkedButton()
            if selected is None:
                return
            for b in group.buttons():
                b.setEnabled(False)
            chosen = group.buttons().index(selected)
            correct = chosen == answer
            if correct:
                state["score"] += 1
                selected.setStyleSheet(_option_state_style(theme.COLOR_SUCCESS))
            else:
                selected.setStyleSheet(_option_state_style(theme.COLOR_DANGER))
                group.buttons()[answer].setStyleSheet(_option_state_style(theme.COLOR_SUCCESS))
            feedback.setText(
                ("Correct. " if correct else f"Not quite - the right answer is {chr(65 + answer)}. ")
                + why
            )
            feedback.setStyleSheet(
                f"background-color: {theme.COLOR_SURFACE_RAISED};"
                f" border-left: 4px solid {theme.COLOR_SUCCESS if correct else theme.COLOR_DANGER};"
                f" border-radius: {theme.RADIUS_SM}px;"
                f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
                f" color: {theme.COLOR_TEXT_SECONDARY};"
            )
            feedback.show()
            next_button.setText("See results" if state["step"] == len(steps) - 1 else "Next step")
            next_button.setEnabled(True)

        def advance():
            state["step"] += 1
            self._render_lab_step()

        for button in group.buttons():
            button.clicked.connect(lambda: next_button.setEnabled(True))
        mode = {"checking": True}

        def on_next():
            if mode["checking"]:
                check()
                mode["checking"] = False
            else:
                advance()

        next_button.clicked.connect(on_next)
        quit_button = QPushButton("Quit lab")
        quit_button.clicked.connect(self._show_lab_list)
        buttons = QHBoxLayout()
        buttons.addWidget(next_button)
        buttons.addWidget(quit_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        self.lab_layout.addWidget(card)
        self.lab_layout.addStretch(1)

    # ----------------------------------------------------------------- quiz
    def _start_quiz(self):
        self._clear(self.quiz_layout)
        self._quiz_state = {"position": 0, "score": 0}
        self._render_quiz()

    def _render_quiz(self):
        state = self._quiz_state
        self._clear(self.quiz_layout)
        if state is None:
            return
        if state["position"] >= len(_QUIZ_BANK):
            card, layout = self._card("Quiz complete")
            score = state["score"]
            total = len(_QUIZ_BANK)
            pct = round(score / total * 100)
            summary = QLabel(f"{score} out of {total} correct ({pct}%).")
            layout.addWidget(summary)
            if score >= 10:
                advice = QLabel("Strong grasp of firewall fundamentals.")
            else:
                advice = QLabel("Re-read the explain blocks in the three builders, then retake the quiz.")
            advice.setWordWrap(True)
            advice.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
            layout.addWidget(advice)
            again = QPushButton("Restart quiz")
            again.clicked.connect(self._start_quiz)
            layout.addWidget(again, alignment=Qt.AlignmentFlag.AlignLeft)
            self.quiz_layout.addWidget(card)
            self.quiz_layout.addStretch(1)
            return
        question, options, answer, why = _QUIZ_BANK[state["position"]]
        meta = QLabel(
            f"Question {state['position'] + 1} of {len(_QUIZ_BANK)}  -  Score: {state['score']}"
        )
        meta.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        card, layout = self._card("", question)
        group = QButtonGroup(self)
        for index, option in enumerate(options):
            button = QPushButton(f"{chr(65 + index)}. {option}")
            button.setCheckable(True)
            button.setStyleSheet(_option_style())
            group.addButton(button)
            layout.addWidget(button)
        feedback = QLabel("")
        feedback.setWordWrap(True)
        feedback.hide()
        next_button = QPushButton("Check answer")
        next_button.setEnabled(False)
        mode = {"checking": True}

        def check():
            selected = group.checkedButton()
            if selected is None:
                return
            for b in group.buttons():
                b.setEnabled(False)
            chosen = group.buttons().index(selected)
            correct = chosen == answer
            if correct:
                state["score"] += 1
                selected.setStyleSheet(_option_state_style(theme.COLOR_SUCCESS))
            else:
                selected.setStyleSheet(_option_state_style(theme.COLOR_DANGER))
                group.buttons()[answer].setStyleSheet(_option_state_style(theme.COLOR_SUCCESS))
            feedback.setText(
                ("Correct. " if correct else f"Not quite - the answer is {chr(65 + answer)}. ")
                + why
            )
            feedback.setStyleSheet(
                f"background-color: {theme.COLOR_SURFACE_RAISED};"
                f" border-left: 4px solid {theme.COLOR_SUCCESS if correct else theme.COLOR_DANGER};"
                f" border-radius: {theme.RADIUS_SM}px;"
                f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
                f" color: {theme.COLOR_TEXT_SECONDARY};"
            )
            feedback.show()
            next_button.setText("See results" if state["position"] == len(_QUIZ_BANK) - 1 else "Next question")
            next_button.setEnabled(True)

        def on_next():
            if mode["checking"]:
                check()
                mode["checking"] = False
            else:
                state["position"] += 1
                self._render_quiz()

        for button in group.buttons():
            button.clicked.connect(lambda: next_button.setEnabled(True))
        next_button.clicked.connect(on_next)
        layout.addWidget(feedback)
        layout.addWidget(next_button, alignment=Qt.AlignmentFlag.AlignLeft)
        self.quiz_layout.addWidget(card)
        self.quiz_layout.addStretch(1)


def _option_style() -> str:
    return (
        f"QPushButton {{ background-color: {theme.COLOR_SURFACE};"
        f" color: {theme.COLOR_TEXT_PRIMARY};"
        f" border: 1px solid {theme.COLOR_BORDER};"
        f" border-radius: {theme.RADIUS_MD}px;"
        f" padding: 10px 14px; text-align: left; }}"
        f"QPushButton:hover {{ border-color: {theme.COLOR_ACCENT}; }}"
        f"QPushButton:checked {{ border-color: {theme.COLOR_ACCENT};"
        f" color: {theme.COLOR_ACCENT}; font-weight: 600; }}"
    )


def _option_state_style(color: str) -> str:
    return (
        f"QPushButton {{ background-color: {theme.COLOR_SURFACE};"
        f" color: {color}; font-weight: 700;"
        f" border: 2px solid {color};"
        f" border-radius: {theme.RADIUS_MD}px;"
        f" padding: 10px 14px; text-align: left; }}"
    )
