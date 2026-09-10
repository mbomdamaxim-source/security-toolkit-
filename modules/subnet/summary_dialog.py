"""Native PySide6 Route summarisation dialog for the Subnet and VLSM module.

Opened from the module's upper-right 'Route summariser' button. Paste the
networks you manage (one CIDR per line); the dialog finds the smallest
summary route that covers them (supernetting practice).
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QDialog, QFrame, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton,
    QVBoxLayout,
)

from core import theme
from modules.subnet.logic import find_summary_route

_EXAMPLE = "192.168.1.0/24\n192.168.2.0/24\n192.168.3.0/24\n192.168.0.0/24"

_STYLE_NOTE = (
    f"background-color: {theme.COLOR_SURFACE_RAISED};"
    f" border-left: 4px solid {theme.COLOR_INFO};"
    f" border-radius: {theme.RADIUS_SM}px;"
    f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
    f" color: {theme.COLOR_TEXT_SECONDARY};"
)


class RouteSummaryDialog(QDialog):
    """Small auto-sized overlay for supernetting practice."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Route summariser")
        self.resize(620, 460)
        self.setWindowModality(Qt.WindowModality.WindowModal)

        root = QVBoxLayout(self)
        root.setContentsMargins(theme.SPACE_LG, theme.SPACE_LG, theme.SPACE_LG, theme.SPACE_LG)
        root.setSpacing(theme.SPACE_MD)

        # header band: title left, close button top-right
        header = QFrame()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, theme.SPACE_SM)
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        title = QLabel("Route summarisation helper")
        title.setStyleSheet(f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 700;")
        subtitle = QLabel(
            "Paste the networks you manage - one CIDR per line - and find the "
            "smallest single summary route that covers them (supernetting)."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_layout.addLayout(title_box, 1)
        close_button = QPushButton("\u2715 Close")
        close_button.setAccessibleName("Close route summariser")
        close_button.clicked.connect(self.reject)
        header_layout.addWidget(close_button, 0, Qt.AlignmentFlag.AlignTop)
        header.setStyleSheet(f"border-bottom: 1px solid {theme.COLOR_BORDER};")
        root.addWidget(header)

        self.input_edit = QPlainTextEdit(_EXAMPLE)
        self.input_edit.setAccessibleName("Networks to summarise")
        self.input_edit.setAccessibleDescription(
            "One IPv4 network in CIDR form per line, for example 192.168.1.0/24."
        )
        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self.input_edit.setFont(mono)
        root.addWidget(self.input_edit, 1)

        actions = QHBoxLayout()
        self.run_button = QPushButton("Find summary route")
        self.run_button.clicked.connect(self._run)
        actions.addWidget(self.run_button)
        actions.addStretch(1)
        root.addLayout(actions)

        self.output = QLabel("Press the button to summarise the networks above.")
        self.output.setWordWrap(True)
        self.output.setStyleSheet(_STYLE_NOTE)
        self.output.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        root.addWidget(self.output)

    def _run(self):
        lines = [line.strip() for line in self.input_edit.toPlainText().splitlines() if line.strip()]
        try:
            result = find_summary_route(lines)
        except ValueError as error:
            self.output.setText(str(error))
            self.output.setStyleSheet(_STYLE_NOTE.replace(theme.COLOR_INFO, theme.COLOR_DANGER))
            return
        mask = str(_prefix_mask(result["prefix"]))
        unused_note = (
            "(exact summarisation)"
            if result["wasted"] == 0
            else "(summarisation is not exact - confirm this is acceptable for your routing policy)"
        )
        self.output.setText(
            f"Summary route: {result['network']}/{result['prefix']}\n"
            f"Block size: {result['addresses']} addresses (mask {mask})\n"
            f"Covers: {result['covers']} network(s)\n"
            f"Unused inside the block: {result['wasted']} addresses {unused_note}"
        )
        self.output.setStyleSheet(_STYLE_NOTE)


def _prefix_mask(prefix: int) -> str:
    import ipaddress
    return ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask
