"""Native PySide6 interface for the credential auditor.

The password typed by the user is analysed in memory only: it is never
stored, logged, written to disk, or transmitted anywhere.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
    QProgressBar, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from core import theme
from core.context import AppContext
from core.status_widgets import ModuleHeader
from modules.credentials.crypto_ui import CryptoLabDialog
from modules.credentials.logic import (
    COMMON_PASSWORDS,
    PATTERN_LABELS,
    PasswordReport,
    analyze_password,
    format_duration,
    generate_passphrase,
    generate_password,
)

_STRENGTH_COLORS = {
    "Very weak": theme.COLOR_DANGER,
    "Weak": theme.COLOR_WARNING,
    "Fair": theme.COLOR_INFO,
    "Strong": theme.COLOR_SUCCESS,
    "Very strong": theme.COLOR_SUCCESS,
}

_OFFLINE_RATE_LABEL = "Offline attack (1 billion guesses per second)"
_ONLINE_RATE_LABEL = "Online attack (1,000 guesses per second)"

_BADGE_STYLE = (
    "font-weight: 700;"
    " padding: 4px 12px;"
    " border-radius: 4px;"
    " color: {background};"
    " background-color: {color};"
)
_CARD_STYLE = (
    "background-color: {surface};"
    " border: 1px solid {border};"
    " border-radius: 8px;"
    " padding: 12px;"
)
_ALERT_STYLE = (
    "background-color: {surface};"
    " border-left: 4px solid {danger};"
    " border-radius: 4px;"
    " padding: 10px 12px;"
)
_PROGRESS_BAR_STYLE = (
    "QProgressBar {{"
    " background-color: {raised};"
    " border: none;"
    " border-radius: 8px;"
    "}}"
    "QProgressBar::chunk {{"
    " background-color: {color};"
    " border-radius: 8px;"
    "}}"
)
_CHECK_STYLE = (
    "background-color: {surface};"
    " border: 1px solid {border};"
    " border-left: 3px solid {mark};"
    " border-radius: 4px;"
    " padding: 6px 10px;"
)
_MUTED_STYLE = "color: {secondary};"


def _style(template: str, **values) -> str:
    return template.format(**values)


class CredentialAuditorModule(QWidget):
    """Live, local-only password strength analysis."""

    def __init__(self, context: AppContext):
        super().__init__()
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL)
        layout.setSpacing(theme.SPACE_MD)
        header_row = QHBoxLayout()
        header_row.setSpacing(theme.SPACE_MD)
        header_row.addWidget(ModuleHeader(
            "Credential Auditor",
            "Review password strength without exposing plaintext credentials.",
        ), 1)
        self.crypto_lab_button = QPushButton("Crypto Lab")
        self.crypto_lab_button.setAccessibleName("Open Crypto Lab")
        self.crypto_lab_button.setAccessibleDescription(
            "Open the learning panel with hands-on cryptography tools and a quiz."
        )
        self.crypto_lab_button.clicked.connect(self._open_crypto_lab)
        header_row.addWidget(self.crypto_lab_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header_row)
        layout.addWidget(self._privacy_banner())
        layout.addWidget(self._input_panel())
        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_layout.setSpacing(theme.SPACE_MD)
        results_scroll = QScrollArea()
        results_scroll.setWidgetResizable(True)
        results_scroll.setFrameShape(QFrame.Shape.NoFrame)
        results_scroll.setWidget(self.results_container)
        layout.addWidget(results_scroll, 1)
        self._show_hint()

    def _open_crypto_lab(self) -> None:
        """Show the Crypto Lab as a centred overlay window over this module."""
        dialog = CryptoLabDialog(self)
        dialog.resize(980, 760)
        window = self.window()
        if window is not None:
            dialog.move(window.geometry().center() - dialog.rect().center())
        dialog.exec()
        dialog.deleteLater()

    def _privacy_banner(self) -> QFrame:
        banner = QFrame()
        banner.setStyleSheet(_style(
            "background-color: {raised};"
            " border-left: 4px solid {info};"
            " border-radius: 4px;"
            " padding: 8px 12px;",
            raised=theme.COLOR_SURFACE_RAISED,
            info=theme.COLOR_INFO,
        ))
        row = QHBoxLayout(banner)
        row.setContentsMargins(theme.SPACE_MD, theme.SPACE_SM, theme.SPACE_MD, theme.SPACE_SM)
        label = QLabel(
            "<b>Privacy:</b> Nothing you type here is stored, logged, or "
            "transmitted. The analysis runs entirely on this device."
        )
        label.setWordWrap(True)
        row.addWidget(label, 1)
        return banner

    def _input_panel(self) -> QWidget:
        panel = QWidget()
        grid = QGridLayout(panel)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(theme.SPACE_MD)
        grid.setVerticalSpacing(theme.SPACE_SM)

        label = QLabel("Password to analyse")
        grid.addWidget(label, 0, 0, 1, 3)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Type a password to analyse")
        self.password_input.setAccessibleName("Password to analyse")
        self.password_input.setAccessibleDescription(
            "The password is analysed on this device only and is never stored."
        )
        self.password_input.textChanged.connect(self._on_input_changed)
        grid.addWidget(self.password_input, 1, 0)

        self.show_checkbox = QCheckBox("Show")
        self.show_checkbox.setAccessibleName("Show password")
        self.show_checkbox.setAccessibleDescription(
            "Reveal the typed password while it is being analysed."
        )
        self.show_checkbox.toggled.connect(self._toggle_visibility)
        grid.addWidget(self.show_checkbox, 1, 1)

        context_label = QLabel("Personal context (optional)")
        context_label.setStyleSheet(_style(_MUTED_STYLE, secondary=theme.COLOR_TEXT_SECONDARY))
        grid.addWidget(context_label, 2, 0, 1, 3)

        self.context_input = QLineEdit()
        self.context_input.setPlaceholderText("e.g. your name, birth year, or email to check against")
        self.context_input.setAccessibleName("Personal context")
        self.context_input.setAccessibleDescription(
            "Optional personal information the password is checked against, "
            "such as a name or birth year."
        )
        self.context_input.textChanged.connect(self._on_input_changed)
        grid.addWidget(self.context_input, 3, 0, 1, 3)

        controls = QHBoxLayout()
        controls.setSpacing(theme.SPACE_SM)
        generate = QPushButton("Generate strong password")
        generate.setAccessibleDescription(
            "Create a cryptographically secure random password using the "
            "operating system's secure random source."
        )
        generate.clicked.connect(self._generate_password)
        passphrase_button = QPushButton("Generate passphrase (4 words)")
        passphrase_button.setAccessibleName("Generate passphrase of four words")
        passphrase_button.setAccessibleDescription(
            "Create a NIST SP 800-63B style passphrase: four random words from a "
            "7,776-word style list (about 51.7 bits)."
        )
        passphrase_button.clicked.connect(self._generate_passphrase)
        self.copy_button = QPushButton("Copy")
        self.copy_button.setAccessibleName("Copy password to clipboard")
        self.copy_button.clicked.connect(self._copy_password)
        self.copy_status = QLabel("")
        self.copy_status.setStyleSheet(_style(_MUTED_STYLE, secondary=theme.COLOR_TEXT_SECONDARY))
        controls.addWidget(generate)
        controls.addWidget(passphrase_button)
        controls.addWidget(self.copy_button)
        controls.addWidget(self.copy_status)
        controls.addStretch(1)
        grid.addLayout(controls, 4, 0, 1, 3)
        return panel

    def _generate_password(self) -> None:
        self.password_input.setText(generate_password())
        self.copy_status.setText("Generated — review it, then copy.")

    def _generate_passphrase(self) -> None:
        self.password_input.setText(generate_passphrase(4))
        self.copy_status.setText("Passphrase generated — four random words.")

    def _copy_password(self) -> None:
        if not self.password_input.text():
            self.copy_status.setText("Nothing to copy yet.")
            return
        QApplication.clipboard().setText(self.password_input.text())
        self.copy_status.setText("Copied to clipboard.")

    def _toggle_visibility(self, visible: bool) -> None:
        self.password_input.setEchoMode(
            QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        )

    def _on_input_changed(self, _text: str) -> None:
        self._clear_results()
        password = self.password_input.text()
        if not password:
            self._show_hint()
            return
        try:
            report = analyze_password(password, context=self.context_input.text() or None)
        except TypeError:
            self._clear_results()
            self._show_hint()
            return
        self._show_report(report)

    def _clear_results(self) -> None:
        while self.results_layout.count():
            item = self.results_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _show_hint(self) -> None:
        hint = QLabel("Start typing a password to see its strength analysis.")
        hint.setWordWrap(True)
        hint.setStyleSheet(_style(_MUTED_STYLE, secondary=theme.COLOR_TEXT_SECONDARY))
        self.results_layout.addWidget(hint)

    def _show_report(self, report: PasswordReport) -> None:
        color = _STRENGTH_COLORS[report.strength]

        verdict_row = QHBoxLayout()
        badge = QLabel(report.strength)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setStyleSheet(_style(
            _BADGE_STYLE, background=theme.COLOR_BACKGROUND, color=color,
        ))
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(report.score)
        bar.setTextVisible(False)
        bar.setFixedHeight(8)
        bar.setStyleSheet(_style(_PROGRESS_BAR_STYLE, raised=theme.COLOR_SURFACE_RAISED, color=color))
        bar.setAccessibleName(f"Password strength score: {report.score} out of 100")
        score_label = QLabel(f"{report.score}/100")
        verdict_row.addWidget(badge)
        verdict_row.addWidget(bar, 1)
        verdict_row.addWidget(score_label)
        row_widget = QWidget()
        row_widget.setLayout(verdict_row)
        self.results_layout.addWidget(row_widget)

        entropy = QLabel(
            f"Random-choice entropy: {report.random_entropy_bits:.1f} bits — "
            f"pattern-aware estimate: {report.entropy_bits:.1f} bits."
        )
        entropy.setWordWrap(True)
        entropy.setStyleSheet(_style(_MUTED_STYLE, secondary=theme.COLOR_TEXT_SECONDARY))
        self.results_layout.addWidget(entropy)

        if report.is_passphrase:
            passphrase_note = QLabel(
                "<b>Passphrase pattern:</b> this password is a sequence of words. "
                f"Estimated at {report.entropy_bits:.1f} bits using the word-list model "
                "(each word counts as log2(7776), the NIST SP 800-63B recommended pattern). "
                "Length and words matter more than forced symbols."
            )
            passphrase_note.setWordWrap(True)
            passphrase_note.setStyleSheet(_style(
                _ALERT_STYLE,
                surface=theme.COLOR_SURFACE,
                danger=theme.COLOR_SUCCESS,
            ))
            self.results_layout.addWidget(passphrase_note)

        if report.patterns:
            pattern_line = QLabel(
                "Detected patterns: "
                + ", ".join(PATTERN_LABELS.get(kind, kind) for kind in report.patterns)
                + "."
            )
            pattern_line.setWordWrap(True)
            pattern_line.setStyleSheet(_style(
                _ALERT_STYLE,
                surface=theme.COLOR_SURFACE,
                danger=theme.COLOR_WARNING,
            ))
            self.results_layout.addWidget(pattern_line)

        crack_grid = QGridLayout()
        crack_grid.setHorizontalSpacing(theme.SPACE_MD)
        crack_grid.setVerticalSpacing(theme.SPACE_MD)
        offline = self._crack_card(
            _OFFLINE_RATE_LABEL, format_duration(report.offline_crack_seconds)
        )
        online = self._crack_card(
            _ONLINE_RATE_LABEL, format_duration(report.online_crack_seconds)
        )
        crack_grid.addWidget(offline, 0, 0)
        crack_grid.addWidget(online, 0, 1)
        grid_widget = QWidget()
        grid_widget.setLayout(crack_grid)
        self.results_layout.addWidget(grid_widget)

        if report.in_common_list:
            alert = QLabel(
                f"This password appears in the bank of {len(COMMON_PASSWORDS)} "
                f"most common passwords (matched: \"{report.common_match}\"). "
                "An attacker's first pass would try it within moments."
            )
            alert.setWordWrap(True)
            alert.setStyleSheet(_style(
                _ALERT_STYLE,
                surface=theme.COLOR_SURFACE,
                danger=theme.COLOR_DANGER,
            ))
            self.results_layout.addWidget(alert)

        for check in report.checks:
            row = QFrame()
            mark_color = theme.COLOR_SUCCESS if check.passed else theme.COLOR_DANGER
            row.setStyleSheet(_style(
                _CHECK_STYLE,
                surface=theme.COLOR_SURFACE,
                border=theme.COLOR_BORDER,
                mark=mark_color,
            ))
            inner = QHBoxLayout(row)
            inner.setContentsMargins(theme.SPACE_MD, theme.SPACE_SM, theme.SPACE_MD, theme.SPACE_SM)
            inner.setSpacing(theme.SPACE_SM)
            mark = QLabel("✓" if check.passed else "✕")
            mark.setStyleSheet(f"color: {mark_color}; font-weight: 700;")
            text = QLabel(check.label)
            text.setWordWrap(True)
            if not check.passed:
                text.setStyleSheet(_style(_MUTED_STYLE, secondary=theme.COLOR_TEXT_SECONDARY))
            inner.addWidget(mark)
            inner.addWidget(text, 1)
            self.results_layout.addWidget(row)

        footnote = QLabel(
            "Estimates assume a pattern-aware offline attacker at the stated "
            "guess rate and that the password does not appear in larger "
            "breach lists. Real-world cracking time varies with attacker "
            "skill and hardware."
        )
        footnote.setWordWrap(True)
        footnote.setStyleSheet(_style(_MUTED_STYLE, secondary=theme.COLOR_TEXT_SECONDARY))
        self.results_layout.addWidget(footnote)

    def hideEvent(self, event) -> None:
        """Memory hygiene: wipe the plaintext password when leaving the module."""
        self.password_input.clear()
        self.copy_status.setText("")
        super().hideEvent(event)

    def _crack_card(self, title: str, value: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet(_style(
            _CARD_STYLE,
            surface=theme.COLOR_SURFACE,
            border=theme.COLOR_BORDER,
        ))
        inner = QVBoxLayout(card)
        inner.setContentsMargins(theme.SPACE_MD, theme.SPACE_MD, theme.SPACE_MD, theme.SPACE_MD)
        inner.setSpacing(theme.SPACE_XS)
        label = QLabel(title)
        label.setWordWrap(True)
        label.setStyleSheet(_style(_MUTED_STYLE, secondary=theme.COLOR_TEXT_SECONDARY))
        value_label = QLabel(value)
        value_label.setWordWrap(True)
        value_label.setStyleSheet("font-weight: 700;")
        inner.addWidget(label)
        inner.addWidget(value_label)
        return card
