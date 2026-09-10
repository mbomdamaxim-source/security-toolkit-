"""Native PySide6 Crypto Lab: an overlay dialog with hands-on crypto tools
and a full-featured verified quiz.

Everything runs locally. Real cryptography uses the audited `cryptography`
library; classic ciphers are clearly labelled as educational only.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
from pathlib import Path
import random

from PySide6.QtCore import QStandardPaths, Qt, QTimer
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QDialog, QFrame, QGridLayout, QHBoxLayout,
    QLabel, QLineEdit, QPlainTextEdit, QProgressBar, QPushButton,
    QRadioButton, QSpinBox, QStackedWidget, QTabWidget, QVBoxLayout, QWidget,
)

from core import theme
from core.quiz_history import QuizHistory
from modules.credentials.crypto_logic import (
    CRYPTO_CATEGORY_LABELS,
    CRYPTO_QUIZ_BANK,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    base64_decode,
    base64_encode,
    caesar,
    caesar_break,
    crypto_choices,
    hash_with_salt,
    rsa_decrypt,
    rsa_encrypt,
    rsa_generate_keypair,
    sha256_hex,
    verify_salted_hash,
    vigenere,
)

_CARD_STYLE = (
    f"background-color: {theme.COLOR_SURFACE};"
    f" border: 1px solid {theme.COLOR_BORDER};"
    f" border-radius: {theme.RADIUS_MD}px;"
    f" padding: {theme.SPACE_LG}px;"
)
_TOOL_HEAD_STYLE = (
    f"background-color: {theme.COLOR_SURFACE_RAISED};"
    f" border: 1px solid {theme.COLOR_BORDER};"
    f" border-left: 4px solid {theme.COLOR_ACCENT};"
    f" border-radius: {theme.RADIUS_SM}px;"
    f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
)
_NOTE_STYLE = (
    f"background-color: {theme.COLOR_SURFACE_RAISED};"
    f" border-left: 4px solid {theme.COLOR_INFO};"
    f" border-radius: {theme.RADIUS_SM}px;"
    f" padding: {theme.SPACE_SM}px {theme.SPACE_MD}px;"
    f" color: {theme.COLOR_TEXT_SECONDARY};"
)
_FEEDBACK_STYLE = (
    f"background-color: {theme.COLOR_SURFACE_RAISED};"
    f" border-left: 4px solid {theme.COLOR_INFO};"
    f" border-radius: {theme.RADIUS_SM}px;"
    f" padding: {theme.SPACE_MD}px;"
)
_PROGRESS_BAR_STYLE = (
    f"QProgressBar {{ background-color: {theme.COLOR_SURFACE_RAISED};"
    f" border: none; border-radius: {theme.RADIUS_SM}px; }}"
    f"QProgressBar::chunk {{ background-color: {theme.COLOR_ACCENT};"
    f" border-radius: {theme.RADIUS_SM}px; }}"
)
_ANSWER_BASE_STYLE = (
    f"QRadioButton {{ background-color: {theme.COLOR_SURFACE};"
    f" border: 1px solid {theme.COLOR_BORDER};"
    f" border-radius: {theme.RADIUS_MD}px;"
    f" padding: 10px 14px; }}"
    f"QRadioButton:hover {{ border-color: {theme.COLOR_ACCENT}; }}"
    f"QRadioButton:checked {{ border-color: {theme.COLOR_ACCENT};"
    f" color: {theme.COLOR_ACCENT}; font-weight: 600; }}"
)
_MUTED_STYLE = f"color: {theme.COLOR_TEXT_SECONDARY};"
_HEADING_STYLE = f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 600;"
_OUTPUT_STYLE = (
    f"QPlainTextEdit {{ background-color: {theme.COLOR_BACKGROUND};"
    f" color: {theme.COLOR_TEXT_PRIMARY};"
    f" border: 1px solid {theme.COLOR_BORDER};"
    f" border-radius: {theme.RADIUS_SM}px;"
    f" padding: {theme.SPACE_SM}px; }}"
)
_LABELS_BY_KEY = {key: label for label, key in CRYPTO_CATEGORY_LABELS.items()}
_LAB_TOOLS = (
    ("Caesar", "Shift every letter by a fixed amount (1-25)."),
    ("Vigenere", "Vary the shift per letter using a keyword."),
    ("Base64", "Encode or decode text - it is not encryption."),
    ("SHA-256", "One-way hash that updates live as you type."),
    ("AES-GCM", "Real encryption: derive a key, encrypt, and prove tamper detection."),
    ("Caesar breaker", "Try all 25 shifts at once to reveal the plaintext."),
    ("Salted hashing", "Hash a password with a random salt, then verify it."),
    ("RSA", "Asymmetric: the public key encrypts, the private key decrypts."),
)

_SHORTCUT_ANSWER_INDEX = {
    Qt.Key.Key_A: 0,
    Qt.Key.Key_B: 1,
    Qt.Key.Key_C: 2,
    Qt.Key.Key_D: 3,
}


def _card_button_style(selected: bool = False) -> str:
    border = theme.COLOR_ACCENT if selected else theme.COLOR_BORDER
    color = theme.COLOR_ACCENT if selected else theme.COLOR_TEXT_PRIMARY
    return (
        f"QPushButton {{ background-color: {theme.COLOR_SURFACE_RAISED}; color: {color};"
        f" border: 1px solid {border}; border-radius: {theme.RADIUS_MD}px;"
        f" padding: {theme.SPACE_MD}px; text-align: center; font-weight: 600; }}"
        f"QPushButton:hover {{ border-color: {theme.COLOR_ACCENT}; }}"
    )


def _answer_state_style(color: str) -> str:
    return (
        f"QRadioButton {{ color: {color}; font-weight: 700;"
        f" background-color: {theme.COLOR_SURFACE};"
        f" border: 1px solid {color}; border-radius: {theme.RADIUS_MD}px;"
        f" padding: 10px 14px; }}"
    )


def _recommendation(category: str, percent: int) -> str:
    if percent < 60:
        return f"{category}: revise the underlying concept and retry this category."
    if percent < 80:
        return f"{category}: practise more questions to make your answers consistent."
    return f"{category}: strong result. Continue reviewing it alongside the other topics."


class CryptoLabDialog(QDialog):
    """Floating Crypto Lab window shown over the Credential Auditor."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Crypto Lab")
        self.resize(980, 760)
        self.setWindowModality(Qt.WindowModality.WindowModal)

        data_directory = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppLocalDataLocation) or str(Path.home())
        self.history_store = QuizHistory(Path(data_directory) / "crypto_quiz_history.json")

        # quiz state
        self._quiz_live = False
        self._in_question = False
        self.missed = []
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)

        # RSA demo state (kept in memory only)
        self._rsa_private_pem = None
        self._rsa_public_pem = None

        root = QVBoxLayout(self)
        root.setContentsMargins(theme.SPACE_XL, theme.SPACE_LG, theme.SPACE_XL, theme.SPACE_LG)
        root.setSpacing(theme.SPACE_MD)

        header = QHBoxLayout()
        header.setSpacing(theme.SPACE_MD)
        title_box = QVBoxLayout()
        title_box.setSpacing(theme.SPACE_XS)
        title = QLabel("Crypto Lab")
        title.setStyleSheet(f"font-size: {theme.FONT_SIZE_TITLE}pt; font-weight: 700;")
        subtitle = QLabel("Hands-on encryption, hashing and encoding - and a quiz to test what you learned.")
        subtitle.setStyleSheet(_MUTED_STYLE)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box, 1)
        close_button = QPushButton("\u2715 Close")
        close_button.setAccessibleName("Close Crypto Lab")
        close_button.clicked.connect(self.reject)
        header.addWidget(close_button, 0, Qt.AlignmentFlag.AlignTop)
        root.addLayout(header)

        self.tabs = QTabWidget()
        self.lab_tab = self._build_lab_tab()
        self.quiz_tab = QWidget()
        self.quiz_layout = QVBoxLayout(self.quiz_tab)
        self.quiz_layout.setSpacing(theme.SPACE_MD)
        self.tabs.addTab(self.lab_tab, "Lab")
        self.tabs.addTab(self.quiz_tab, "Quiz")
        root.addWidget(self.tabs, 1)

        self._show_quiz_setup()

    def closeEvent(self, event) -> None:
        self.timer.stop()
        self._quiz_live = False
        super().closeEvent(event)

    # ---------------------------------------------------------------- Lab tab
    def _build_lab_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(theme.SPACE_MD)

        self.tool_group = QButtonGroup(self)
        self.tool_group.setExclusive(True)
        grid = QGridLayout()
        grid.setHorizontalSpacing(theme.SPACE_MD)
        grid.setVerticalSpacing(theme.SPACE_MD)
        for index, (name, _description) in enumerate(_LAB_TOOLS):
            button = QPushButton(name)
            button.setCheckable(True)
            button.setAccessibleName(f"Crypto tool: {name}")
            button.setStyleSheet(_card_button_style(index == 0))
            self.tool_group.addButton(button, index)
            button.clicked.connect(lambda checked=False, selected=button: self._select_tool(selected))
            grid.addWidget(button, index // 4, index % 4)
        self.tool_group.button(0).setChecked(True)
        layout.addLayout(grid)

        self.lab_stack = QStackedWidget()
        for name, description in _LAB_TOOLS:
            self.lab_stack.addWidget(self._build_tool_page(name, description))
        layout.addWidget(self.lab_stack, 1)
        return tab

    def _select_tool(self, clicked) -> None:
        for button in self.tool_group.buttons():
            button.setStyleSheet(_card_button_style(button is clicked))
        self.lab_stack.setCurrentIndex(self.tool_group.id(clicked))

    def _build_tool_page(self, name: str, description: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(theme.SPACE_SM)
        head = QFrame()
        head.setStyleSheet(_TOOL_HEAD_STYLE)
        head_layout = QVBoxLayout(head)
        head_layout.setContentsMargins(theme.SPACE_MD, theme.SPACE_SM, theme.SPACE_MD, theme.SPACE_SM)
        head_layout.setSpacing(2)
        title = QLabel(name)
        title.setStyleSheet(f"font-weight: 700; font-size: {theme.FONT_SIZE_HEADING}pt;")
        desc = QLabel(description)
        desc.setStyleSheet(_MUTED_STYLE)
        head_layout.addWidget(title)
        head_layout.addWidget(desc)
        layout.addWidget(head)

        builder = {
            "Caesar": self._build_caesar,
            "Vigenere": self._build_vigenere,
            "Base64": self._build_base64,
            "SHA-256": self._build_sha256,
            "AES-GCM": self._build_aes,
            "Caesar breaker": self._build_breaker,
            "Salted hashing": self._build_salted,
            "RSA": self._build_rsa,
        }[name]
        builder(layout, page)
        layout.addStretch(1)
        return page

    # ---- shared lab helpers ----
    def _lab_output(self) -> QPlainTextEdit:
        output = QPlainTextEdit()
        output.setReadOnly(True)
        output.setMaximumHeight(190)
        output.setStyleSheet(_OUTPUT_STYLE)
        font = output.font()
        font.setFamily("Consolas")
        font.setPointSize(9)
        output.setFont(font)
        return output

    def _lab_note(self, text: str) -> QLabel:
        note = QLabel(text)
        note.setWordWrap(True)
        note.setStyleSheet(_NOTE_STYLE)
        return note

    def _lab_button(self, text: str) -> QPushButton:
        button = QPushButton(text)
        return button

    # ---- tool builders ----
    def _build_caesar(self, layout, page):
        text = QLineEdit()
        text.setPlaceholderText("Enter a message")
        shift = QSpinBox()
        shift.setRange(1, 25)
        shift.setValue(3)
        shift.setAccessibleName("Caesar shift")
        row = QHBoxLayout()
        row.addWidget(QLabel("Shift"))
        row.addWidget(shift)
        row.addStretch(1)
        layout.addWidget(QLabel("Text"))
        layout.addWidget(text)
        layout.addLayout(row)
        out = self._lab_output()
        buttons = QHBoxLayout()
        def run(decrypt: bool):
            try:
                out.setPlainText(caesar(text.text(), shift.value(), decrypt=decrypt))
            except ValueError as error:
                out.setPlainText(str(error))
        encrypt = self._lab_button("Encrypt")
        encrypt.clicked.connect(lambda: run(False))
        decrypt = self._lab_button("Decrypt")
        decrypt.clicked.connect(lambda: run(True))
        buttons.addWidget(encrypt)
        buttons.addWidget(decrypt)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addWidget(out)
        layout.addWidget(self._lab_note(
            "Why it matters: only 25 possible shifts - a computer breaks this instantly "
            "by trying every shift. Classic ciphers teach the concept; they never protect real data."
        ))

    def _build_vigenere(self, layout, page):
        text = QLineEdit()
        text.setPlaceholderText("Enter a message")
        key = QLineEdit()
        key.setPlaceholderText("e.g. LEMON")
        layout.addWidget(QLabel("Text"))
        layout.addWidget(text)
        layout.addWidget(QLabel("Keyword"))
        layout.addWidget(key)
        out = self._lab_output()
        buttons = QHBoxLayout()
        def run(decrypt: bool):
            try:
                out.setPlainText(vigenere(text.text(), key.text(), decrypt=decrypt))
            except ValueError as error:
                out.setPlainText(str(error))
        encrypt = self._lab_button("Encrypt")
        encrypt.clicked.connect(lambda: run(False))
        decrypt = self._lab_button("Decrypt")
        decrypt.clicked.connect(lambda: run(True))
        buttons.addWidget(encrypt)
        buttons.addWidget(decrypt)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addWidget(out)
        layout.addWidget(self._lab_note(
            "Why it matters: each letter gets a different shift based on a keyword. "
            "That is stronger than Caesar, but a short keyword is still broken by Kasiski "
            "examination and frequency analysis - never use it for real secrets."
        ))

    def _build_base64(self, layout, page):
        text = QLineEdit()
        text.setPlaceholderText("Enter text or Base64")
        layout.addWidget(QLabel("Text or Base64"))
        layout.addWidget(text)
        out = self._lab_output()
        buttons = QHBoxLayout()
        def encode():
            try:
                out.setPlainText(base64_encode(text.text()))
            except ValueError as error:
                out.setPlainText(str(error))
        def decode():
            try:
                out.setPlainText(base64_decode(text.text()))
            except ValueError as error:
                out.setPlainText(str(error))
        enc = self._lab_button("Encode")
        enc.clicked.connect(encode)
        dec = self._lab_button("Decode")
        dec.clicked.connect(decode)
        buttons.addWidget(enc)
        buttons.addWidget(dec)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addWidget(out)
        layout.addWidget(self._lab_note(
            "Why it matters: Base64 is encoding, not encryption. Anyone can decode it "
            "without a key - it only makes data safe to transport. Never confuse the two."
        ))

    def _build_sha256(self, layout, page):
        text = QLineEdit()
        text.setPlaceholderText("Type anything - the hash updates live")
        layout.addWidget(QLabel("Text"))
        layout.addWidget(text)
        out = self._lab_output()
        out.setMaximumHeight(90)
        layout.addWidget(out)
        text.textChanged.connect(lambda value: out.setPlainText(sha256_hex(value)))
        layout.addWidget(self._lab_note(
            "Why it matters: SHA-256 is one-way: you cannot recover the input from the hash. "
            "Change one letter and the whole hash changes (avalanche effect). This is how "
            "password storage and file integrity checks work."
        ))

    def _build_aes(self, layout, page):
        page._aes_blob = None
        passphrase = QLineEdit()
        passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        passphrase.setPlaceholderText("The key is derived from this")
        message = QLineEdit()
        message.setPlaceholderText("Secret message")
        layout.addWidget(QLabel("Passphrase"))
        layout.addWidget(passphrase)
        layout.addWidget(QLabel("Message"))
        layout.addWidget(message)
        out = self._lab_output()
        buttons = QHBoxLayout()

        def encrypt():
            try:
                salt, nonce, ciphertext = aes_gcm_encrypt(passphrase.text(), message.text())
                page._aes_blob = f"{salt.hex()}:{nonce.hex()}:{ciphertext.hex()}"
                out.setPlainText(page._aes_blob)
            except ValueError as error:
                out.setPlainText(str(error))

        def decrypt():
            if not page._aes_blob:
                out.setPlainText("Encrypt something first.")
                return
            try:
                salt, nonce, ciphertext = (bytes.fromhex(part) for part in page._aes_blob.split(":"))
                plain = aes_gcm_decrypt(passphrase.text(), salt, nonce, ciphertext)
                out.setPlainText(f"{plain}\n- decrypted successfully with the correct passphrase.")
            except ValueError as error:
                out.setPlainText(str(error))

        def tamper():
            if not page._aes_blob:
                out.setPlainText("Encrypt something first, then tamper with it.")
                return
            flipped = ("1" if page._aes_blob[0] == "0" else "0") + page._aes_blob[1:]
            page._aes_blob = flipped
            try:
                salt, nonce, ciphertext = (bytes.fromhex(part) for part in page._aes_blob.split(":"))
                aes_gcm_decrypt(passphrase.text(), salt, nonce, ciphertext)
                out.setPlainText("Unexpected: decryption succeeded after tampering.")
            except ValueError:
                out.setPlainText(
                    "Tampering detected: decryption failed because the ciphertext was modified.\n"
                    "One changed byte in the ciphertext breaks the GCM authentication tag - that is integrity protection."
                )

        enc = self._lab_button("Encrypt")
        enc.clicked.connect(encrypt)
        dec = self._lab_button("Decrypt")
        dec.clicked.connect(decrypt)
        tam = self._lab_button("Tamper demo")
        tam.clicked.connect(tamper)
        buttons.addWidget(enc)
        buttons.addWidget(dec)
        buttons.addWidget(tam)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addWidget(out)
        layout.addWidget(self._lab_note(
            "Why it matters: this is real encryption - AES-256-GCM with a key derived from "
            "your passphrase (PBKDF2). The salt and nonce are random each time. If anyone "
            "changes even one byte of the ciphertext, decryption fails: that is integrity "
            "protection. Modern HTTPS works this way."
        ))

    def _build_breaker(self, layout, page):
        text = QLineEdit()
        text.setPlaceholderText("e.g. FDW")
        layout.addWidget(QLabel("Ciphertext"))
        layout.addWidget(text)
        out = self._lab_output()
        out.setMaximumHeight(300)
        buttons = QHBoxLayout()
        def run():
            results = caesar_break(text.text())
            out.setPlainText("\n".join(f"Shift {shift:02d}: {result}" for shift, result in results))
        run_button = self._lab_button("Break - try all 25 shifts")
        run_button.clicked.connect(run)
        buttons.addWidget(run_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addWidget(out)
        layout.addWidget(self._lab_note(
            "Why it matters: all 25 possible outputs appear at once - one of them is always "
            "the plaintext. This is why Caesar (and any small-key classic cipher) provides "
            "no real secrecy."
        ))

    def _build_salted(self, layout, page):
        password = QLineEdit()
        password.setEchoMode(QLineEdit.EchoMode.Password)
        password.setPlaceholderText("Hash this password")
        layout.addWidget(QLabel("Password"))
        layout.addWidget(password)
        out = self._lab_output()
        out.setMaximumHeight(220)
        buttons = QHBoxLayout()

        def hash_twice():
            if not password.text():
                out.setPlainText("Enter a password first.")
                return
            salt1, hash1 = hash_with_salt(password.text())
            salt2, hash2 = hash_with_salt(password.text())
            out.setPlainText(
                f"Hash 1 (salt {salt1}):\n{hash1}\n\n"
                f"Hash 2 (salt {salt2}):\n{hash2}\n\n"
                "Same password - completely different hashes."
            )

        run_button = self._lab_button("Hash twice (new salt each time)")
        run_button.clicked.connect(hash_twice)
        buttons.addWidget(run_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addWidget(out)

        verify_password = QLineEdit()
        verify_password.setEchoMode(QLineEdit.EchoMode.Password)
        verify_password.setPlaceholderText("Password to check")
        verify_blob = QLineEdit()
        verify_blob.setPlaceholderText("salt:hash from above")
        result = QLabel("")
        result.setWordWrap(True)
        layout.addWidget(QLabel("Verify a password"))
        layout.addWidget(verify_password)
        layout.addWidget(QLabel("Stored salt:hash"))
        layout.addWidget(verify_blob)
        verify_buttons = QHBoxLayout()

        def verify():
            parts = verify_blob.text().strip().split(":")
            if len(parts) != 2:
                result.setText("Expected a salt:hash value.")
                result.setStyleSheet(f"color: {theme.COLOR_DANGER}; font-weight: 700;")
                return
            ok = verify_salted_hash(verify_password.text(), parts[0], parts[1])
            result.setText("Match - the password is correct." if ok else "No match - wrong password or corrupted record.")
            result.setStyleSheet(f"color: {theme.COLOR_SUCCESS if ok else theme.COLOR_DANGER}; font-weight: 700;")

        verify_button = self._lab_button("Verify")
        verify_button.clicked.connect(verify)
        verify_buttons.addWidget(verify_button)
        verify_buttons.addStretch(1)
        layout.addLayout(verify_buttons)
        layout.addWidget(result)
        layout.addWidget(self._lab_note(
            "Why it matters: the same password hashed with two different salts gives two "
            "completely different hashes. That defeats rainbow tables: an attacker cannot "
            "precompute one lookup table for every account. Real systems store salt + hash "
            "and re-derive on login."
        ))

    def _build_rsa(self, layout, page):
        status = QLabel("")
        status.setWordWrap(True)
        status.setStyleSheet(_MUTED_STYLE)
        layout.addWidget(status)
        buttons = QHBoxLayout()

        def generate():
            self._rsa_private_pem, self._rsa_public_pem = rsa_generate_keypair()
            fingerprint = hashlib.sha256(self._rsa_public_pem).hexdigest()[:32]
            status.setText(
                f"Key pair generated.\nPublic key fingerprint (SHA-256, first 16 bytes): {fingerprint}\n"
                "The private key stays in this application only."
            )

        gen = self._lab_button("Generate RSA-2048 key pair")
        gen.clicked.connect(generate)
        buttons.addWidget(gen)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        message = QLineEdit()
        message.setPlaceholderText("Secret message")
        layout.addWidget(QLabel("Message"))
        layout.addWidget(message)
        out = self._lab_output()
        crypto_buttons = QHBoxLayout()

        def encrypt():
            if self._rsa_public_pem is None:
                out.setPlainText("Generate a key pair first.")
                return
            try:
                out.setPlainText(rsa_encrypt(self._rsa_public_pem, message.text()))
            except ValueError as error:
                out.setPlainText(str(error))

        def decrypt():
            if self._rsa_private_pem is None:
                out.setPlainText("Generate a key pair first.")
                return
            try:
                lines = out.toPlainText().strip().splitlines()
                if not lines:
                    out.setPlainText("Encrypt a message first.")
                    return
                ciphertext = lines[0]
                plain = rsa_decrypt(self._rsa_private_pem, ciphertext)
                out.setPlainText(f"{plain}\n- decrypted with the private key.")
            except ValueError as error:
                out.setPlainText(str(error))

        enc = self._lab_button("Encrypt with public key")
        enc.clicked.connect(encrypt)
        dec = self._lab_button("Decrypt with private key")
        dec.clicked.connect(decrypt)
        crypto_buttons.addWidget(enc)
        crypto_buttons.addWidget(dec)
        crypto_buttons.addStretch(1)
        layout.addLayout(crypto_buttons)
        layout.addWidget(out)
        layout.addWidget(self._lab_note(
            "Why it matters: the public key encrypts, only the matching private key decrypts. "
            "The private key never leaves the owner - this is how secure email and TLS "
            "certificates work. (Demo uses RSA-OAEP-SHA256, 2048 bits.)"
        ))

    # ---------------------------------------------------------------- Quiz tab
    def _clear_quiz(self):
        while self.quiz_layout.count():
            item = self.quiz_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _show_quiz_setup(self):
        self._quiz_live = False
        self._in_question = False
        self.timer.stop()
        self._clear_quiz()
        heading = QLabel("Crypto quiz")
        heading.setStyleSheet(f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 700;")
        self.quiz_layout.addWidget(heading)
        description = QLabel("Choose a study mode and a verified cryptography category. 10 verified questions per topic.")
        description.setWordWrap(True)
        description.setStyleSheet(_MUTED_STYLE)
        self.quiz_layout.addWidget(description)

        mode_heading = QLabel("Choose a study mode")
        mode_heading.setStyleSheet(_HEADING_STYLE)
        self.quiz_layout.addWidget(mode_heading)
        mode_description = QLabel("Practice has no time limit. Exam mode adds a countdown.")
        mode_description.setStyleSheet(_MUTED_STYLE)
        self.quiz_layout.addWidget(mode_description)
        mode_grid = QGridLayout()
        mode_grid.setHorizontalSpacing(theme.SPACE_MD)
        mode_grid.setVerticalSpacing(theme.SPACE_MD)
        self.mode_group = QButtonGroup(self)
        self.mode_group.setExclusive(True)
        for index, (title, detail, duration) in enumerate(
            (("Practice mode", "No time limit", 0),
             ("Exam mode", "10 minutes", 600),
             ("Exam mode", "20 minutes", 1200),
             ("Exam mode", "30 minutes", 1800))
        ):
            button = QPushButton(f"{title}\n{detail}")
            button.setCheckable(True)
            button.setAccessibleName(f"{title} - {detail}")
            self.mode_group.addButton(button, duration)
            button.setStyleSheet(_card_button_style(index == 0))
            button.clicked.connect(lambda checked=False, selected=button: self._select_mode(selected))
            mode_grid.addWidget(button, index // 2, index % 2)
        self.mode_group.button(0).setChecked(True)
        self.quiz_layout.addLayout(mode_grid)

        category_heading = QLabel("Choose a quiz category")
        category_heading.setStyleSheet(_HEADING_STYLE)
        self.quiz_layout.addWidget(category_heading)
        category_grid = QGridLayout()
        category_grid.setHorizontalSpacing(theme.SPACE_MD)
        category_grid.setVerticalSpacing(theme.SPACE_MD)
        categories = ["Mixed topics", *CRYPTO_CATEGORY_LABELS]
        for index, label in enumerate(categories):
            button = QPushButton(label)
            button.setAccessibleName(f"Start quiz: {label}")
            button.setStyleSheet(_card_button_style(False))
            button.clicked.connect(lambda checked=False, selected=label: self._start_quiz(selected))
            category_grid.addWidget(button, index // 3, index % 3)
        self.quiz_layout.addLayout(category_grid)

        history_card = QFrame()
        history_card.setStyleSheet(_CARD_STYLE)
        history_layout = QVBoxLayout(history_card)
        history_layout.setSpacing(theme.SPACE_SM)
        history_title = QLabel("Recent quiz history")
        history_title.setStyleSheet(_HEADING_STYLE)
        history_layout.addWidget(history_title)
        entries = self.history_store.load()
        if not entries:
            history_layout.addWidget(QLabel("No crypto quiz attempts have been recorded yet."))
        else:
            for entry in entries[:5]:
                line = QLabel(
                    f"{entry['date']} - {entry['category']} - {entry['mode']} - "
                    f"{entry['score']}/{entry['total']} ({entry['percentage']}%)"
                )
                line.setStyleSheet(_MUTED_STYLE)
                history_layout.addWidget(line)
        self.quiz_layout.addWidget(history_card)
        self.quiz_layout.addStretch(1)

    def _select_mode(self, clicked):
        for button in self.mode_group.buttons():
            button.setStyleSheet(_card_button_style(button is clicked))

    def _start_quiz(self, category_label, duration=None):
        self._quiz_live = True
        self.session_category = category_label
        key = CRYPTO_CATEGORY_LABELS.get(category_label)
        self.questions = [q for q in CRYPTO_QUIZ_BANK if key is None or q.category == key]
        random.shuffle(self.questions)
        self.position = 0
        self.score = 0
        self.results = {label: [0, 0] for label in CRYPTO_CATEGORY_LABELS}
        self.missed = []
        self.duration = self.mode_group.checkedId() if duration is None else duration
        self.session_mode = "Practice" if not self.duration else f"Exam {self.duration // 60} minutes"
        self.deadline = self.duration
        self.timer.stop()
        self.tabs.setCurrentWidget(self.quiz_tab)
        self._show_question()
        if self.duration:
            self.timer.start(1000)

    def _tick(self):
        self.deadline -= 1
        if self.deadline <= 0:
            self.timer.stop()
            self.position = len(self.questions)
            self._show_question()
        else:
            self.timer_label.setText(f"Time remaining: {self.deadline // 60}:{self.deadline % 60:02d}")
            self._style_timer()

    def _style_timer(self):
        if not self.duration:
            self.timer_label.setStyleSheet(_MUTED_STYLE)
            return
        remaining = self.deadline
        if remaining <= 10:
            self.timer_label.setStyleSheet(f"color: {theme.COLOR_DANGER}; font-weight: 700;")
        elif remaining <= 60:
            self.timer_label.setStyleSheet(f"color: {theme.COLOR_WARNING}; font-weight: 700;")
        else:
            self.timer_label.setStyleSheet(_MUTED_STYLE)

    def _show_question(self):
        self._clear_quiz()
        if self.position >= len(self.questions):
            self.timer.stop()
            self._in_question = False
            self._show_report()
            return
        self._in_question = True
        question = self.questions[self.position]
        category_label = QLabel(_LABELS_BY_KEY.get(question.category, question.category))
        category_label.setStyleSheet(f"color: {theme.COLOR_ACCENT}; font-weight: 700;")
        self.quiz_layout.addWidget(category_label)
        self.progress_label = QLabel()
        self.quiz_layout.addWidget(self.progress_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setStyleSheet(_PROGRESS_BAR_STYLE)
        self.progress_bar.setAccessibleName("Quiz progress")
        self.quiz_layout.addWidget(self.progress_bar)
        self.timer_label = QLabel(
            "Practice mode — no time limit"
            if not self.duration
            else f"Time remaining: {self.deadline // 60}:{self.deadline % 60:02d}"
        )
        self.quiz_layout.addWidget(self.timer_label)
        self._style_timer()
        card = QFrame()
        card.setStyleSheet(f"background-color: {theme.COLOR_SURFACE}; border-radius: {theme.RADIUS_MD}px; padding: {theme.SPACE_LG}px;")
        card_layout = QVBoxLayout(card)
        self.question_label = QLabel(question.question_text)
        self.question_label.setWordWrap(True)
        self.question_label.setStyleSheet(f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 600;")
        card_layout.addWidget(self.question_label)
        self.quiz_layout.addWidget(card)
        answer_heading = QLabel("Answer choices")
        answer_heading.setAccessibleName("Answer choices")
        self.quiz_layout.addWidget(answer_heading)
        self.answer_group = QButtonGroup(self)
        self.answer_buttons = []
        for index, answer in enumerate(crypto_choices(question.correct_answer)):
            button = QRadioButton(f"{chr(65 + index)}. {answer}")
            button.setProperty("answer", answer)
            button.setAccessibleName(f"Answer {chr(65 + index)}: {answer}")
            button.setAccessibleDescription("Select this answer choice.")
            button.setStyleSheet(_ANSWER_BASE_STYLE)
            self.answer_group.addButton(button)
            self.answer_buttons.append(button)
            self.quiz_layout.addWidget(button)
        self.feedback = QLabel()
        self.feedback.setWordWrap(True)
        self.feedback.setAccessibleName("Answer feedback")
        self.feedback.setAccessibleDescription("Correctness result and a brief explanation.")
        self.feedback.setStyleSheet(_FEEDBACK_STYLE)
        self.quiz_layout.addWidget(self.feedback)
        self.next_button = QPushButton("Check answer")
        self.next_button.setAccessibleName("Check selected answer")
        self.next_button.clicked.connect(self._check_answer)
        self.quiz_layout.addWidget(self.next_button, alignment=Qt.AlignmentFlag.AlignLeft)
        self.quiz_layout.addStretch(1)
        self.answer_buttons[0].setFocus(Qt.FocusReason.OtherFocusReason)
        self._update_progress()

    def _update_progress(self):
        answered = self.position + (1 if self.next_button.text() == "Next question" else 0)
        percent = round(self.score / answered * 100) if answered else 0
        self.progress_label.setText(
            f"Question {self.position + 1} of {len(self.questions)} - Score: {self.score}/{answered} ({percent}%)"
        )
        self.progress_bar.setValue(round(answered / len(self.questions) * 100))

    def _check_answer(self):
        if self.next_button.text() == "Next question":
            self.position += 1
            self._show_question()
            return
        button = self.answer_group.checkedButton()
        if button is None:
            self.feedback.setText("Choose one answer before checking it.")
            return
        question = self.questions[self.position]
        correct = button.property("answer") == question.correct_answer
        category_label = _LABELS_BY_KEY.get(question.category, question.category)
        self.results[category_label][1] += 1
        if correct:
            self.score += 1
            self.results[category_label][0] += 1
        else:
            self.missed.append((question, str(button.property("answer"))))
        for item in self.answer_buttons:
            item.setEnabled(False)
            if item.property("answer") == question.correct_answer:
                item.setText(f"{item.text()}  \u2713")
                item.setStyleSheet(_answer_state_style(theme.COLOR_SUCCESS))
            elif item is button:
                item.setText(f"{item.text()}  \u2715")
                item.setStyleSheet(_answer_state_style(theme.COLOR_DANGER))
        self.feedback.setText(
            ("Correct. The green tick marks the right answer. "
             if correct
             else f"Not quite. The green tick marks the correct answer: {question.correct_answer}. ")
            + question.explanation
        )
        self.next_button.setText("Next question")
        self._update_progress()

    def _show_report(self):
        self._clear_quiz()
        total = len(self.questions)
        percent = round(self.score / total * 100) if total else 0
        heading = QLabel("Crypto quiz performance report")
        heading.setStyleSheet(f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 700;")
        self.quiz_layout.addWidget(heading)
        summary = QLabel(f"Final score: {self.score} out of {total} ({percent}%).")
        self.quiz_layout.addWidget(summary)
        guidance = QLabel(
            "Use the category recommendations to focus your next revision session. "
            "Start with the lowest-scoring topic."
        )
        guidance.setWordWrap(True)
        guidance.setStyleSheet(_MUTED_STYLE)
        self.quiz_layout.addWidget(guidance)
        for category, (correct, attempted) in self.results.items():
            if not attempted:
                continue
            category_percent = round(correct / attempted * 100)
            card = QFrame()
            card.setStyleSheet(_CARD_STYLE)
            card_layout = QVBoxLayout(card)
            card_layout.setSpacing(theme.SPACE_SM)
            title = QLabel(f"{category}: {correct}/{attempted} correct ({category_percent}%)")
            title.setStyleSheet("font-weight: 600;")
            card_layout.addWidget(title)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(category_percent)
            bar.setTextVisible(False)
            bar.setFixedHeight(8)
            bar.setStyleSheet(_PROGRESS_BAR_STYLE)
            bar.setAccessibleName(f"{category} score")
            card_layout.addWidget(bar)
            advice = QLabel(_recommendation(category, category_percent))
            advice.setWordWrap(True)
            advice.setStyleSheet(_MUTED_STYLE)
            card_layout.addWidget(advice)
            self.quiz_layout.addWidget(card)
        self.history_store.record({
            "date": datetime.now().strftime("%Y-%m-%d"),
            "category": self.session_category,
            "mode": self.session_mode,
            "score": self.score,
            "total": total,
            "percentage": percent,
        })
        if self.missed:
            review = QPushButton(f"Review missed questions ({len(self.missed)})")
            review.clicked.connect(self._show_missed_review)
            self.quiz_layout.addWidget(review, alignment=Qt.AlignmentFlag.AlignLeft)
        new_session = QPushButton("Start a new session")
        new_session.clicked.connect(lambda: self._start_quiz(self.session_category, self.duration))
        self.quiz_layout.addWidget(new_session, alignment=Qt.AlignmentFlag.AlignLeft)
        restart = QPushButton("Return to quiz setup")
        restart.clicked.connect(self._show_quiz_setup)
        self.quiz_layout.addWidget(restart, alignment=Qt.AlignmentFlag.AlignLeft)
        self.quiz_layout.addStretch(1)

    def _show_missed_review(self):
        self._clear_quiz()
        heading = QLabel("Review missed questions")
        heading.setStyleSheet(f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 700;")
        self.quiz_layout.addWidget(heading)
        description = QLabel("Review your selected answer, the correct answer, and a brief explanation.")
        description.setWordWrap(True)
        description.setStyleSheet(_MUTED_STYLE)
        self.quiz_layout.addWidget(description)
        for question, chosen in self.missed:
            card = QFrame()
            card.setStyleSheet(_CARD_STYLE)
            card_layout = QVBoxLayout(card)
            card_layout.setSpacing(theme.SPACE_SM)
            text = QLabel(question.question_text)
            text.setWordWrap(True)
            text.setStyleSheet("font-weight: 600;")
            card_layout.addWidget(text)
            yours = QLabel(f"Your answer: {chosen} \u2715")
            yours.setStyleSheet(f"color: {theme.COLOR_DANGER};")
            card_layout.addWidget(yours)
            correct = QLabel(f"Correct answer: {question.correct_answer} \u2713")
            correct.setStyleSheet(f"color: {theme.COLOR_SUCCESS};")
            card_layout.addWidget(correct)
            explanation = QLabel(question.explanation)
            explanation.setWordWrap(True)
            explanation.setStyleSheet(_MUTED_STYLE)
            card_layout.addWidget(explanation)
            self.quiz_layout.addWidget(card)
        restart = QPushButton("Return to quiz setup")
        restart.clicked.connect(self._show_quiz_setup)
        self.quiz_layout.addWidget(restart, alignment=Qt.AlignmentFlag.AlignLeft)
        self.quiz_layout.addStretch(1)

    # ---------------------------------------------------------------- shortcuts
    def _quiz_shortcuts_active(self) -> bool:
        if not self._quiz_live:
            return False
        if self.tabs.currentWidget() is not self.quiz_tab:
            return False
        focus = QApplication.focusWidget()
        if isinstance(focus, (QLineEdit, QSpinBox, QPlainTextEdit)):
            return False
        return True

    def keyPressEvent(self, event):
        if self._quiz_shortcuts_active():
            key = event.key()
            index = _SHORTCUT_ANSWER_INDEX.get(key)
            if self._in_question and index is not None:
                button = self.answer_buttons[index]
                if button.isEnabled():
                    button.setChecked(True)
                    button.setFocus()
                    event.accept()
                    return
            if self._in_question and key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                self.next_button.click()
                event.accept()
                return
            if key == Qt.Key.Key_Escape:
                self._show_quiz_setup()
                event.accept()
                return
        super().keyPressEvent(event)
