"""Reusable, content-sized status components shared by every module."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from core import theme


_STATUS_COLORS = {
    "info": theme.COLOR_INFO,
    "success": theme.COLOR_SUCCESS,
    "warning": theme.COLOR_WARNING,
    "danger": theme.COLOR_DANGER,
}


class StatusBanner(QFrame):
    """A concise status message with an optional, explicit action."""

    def __init__(self, message: str, status: str = "info", parent: QWidget | None = None):
        super().__init__(parent)
        if status not in _STATUS_COLORS:
            raise ValueError("Unsupported banner status.")
        self.setObjectName("statusBanner")
        self.setFrameShape(QFrame.Shape.NoFrame)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(theme.SPACE_MD, theme.SPACE_SM, theme.SPACE_MD, theme.SPACE_SM)
        self._layout.setSpacing(theme.SPACE_SM)
        self.message_label = QLabel(message)
        self.message_label.setWordWrap(True)
        self.message_label.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        self._layout.addWidget(self.message_label, 1)
        self.set_status(status)

    def set_status(self, status: str) -> None:
        if status not in _STATUS_COLORS:
            raise ValueError("Unsupported banner status.")
        self.setStyleSheet(
            f"#statusBanner {{ background-color: {theme.COLOR_SURFACE_RAISED}; "
            f"border-left: {theme.SPACE_XS}px solid {_STATUS_COLORS[status]}; "
            f"border-radius: {theme.RADIUS_SM}px; }}"
        )

    def add_action(self, label: str, callback, enabled: bool = True) -> QPushButton:
        button = QPushButton(label, self)
        button.setEnabled(enabled)
        button.clicked.connect(callback)
        self._layout.addWidget(button, 0, Qt.AlignmentFlag.AlignVCenter)
        return button


class SeverityBadge(QLabel):
    """A compact severity label for findings in later modules."""

    _COLORS = {
        "info": theme.COLOR_INFO,
        "low": theme.COLOR_SUCCESS,
        "medium": theme.COLOR_WARNING,
        "high": theme.COLOR_DANGER,
        "critical": theme.COLOR_DANGER,
    }

    def __init__(self, severity: str, parent: QWidget | None = None):
        normalized = severity.strip().lower()
        if normalized not in self._COLORS:
            raise ValueError("Unsupported severity.")
        super().__init__(normalized.capitalize(), parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            f"background-color: {self._COLORS[normalized]}; color: {theme.COLOR_BACKGROUND}; "
            f"border-radius: {theme.RADIUS_SM}px; padding: {theme.SPACE_XS}px {theme.SPACE_SM}px;"
        )


class EmptyState(QWidget):
    """A centered explanation for a view that has no data yet."""

    def __init__(self, title: str, description: str, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL)
        layout.setSpacing(theme.SPACE_SM)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label = QLabel(title)
        title_label.setStyleSheet(f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 600;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description_label = QLabel(description)
        description_label.setWordWrap(True)
        description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description_label.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        layout.addWidget(title_label)
        layout.addWidget(description_label)


class ModuleHeader(QWidget):
    """Consistent title and explanatory text at the start of each module."""

    def __init__(self, title: str, description: str, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(theme.SPACE_XS)
        title_label = QLabel(title)
        title_label.setStyleSheet(f"font-size: {theme.FONT_SIZE_TITLE}pt; font-weight: 700;")
        title_label.setWordWrap(True)
        description_label = QLabel(description)
        description_label.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        description_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(description_label)
