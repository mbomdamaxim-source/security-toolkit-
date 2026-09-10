"""Bastion desktop application entry point."""
from __future__ import annotations

import sys

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPalette, QPen
from PySide6.QtWidgets import (
    QApplication, QDialog, QHBoxLayout, QLabel, QListWidget, QMainWindow,
    QPushButton, QSizePolicy, QStackedWidget, QToolButton, QVBoxLayout, QWidget,
)

from core import theme
from core.branding import icon_path, is_frozen
from core.connectivity import check_connectivity
from core.context import AppContext
from core.elevation import can_request_administrator_relaunch, is_administrator, request_relaunch_and_exit
from core.status_widgets import StatusBanner
from modules.credentials.ui import CredentialAuditorModule
from modules.firewall.ui import FirewallModule
from modules.scanner.ui import LocalScanModule
from modules.subnet.ui import SubnetModule
from modules.traffic.ui import TrafficModule


class AboutDialog(QDialog):
    """Small product-information window (name, version, purpose, build)."""

    MODULES = (
        "Subnet and VLSM - address planning, route summarisation and verified quizzes",
        "Credential Auditor - password strength science plus the Crypto Lab",
        "Scan Reports - read-only exposure map with CIS-style baseline checks",
        "Firewall Builder - validated rules for Windows, MikroTik and Cisco",
        "Traffic Dashboard - live local traffic observation and anomaly hints",
    )

    def __init__(self, version: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About Bastion")
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.resize(560, 460)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL)
        layout.setSpacing(theme.SPACE_MD)

        title = QLabel(f"{theme.APP_NAME} {version}")
        title.setStyleSheet(f"font-size: {theme.FONT_SIZE_TITLE}pt; font-weight: 700;")
        layout.addWidget(title)
        tagline = QLabel(theme.APP_TAGLINE)
        tagline.setStyleSheet(f"color: {theme.COLOR_ACCENT}; font-weight: 600;")
        layout.addWidget(tagline)

        purpose = QLabel(
            "Bastion helps you understand and improve the security of the Windows "
            "device it runs on. Everything is local: no data is uploaded, no packets "
            "are captured, and no action is taken without your confirmation."
        )
        purpose.setWordWrap(True)
        purpose.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        layout.addWidget(purpose)

        modules_heading = QLabel("Modules")
        modules_heading.setStyleSheet("font-weight: 700;")
        layout.addWidget(modules_heading)
        for entry in self.MODULES:
            line = QLabel("\u2022 " + entry)
            line.setWordWrap(True)
            line.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
            layout.addWidget(line)

        build = QLabel(
            "Running from: " + ("packaged executable" if is_frozen() else "Python source")
        )
        build.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        layout.addWidget(build)
        layout.addStretch(1)

        close_row = QHBoxLayout()
        close_row.addStretch(1)
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        close_row.addWidget(close_button)
        layout.addLayout(close_row)


class ConnectivityWorker(QThread):
    """Probes the internet off the UI thread."""

    result = Signal(object)  # ConnectivityReport

    def run(self):
        try:
            self.result.emit(check_connectivity())
        except Exception as error:  # pragma: no cover - defensive
            from core.connectivity import ConnectivityReport, ProbeResult
            self.result.emit(ConnectivityReport(
                online=False,
                probes=(ProbeResult(host="?", port=0, ok=False, latency_ms=None,
                                    error=str(error)),),
                detail="Offline - probe failed",
            ))


class SidebarToggle(QToolButton):
    """Icon button: shows a cross when the sidebar is open (click to close)
    and a hamburger when it is collapsed (click to open)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._sidebar_open = True
        self.setFixedSize(34, 34)
        self.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._update_accessibility()

    def _update_accessibility(self):
        if self._sidebar_open:
            self.setAccessibleName("Collapse navigation")
            self.setToolTip("Collapse navigation")
        else:
            self.setAccessibleName("Expand navigation")
            self.setToolTip("Expand navigation")

    def set_sidebar_open(self, open_state: bool) -> None:
        self._sidebar_open = open_state
        self._update_accessibility()
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(theme.COLOR_TEXT_SECONDARY), 2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        width, height = self.width(), self.height()
        if self._sidebar_open:
            # cross - indicates the sidebar can be closed
            painter.drawLine(int(width * 0.3), int(height * 0.3), int(width * 0.7), int(height * 0.7))
            painter.drawLine(int(width * 0.7), int(height * 0.3), int(width * 0.3), int(height * 0.7))
        else:
            # hamburger - three aligned rows
            for fraction in (0.35, 0.5, 0.65):
                y = int(height * fraction)
                painter.drawLine(int(width * 0.22), y, int(width * 0.78), y)
        painter.end()


class MainWindow(QMainWindow):
    def __init__(self, context: AppContext):
        super().__init__()
        self.context = context
        self.setWindowTitle(f"{theme.APP_NAME} {context.app_version} — {theme.APP_TAGLINE}")
        self.resize(1120, 720)
        icon_file = icon_path()
        if icon_file.exists():
            self.setWindowIcon(QIcon(str(icon_file)))
        self._build_ui()

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(theme.SPACE_LG, theme.SPACE_LG, theme.SPACE_LG, theme.SPACE_LG)
        root_layout.setSpacing(theme.SPACE_MD)
        root_layout.addWidget(self._create_elevation_banner())

        header_layout = QHBoxLayout()
        header_layout.setSpacing(theme.SPACE_MD)
        self.sidebar_toggle = SidebarToggle()
        self.sidebar_toggle.clicked.connect(self._toggle_sidebar)
        header_layout.addWidget(self.sidebar_toggle)
        self.internet_label = QLabel("Internet: checking…")
        self.internet_label.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        self.internet_label.setToolTip("Click Check to probe public endpoints again.")
        header_layout.addWidget(self.internet_label)
        self.internet_button = QPushButton("Check")
        self.internet_button.setAccessibleName("Check internet access")
        self.internet_button.setFixedHeight(24)
        self.internet_button.clicked.connect(self._check_internet)
        header_layout.addWidget(self.internet_button)
        self.about_button = QPushButton("About")
        self.about_button.setAccessibleName("About Bastion")
        self.about_button.setFixedHeight(24)
        self.about_button.clicked.connect(self._show_about)
        header_layout.addWidget(self.about_button)
        header_layout.addStretch(1)
        root_layout.addLayout(header_layout)
        self._connectivity_worker = None
        self._connectivity_timer = QTimer(self)
        self._connectivity_timer.setInterval(30_000)
        self._connectivity_timer.timeout.connect(self._check_internet)
        self._connectivity_timer.start()

        content_layout = QHBoxLayout()
        content_layout.setSpacing(theme.SPACE_MD)
        self.navigation = QListWidget()
        self.navigation.setFixedWidth(210)
        self.navigation.setAccessibleName("Security module navigation")
        self.navigation.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        self.stack = QStackedWidget()
        self.stack.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        modules = [
            ("Subnet and VLSM", SubnetModule(self.context)),
            ("Credential Auditor", CredentialAuditorModule(self.context)),
            ("Scan Reports", LocalScanModule(self.context)),
            ("Firewall Builder", FirewallModule(self.context)),
            ("Traffic Dashboard", TrafficModule(self.context)),
        ]
        for label, module in modules:
            self.navigation.addItem(label)
            self.stack.addWidget(module)
        self.navigation.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.navigation.setCurrentRow(0)

        content_layout.addWidget(self.navigation)
        content_layout.addWidget(self.stack, 1)
        root_layout.addLayout(content_layout, 1)
        self.setCentralWidget(root)

    def _create_elevation_banner(self) -> StatusBanner:
        if self.context.is_admin:
            return StatusBanner(
                "Administrator privileges are active. System security actions are available.",
                "success",
            )
        banner = StatusBanner(
            "Administrator privileges are not active. Actions that change system security settings are unavailable.",
            "warning",
        )
        banner.add_action(
            "Restart with administrator privileges",
            self._restart_as_administrator,
            enabled=can_request_administrator_relaunch(),
        )
        return banner

    def _show_about(self):
        dialog = AboutDialog(self.context.app_version, self)
        dialog.exec()
        dialog.deleteLater()

    def _check_internet(self):
        if self._connectivity_worker is not None and self._connectivity_worker.isRunning():
            return
        self.internet_label.setText("Internet: checking…")
        self.internet_label.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
        self._connectivity_worker = ConnectivityWorker(parent=self)
        self._connectivity_worker.result.connect(self._on_connectivity)
        self._connectivity_worker.start()

    def _on_connectivity(self, report):
        if report.online:
            latency = report.latency_ms
            suffix = f" ({latency:.0f} ms)" if latency is not None else ""
            self.internet_label.setText(f"Internet: Online{suffix}")
            self.internet_label.setStyleSheet(f"color: {theme.COLOR_SUCCESS}; font-weight: 600;")
        else:
            self.internet_label.setText("Internet: Offline")
            self.internet_label.setStyleSheet(f"color: {theme.COLOR_DANGER}; font-weight: 600;")
        self.internet_label.setToolTip(report.detail)

    def _toggle_sidebar(self) -> None:
        collapsed = self.navigation.isHidden()
        self.navigation.setVisible(collapsed)
        self.sidebar_toggle.set_sidebar_open(collapsed)

    def _restart_as_administrator(self) -> None:
        if request_relaunch_and_exit():
            QApplication.quit()


def _create_dark_palette() -> QPalette:
    """Dark application palette so native Qt subcontrols (spin-box arrows,
    radio indicators, scroll-bar buttons, menu glyphs) draw dark instead of
    falling back to the light Windows default palette."""
    colors = {
        QPalette.ColorRole.Window: theme.COLOR_BACKGROUND,
        QPalette.ColorRole.WindowText: theme.COLOR_TEXT_PRIMARY,
        QPalette.ColorRole.Base: theme.COLOR_SURFACE,
        QPalette.ColorRole.AlternateBase: theme.COLOR_BACKGROUND,
        QPalette.ColorRole.Text: theme.COLOR_TEXT_PRIMARY,
        QPalette.ColorRole.Button: theme.COLOR_SURFACE_RAISED,
        QPalette.ColorRole.ButtonText: theme.COLOR_TEXT_PRIMARY,
        QPalette.ColorRole.BrightText: theme.COLOR_DANGER,
        QPalette.ColorRole.Highlight: theme.COLOR_ACCENT,
        QPalette.ColorRole.HighlightedText: theme.COLOR_BACKGROUND,
        QPalette.ColorRole.ToolTipBase: theme.COLOR_SURFACE_RAISED,
        QPalette.ColorRole.ToolTipText: theme.COLOR_TEXT_PRIMARY,
        QPalette.ColorRole.PlaceholderText: theme.COLOR_TEXT_SECONDARY,
        QPalette.ColorRole.Link: theme.COLOR_ACCENT,
    }
    palette = QPalette()
    for role, color in colors.items():
        palette.setColor(role, QColor(color))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(theme.COLOR_TEXT_SECONDARY))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(theme.COLOR_TEXT_SECONDARY))
    return palette


def create_application(argv: list[str] | None = None) -> QApplication:
    application = QApplication(argv if argv is not None else sys.argv)
    application.setApplicationName(theme.APP_NAME)
    application.setApplicationDisplayName(theme.APP_NAME)
    icon_file = icon_path()
    if icon_file.exists():
        application.setWindowIcon(QIcon(str(icon_file)))
    application.setPalette(_create_dark_palette())
    application.setStyleSheet(theme.APPLICATION_STYLESHEET)
    return application


def main() -> int:
    application = create_application()
    context = AppContext(is_admin=is_administrator(), app_version=theme.APP_VERSION)
    window = MainWindow(context)
    window.show()
    return application.exec()


if __name__ == "__main__":
    sys.exit(main())
