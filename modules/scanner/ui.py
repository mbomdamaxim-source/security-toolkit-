"""Native PySide6 interface for Scan Reports.

Runs the read-only PowerShell scan on a background thread so the interface
stays responsive, then renders findings, tables, drift and firewall state.
The last scan payload and the user's allowlist are stored locally under
%LOCALAPPDATA%\\Bastion - nothing sensitive leaves this device.
"""
from __future__ import annotations

from pathlib import Path
import json

from PySide6.QtCore import QStandardPaths, Qt, QThread, Signal
from PySide6.QtGui import QBrush, QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel,
    QProgressBar, QPushButton, QScrollArea, QTableWidget, QTableWidgetItem,
    QToolButton, QVBoxLayout, QWidget,
)

from core import theme
from core.context import AppContext
from core.status_widgets import ModuleHeader, SeverityBadge
from modules.scanner.logic import (
    PORT_SERVICES,
    UDP_PORT_SERVICES,
    ScanError,
    ScanReport,
    append_hardening_score,
    assess_baseline,
    baseline_summary,
    build_report,
    diff_reports,
    exposure_summary,
    load_allowlist,
    load_hardening_history,
    run_local_scan,
)
from modules.scanner.report import export_scan_docx

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEVERITY_COLORS = {
    "info": theme.COLOR_INFO,
    "low": theme.COLOR_SUCCESS,
    "medium": theme.COLOR_WARNING,
    "high": theme.COLOR_DANGER,
    "critical": theme.COLOR_DANGER,
}
_FINDING_BORDER = {
    "info": theme.COLOR_INFO,
    "low": theme.COLOR_SUCCESS,
    "medium": theme.COLOR_WARNING,
    "high": theme.COLOR_DANGER,
    "critical": theme.COLOR_DANGER,
}
_CARD_STYLE = (
    f"background-color: {theme.COLOR_SURFACE};"
    f" border: 1px solid {theme.COLOR_BORDER};"
    f" border-radius: {theme.RADIUS_MD}px;"
    f" padding: {theme.SPACE_MD}px;"
)
_SECTION_STYLE = f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 700; margin-top: {theme.SPACE_LG}px;"
_MUTED = f"color: {theme.COLOR_TEXT_SECONDARY};"


def _app_data() -> Path:
    directory = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppLocalDataLocation)
    return Path(directory) if directory else Path.home()


class ScanWorker(QThread):
    """Runs the PowerShell scan off the UI thread."""

    succeeded = Signal(object)  # raw payload dict
    failed = Signal(str)

    def __init__(self, powershell: str = "powershell.exe", parent=None):
        super().__init__(parent)
        self._powershell = powershell

    def run(self):
        try:
            payload = run_local_scan(powershell=self._powershell, timeout=150)
            self.succeeded.emit(payload)
        except ScanError as error:
            self.failed.emit(str(error))


class DonutChart(QWidget):
    """A small severity donut drawn with QPainter."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._segments = []      # [(fraction, color-hex), ...]
        self._center_text = ""
        self.setFixedSize(150, 150)

    def set_data(self, segments, center_text: str):
        self._segments = [(fraction, QColor(color)) for fraction, color in segments]
        self._center_text = center_text
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(12, 12, -12, -12)
        pen = QPen()
        pen.setWidth(22)
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        total = sum(fraction for fraction, _ in self._segments) or 1
        start_angle = 90 * 16
        for fraction, color in self._segments:
            if fraction <= 0:
                continue
            span = int(round(-fraction / total * 360 * 16))
            pen.setColor(color)
            painter.setPen(pen)
            painter.drawArc(rect, start_angle, span)
            start_angle += span
        # centre text
        painter.setPen(QPen(QColor(theme.COLOR_TEXT_PRIMARY)))
        font = painter.font()
        font.setPointSize(15)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, self._center_text)
        painter.end()


class LocalScanModule(QWidget):
    """Scan Reports: local exposure map of this Windows device."""

    def __init__(self, context: AppContext):
        super().__init__()
        self.context = context
        self.data_directory = _app_data()
        self.data_directory.mkdir(parents=True, exist_ok=True)
        self.allowlist_path = self.data_directory / "scan_allowlist.json"
        self.last_scan_path = self.data_directory / "last_scan.json"
        self.allowlist = load_allowlist(self.allowlist_path)
        self.worker = None
        self.report: ScanReport | None = None
        self._hardening_history: list = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL)
        layout.setSpacing(theme.SPACE_MD)
        layout.addWidget(ModuleHeader(
            "Scan Reports",
            "Map this Windows device's open ports, running services, and missing patches.",
        ))

        controls = QHBoxLayout()
        controls.setSpacing(theme.SPACE_SM)
        self.scan_button = QPushButton("Run local scan")
        self.scan_button.setAccessibleName("Run local scan")
        self.scan_button.setAccessibleDescription(
            "Queries this device with read-only PowerShell cmdlets. Nothing leaves the machine."
        )
        self.scan_button.clicked.connect(self.start_scan)
        self.export_button = QPushButton("Export Word Report")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_report)
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        controls.addWidget(self.scan_button)
        controls.addWidget(self.export_button)
        controls.addWidget(self.status_label, 1)
        layout.addLayout(controls)

        explainer_button = QToolButton()
        explainer_button.setText("Ports 101 - how to read this report")
        explainer_button.setCheckable(True)
        explainer_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        explainer_button.toggled.connect(lambda on: self._explainer.setVisible(on))
        layout.addWidget(explainer_button, alignment=Qt.AlignmentFlag.AlignLeft)
        self._explainer = QLabel(
            "A listening port is a door a program opened. A port bound to 127.0.0.1 only accepts "
            "connections from this device; a port bound to 0.0.0.0 accepts connections from the "
            "whole network - if the firewall lets them through. Exposure is therefore two facts: "
            "who listens (Get-NetTCPConnection) and what the firewall allows (Get-NetFirewallRule). "
            "A service that listens on 0.0.0.0 but is blocked by the firewall is reported as info, "
            "not as a hole."
        )
        self._explainer.setWordWrap(True)
        self._explainer.setStyleSheet(_MUTED)
        self._explainer.setVisible(False)
        layout.addWidget(self._explainer)

        self.results_host = QWidget()
        self.results_layout = QVBoxLayout(self.results_host)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_layout.setSpacing(theme.SPACE_SM)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self.results_host)
        layout.addWidget(scroll, 1)
        self._idle_message()

    # ------------------------------------------------------------- scanning
    def start_scan(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.scan_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.status_label.setText("Scanning this device (read-only PowerShell queries)...")
        self.status_label.setStyleSheet(theme.COLOR_TEXT_SECONDARY and f"color: {theme.COLOR_TEXT_SECONDARY};")
        self.worker = ScanWorker(parent=self)
        self.worker.succeeded.connect(self._on_scan_succeeded)
        self.worker.failed.connect(self._on_scan_failed)
        self.worker.finished.connect(lambda: self.scan_button.setEnabled(True))
        self.worker.start()

    def _on_scan_failed(self, message: str):
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {theme.COLOR_DANGER};")

    def _on_scan_succeeded(self, payload: dict):
        self.status_label.setText("Scan complete.")
        self.status_label.setStyleSheet(f"color: {theme.COLOR_SUCCESS};")
        # drift: compare against the previous scan payload, if any
        previous = None
        try:
            previous_payload = json.loads(self.last_scan_path.read_text(encoding="utf-8"))
            previous = build_report(previous_payload, allowlist=self.allowlist)
        except (OSError, ValueError, ScanError):
            previous = None
        self.report = build_report(payload, allowlist=self.allowlist)
        try:
            self.last_scan_path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError:
            pass
        drift = diff_reports(previous, self.report) if previous is not None else ()
        baseline = assess_baseline(self.report)
        summary = baseline_summary(baseline)
        try:
            append_hardening_score(self.data_directory / "hardening_history.json",
                                   summary["hardening"])
        except (ValueError, OSError):
            pass
        self._hardening_history = load_hardening_history(self.data_directory / "hardening_history.json")
        self.export_button.setEnabled(True)
        self._render_report(self.report, drift, baseline, summary)

    # ------------------------------------------------------------- rendering
    def _clear_results(self):
        while self.results_layout.count():
            item = self.results_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _idle_message(self):
        self._clear_results()
        hint = QLabel(
            "No scan has been run yet. Click 'Run local scan' to map the listening ports, "
            "services, firewall state and installed updates of this device."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(_MUTED)
        self.results_layout.addWidget(hint)

    def _section(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet(_SECTION_STYLE)
        return label

    def _collapsible_section(self, title: str, content: QWidget, expanded: bool = False) -> QWidget:
        """A titled, collapsible group so long reports stay compact and the
        user expands only what they need."""
        host = QWidget()
        host_layout = QVBoxLayout(host)
        host_layout.setContentsMargins(0, 0, 0, 0)
        host_layout.setSpacing(theme.SPACE_XS)
        toggle = QToolButton()
        toggle.setText(title)
        toggle.setCheckable(True)
        toggle.setChecked(expanded)
        toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        toggle.setAccessibleName(title)
        toggle.setStyleSheet("font-weight: 700; text-align: left;")
        arrow = "\u25be" if expanded else "\u25b8"
        toggle.setText(f"{arrow} {title}")
        content.setVisible(expanded)

        def on_toggle(checked):
            content.setVisible(checked)
            toggle.setText(("\u25be " if checked else "\u25b8 ") + title)

        toggle.toggled.connect(on_toggle)
        host_layout.addWidget(toggle, alignment=Qt.AlignmentFlag.AlignLeft)
        host_layout.addWidget(content)
        return host

    def _render_report(self, report: ScanReport, drift, baseline=None, baseline_summ=None):
        self._clear_results()

        # firewall banner
        if report.firewall.available:
            if report.firewall.enabled:
                message = (
                    f"Windows Defender Firewall: enabled ({report.firewall.enabled_profile_count} "
                    f"profile(s) active, default inbound: {report.firewall.default_inbound or 'unknown'}, "
                    f"default outbound: {report.firewall.default_outbound or 'unknown'}). A listener is "
                    "only reachable from the network when the firewall allows it."
                )
            else:
                message = (
                    "Windows Defender Firewall is NOT enabled. Every listening port on 0.0.0.0 is "
                    "reachable from the network. Enable the firewall for all profiles."
                )
            self.results_layout.addWidget(self._banner(message, "info" if report.firewall.enabled else "high"))

        # drift
        if drift:
            card = QFrame()
            card.setStyleSheet(_CARD_STYLE)
            card_layout = QVBoxLayout(card)
            title = QLabel("What changed since the last scan")
            title.setStyleSheet("font-weight: 700;")
            card_layout.addWidget(title)
            for change in drift:
                line = QLabel(f"[{change.severity.upper()}] {change.title}\n{change.detail}")
                line.setWordWrap(True)
                line.setStyleSheet(
                    f"color: {_SEVERITY_COLORS.get(change.severity, theme.COLOR_TEXT_PRIMARY)};"
                    if change.kind != "removed_listener" else _MUTED
                )
                card_layout.addWidget(line)
            self.results_layout.addWidget(card)

        # hardening baseline (collapsible, CIS Level-1 style)
        if baseline is not None and baseline_summ is not None:
            baseline_host = QWidget()
            baseline_layout = QVBoxLayout(baseline_host)
            baseline_layout.setContentsMargins(0, 0, 0, 0)
            baseline_layout.setSpacing(theme.SPACE_SM)

            score_card = QFrame()
            score_card.setStyleSheet(_CARD_STYLE)
            score_layout = QVBoxLayout(score_card)
            score_layout.setSpacing(theme.SPACE_XS)
            score_title = QLabel(
                f"Hardening score: {baseline_summ['hardening']}%  "
                f"({baseline_summ['counts']['pass']} pass / "
                f"{baseline_summ['counts']['fail']} fail / "
                f"{baseline_summ['counts']['unknown']} not verifiable)"
            )
            score_title.setStyleSheet("font-weight: 700;")
            score_layout.addWidget(score_title)
            score_bar = QProgressBar()
            score_bar.setRange(0, 100)
            score_bar.setValue(baseline_summ["hardening"])
            score_bar.setTextVisible(False)
            score_bar.setFixedHeight(8)
            score_color = (
                theme.COLOR_DANGER if baseline_summ["hardening"] < 50
                else theme.COLOR_WARNING if baseline_summ["hardening"] < 80
                else theme.COLOR_SUCCESS
            )
            score_bar.setStyleSheet(
                f"QProgressBar {{ background-color: {theme.COLOR_SURFACE_RAISED};"
                f" border: none; border-radius: 4px; }}"
                f"QProgressBar::chunk {{ background-color: {score_color};"
                f" border-radius: 4px; }}"
            )
            score_layout.addWidget(score_bar)
            if len(self._hardening_history) >= 2:
                trend = " -> ".join(str(entry["hardening"]) for entry in self._hardening_history[-5:])
                trend_label = QLabel(f"History (last scans): {trend}")
                trend_label.setStyleSheet(_MUTED)
                score_layout.addWidget(trend_label)
            baseline_layout.addWidget(score_card)

            for result in baseline.values():
                row = QFrame()
                status_color = (
                    theme.COLOR_SUCCESS if result["status"] == "pass"
                    else theme.COLOR_DANGER if result["status"] == "fail"
                    else theme.COLOR_TEXT_SECONDARY
                )
                row.setStyleSheet(
                    f"background-color: {theme.COLOR_SURFACE};"
                    f" border: 1px solid {theme.COLOR_BORDER};"
                    f" border-left: 4px solid {status_color};"
                    f" border-radius: {theme.RADIUS_SM}px;"
                )
                row_layout = QVBoxLayout(row)
                head = QHBoxLayout()
                title = QLabel(result["title"])
                title.setStyleSheet("font-weight: 600;")
                badge = SeverityBadge("info")
                badge.setText(result["status"].upper())
                badge.setStyleSheet(
                    f"background-color: {status_color}; color: {theme.COLOR_BACKGROUND};"
                    f" border-radius: {theme.RADIUS_SM}px; padding: {theme.SPACE_XS}px {theme.SPACE_SM}px;"
                )
                head.addWidget(title, 1)
                head.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
                row_layout.addLayout(head)
                note = QLabel(result["note"])
                note.setWordWrap(True)
                note.setStyleSheet(_MUTED)
                row_layout.addWidget(note)
                why = QLabel("Why: " + result["why"])
                why.setWordWrap(True)
                why.setStyleSheet(_MUTED)
                row_layout.addWidget(why)
                baseline_layout.addWidget(row)
            baseline_layout.addStretch(1)
            self.results_layout.addWidget(
                self._collapsible_section("Hardening baseline (CIS Level-1 style)", baseline_host, expanded=True)
            )

        # summary cards
        grid = QGridLayout()
        grid.setHorizontalSpacing(theme.SPACE_MD)
        grid.setVerticalSpacing(theme.SPACE_MD)
        summaries = (
            ("Listening ports", str(len(report.ports))),
            ("Services queried", str(len(report.services))),
            ("Hotfixes installed", str(len(report.patches))),
            ("Findings", str(len(report.findings))),
        )
        for index, (label, value) in enumerate(summaries):
            grid.addWidget(self._summary_card(label, value), 0, index)
        grid_widget = QWidget()
        grid_widget.setLayout(grid)
        self.results_layout.addWidget(grid_widget)

        # posture + exposure score (mirrors the browser preview)
        summary = exposure_summary(report)
        posture_row = QHBoxLayout()
        posture_row.setSpacing(theme.SPACE_LG)
        donut = DonutChart()
        segments = [
            (summary["counts"][sev], _SEVERITY_COLORS.get(sev, theme.COLOR_BORDER))
            for sev in ("critical", "high", "medium", "low", "info")
            if summary["counts"][sev] > 0
        ]
        donut.set_data(segments, str(sum(report.findings)))
        donut.setAccessibleName(f"Findings by severity: {summary['counts']}")
        posture_row.addWidget(donut, 0, Qt.AlignmentFlag.AlignTop)

        posture_card = QFrame()
        posture_card.setStyleSheet(_CARD_STYLE)
        posture_card_layout = QVBoxLayout(posture_card)
        posture_card_layout.setSpacing(theme.SPACE_SM)
        posture_label = QLabel("Security posture")
        posture_label.setStyleSheet(_MUTED)
        posture_card_layout.addWidget(posture_label)
        posture_value = QLabel(summary["posture"])
        posture_value.setStyleSheet(
            f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 800;"
            f" color: {_SEVERITY_COLORS.get(summary['tone'], theme.COLOR_TEXT_PRIMARY)};"
        )
        posture_value.setWordWrap(True)
        posture_card_layout.addWidget(posture_value)
        score_text = QLabel(f"Exposure score: {summary['score']}/100")
        score_text.setStyleSheet(_MUTED)
        posture_card_layout.addWidget(score_text)
        score_bar = QProgressBar()
        score_bar.setRange(0, 100)
        score_bar.setValue(summary["score"])
        score_bar.setTextVisible(False)
        score_bar.setFixedHeight(10)
        score_color = (
            theme.COLOR_DANGER if summary["score"] < 40
            else theme.COLOR_WARNING if summary["score"] < 70
            else theme.COLOR_SUCCESS
        )
        score_bar.setStyleSheet(
            f"QProgressBar {{ background-color: {theme.COLOR_SURFACE_RAISED};"
            f" border: none; border-radius: 5px; }}"
            f"QProgressBar::chunk {{ background-color: {score_color};"
            f" border-radius: 5px; }}"
        )
        score_bar.setAccessibleName(f"Exposure score {summary['score']} out of 100")
        posture_card_layout.addWidget(score_bar)
        posture_row.addWidget(posture_card, 1)

        # legend
        legend_card = QFrame()
        legend_card.setStyleSheet(_CARD_STYLE)
        legend_layout = QVBoxLayout(legend_card)
        legend_layout.setSpacing(theme.SPACE_XS)
        for severity in ("critical", "high", "medium", "low", "info"):
            count = summary["counts"].get(severity, 0)
            if count == 0:
                continue
            line = QHBoxLayout()
            line.setSpacing(theme.SPACE_SM)
            dot = QLabel("  ")
            dot.setStyleSheet(
                f"background-color: {_SEVERITY_COLORS.get(severity, theme.COLOR_BORDER)};"
                f" border-radius: {theme.RADIUS_SM}px; padding: 4px;"
            )
            text = QLabel(f"{severity} ({count})")
            line.addWidget(dot, 0)
            line.addWidget(text, 1)
            legend_layout.addLayout(line)
        legend_layout.addStretch(1)
        posture_row.addWidget(legend_card, 0, Qt.AlignmentFlag.AlignTop)
        posture_widget = QWidget()
        posture_widget.setLayout(posture_row)
        self.results_layout.addWidget(posture_widget)

        # findings (collapsible)
        findings_host = QWidget()
        findings_layout = QVBoxLayout(findings_host)
        findings_layout.setContentsMargins(0, 0, 0, 0)
        findings_layout.setSpacing(theme.SPACE_SM)
        if not report.findings:
            findings_layout.addWidget(QLabel("No findings - the device looks tidy."))
        for finding in sorted(
            report.findings,
            key=lambda f: (_SEVERITY_ORDER.index(f.severity) if f.severity in _SEVERITY_ORDER else 9, f.title),
        ):
            findings_layout.addWidget(self._finding_card(finding))
        findings_layout.addStretch(1)
        self.results_layout.addWidget(self._collapsible_section("Findings", findings_host, expanded=True))

        # ports tables
        tcp = [p for p in report.ports if p.protocol.upper() == "TCP"]
        udp = [p for p in report.ports if p.protocol.upper() == "UDP"]
        if tcp:
            self.results_layout.addWidget(self._section("Listening ports (TCP)"))
            self.results_layout.addWidget(self._port_table(tcp))
        if udp:
            self.results_layout.addWidget(self._section("Listening ports (UDP)"))
            self.results_layout.addWidget(self._port_table(udp))

        # connections
        if report.connections:
            self.results_layout.addWidget(self._section("Active connections"))
            note = QLabel(
                "A connection to a public address on a non-standard port, or from a user-writable "
                "folder (AppData/Temp/Downloads), is flagged."
            )
            note.setWordWrap(True)
            note.setStyleSheet(_MUTED)
            self.results_layout.addWidget(note)
            self.results_layout.addWidget(self._connection_table(report.connections))

        # services
        if report.services:
            self.results_layout.addWidget(self._section("Services"))
            self.results_layout.addWidget(self._service_table(report.services))

        # patches
        if report.patches:
            self.results_layout.addWidget(self._section("Installed hotfixes"))
            self.results_layout.addWidget(self._patch_table(report.patches))

        footer = QLabel(
            f"Scanned at {report.scanned_at}. The previous scan's report is stored locally and used "
            "for drift detection. Allowlisted (expected) listeners are excluded from findings."
        )
        footer.setWordWrap(True)
        footer.setStyleSheet(_MUTED)
        self.results_layout.addWidget(footer)
        self.results_layout.addStretch(1)

    def _banner(self, message: str, status: str) -> QFrame:
        frame = QFrame()
        color = _FINDING_BORDER.get(status, theme.COLOR_INFO)
        frame.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE_RAISED};"
            f" border-left: {theme.SPACE_XS}px solid {color};"
            f" border-radius: {theme.RADIUS_SM}px;"
        )
        row = QHBoxLayout(frame)
        label = QLabel(message)
        label.setWordWrap(True)
        row.addWidget(label, 1)
        return frame

    def _summary_card(self, label: str, value: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet(_CARD_STYLE)
        layout = QVBoxLayout(card)
        layout.setSpacing(2)
        number = QLabel(value)
        number.setStyleSheet("font-size: 20pt; font-weight: 700;")
        text = QLabel(label)
        text.setStyleSheet(_MUTED)
        layout.addWidget(number)
        layout.addWidget(text)
        return card

    def _finding_card(self, finding) -> QFrame:
        card = QFrame()
        color = _FINDING_BORDER.get(finding.severity, theme.COLOR_BORDER)
        card.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE};"
            f" border: 1px solid {theme.COLOR_BORDER};"
            f" border-left: 4px solid {color};"
            f" border-radius: {theme.RADIUS_SM}px;"
        )
        layout = QVBoxLayout(card)
        head = QHBoxLayout()
        title = QLabel(finding.title)
        title.setWordWrap(True)
        title.setStyleSheet("font-weight: 600;")
        badge = SeverityBadge(finding.severity)
        head.addWidget(title, 1)
        head.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(head)
        detail = QLabel(finding.detail)
        detail.setWordWrap(True)
        detail.setStyleSheet(_MUTED)
        layout.addWidget(detail)
        return card

    # ------------------------------------------------------------- tables
    def _make_table(self, headers: tuple[str, ...], rows: int) -> QTableWidget:
        table = QTableWidget(rows, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    @staticmethod
    def _item(text: str, color: str | None = None) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        if color:
            item.setForeground(QBrush(QColor(color)))
        return item

    def _port_table(self, records) -> QTableWidget:
        table = self._make_table(("Port", "Service / process", "Address", "Firewall truth"), len(records))
        for row, record in enumerate(records):
            service = PORT_SERVICES if record.protocol.upper() == "TCP" else UDP_PORT_SERVICES
            label = service.get(record.local_port, "")
            service_text = f"{label} ({record.process_name or record.process_id})" if label else (record.process_name or str(record.process_id))
            allowlisted = (record.protocol.upper(), record.local_port) in self.allowlist
            if record.local_address in ("0.0.0.0", "::"):
                if allowlisted:
                    truth, color = "Expected (allowlisted)", theme.COLOR_SUCCESS
                elif record.allowed is True:
                    truth, color = "Exposed - firewall allows", theme.COLOR_DANGER
                elif record.allowed is False:
                    truth, color = "Blocked by firewall", theme.COLOR_INFO
                else:
                    truth, color = "Firewall unknown", theme.COLOR_TEXT_SECONDARY
            elif record.local_address in ("127.0.0.1", "::1"):
                truth, color = "Loopback only", theme.COLOR_INFO
            else:
                truth, color = record.local_address, theme.COLOR_TEXT_SECONDARY
            table.setItem(row, 0, self._item(str(record.local_port), theme.COLOR_TEXT_PRIMARY))
            table.setItem(row, 1, self._item(service_text))
            table.setItem(row, 2, self._item(record.local_address))
            table.setItem(row, 3, self._item(truth, color))
        return table

    def _connection_table(self, connections) -> QTableWidget:
        table = self._make_table(("Process", "Remote address", "Remote port", "Flag"), len(connections))
        for row, connection in enumerate(connections):
            from modules.scanner.logic import is_suspicious_path
            suspicious = is_suspicious_path(connection.process_path)
            standard = connection.remote_port in {
                21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 8080, 8443,
            }
            if suspicious and not standard:
                flag, flag_color = "Review - suspicious path + unusual port", theme.COLOR_DANGER
            elif suspicious:
                flag, flag_color = "Review - runs from user-writable folder", theme.COLOR_WARNING
            elif not standard:
                flag, flag_color = "Non-standard port", theme.COLOR_TEXT_SECONDARY
            else:
                flag, flag_color = "Normal", theme.COLOR_SUCCESS
            table.setItem(row, 0, self._item(f"{connection.process_name or connection.process_id}"))
            table.setItem(row, 1, self._item(f"{connection.remote_address}:{connection.remote_port}"))
            table.setItem(row, 2, self._item(str(connection.remote_port)))
            table.setItem(row, 3, self._item(flag, flag_color))
        return table

    def _service_table(self, services) -> QTableWidget:
        table = self._make_table(("Name", "Display name", "Status", "Start type"), len(services))
        for row, service in enumerate(services):
            running = service.status.casefold() == "running"
            table.setItem(row, 0, self._item(service.name))
            table.setItem(row, 1, self._item(service.display_name))
            table.setItem(row, 2, self._item(
                service.status,
                theme.COLOR_SUCCESS if running else theme.COLOR_DANGER,
            ))
            table.setItem(row, 3, self._item(service.start_type))
        return table

    def _patch_table(self, patches) -> QTableWidget:
        table = self._make_table(("Hotfix ID", "Description", "Installed on"), len(patches))
        for row, patch in enumerate(patches):
            table.setItem(row, 0, self._item(patch.hotfix_id))
            table.setItem(row, 1, self._item(patch.description))
            table.setItem(row, 2, self._item(patch.installed_on))
        return table

    # ------------------------------------------------------------- actions
    def export_report(self):
        if self.report is None:
            return
        destination, _ = QFileDialog.getSaveFileName(
            self, "Export Scan Word Report", "Scan_Report.docx", "Word documents (*.docx)"
        )
        if not destination:
            return
        if not destination.lower().endswith(".docx"):
            destination += ".docx"
        try:
            path = export_scan_docx(destination, self.report)
        except (OSError, ValueError) as error:
            self.status_label.setText(f"Could not export the Word report: {error}")
            self.status_label.setStyleSheet(f"color: {theme.COLOR_DANGER};")
            return
        self.status_label.setText(f"Word report exported to {path}.")
        self.status_label.setStyleSheet(f"color: {theme.COLOR_SUCCESS};")

    # A future enhancement will add per-row "mark as expected" checkboxes;
    # the allowlist API is already wired through build_report(... allowlist=...).
