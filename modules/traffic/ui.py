"""Native PySide6 Traffic Dashboard: live, read-only observation of this
device's network activity.

The dashboard samples adapter byte counters and established connections
every few seconds (PowerShell cmdlets on a background thread), shows moving
throughput, colour-codes what changed between samples, flags new processes,
and runs a light beaconing check over a rolling window of snapshots.
"""
from __future__ import annotations

from collections import deque
from pathlib import Path

from PySide6.QtCore import QStandardPaths, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QLabel, QProgressBar, QPushButton, QScrollArea, QTableWidget,
    QTableWidgetItem, QToolButton, QVBoxLayout, QWidget,
)

from core import theme
from core.context import AppContext
from core.status_widgets import ModuleHeader, SeverityBadge
from modules.traffic.logic import (
    Anomaly,
    TrafficError,
    analyze_connections,
    beacon_anomalies,
    compute_rates,
    detect_beacons,
    diff_connections,
    format_bits_per_second,
    new_process_alerts,
    parse_snapshot,
    run_snapshot,
    summarize,
)
from modules.traffic.report import export_snapshot_csv

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
_SECTION_STYLE = f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 700;"
_MUTED = f"color: {theme.COLOR_TEXT_SECONDARY};"
_NEW_COLOR = theme.COLOR_SUCCESS
_CLOSED_COLOR = theme.COLOR_TEXT_SECONDARY


def _app_data() -> Path:
    directory = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppLocalDataLocation)
    return Path(directory) if directory else Path.home()


class SnapshotWorker(QThread):
    """Runs one PowerShell snapshot off the UI thread."""

    succeeded = Signal(object)   # raw payload dict
    failed = Signal(str)

    def __init__(self, powershell: str = "powershell.exe", parent=None):
        super().__init__(parent)
        self._powershell = powershell

    def run(self):
        try:
            payload = run_snapshot(powershell=self._powershell, timeout=45)
            self.succeeded.emit(payload)
        except TrafficError as error:
            self.failed.emit(str(error))


class ResolveWorker(QThread):
    """Resolves a batch of IP addresses to hostnames off the UI thread."""

    resolved = Signal(object)  # dict address -> hostname (or None on failure)

    def __init__(self, addresses, parent=None):
        super().__init__(parent)
        self._addresses = addresses

    def run(self):
        import socket
        mapping = {}
        for address in self._addresses:
            try:
                mapping[address] = socket.gethostbyaddr(address)[0]
            except OSError:
                mapping[address] = None
        self.resolved.emit(mapping)


class TrafficModule(QWidget):
    """Live local traffic dashboard."""

    def __init__(self, context: AppContext):
        super().__init__()
        self.context = context
        self.worker: SnapshotWorker | None = None
        self.previous = None
        self._sampling = False
        self._snapshot_window: deque = deque(maxlen=12)
        self._changes_shown: list = []      # last shown change lines
        self._last_connection_keys = set()
        self._hostnames: dict = {}           # address -> resolved hostname
        self._resolve_worker = None

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._sample_once)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL)
        layout.setSpacing(theme.SPACE_MD)
        layout.addWidget(ModuleHeader(
            "Traffic Dashboard",
            "Observe this device's network activity and potential anomalies.",
        ))

        note = QLabel(
            "<b>Read-only:</b> the dashboard samples adapter byte counters and established "
            "connections with PowerShell cmdlets. Nothing is captured, stored or sent anywhere - "
            "and no packet data is collected."
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
        self.start_button = QPushButton("Start monitoring")
        self.start_button.clicked.connect(self._toggle_monitoring)
        controls.addWidget(self.start_button)
        controls.addWidget(QLabel("Interval"))
        self.interval_combo = QComboBox()
        self.interval_combo.addItem("3 seconds", 3000)
        self.interval_combo.addItem("5 seconds", 5000)
        self.interval_combo.addItem("10 seconds", 10000)
        self.interval_combo.currentIndexChanged.connect(self._interval_changed)
        controls.addWidget(self.interval_combo)
        self.export_button = QPushButton("Export CSV")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export_csv)
        controls.addWidget(self.export_button)
        self.resolve_checkbox = QCheckBox("Resolve hostnames")
        self.resolve_checkbox.setAccessibleName("Resolve hostnames")
        self.resolve_checkbox.setAccessibleDescription(
            "Reverse-resolve remote addresses to host names. Uses the network, so it is "
            "disabled when the device is offline. Off by default."
        )
        self.resolve_checkbox.setChecked(False)
        self.resolve_checkbox.toggled.connect(self._on_resolve_toggled)
        controls.addWidget(self.resolve_checkbox)
        self.status_label = QLabel("Monitoring is stopped.")
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet(_MUTED)
        controls.addWidget(self.status_label, 1)
        layout.addLayout(controls)

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

    # ------------------------------------------------------------- lifecycle
    def hideEvent(self, event):
        self._stop_monitoring()
        super().hideEvent(event)

    def closeEvent(self, event):
        self._stop_monitoring()
        super().closeEvent(event)

    # ------------------------------------------------------------- controls
    def _on_resolve_toggled(self, enabled):
        if not enabled:
            return
        if self._resolve_worker is not None and self._resolve_worker.isRunning():
            return
        # Resolve any currently visible public addresses that are not cached.
        addresses = []
        if self._snapshot_window:
            from modules.traffic.logic import is_public_remote
            for connection in self._snapshot_window[-1].connections:
                if is_public_remote(connection.remote_address) and connection.remote_address not in self._hostnames:
                    if connection.remote_address not in addresses:
                        addresses.append(connection.remote_address)
        if not addresses:
            self.status_label.setText("All visible addresses are already resolved (or none are public).")
            self.status_label.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
            return
        self._resolve_worker = ResolveWorker(addresses[:20], parent=self)
        self._resolve_worker.resolved.connect(self._on_resolved)
        self._resolve_worker.start()

    def _on_resolved(self, mapping):
        for address, name in mapping.items():
            if name:
                self._hostnames[address] = name
        self.status_label.setText("")
        self._rerender()

    def _toggle_monitoring(self):
        if self._sampling:
            self._stop_monitoring()
        else:
            self._start_monitoring()

    def _start_monitoring(self):
        if self._sampling:
            return
        self._sampling = True
        self.start_button.setText("Stop monitoring")
        self.status_label.setText("Starting the first sample...")
        self.interval_combo.setEnabled(False)
        self._sample_once()
        self.timer.start(self.interval_combo.currentData())

    def _stop_monitoring(self):
        self._sampling = False
        self.timer.stop()
        self.start_button.setText("Start monitoring")
        self.interval_combo.setEnabled(True)
        if not self._snapshot_window:
            self.status_label.setText("Monitoring is stopped.")
            self._idle_message()

    def _interval_changed(self):
        if self._sampling:
            self.timer.start(self.interval_combo.currentData())

    def _sample_once(self):
        if self.worker is not None and self.worker.isRunning():
            return
        self.status_label.setText("Sampling network activity...")
        self.worker = SnapshotWorker(parent=self)
        self.worker.succeeded.connect(self._on_sample)
        self.worker.failed.connect(self._on_sample_failed)
        self.worker.start()

    def _on_sample_failed(self, message: str):
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {theme.COLOR_DANGER};")

    def _on_sample(self, payload: dict):
        self.status_label.setText("")
        snapshot = parse_snapshot(payload)
        self._snapshot_window.append(snapshot)
        changes = diff_connections(self.previous, snapshot)
        alerts = new_process_alerts(self.previous, snapshot)
        beacons = detect_beacons(list(self._snapshot_window), min_samples=3)
        beacon_findings = beacon_anomalies(beacons)
        self.previous = snapshot
        self.export_button.setEnabled(True)
        self._last_render = (snapshot, changes, alerts + beacon_findings, beacons)
        self._render(snapshot, changes, alerts + beacon_findings, beacons)
        if self.resolve_checkbox.isChecked() and not (self._resolve_worker is not None and self._resolve_worker.isRunning()):
            self._on_resolve_toggled(True)

    def _rerender(self):
        if getattr(self, "_last_render", None):
            self._render(*self._last_render)

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
            "No samples yet. Press 'Start monitoring' to watch this device's adapters and "
            "connections update live every few seconds."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(_MUTED)
        self.results_layout.addWidget(hint)

    def _section(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet(_SECTION_STYLE)
        return label

    def _collapsible_section(self, title: str, content: QWidget, expanded: bool = False) -> QWidget:
        host = QWidget()
        host_layout = QVBoxLayout(host)
        host_layout.setContentsMargins(0, 0, 0, 0)
        host_layout.setSpacing(theme.SPACE_XS)
        toggle = QToolButton()
        toggle.setCheckable(True)
        toggle.setChecked(expanded)
        toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        toggle.setAccessibleName(title)
        toggle.setStyleSheet("font-weight: 700; text-align: left;")
        toggle.setText(("\u25be " if expanded else "\u25b8 ") + title)
        content.setVisible(expanded)

        def on_toggle(checked):
            content.setVisible(checked)
            toggle.setText(("\u25be " if checked else "\u25b8 ") + title)

        toggle.toggled.connect(on_toggle)
        host_layout.addWidget(toggle, alignment=Qt.AlignmentFlag.AlignLeft)
        host_layout.addWidget(content)
        return host

    def _render(self, snapshot, changes, extra_findings, beacon_candidates=()):
        self._clear_results()
        summary = summarize(snapshot)

        # summary cards
        grid = QGridLayout()
        grid.setHorizontalSpacing(theme.SPACE_MD)
        grid.setVerticalSpacing(theme.SPACE_MD)
        cards = (
            ("Established connections", str(summary["connections"])),
            ("To public addresses", str(summary["public"])),
            ("Changes since last sample", str(len(changes))),
            ("Findings", str(len(extra_findings) + len(analyze_connections(snapshot.connections)))),
        )
        for index, (label, value) in enumerate(cards):
            card = QFrame()
            card.setStyleSheet(_CARD_STYLE)
            card_layout = QVBoxLayout(card)
            card_layout.setSpacing(2)
            number = QLabel(value)
            number.setStyleSheet("font-size: 18pt; font-weight: 700;")
            text = QLabel(label)
            text.setStyleSheet(_MUTED)
            card_layout.addWidget(number)
            card_layout.addWidget(text)
            grid.addWidget(card, 0, index)
        grid_widget = QWidget()
        grid_widget.setLayout(grid)
        self.results_layout.addWidget(grid_widget)

        # adapter throughput (needs at least two samples)
        if len(self._snapshot_window) >= 2:
            rates = compute_rates(self._snapshot_window[-2], snapshot,
                                  interval_hint=self.interval_combo.currentData() / 1000.0)
            if rates:
                self.results_layout.addWidget(self._section(
                    "Throughput (sampled over the last interval)"
                ))
                grid2 = QGridLayout()
                grid2.setHorizontalSpacing(theme.SPACE_MD)
                grid2.setVerticalSpacing(theme.SPACE_MD)
                for index, rate in enumerate(rates):
                    grid2.addWidget(self._rate_card(rate), 0, index)
                grid2_host = QWidget()
                grid2_host.setLayout(grid2)
                self.results_layout.addWidget(grid2_host)

        # recent changes
        if changes:
            self.results_layout.addWidget(self._section("What changed since the last sample"))
            for change in changes[:8]:
                color = _NEW_COLOR if change.kind == "new" else _CLOSED_COLOR
                marker = "NEW" if change.kind == "new" else "CLOSED"
                line = QLabel(f"[{marker}] {change.detail}")
                line.setWordWrap(True)
                line.setStyleSheet(f"color: {color};")
                self.results_layout.addWidget(line)

        # findings (anomalies + new-process alerts + beacons)
        findings = list(analyze_connections(snapshot.connections)) + list(extra_findings)
        if findings:
            findings_host = QWidget()
            findings_layout = QVBoxLayout(findings_host)
            findings_layout.setContentsMargins(0, 0, 0, 0)
            findings_layout.setSpacing(theme.SPACE_SM)
            for finding in sorted(findings, key=lambda f: (0 if f.severity == "high" else 1 if f.severity == "medium" else 2)):
                findings_layout.addWidget(self._finding_card(finding))
            findings_layout.addStretch(1)
            self.results_layout.addWidget(self._collapsible_section("Findings", findings_host, expanded=True))

        # beacon candidates (dedicated panel like the preview)
        if beacon_candidates:
            self.results_layout.addWidget(self._section("Beacon candidates (regular rhythms)"))
            note = QLabel(
                "A connection that reappears to the same remote at a very regular interval can be "
                "command-and-control beaconing - or a legitimate update checker. Low jitter = more "
                "regular timing. The median interval and jitter come from the last "
                f"{len(beacon_candidates) + 2} samples."
            )
            note.setWordWrap(True)
            note.setStyleSheet(_MUTED)
            self.results_layout.addWidget(note)
            for candidate in beacon_candidates:
                line = QLabel(
                    f"{candidate.process} -> {candidate.remote}:{candidate.remote_port}  -  "
                    f"median interval {candidate.median_interval:.1f}s, "
                    f"{candidate.jitter * 100:.0f}% jitter ({candidate.samples} samples)"
                )
                line.setStyleSheet(
                    f"font-family: Consolas; color: "
                    f"{theme.COLOR_WARNING if candidate.jitter > 0.15 else theme.COLOR_DANGER};"
                )
                self.results_layout.addWidget(line)

        # talkers
        if summary["top"]:
            self.results_layout.addWidget(self._section("Top talkers"))
            self.results_layout.addWidget(self._talkers_widget(summary["top"]))

        # connections table (collapsible)
        table_host = QWidget()
        table_layout = QVBoxLayout(table_host)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.addWidget(self._connections_table(snapshot))
        self.results_layout.addWidget(self._collapsible_section("Established connections", table_host))

        footer = QLabel(
            f"Last sample at {snapshot.taken_at}. "
            "Colour legend: green = new connection since the previous sample; muted = closed. "
            "Beacon candidates are regular rhythms - they can also be legitimate update checkers."
        )
        footer.setWordWrap(True)
        footer.setStyleSheet(_MUTED)
        self.results_layout.addWidget(footer)
        self.results_layout.addStretch(1)

    def _rate_card(self, rate) -> QFrame:
        card = QFrame()
        card.setStyleSheet(_CARD_STYLE)
        layout = QVBoxLayout(card)
        layout.setSpacing(theme.SPACE_XS)
        title = QLabel(rate.name)
        title.setStyleSheet("font-weight: 700;")
        layout.addWidget(title)
        meta = QLabel(f"{rate.status} - link {rate.link_speed}")
        meta.setStyleSheet(_MUTED)
        layout.addWidget(meta)
        for direction, value, color in (
            ("Down", format_bits_per_second(rate.down_bps), theme.COLOR_ACCENT),
            ("Up", format_bits_per_second(rate.up_bps), theme.COLOR_SUCCESS),
        ):
            row = QHBoxLayout()
            label = QLabel(direction)
            label.setStyleSheet(_MUTED)
            value_label = QLabel(value)
            value_label.setStyleSheet(f"font-weight: 700; color: {color}; font-family: Consolas;")
            row.addWidget(label)
            row.addStretch(1)
            row.addWidget(value_label)
            layout.addLayout(row)
        return card

    def _finding_card(self, finding: Anomaly) -> QFrame:
        card = QFrame()
        color = _FINDING_BORDER.get(finding.severity, theme.COLOR_BORDER)
        card.setStyleSheet(
            f"background-color: {theme.COLOR_SURFACE};"
            f" border: 1px solid {theme.COLOR_BORDER};"
            f" border-left: 4px solid {color};"
            f" border-radius: {theme.RADIUS_SM}px;"
        )
        card_layout = QVBoxLayout(card)
        head = QHBoxLayout()
        title = QLabel(finding.title)
        title.setWordWrap(True)
        title.setStyleSheet("font-weight: 600;")
        badge = SeverityBadge(finding.severity)
        head.addWidget(title, 1)
        head.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
        card_layout.addLayout(head)
        detail = QLabel(finding.detail)
        detail.setWordWrap(True)
        detail.setStyleSheet(_MUTED)
        card_layout.addWidget(detail)
        return card

    def _talkers_widget(self, talkers) -> QWidget:
        host = QWidget()
        layout = QVBoxLayout(host)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(theme.SPACE_XS)
        maximum = max((talker.connections for talker in talkers), default=1)
        for talker in talkers:
            row = QHBoxLayout()
            name = QLabel(talker.process)
            name.setMinimumWidth(140)
            name.setMaximumWidth(200)
            bar = QProgressBar()
            bar.setRange(0, maximum)
            bar.setValue(talker.connections)
            bar.setTextVisible(False)
            bar.setFixedHeight(10)
            bar.setStyleSheet(
                f"QProgressBar {{ background-color: {theme.COLOR_SURFACE_RAISED};"
                f" border: none; border-radius: 5px; }}"
                f"QProgressBar::chunk {{ background-color: {theme.COLOR_ACCENT};"
                f" border-radius: 5px; }}"
            )
            meta = QLabel(f"{talker.connections} connection(s) - {talker.distinct_remotes} remote(s)")
            meta.setStyleSheet(_MUTED)
            row.addWidget(name)
            row.addWidget(bar, 1)
            row.addWidget(meta)
            layout.addLayout(row)
        return host

    def _connections_table(self, snapshot):
        connections = list(snapshot.connections)
        table = QTableWidget(len(connections), 4)
        table.setHorizontalHeaderLabels(("Process", "Remote address", "Remote port", "Reach"))
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.setColumnWidth(0, 150)
        table.setColumnWidth(1, 180)
        current_keys = {
            (c.process_name or str(c.process_id), c.remote_address, c.remote_port)
            for c in connections
        }
        for row, connection in enumerate(connections):
            process_item = QTableWidgetItem(connection.process_name or str(connection.process_id))
            hostname = self._hostnames.get(connection.remote_address)
            if hostname:
                remote_item = QTableWidgetItem(f"{hostname} ({connection.remote_address}:{connection.remote_port})")
                remote_item.setToolTip(f"{connection.remote_address}:{connection.remote_port}")
            else:
                remote_item = QTableWidgetItem(f"{connection.remote_address}:{connection.remote_port}")
            port_item = QTableWidgetItem(str(connection.remote_port))
            from modules.traffic.logic import is_public_remote
            if is_public_remote(connection.remote_address):
                reach_item = QTableWidgetItem("public")
                reach_item.setForeground(QBrush(QColor(theme.COLOR_SUCCESS)))
            else:
                reach_item = QTableWidgetItem("private")
                reach_item.setForeground(QBrush(QColor(theme.COLOR_INFO)))
            key = (connection.process_name or str(connection.process_id),
                   connection.remote_address, connection.remote_port)
            if key not in self._last_connection_keys:
                process_item.setForeground(QBrush(QColor(_NEW_COLOR)))
                remote_item.setForeground(QBrush(QColor(_NEW_COLOR)))
                port_item.setForeground(QBrush(QColor(_NEW_COLOR)))
            table.setItem(row, 0, process_item)
            table.setItem(row, 1, remote_item)
            table.setItem(row, 2, port_item)
            table.setItem(row, 3, reach_item)
        self._last_connection_keys = current_keys
        return table

    def _export_csv(self):
        if not self._snapshot_window:
            return
        snapshot = self._snapshot_window[-1]
        destination, _ = QFileDialog.getSaveFileName(
            self, "Export traffic snapshot", "Traffic_Snapshot.csv", "CSV files (*.csv)"
        )
        if not destination:
            return
        if not destination.lower().endswith(".csv"):
            destination += ".csv"
        try:
            path = export_snapshot_csv(destination, snapshot)
        except (OSError, ValueError) as error:
            self.status_label.setText(f"Could not export the CSV: {error}")
            self.status_label.setStyleSheet(f"color: {theme.COLOR_DANGER};")
            return
        self.status_label.setText(f"Snapshot exported to {path}.")
        self.status_label.setStyleSheet(f"color: {theme.COLOR_SUCCESS};")
