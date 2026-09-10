"""Native PySide6 interface for VLSM planning and verified quiz practice."""
from __future__ import annotations

from datetime import datetime
import ipaddress
from pathlib import Path
import random

from PySide6.QtCore import QStandardPaths, QTimer, Qt
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QFileDialog, QFormLayout, QFrame, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QProgressBar, QPushButton,
    QRadioButton, QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget,
    QVBoxLayout, QWidget, QHeaderView,
)

from core import theme
from core.context import AppContext
from core.quiz_history import QuizHistory
from core.status_widgets import ModuleHeader
from modules.subnet.logic import (
    QUIZ_BANK, aggregate_mastery, allocate_vlsm, quiz_choices,
)
from modules.subnet.summary_dialog import RouteSummaryDialog
from modules.subnet.report import export_vlsm_docx


_CATEGORY_LABELS = {
    "Mixed topics": None,
    "Subnet membership": "subnet_membership",
    "Broadcast address": "broadcast_address",
    "Usable hosts": "usable_hosts",
    "CIDR-to-mask": "cidr_to_mask",
    "First/last usable host": {"first_usable_host", "last_usable_host"},
    "Wildcard masks": "wildcard_mask",
}

_CARD_STYLE = (
    f"background-color: {theme.COLOR_SURFACE};"
    f" border: 1px solid {theme.COLOR_BORDER};"
    f" border-radius: {theme.RADIUS_MD}px;"
    f" padding: {theme.SPACE_LG}px;"
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


def _heading_style() -> str:
    return f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 600;"


_SHORTCUT_ANSWER_INDEX = {
    Qt.Key.Key_A: 0,
    Qt.Key.Key_B: 1,
    Qt.Key.Key_C: 2,
    Qt.Key.Key_D: 3,
}


def _recommendation(category: str, percent: int) -> str:
    if percent < 60:
        return f"{category}: revise the underlying calculation method and retry this category."
    if percent < 80:
        return f"{category}: practise more questions to make your calculations consistent."
    return f"{category}: strong result. Continue reviewing it alongside the other topics."


class SubnetModule(QWidget):
    def __init__(self, context: AppContext):
        super().__init__()
        self.context, self.allocations = context, []
        self._quiz_live = False
        self._in_question = False
        self.missed = []
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        data_directory = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppLocalDataLocation) or str(Path.home())
        self.history_store = QuizHistory(Path(data_directory) / "quiz_history.json")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL)
        layout.setSpacing(theme.SPACE_LG)
        header = QHBoxLayout()
        header.setSpacing(theme.SPACE_MD)
        header.addWidget(ModuleHeader(
            "Subnet and VLSM",
            "Plan IPv4 address space and practise fixed, verified CCNA-style questions.",
        ), 1)
        self.summary_button = QPushButton("Route summariser")
        self.summary_button.setAccessibleName("Open route summariser")
        self.summary_button.setAccessibleDescription(
            "Open the supernetting helper that finds the smallest summary route for your networks."
        )
        self.summary_button.clicked.connect(self._open_summary_dialog)
        header.addWidget(self.summary_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)
        tabs = QTabWidget()
        self.quiz_tabs = tabs
        self.quiz_tab_widget = self._quiz_tab()
        tabs.addTab(self._calculator_tab(), "Calculator")
        tabs.addTab(self.quiz_tab_widget, "Quiz")
        layout.addWidget(tabs, 1)

    def _open_summary_dialog(self):
        dialog = RouteSummaryDialog(self)
        window = self.window()
        if window is not None:
            dialog.move(window.geometry().center() - dialog.rect().center())
        dialog.exec()
        dialog.deleteLater()

    def _calculator_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab); layout.setSpacing(theme.SPACE_MD)
        form = QFormLayout(); self.network = QLineEdit("192.168.10.0/24"); self.network.setAccessibleName("Base IPv4 network"); self.network.setAccessibleDescription("Enter the base network in IPv4 CIDR notation."); form.addRow("Base network", self.network)
        self.requirements_layout = QGridLayout(); self.requirements_layout.addWidget(QLabel("Network requirement"), 0, 0); self.requirements_layout.addWidget(QLabel("Usable hosts"), 0, 1); self.requirements_layout.addWidget(QLabel("Action"), 0, 2)
        self.inputs = []; self.custom_rows = []
        for name, value in (("Users", 100), ("Servers", 50), ("Management", 20)): self._add_requirement(name, value, fixed=True)
        requirements_widget = QWidget(); requirements_widget.setLayout(self.requirements_layout); form.addRow("Host requirements", requirements_widget)
        layout.addLayout(form)
        add = QPushButton("Add network requirement"); add.clicked.connect(lambda: self._add_requirement("", 1, fixed=False)); layout.addWidget(add, alignment=Qt.AlignmentFlag.AlignLeft)
        controls = QHBoxLayout(); calculate = QPushButton("Calculate VLSM allocation"); calculate.clicked.connect(self.calculate); self.export = QPushButton("Export Word Report"); self.export.setEnabled(False); self.export.clicked.connect(self.export_report); self.copy_summary = QPushButton("Copy allocation summary"); self.copy_summary.setEnabled(False); self.copy_summary.clicked.connect(self.copy_allocation_summary); reset = QPushButton("Reset calculator"); reset.clicked.connect(self.reset_calculator); controls.addWidget(calculate); controls.addWidget(self.export); controls.addWidget(self.copy_summary); controls.addWidget(reset); controls.addStretch(1); layout.addLayout(controls)
        self.message = QLabel(); self.message.setWordWrap(True); layout.addWidget(self.message)
        self.unallocated = QLabel(); self.unallocated.setWordWrap(True); self.unallocated.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};"); layout.addWidget(self.unallocated)
        self.explanations = QLabel(); self.explanations.setWordWrap(True); self.explanations.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};"); layout.addWidget(self.explanations)
        self.table = QTableWidget(0, 9); self.table.setHorizontalHeaderLabels(("Requirement", "Requested", "Network", "CIDR", "Mask", "Usable range", "Broadcast", "Capacity", "Unused")); self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents); self.table.horizontalHeader().setStretchLastSection(True); layout.addWidget(self.table, 1)
        return tab

    def _add_requirement(self, name, value, fixed):
        row = len(self.inputs) + 1
        name_widget = QLabel(name) if fixed else QLineEdit(name)
        hosts = QSpinBox(); hosts.setRange(1, 2_147_483_647); hosts.setValue(value); hosts.setAccessibleName(f"Usable hosts for {name or 'custom network requirement'}")
        self.requirements_layout.addWidget(name_widget, row, 0); self.requirements_layout.addWidget(hosts, row, 1)
        remove = QLabel("—")
        if not fixed:
            remove = QPushButton("Remove")
            remove.clicked.connect(lambda: self._remove_requirement(name_widget, hosts, remove))
        self.requirements_layout.addWidget(remove, row, 2)
        self.inputs.append((name_widget, hosts, fixed))
        if not fixed: self.custom_rows.append((name_widget, hosts, remove))

    def _remove_requirement(self, name_widget, hosts, remove):
        self.inputs = [entry for entry in self.inputs if entry[1] is not hosts]
        self.custom_rows = [entry for entry in self.custom_rows if entry[1] is not hosts]
        for widget in (name_widget, hosts, remove): widget.deleteLater()

    def _requirements(self):
        rows = []
        for name_widget, hosts, fixed in self.inputs:
            name = name_widget.text() if fixed else name_widget.text().strip()
            rows.append((name, hosts.value()))
        return rows

    def calculate(self):
        try: self.allocations = allocate_vlsm(self.network.text(), self._requirements())
        except ValueError as error:
            self.table.setRowCount(0); self.export.setEnabled(False); self.copy_summary.setEnabled(False); self.unallocated.clear(); self.explanations.clear(); self.message.setText(str(error)); self.message.setStyleSheet(f"color: {theme.COLOR_DANGER};"); return
        self.table.setRowCount(len(self.allocations)); reasons = []
        for row, item in enumerate(self.allocations):
            prefix = int(item["cidr"][1:]); size, capacity = 1 << (32 - prefix), (1 << (32 - prefix)) - 2; unused = capacity - item["requested_hosts"]
            values = (item["name"], item["requested_hosts"], item["network"], item["cidr"], str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask), item["usable_range"], item["broadcast"], capacity, unused)
            for col, value in enumerate(values): self.table.setItem(row, col, QTableWidgetItem(str(value)))
            reasons.append(f"{item['name']}: {item['requested_hosts']} required hosts need {item['requested_hosts'] + 2} addresses including network and broadcast. A /{prefix} block has {size} addresses and {capacity} usable hosts, leaving {unused} unused.")
        base = ipaddress.IPv4Network(self.network.text(), strict=False)
        last_used = max(ipaddress.IPv4Address(item["broadcast"]) for item in self.allocations)
        if last_used < base.broadcast_address:
            start = last_used + 1; remaining = int(base.broadcast_address) - int(last_used)
            self.unallocated.setText(f"Unallocated address space: {start} – {base.broadcast_address} ({remaining} total addresses remain).")
        else:
            self.unallocated.setText("Unallocated address space: none. The allocation uses the complete base network.")
        self.explanations.setText("\n\n".join(reasons)); self.export.setEnabled(True); self.copy_summary.setEnabled(True); self.message.setText("Allocation calculated. Export or copy the summary when ready."); self.message.setStyleSheet(f"color: {theme.COLOR_SUCCESS};")

    def copy_allocation_summary(self):
        lines = [f"Base network: {ipaddress.IPv4Network(self.network.text(), strict=False).with_prefixlen}"]
        lines.extend(f"{item['name']}: {item['network']}{item['cidr']} | {item['usable_range']} | Broadcast {item['broadcast']}" for item in self.allocations)
        lines.append(self.unallocated.text())
        QApplication.clipboard().setText("\n".join(lines))
        self.message.setText("Allocation summary copied to the clipboard."); self.message.setStyleSheet(f"color: {theme.COLOR_SUCCESS};")

    def reset_calculator(self):
        self.network.setText("192.168.10.0/24")
        defaults = {"Users": 100, "Servers": 50, "Management": 20}
        for name_widget, hosts, fixed in self.inputs:
            if fixed: hosts.setValue(defaults[name_widget.text()])
        for name_widget, hosts, remove in list(self.custom_rows):
            self._remove_requirement(name_widget, hosts, remove)
        self.allocations = []; self.table.setRowCount(0); self.explanations.clear(); self.unallocated.clear(); self.export.setEnabled(False); self.copy_summary.setEnabled(False); self.message.setText("Calculator reset to the verified example."); self.message.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")

    def export_report(self):
        destination, _ = QFileDialog.getSaveFileName(self, "Export VLSM Word Report", "VLSM_Allocation_Report.docx", "Word documents (*.docx)")
        if not destination: return
        if not destination.lower().endswith(".docx"): destination += ".docx"
        try: path = export_vlsm_docx(destination, self.network.text(), self.allocations)
        except (OSError, ValueError) as error: self.message.setText(f"Could not export the Word report: {error}"); self.message.setStyleSheet(f"color: {theme.COLOR_DANGER};"); return
        self.message.setText(f"Word report exported to {path}."); self.message.setStyleSheet(f"color: {theme.COLOR_SUCCESS};")

    def _quiz_tab(self):
        tab = QWidget(); self.quiz_layout = QVBoxLayout(tab); self.quiz_layout.setSpacing(theme.SPACE_MD); self._show_quiz_setup(); return tab

    def _clear_quiz(self):
        while self.quiz_layout.count():
            item = self.quiz_layout.takeAt(0); widget = item.widget()
            if widget: widget.deleteLater()

    def _show_quiz_setup(self):
        self._quiz_live = False
        self._in_question = False
        self.timer.stop()
        self._clear_quiz()
        self.quiz_layout.addWidget(ModuleHeader("Quiz", "Choose a study mode and a verified subnetting category."))
        mode_heading = QLabel("Choose a study mode"); mode_heading.setStyleSheet(_heading_style()); self.quiz_layout.addWidget(mode_heading)
        mode_description = QLabel("Practice has no time limit. Exam mode adds a countdown."); mode_description.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};"); self.quiz_layout.addWidget(mode_description)
        mode_grid = QGridLayout(); mode_grid.setHorizontalSpacing(theme.SPACE_MD); mode_grid.setVerticalSpacing(theme.SPACE_MD)
        self.mode_group = QButtonGroup(self); self.mode_group.setExclusive(True)
        for index, (title, detail, duration) in enumerate((("Practice mode", "No time limit", 0), ("Exam mode", "10 minutes", 600), ("Exam mode", "20 minutes", 1200), ("Exam mode", "30 minutes", 1800))):
            button = QPushButton(f"{title}\n{detail}"); button.setCheckable(True); button.setAccessibleName(f"{title} — {detail}")
            self.mode_group.addButton(button, duration); button.setStyleSheet(_card_button_style(index == 0))
            button.clicked.connect(lambda checked=False, selected=button: self._select_mode(selected))
            mode_grid.addWidget(button, index // 2, index % 2)
        self.mode_group.button(0).setChecked(True); self.quiz_layout.addLayout(mode_grid)
        category_heading = QLabel("Choose a quiz category"); category_heading.setStyleSheet(_heading_style()); self.quiz_layout.addWidget(category_heading)
        category_grid = QGridLayout(); category_grid.setHorizontalSpacing(theme.SPACE_MD); category_grid.setVerticalSpacing(theme.SPACE_MD)
        for index, label in enumerate(_CATEGORY_LABELS):
            button = QPushButton(label); button.setAccessibleName(f"Start quiz: {label}"); button.setStyleSheet(_card_button_style(False))
            button.clicked.connect(lambda checked=False, selected=label: self._start_quiz(selected))
            category_grid.addWidget(button, index // 3, index % 3)
        self.quiz_layout.addLayout(category_grid)
        history_card = QFrame(); history_card.setStyleSheet(_CARD_STYLE)
        history_layout = QVBoxLayout(history_card); history_layout.setSpacing(theme.SPACE_SM)
        history_title = QLabel("Recent quiz history"); history_title.setStyleSheet(_heading_style()); history_layout.addWidget(history_title)
        entries = self.history_store.load()
        if not entries:
            history_layout.addWidget(QLabel("No quiz attempts have been recorded yet."))
        else:
            mastery = aggregate_mastery(entries)
            if mastery:
                mastery_heading = QLabel("Category mastery")
                mastery_heading.setStyleSheet("font-weight: 700;")
                history_layout.addWidget(mastery_heading)
                for row in mastery[:5]:
                    percent = row["percentage"]
                    attempts = row["attempts"]
                    color = theme.COLOR_DANGER if percent < 60 else theme.COLOR_WARNING if percent < 80 else theme.COLOR_SUCCESS
                    line_layout = QHBoxLayout()
                    line_layout.setSpacing(theme.SPACE_SM)
                    name = QLabel(row["category"])
                    name.setMinimumWidth(150)
                    bar = QProgressBar()
                    bar.setRange(0, 100)
                    bar.setValue(percent)
                    bar.setTextVisible(False)
                    bar.setFixedHeight(8)
                    bar.setStyleSheet(
                        f"QProgressBar {{ background-color: {theme.COLOR_SURFACE_RAISED};"
                        f" border: none; border-radius: 4px; }}"
                        f"QProgressBar::chunk {{ background-color: {color};"
                        f" border-radius: 4px; }}"
                    )
                    bar.setAccessibleName(f"{row['category']} mastery {percent} percent")
                    meta = QLabel(f"{attempts} attempt{'s' if attempts != 1 else ''} - {percent}%")
                    meta.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")
                    line_layout.addWidget(name)
                    line_layout.addWidget(bar, 1)
                    line_layout.addWidget(meta)
                    history_layout.addLayout(line_layout)
            for entry in entries[:3]:
                line = QLabel(f"{entry['date']} — {entry['category']} — {entry['mode']} — {entry['score']}/{entry['total']} ({entry['percentage']}%)")
                line.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};"); history_layout.addWidget(line)
        self.quiz_layout.addWidget(history_card)
        self.quiz_layout.addStretch(1)

    def _select_mode(self, clicked):
        for button in self.mode_group.buttons():
            button.setStyleSheet(_card_button_style(button is clicked))

    def _start_quiz(self, category_label, duration=None):
        self._quiz_live = True
        self.session_category = category_label
        selected = _CATEGORY_LABELS[category_label]
        self.questions = [question for question in QUIZ_BANK if selected is None or question.question_type == selected or isinstance(selected, set) and question.question_type in selected]
        random.shuffle(self.questions)
        self.position = self.score = 0
        self.results = {label: [0, 0] for label in _CATEGORY_LABELS if label != "Mixed topics"}
        self.missed = []
        self.duration = self.mode_group.checkedId() if duration is None else duration
        self.session_mode = "Practice" if not self.duration else f"Exam {self.duration // 60} minutes"
        self.deadline = self.duration
        self.timer.stop()
        self._show_question()
        if self.duration: self.timer.start(1000)

    def _tick(self):
        self.deadline -= 1
        if self.deadline <= 0:
            self.timer.stop(); self.position = len(self.questions); self._show_question()
        else:
            self.timer_label.setText(f"Time remaining: {self.deadline // 60}:{self.deadline % 60:02d}")
            self._style_timer()

    def _style_timer(self):
        if not self.duration:
            self.timer_label.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};"); return
        remaining = self.deadline
        if remaining <= 10: self.timer_label.setStyleSheet(f"color: {theme.COLOR_DANGER}; font-weight: 700;")
        elif remaining <= 60: self.timer_label.setStyleSheet(f"color: {theme.COLOR_WARNING}; font-weight: 700;")
        else: self.timer_label.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};")

    def _category(self, question):
        for label, kinds in _CATEGORY_LABELS.items():
            if kinds is None: continue
            if question.question_type == kinds or isinstance(kinds, set) and question.question_type in kinds: return label

    def _show_question(self):
        self._clear_quiz()
        if self.position >= len(self.questions):
            self.timer.stop(); self._in_question = False; self._show_report(); return
        self._in_question = True
        question = self.questions[self.position]; category = QLabel(self._category(question)); category.setStyleSheet(f"color: {theme.COLOR_ACCENT}; font-weight: 700;"); self.quiz_layout.addWidget(category)
        self.progress_label = QLabel(); self.quiz_layout.addWidget(self.progress_label)
        self.progress_bar = QProgressBar(); self.progress_bar.setRange(0, 100); self.progress_bar.setValue(0); self.progress_bar.setTextVisible(False); self.progress_bar.setFixedHeight(8); self.progress_bar.setStyleSheet(_PROGRESS_BAR_STYLE); self.progress_bar.setAccessibleName("Quiz progress"); self.quiz_layout.addWidget(self.progress_bar)
        self.timer_label = QLabel("Practice mode — no time limit" if not self.duration else f"Time remaining: {self.deadline // 60}:{self.deadline % 60:02d}"); self.quiz_layout.addWidget(self.timer_label); self._style_timer()
        card = QFrame(); card.setStyleSheet(f"background-color: {theme.COLOR_SURFACE}; border-radius: {theme.RADIUS_MD}px; padding: {theme.SPACE_LG}px;"); card_layout = QVBoxLayout(card); self.question_label = QLabel(question.question_text); self.question_label.setWordWrap(True); self.question_label.setStyleSheet(f"font-size: {theme.FONT_SIZE_HEADING}pt; font-weight: 600;"); card_layout.addWidget(self.question_label); self.quiz_layout.addWidget(card)
        answer_heading = QLabel("Answer choices"); answer_heading.setAccessibleName("Answer choices"); self.quiz_layout.addWidget(answer_heading)
        self.answer_group = QButtonGroup(self); self.answer_buttons = []
        for index, answer in enumerate(quiz_choices(question.correct_answer)):
            button = QRadioButton(f"{chr(65+index)}. {answer}"); button.setProperty("answer", answer); button.setAccessibleName(f"Answer {chr(65+index)}: {answer}"); button.setAccessibleDescription("Select this answer choice."); button.setStyleSheet(_ANSWER_BASE_STYLE); self.answer_group.addButton(button); self.answer_buttons.append(button); self.quiz_layout.addWidget(button)
        self.feedback = QLabel(); self.feedback.setWordWrap(True); self.feedback.setAccessibleName("Answer feedback"); self.feedback.setAccessibleDescription("Correctness result and calculation explanation."); self.feedback.setStyleSheet(_FEEDBACK_STYLE); self.quiz_layout.addWidget(self.feedback)
        self.next_button = QPushButton("Check answer"); self.next_button.setAccessibleName("Check selected answer"); self.next_button.clicked.connect(self._check_answer); self.quiz_layout.addWidget(self.next_button, alignment=Qt.AlignmentFlag.AlignLeft); self.quiz_layout.addStretch(1); self.answer_buttons[0].setFocus(Qt.FocusReason.OtherFocusReason); self._update_progress()

    def _update_progress(self):
        answered = self.position + (1 if self.next_button.text() == "Next question" else 0)
        self.progress_label.setText(f"Question {self.position + 1} of {len(self.questions)} · Score: {self.score}/{answered} ({round(self.score / answered * 100) if answered else 0}%)")
        self.progress_bar.setValue(round(answered / len(self.questions) * 100))

    def _check_answer(self):
        if self.next_button.text() == "Next question": self.position += 1; self._show_question(); return
        button = self.answer_group.checkedButton()
        if button is None: self.feedback.setText("Choose one answer before checking it."); return
        question = self.questions[self.position]; correct = button.property("answer") == question.correct_answer; category = self._category(question); self.results[category][1] += 1
        if correct: self.score += 1; self.results[category][0] += 1
        else: self.missed.append((question, str(button.property("answer"))))
        for item in self.answer_buttons:
            item.setEnabled(False)
            if item.property("answer") == question.correct_answer:
                item.setText(f"{item.text()}  ✓"); item.setStyleSheet(_answer_state_style(theme.COLOR_SUCCESS))
            elif item is button:
                item.setText(f"{item.text()}  ✕"); item.setStyleSheet(_answer_state_style(theme.COLOR_DANGER))
        self.feedback.setText(("Correct. The green tick marks the right answer. " if correct else f"Not quite. The green tick marks the correct answer: {question.correct_answer}. ") + self._explanation(question)); self.next_button.setText("Next question"); self._update_progress()

    def _explanation(self, question):
        if question.question_type == "usable_hosts": return "Usable hosts equal total addresses minus the network and broadcast addresses."
        if question.question_type == "cidr_to_mask": return f"The / prefix maps to mask {question.correct_answer}."
        if question.question_type == "wildcard_mask": return "A Cisco wildcard mask is the inverse of the subnet mask."
        if question.question_type in {"first_usable_host", "last_usable_host"}: return "Usable hosts sit between the network address and broadcast address."
        return "Apply the supplied prefix boundary to determine the network range."

    def _show_report(self):
        self._clear_quiz(); total = len(self.questions); percent = round(self.score / total * 100) if total else 0
        self.quiz_layout.addWidget(ModuleHeader("Quiz performance report", f"Final score: {self.score} out of {total} ({percent}%)."))
        guidance = QLabel("Use the category recommendations to focus your next revision session. Start with the lowest-scoring topic."); guidance.setWordWrap(True); guidance.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};"); self.quiz_layout.addWidget(guidance)
        for category, (correct, attempted) in self.results.items():
            if not attempted: continue
            category_percent = round(correct / attempted * 100)
            card = QFrame(); card.setStyleSheet(_CARD_STYLE); card_layout = QVBoxLayout(card); card_layout.setSpacing(theme.SPACE_SM)
            title = QLabel(f"{category}: {correct}/{attempted} correct ({category_percent}%)"); title.setStyleSheet("font-weight: 600;"); card_layout.addWidget(title)
            bar = QProgressBar(); bar.setRange(0, 100); bar.setValue(category_percent); bar.setTextVisible(False); bar.setFixedHeight(8); bar.setStyleSheet(_PROGRESS_BAR_STYLE); bar.setAccessibleName(f"{category} score"); card_layout.addWidget(bar)
            advice = QLabel(_recommendation(category, category_percent)); advice.setWordWrap(True); advice.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};"); card_layout.addWidget(advice)
            self.quiz_layout.addWidget(card)
        self.history_store.record({"date": datetime.now().strftime("%Y-%m-%d"), "category": self.session_category, "mode": self.session_mode, "score": self.score, "total": total, "percentage": percent})
        if self.missed:
            review = QPushButton(f"Review missed questions ({len(self.missed)})"); review.clicked.connect(self._show_missed_review); self.quiz_layout.addWidget(review, alignment=Qt.AlignmentFlag.AlignLeft)
        new_session = QPushButton("Start a new session"); new_session.clicked.connect(lambda: self._start_quiz(self.session_category, self.duration)); self.quiz_layout.addWidget(new_session, alignment=Qt.AlignmentFlag.AlignLeft)
        restart = QPushButton("Return to quiz setup"); restart.clicked.connect(self._show_quiz_setup); self.quiz_layout.addWidget(restart, alignment=Qt.AlignmentFlag.AlignLeft)
        self.quiz_layout.addStretch(1)

    def _show_missed_review(self):
        self._clear_quiz()
        self.quiz_layout.addWidget(ModuleHeader("Review missed questions", "Review your selected answer, the correct answer, and the calculation explanation."))
        for question, chosen in self.missed:
            card = QFrame(); card.setStyleSheet(_CARD_STYLE); card_layout = QVBoxLayout(card); card_layout.setSpacing(theme.SPACE_SM)
            text = QLabel(question.question_text); text.setWordWrap(True); text.setStyleSheet("font-weight: 600;"); card_layout.addWidget(text)
            yours = QLabel(f"Your answer: {chosen} ✕"); yours.setStyleSheet(f"color: {theme.COLOR_DANGER};"); card_layout.addWidget(yours)
            correct = QLabel(f"Correct answer: {question.correct_answer} ✓"); correct.setStyleSheet(f"color: {theme.COLOR_SUCCESS};"); card_layout.addWidget(correct)
            explanation = QLabel(self._explanation(question)); explanation.setWordWrap(True); explanation.setStyleSheet(f"color: {theme.COLOR_TEXT_SECONDARY};"); card_layout.addWidget(explanation)
            self.quiz_layout.addWidget(card)
        restart = QPushButton("Return to quiz setup"); restart.clicked.connect(self._show_quiz_setup); self.quiz_layout.addWidget(restart, alignment=Qt.AlignmentFlag.AlignLeft); self.quiz_layout.addStretch(1)

    def _quiz_shortcuts_active(self):
        if QApplication.activeModalWidget() is not None: return False
        if not self._quiz_live: return False
        if self.quiz_tabs.currentWidget() is not self.quiz_tab_widget: return False
        focus = QApplication.focusWidget()
        if isinstance(focus, (QLineEdit, QSpinBox, QPlainTextEdit)): return False
        return True

    def keyPressEvent(self, event):
        if self._quiz_shortcuts_active():
            key = event.key()
            index = _SHORTCUT_ANSWER_INDEX.get(key)
            if self._in_question and index is not None:
                button = self.answer_buttons[index]
                if button.isEnabled():
                    button.setChecked(True); button.setFocus(); event.accept(); return
            if self._in_question and key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                self.next_button.click(); event.accept(); return
            if key == Qt.Key.Key_Escape:
                self._show_quiz_setup(); event.accept(); return
        super().keyPressEvent(event)
