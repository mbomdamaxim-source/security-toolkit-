"""The global stylesheet must theme every widget type Qt would otherwise
render with native light OS styling (tabs, tables, scroll bars, menus...)."""
from core import theme

_REQUIRED_SELECTORS = [
    "QTabWidget::pane",
    "QTabBar::tab",
    "QTabBar::tab:selected",
    "QTabBar::tab:hover:!selected",
    "QLineEdit, QSpinBox, QPlainTextEdit, QTextEdit",
    "QSpinBox::up-button",
    "QTableWidget, QTableView",
    "QHeaderView::section",
    "QScrollBar::handle:vertical",
    "QScrollBar::handle:horizontal",
    "QMenu::item:selected",
    "QToolTip",
    "QComboBox QAbstractItemView",
    "QRadioButton::indicator:checked",
]


def test_stylesheet_themes_native_widgets():
    for selector in _REQUIRED_SELECTORS:
        assert selector in theme.APPLICATION_STYLESHEET, f"missing stylesheet rule: {selector}"


def test_stylesheet_uses_named_theme_constants():
    for color in (theme.COLOR_BORDER, theme.COLOR_SURFACE, theme.COLOR_SURFACE_RAISED, theme.COLOR_ACCENT):
        assert color in theme.APPLICATION_STYLESHEET


def test_stylesheet_has_no_light_default_fallback_values():
    lowered = theme.APPLICATION_STYLESHEET.lower()
    for token in ("white", "lightgray", "lightgrey", "light gray"):
        assert token not in lowered, f"light fallback value leaked into stylesheet: {token}"
