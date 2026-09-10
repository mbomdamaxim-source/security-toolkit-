"""Central visual language for Bastion."""

APP_NAME = "Bastion"
APP_TAGLINE = "Learn your system. Secure your system."
APP_VERSION = "0.1.0"

COLOR_BACKGROUND = "#101820"
COLOR_SURFACE = "#17242E"
COLOR_SURFACE_RAISED = "#20313D"
COLOR_TEXT_PRIMARY = "#F4F7F9"
COLOR_TEXT_SECONDARY = "#B8C5CE"
COLOR_BORDER = "#38505F"
COLOR_ACCENT = "#36B4D7"
COLOR_SUCCESS = "#40B978"
COLOR_WARNING = "#F0B84D"
COLOR_DANGER = "#E26464"
COLOR_INFO = "#5EA8E8"

FONT_FAMILY = "Segoe UI"
FONT_SIZE_BODY = 10
FONT_SIZE_SMALL = 9
FONT_SIZE_TITLE = 18
FONT_SIZE_HEADING = 13

SPACE_XS = 4
SPACE_SM = 8
SPACE_MD = 12
SPACE_LG = 16
SPACE_XL = 24

RADIUS_SM = 4
RADIUS_MD = 8

APPLICATION_STYLESHEET = f"""
QWidget {{
    background-color: {COLOR_BACKGROUND};
    color: {COLOR_TEXT_PRIMARY};
    font-family: "{FONT_FAMILY}";
    font-size: {FONT_SIZE_BODY}pt;
}}
QMainWindow {{ background-color: {COLOR_BACKGROUND}; }}
QListWidget {{
    background-color: {COLOR_SURFACE};
    border: none;
    outline: none;
    padding: {SPACE_SM}px;
}}
QListWidget::item {{
    border-radius: {RADIUS_SM}px;
    padding: {SPACE_MD}px;
    margin: {SPACE_XS}px 0;
}}
QListWidget::item:selected {{
    background-color: {COLOR_ACCENT};
    color: {COLOR_BACKGROUND};
    font-weight: 600;
}}
QPushButton {{
    background-color: {COLOR_ACCENT};
    color: {COLOR_BACKGROUND};
    border: none;
    border-radius: {RADIUS_SM}px;
    padding: {SPACE_SM}px {SPACE_MD}px;
    font-weight: 600;
}}
QPushButton:disabled {{
    background-color: {COLOR_SURFACE_RAISED};
    color: {COLOR_TEXT_SECONDARY};
}}
QPushButton:focus, QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QTextEdit:focus {{
    border: 2px solid {COLOR_ACCENT};
}}
QRadioButton:focus {{
    color: {COLOR_ACCENT};
    font-weight: 600;
}}

/* --- Widgets Qt would otherwise render with native light OS styling --- */

/* Tab widget: panel frame and tab bar (matches the browser preview's flat
   tabs with an accent underline on the active tab). */
QTabWidget::pane {{
    border: 1px solid {COLOR_BORDER};
    background-color: {COLOR_BACKGROUND};
    top: -1px;
    border-bottom-left-radius: {RADIUS_SM}px;
    border-bottom-right-radius: {RADIUS_SM}px;
}}
QTabBar {{
    background-color: {COLOR_BACKGROUND};
}}
QTabBar::tab {{
    background: transparent;
    color: {COLOR_TEXT_SECONDARY};
    padding: {SPACE_SM}px {SPACE_LG}px;
    border: none;
    border-bottom: 3px solid transparent;
    margin-right: {SPACE_XS}px;
}}
QTabBar::tab:selected {{
    color: {COLOR_TEXT_PRIMARY};
    border-bottom: 3px solid {COLOR_ACCENT};
}}
QTabBar::tab:hover:!selected {{
    color: {COLOR_TEXT_PRIMARY};
}}

/* Text inputs and spin boxes */
QLineEdit, QSpinBox, QPlainTextEdit, QTextEdit {{
    background-color: {COLOR_SURFACE};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    border-radius: {RADIUS_SM}px;
    padding: 6px 8px;
    selection-background-color: {COLOR_ACCENT};
    selection-color: {COLOR_BACKGROUND};
}}
QLineEdit:disabled, QSpinBox:disabled, QPlainTextEdit:disabled, QTextEdit:disabled {{
    color: {COLOR_TEXT_SECONDARY};
}}
QSpinBox::up-button, QSpinBox::down-button {{
    background-color: {COLOR_SURFACE_RAISED};
    border: none;
    border-left: 1px solid {COLOR_BORDER};
    width: 18px;
}}
QSpinBox::up-button {{
    border-top-right-radius: {RADIUS_SM}px;
}}
QSpinBox::down-button {{
    border-bottom-right-radius: {RADIUS_SM}px;
}}

/* Tables and their headers */
QTableWidget, QTableView {{
    background-color: {COLOR_SURFACE};
    alternate-background-color: {COLOR_BACKGROUND};
    gridline-color: {COLOR_BORDER};
    border: 1px solid {COLOR_BORDER};
    border-radius: {RADIUS_SM}px;
}}
QTableView::item {{
    padding: 4px 8px;
}}
QTableView::item:selected {{
    background-color: {COLOR_ACCENT};
    color: {COLOR_BACKGROUND};
}}
QHeaderView::section {{
    background-color: {COLOR_SURFACE_RAISED};
    color: {COLOR_TEXT_PRIMARY};
    border: none;
    border-right: 1px solid {COLOR_BORDER};
    border-bottom: 1px solid {COLOR_BORDER};
    padding: 6px 8px;
    font-weight: 600;
}}
QTableCornerButton::section {{
    background-color: {COLOR_SURFACE_RAISED};
    border: none;
}}

/* Scroll bars */
QScrollBar:vertical {{
    background: transparent;
    width: 12px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {COLOR_SURFACE_RAISED};
    border-radius: 6px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background: {COLOR_BORDER};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QScrollBar:horizontal {{
    background: transparent;
    height: 12px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {COLOR_SURFACE_RAISED};
    border-radius: 6px;
    min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {COLOR_BORDER};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}

/* Menus and tool tips */
QMenu {{
    background-color: {COLOR_SURFACE};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    padding: {SPACE_XS}px;
}}
QMenu::item {{
    padding: 6px 24px;
    border-radius: {RADIUS_SM}px;
}}
QMenu::item:selected {{
    background-color: {COLOR_ACCENT};
    color: {COLOR_BACKGROUND};
}}
QMenu::separator {{
    height: 1px;
    background-color: {COLOR_BORDER};
    margin: {SPACE_XS}px {SPACE_SM}px;
}}
QToolTip {{
    background-color: {COLOR_SURFACE_RAISED};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    padding: {SPACE_XS}px {SPACE_SM}px;
}}

/* Combo boxes and their popup (used by later modules) */
QComboBox {{
    background-color: {COLOR_SURFACE};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    border-radius: {RADIUS_SM}px;
    padding: 6px 10px;
}}
QComboBox::drop-down {{
    background-color: {COLOR_SURFACE_RAISED};
    border: none;
    border-left: 1px solid {COLOR_BORDER};
    border-top-right-radius: {RADIUS_SM}px;
    border-bottom-right-radius: {RADIUS_SM}px;
    width: 24px;
}}
QComboBox QAbstractItemView {{
    background-color: {COLOR_SURFACE};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    selection-background-color: {COLOR_ACCENT};
    selection-color: {COLOR_BACKGROUND};
    outline: none;
}}

/* Radio button indicators */
QRadioButton {{
    spacing: {SPACE_SM}px;
}}
QRadioButton::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {COLOR_BORDER};
    border-radius: 9px;
    background-color: {COLOR_SURFACE};
}}
QRadioButton::indicator:checked {{
    background-color: {COLOR_ACCENT};
    border-color: {COLOR_ACCENT};
}}
QRadioButton::indicator:hover {{
    border-color: {COLOR_ACCENT};
}}
"""
