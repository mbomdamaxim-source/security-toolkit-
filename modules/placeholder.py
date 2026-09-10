"""Shared temporary presentation used while a feature module is being built."""
from PySide6.QtWidgets import QSizePolicy, QVBoxLayout, QWidget

from core import theme
from core.context import AppContext
from core.status_widgets import EmptyState, ModuleHeader


class PlaceholderModule(QWidget):
    def __init__(self, context: AppContext, title: str, description: str):
        super().__init__()
        self.context = context
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL, theme.SPACE_XL)
        layout.setSpacing(theme.SPACE_XL)
        layout.addWidget(ModuleHeader(title, description))
        layout.addWidget(EmptyState("This module is being prepared", "Its security features will be available in a future development block."), 1)
