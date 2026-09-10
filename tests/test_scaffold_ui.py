import pytest

try:
    from PySide6.QtWidgets import QApplication
except ImportError as error:
    pytest.skip(f"PySide6 GUI dependencies are unavailable: {error}", allow_module_level=True)

from app import MainWindow
from core.context import AppContext
from core.status_widgets import StatusBanner


def test_all_module_placeholders_are_navigable():
    application = QApplication.instance() or QApplication([])
    window = MainWindow(AppContext(is_admin=False, app_version="test"))
    assert window.navigation.count() == 5
    assert window.stack.count() == 5
    for index in range(window.navigation.count()):
        window.navigation.setCurrentRow(index)
        application.processEvents()
        assert window.stack.currentIndex() == index
    banner = window.findChild(StatusBanner)
    assert banner is not None
    assert "Administrator privileges are not active" in banner.message_label.text()
    window.close()
