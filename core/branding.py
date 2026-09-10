"""Branding assets for Bastion, resolvable both from source and from the
PyInstaller bundle (sys._MEIPASS)."""
from __future__ import annotations

import sys
from pathlib import Path


def resource_path(relative: str) -> Path:
    """Return the absolute path of a bundled resource.

    When frozen by PyInstaller the assets live under sys._MEIPASS; when
    running from source they sit next to the project root.
    """
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / relative
    return Path(__file__).resolve().parent.parent / relative


def icon_path() -> Path:
    """Path to the window/executable icon (.ico on Windows, PNG elsewhere)."""
    ico = resource_path("assets/bastion.ico")
    if sys.platform.startswith("win") and ico.exists():
        return ico
    png = resource_path("assets/bastion-256.png")
    return png if png.exists() else ico


def is_frozen() -> bool:
    """True when running from a packaged executable."""
    return bool(getattr(sys, "frozen", False))
