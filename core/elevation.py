"""Windows administrator detection and safe relaunch support."""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path


def is_administrator() -> bool:
    """Return whether this process has Windows administrator privileges."""
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def can_request_administrator_relaunch() -> bool:
    """Return whether this platform can display a Windows UAC elevation prompt."""
    return os.name == "nt" and not is_administrator()


def relaunch_arguments(argv=None) -> list:
    """Arguments to pass to the elevated relaunch.

    When running from a packaged executable argv[0] is the .exe itself, so it
    must not be forwarded as a script argument (that would make Bastion treat
    its own path as an option).
    """
    args = list(sys.argv if argv is None else argv)
    if getattr(sys, "frozen", False) and args:
        args = args[1:]
    return [str(Path(arg)) for arg in args]


def relaunch_as_administrator() -> bool:
    """Request a UAC relaunch and report whether Windows accepted the request.

    The caller must terminate the current process after a successful return. This
    separation keeps the system-side operation testable and prevents two windows
    from remaining open after a successful elevation request.
    """
    if not can_request_administrator_relaunch():
        return False

    executable = Path(sys.executable)
    arguments = subprocess.list2cmdline(relaunch_arguments())
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", str(executable), arguments, None, 1
    )
    return result > 32


def request_relaunch_and_exit(exit_current_process: Callable[[int], None] = sys.exit) -> bool:
    """Request elevation and exit the current process only when the request succeeds."""
    if not relaunch_as_administrator():
        return False
    exit_current_process(0)
    return True
