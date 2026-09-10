"""Packaging tests: build inputs, brand assets and version consistency.

These run everywhere (they do not need PyInstaller); the actual executable
build happens on Windows via build.ps1.
"""
import re
import struct
from pathlib import Path

from core import theme
from core.branding import icon_path, is_frozen, resource_path

ROOT = Path(__file__).resolve().parent.parent


def test_spec_file_exists_and_is_valid_python():
    spec = ROOT / "packaging" / "bastion.spec"
    assert spec.exists()
    source = spec.read_text(encoding="utf-8")
    compile(source, str(spec), "exec")  # spec files are Python
    # key packaging decisions
    assert "console=False" in source          # windowed app, no console
    assert "bastion.ico" in source            # branded executable icon
    assert "version_info.txt" in source       # Windows version metadata
    assert "upx=False" in source              # avoid AV false positives


def test_version_info_matches_theme_and_is_parseable():
    info = (ROOT / "packaging" / "version_info.txt").read_text(encoding="utf-8")
    major, minor, patch = theme.APP_VERSION.split(".")
    assert f"filevers=({major}, {minor}, {patch}, 0)" in info
    assert f"StringStruct('ProductVersion', '{theme.APP_VERSION}')" in info
    assert "Bastion.exe" in info


def test_brand_assets_exist_and_ico_has_expected_sizes():
    icon_png = ROOT / "assets" / "bastion-icon.png"
    icon_256 = ROOT / "assets" / "bastion-256.png"
    icon_ico = ROOT / "assets" / "bastion.ico"
    for path in (icon_png, icon_256, icon_ico):
        assert path.exists() and path.stat().st_size > 0

    data = icon_ico.read_bytes()
    count = struct.unpack("<H", data[4:6])[0]
    sizes = set()
    for index in range(count):
        offset = 6 + index * 16
        width = data[offset] or 256
        sizes.add(width)
    # Windows needs small sizes for lists, large for explorer previews
    assert {16, 32, 48, 256} <= sizes


def test_build_script_and_build_requirements():
    script = (ROOT / "build.ps1").read_text(encoding="utf-8")
    assert "bastion.spec" in script
    assert "requirements-build.txt" in script
    assert "Bastion.exe" in script
    build_reqs = (ROOT / "requirements-build.txt").read_text(encoding="utf-8")
    assert re.search(r"pyinstaller==", build_reqs, re.IGNORECASE)


def test_branding_helpers_resolve_paths_from_source():
    icon = icon_path()
    assert icon.exists()
    assert icon.name in ("bastion.ico", "bastion-256.png")
    assert resource_path("assets").exists()
    assert is_frozen() is False  # tests never run from the packaged exe


def test_frozen_asset_lookup_uses_meipass(monkeypatch, tmp_path):
    import sys
    from core import branding
    bundled = tmp_path / "assets"
    bundled.mkdir()
    (bundled / "bastion-256.png").write_bytes(b"png")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert branding.is_frozen() is True
    assert branding.resource_path("assets") == bundled


def test_windows_ci_workflow_is_present_and_well_formed():
    workflow = ROOT / ".github" / "workflows" / "windows-build.yml"
    assert workflow.exists()
    text = workflow.read_text(encoding="utf-8")

    # runs on a real Windows runner with Python
    assert "runs-on: windows-latest" in text
    assert "actions/setup-python" in text
    assert "QT_QPA_PLATFORM: offscreen" in text   # headless Qt in CI

    # the important stages
    assert "python -m pytest" in text                      # tests
    assert "verify_windows_modules.py" in text             # real-OS verification
    assert "PyInstaller packaging/bastion.spec" in text    # build
    assert "actions/upload-artifact" in text               # artifact for download
    assert "Bastion.exe" in text

    # no bash-only heredoc syntax (this ran in pwsh before and would fail)
    assert "<<'PY'" not in text and '<<"PY"' not in text


def test_windows_verification_script_imports_and_fails_gracefully():
    import subprocess
    import sys
    script = ROOT / "packaging" / "verify_windows_modules.py"
    assert script.exists()
    # Running on Linux (no PowerShell) must exit 1 with a clear message rather
    # than raising an unhandled exception.
    completed = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, timeout=120,
    )
    assert completed.returncode == 1
    assert "Windows only" in (completed.stdout + completed.stderr)


def test_installer_script_is_present_and_consistent():
    iss = ROOT / "packaging" / "bastion-installer.iss"
    assert iss.exists()
    text = iss.read_text(encoding="utf-8")

    # version and branding must match the application
    assert f'AppVersion     "{theme.APP_VERSION}"' in text
    assert "Bastion.exe" in text
    assert "bastion.ico" in text
    # installer must be able to install without admin (per-user) - important for home users
    assert "PrivilegesRequired=lowest" in text
    # uninstall must clean the local state folder it documents
    assert "{localappdata}\\Bastion" in text
    # a literal GUID must use doubled braces
    assert "AppId={{" in text


def test_documentation_set_exists_and_mentions_real_features():
    docs = ROOT / "docs"
    expected = {
        "architecture.md": ["core/", "modules/", "logic.py", "PyInstaller"],
        "user-guide.md": ["start.ps1", "Scan Reports", "Firewall Builder", "%LOCALAPPDATA%"],
        "test-plan.md": ["pytest", "windows-build.yml", "verify_windows_modules.py", "Defect log"],
        "threat-model.md": ["Assets", "out of scope", "Residual risk"],
    }
    for name, needles in expected.items():
        path = docs / name
        assert path.exists(), f"missing {name}"
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            assert needle in text, f"{name} should mention {needle!r}"


def test_build_script_supports_installer_switch():
    script = (ROOT / "build.ps1").read_text(encoding="utf-8")
    assert "[switch]$Installer" in script
    assert "bastion-installer.iss" in script
    assert "ISCC.exe" in script          # Inno Setup compiler lookup
