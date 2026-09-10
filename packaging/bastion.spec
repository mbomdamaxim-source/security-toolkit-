# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build specification for Bastion.

Build on Windows (PyInstaller cannot cross-compile):

    .\\build.ps1                 (recommended - sets everything up)
    pyinstaller packaging\\bastion.spec --noconfirm

Output: dist\\Bastion.exe  (single windowed file, icon + version metadata)
"""
import os

block_cipher = None

PROJECT_ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

analysis = Analysis(
    [os.path.join(PROJECT_ROOT, "app.py")],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=[
        # brand asset only - the browser preview and tests are not shipped
        (os.path.join(PROJECT_ROOT, "assets", "bastion.ico"), "assets"),
        (os.path.join(PROJECT_ROOT, "assets", "bastion-256.png"), "assets"),
    ],
    hiddenimports=[
        # cryptography loads its backend lazily; PyInstaller needs the hint
        "cryptography",
        "cryptography.hazmat.backends.openssl",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # keep the executable lean - none of these are used at runtime
        "tkinter",
        "PIL",
        "pytest",
        "unittest",
        "pydoc",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(analysis.pure, analysis.zipped_data, cipher=block_cipher)

executable = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="Bastion",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                      # UPX can trip antivirus heuristics
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,                  # windowed app: no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(PROJECT_ROOT, "assets", "bastion.ico"),
    version=os.path.join(PROJECT_ROOT, "packaging", "version_info.txt"),
)
