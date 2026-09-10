# ============================================================================
# Bastion - one-click setup and launch (run from a normal PowerShell window):
#
#     .\start.ps1            create venv if needed, install, launch Bastion
#     .\start.ps1 -Test      install, run the test suite, then launch Bastion
#     .\start.ps1 -NoLaunch  install only (no app window)
#     .\start.ps1 -Preview   install, then start the browser preview on port 8000
#
# If PowerShell blocks the script, allow it once for this folder:
#     Set-ExecutionPolicy -Scope Process Bypass
# ============================================================================
[CmdletBinding()]
param(
    [switch]$Test,
    [switch]$NoLaunch,
    [switch]$Preview
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Write-Step($message) {
    Write-Host ""
    Write-Host "==> $message" -ForegroundColor Cyan
}

# --- 1. virtual environment -------------------------------------------------
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Step "Creating virtual environment (.venv)..."
    py -3 -m venv .venv
    if (-not (Test-Path $venvPython)) {
        throw "Could not create .venv. Install Python 3.11+ from https://www.python.org and retry."
    }
} else {
    Write-Step "Virtual environment found (.venv)."
}

# --- 2. dependencies --------------------------------------------------------
Write-Step "Installing requirements..."
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed." }

# --- 3. tests (optional) ----------------------------------------------------
if ($Test) {
    Write-Step "Running the test suite (78+ tests)..."
    & $venvPython -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "Some tests failed - see the output above." }
}

# --- 4. launch --------------------------------------------------------------
if ($NoLaunch) {
    Write-Step "Setup complete. Launch Bastion later with: .\start.ps1"
    exit 0
}
if ($Preview) {
    Write-Step "Starting the browser preview on http://127.0.0.1:8000 ..."
    & $venvPython preview_server.py
    exit 0
}
Write-Step "Launching Bastion..."
& $venvPython app.py
