# ============================================================================
# Bastion - build the Windows executable (run from a normal PowerShell window):
#
#     .\build.ps1              build dist\Bastion.exe
#     .\build.ps1 -Test        run the test suite first, then build
#     .\build.ps1 -Zip         also package dist\ into Bastion-windows.zip
#     .\build.ps1 -Installer   also build installer\Bastion-Setup-<version>.exe
#                              (requires Inno Setup 6: https://jrsoftware.org/isdl.php)
#     .\build.ps1 -Clean       delete build/ and dist/ before building
#
# PyInstaller cannot cross-compile: this script must run on Windows.
# If PowerShell blocks the script:  Set-ExecutionPolicy -Scope Process Bypass
# ============================================================================
[CmdletBinding()]
param(
    [switch]$Test,
    [switch]$Zip,
    [switch]$Clean,
    [switch]$Installer
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
}

# --- 2. dependencies --------------------------------------------------------
Write-Step "Installing runtime and build requirements..."
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r requirements.txt
& $venvPython -m pip install -r requirements-build.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed." }

# --- 3. tests (optional) ----------------------------------------------------
if ($Test) {
    Write-Step "Running the test suite..."
    & $venvPython -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "Some tests failed - fix them before packaging." }
}

# --- 4. clean (optional) ----------------------------------------------------
if ($Clean) {
    Write-Step "Removing previous build output..."
    Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue
}

# --- 5. build ---------------------------------------------------------------
Write-Step "Building Bastion.exe with PyInstaller..."
& $venvPython -m PyInstaller packaging\bastion.spec --noconfirm
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }

$exe = Join-Path $PSScriptRoot "dist\Bastion.exe"
if (-not (Test-Path $exe)) { throw "Expected output not found: $exe" }

$sizeMb = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Step "Build complete: dist\Bastion.exe ($sizeMb MB)"
Write-Host "   Double-click it, or run: .\dist\Bastion.exe" -ForegroundColor Gray
Write-Host "   Note: system-changing actions still ask for administrator rights." -ForegroundColor Gray

# --- 6. optional zip --------------------------------------------------------
if ($Zip) {
    Write-Step "Packaging dist\ into Bastion-windows.zip..."
    $zipPath = Join-Path $PSScriptRoot "Bastion-windows.zip"
    Remove-Item -Force $zipPath -ErrorAction SilentlyContinue
    Compress-Archive -Path (Join-Path $PSScriptRoot "dist\*") -DestinationPath $zipPath
    $zipMb = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
    Write-Step "Created Bastion-windows.zip ($zipMb MB)"
}

# --- 7. optional installer --------------------------------------------------
if ($Installer) {
    Write-Step "Building the Inno Setup installer..."

    # Find the Inno Setup compiler (PATH first, then the default install dirs).
    $iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
    if (-not $iscc) {
        $candidates = @(
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
        )
        $iscc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $iscc) {
        throw "Inno Setup 6 was not found. Install it from https://jrsoftware.org/isdl.php and re-run with -Installer."
    }

    & $iscc "packaging\bastion-installer.iss"
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed." }

    $setup = Get-ChildItem "installer\Bastion-Setup-*.exe" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $setup) { throw "Installer output not found in installer\." }
    $setupMb = [math]::Round($setup.Length / 1MB, 1)
    Write-Step "Created installer\$($setup.Name) ($setupMb MB)"
    Write-Host "   The installer offers per-user (no admin) or per-machine installation." -ForegroundColor Gray
}
