# Bastion

**Learn your system. Secure your system.**

Bastion is a Windows desktop application that helps you understand and improve the
security of the Windows device it runs on. It is a personal, defensive, educational
toolkit - it inspects **this device only** and never scans remote targets.

Everything runs locally: no data is uploaded, no packets are captured, and nothing
is changed on your machine without your explicit confirmation.

---

## The defensive chain

Bastion is organised as five modules that follow a defensive workflow:

| # | Module | What it does |
| --- | --- | --- |
| 1 | **Subnet and VLSM** | Plan IPv4 address space (VLSM), summarise routes, and practise verified CCNA-style questions |
| 2 | **Credential Auditor** | Local password-strength science (word-aware, pattern-aware) plus a Crypto Lab for hands-on encryption, hashing and a crypto quiz |
| 3 | **Scan Reports** | Read-only map of this device's exposure: listening TCP/UDP ports, firewall truth, drift since the last scan, CIS-style hardening baseline checks, and a Word report export |
| 4 | **Firewall Builder** | Validated rule construction for Windows Defender, MikroTik RouterOS and Cisco IOS - with explain mode, templates, an ACL first-match simulator, a live rule audit view, practice labs and a concepts quiz |
| 5 | **Traffic Dashboard** | Live local traffic observation: per-adapter throughput, new/closed connection highlighting, new-process alerts, a light beaconing detector, top talkers and CSV export |

Cross-cutting: a collapsible sidebar, an internet-connectivity indicator, and a
consistent dark theme with accessible controls.

---

## Requirements

* Windows 10 or 11 (x64)
* Python 3.11 or newer - only needed to run from source or to build
* PowerShell 5.1 (included with Windows) for the Scan Reports and Traffic Dashboard modules

---

## Run from source (one click)

```powershell
cd path\to\security-toolkit-
.\start.ps1                 # creates .venv, installs requirements, launches Bastion
```

Useful switches:

```powershell
.\start.ps1 -Test           # run the test suite first
.\start.ps1 -Preview        # serve the browser preview on http://127.0.0.1:8000
.\start.ps1 -NoLaunch       # set the environment up without launching
```

Manual equivalent:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

## Build the Windows executable

```powershell
.\build.ps1 -Test -Zip      # tests -> dist\Bastion.exe -> Bastion-windows.zip
```

`build.ps1` creates the environment if needed, installs the runtime **and** build
requirements, optionally runs the test suite, then calls PyInstaller with
`packaging\bastion.spec`. PyInstaller cannot cross-compile, so this step runs on
Windows.

| Packaging piece | Location |
| --- | --- |
| PyInstaller specification | `packaging/bastion.spec` |
| Windows version resource | `packaging/version_info.txt` |
| Brand assets | `assets/bastion.ico`, `assets/bastion-icon.png` |
| Build requirements | `requirements-build.txt` |
| Frozen-aware asset lookup | `core/branding.py` |
| Windows integration check | `packaging/verify_windows_modules.py` |
| Installer script (Inno Setup 6) | `packaging/bastion-installer.iss` |

Build an installer as well:

```powershell
.\build.ps1 -Test -Zip -Installer     # also produces installer\Bastion-Setup-<version>.exe
```

### Continuous integration (Windows)

`.github/workflows/windows-build.yml` runs on every push to `main` or an `arena/**`
branch, on pull requests, and on demand. On a real `windows-latest` runner it:

1. installs the runtime requirements and runs the test suite,
2. executes `packaging/verify_windows_modules.py` to exercise the PowerShell-backed
   modules (scan, traffic, firewall audit) against the live operating system,
3. builds `dist\Bastion.exe` with PyInstaller,
4. smoke-launches the packaged application to prove it starts and stays alive,
5. uploads the executable as a downloadable build artifact.

You can also run the integration check yourself on any Windows machine:

```powershell
python packaging\verify_windows_modules.py
```

## Tests

```powershell
python -m pytest -q
```

The suite covers every module's pure logic (VLSM and route summarisation, password
analysis and passphrases, cryptography primitives, scan parsing and baseline
assessment, firewall command construction and ACL simulation, traffic rate and
beacon analysis, connectivity probing) plus the packaging inputs. GUI-dependent
tests skip automatically when no display is available.

---

## Where Bastion stores data

Nothing sensitive is ever written to disk. Local storage under
`%LOCALAPPDATA%\Bastion\` is limited to:

| File | Contents |
| --- | --- |
| `quiz_history.json`, `crypto_quiz_history.json` | Quiz attempt summaries (date, category, mode, score) - last 20 |
| `scan_allowlist.json` | Listener ports you marked as expected |
| `last_scan.json` | Previous scan payload, used for drift detection |
| `hardening_history.json` | Hardening scores over time (last 30 scans) |

Passwords, keys, plaintexts and packet data are **never** stored, logged or exported.

---

## Security posture

* **Read-only by default** - inspection uses PowerShell cmdlets (`Get-NetTCPConnection`,
  `Get-NetUDPEndpoint`, `Get-Service`, `Get-HotFix`, `Get-NetFirewallRule`,
  `Get-NetAdapterStatistics`) and never parses localized text output.
* **Generate, don't surprise** - firewall rules are built and validated for review
  before anything is applied; applying requires administrator rights.
* **Fail closed** - unreadable system state is reported as "unknown" rather than
  assumed good, and errors never leave a half-applied change.
* **Educational by design** - every module explains *why* a finding matters and what
  to do about it.

---

## Browser preview

`ui_preview.html` is a self-contained interactive preview of all five modules with
generated sample data (it cannot perform security actions). Serve it locally with:

```powershell
python preview_server.py    # http://127.0.0.1:8000
```

The preview is also the approved design reference used while building the native
PySide6 interface.

---

## Documentation

| Document | Contents |
| --- | --- |
| `docs/architecture.md` | Design principles, layered structure, module internals, data flow, concurrency, parity and packaging |
| `docs/user-guide.md` | How to install, run and use every module, plus privacy notes and troubleshooting |
| `docs/test-plan.md` | Test strategy, the 145-test breakdown, parity and CI verification, the manual acceptance checklist and the defect log |
| `docs/threat-model.md` | Assets protected, adversaries in scope, trust boundaries, threats to Bastion itself, out-of-scope items and residual risk |

## Project layout

```
app.py                     entry point: shell, navigation, connectivity, About
start.ps1 / build.ps1      one-click run and packaging scripts
core/                      theme, context, elevation, status widgets, quiz history,
                           connectivity probing, branding
modules/subnet|credentials|scanner|firewall|traffic/
                           each module: pure logic (logic.py), native UI (ui.py)
                           and any report/learning helpers
packaging/                 PyInstaller spec + Windows version resource
assets/                    application icon (.ico and .png)
tests/                     logic, packaging and UI tests
ui_preview.html            browser preview of all modules
preview_server.py          serves the preview and its Word-report downloads
```

---

## Linux development environments

The target platform is Windows. A Linux environment running PySide6 also needs its
Qt/OpenGL system libraries installed by the operating system before the graphical
application can start. Without them the workspace can compile and run the non-GUI
tests, but cannot display the desktop window.
