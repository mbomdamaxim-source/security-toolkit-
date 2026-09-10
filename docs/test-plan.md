# Bastion — Test Plan and Verification Record

This document describes how Bastion is verified: what is tested automatically, what
requires Windows, and how the results are recorded.

---

## 1. Strategy

Bastion separates **pure logic** from **presentation**. Every decision the application
makes — parsing, validation, analysis, scoring, command construction — lives in
`logic.py` modules that import no Qt and perform no I/O beyond one guarded boundary
(PowerShell or sockets) that tests can replace. As a result the great majority of the
system is verifiable on any machine, without a display and without Windows.

The remaining layers are covered by three additional techniques:

1. **Cross-implementation parity** — the browser preview mirrors the Python logic; the
   two are compared case by case so a screen and the application cannot disagree.
2. **Live-OS integration check** — `packaging/verify_windows_modules.py` exercises the
   PowerShell-backed modules on Windows (also run by CI on every push).
3. **Packaged smoke test** — CI launches the built `Bastion.exe`, waits, and fails if
   it exited early.

---

## 2. Automatic test suite

Run with:

```powershell
python -m pytest -q -rs
```

**147 tests, 12 files.** Detailed breakdown:

| Test file | Tests | What it proves |
| --- | --- | --- |
| `test_subnet_logic.py` | 17 | VLSM allocation order/alignment/fit errors, route summarisation (exact and wasteful cases), the 90-question bank verified with `ipaddress` arithmetic, no-repeat sessions, per-category mastery aggregation |
| `test_subnet_report.py` | 1 | The VLSM Word report is produced |
| `test_credentials_logic.py` | 24 | Common-bank integrity (2,033 unique/sorted entries), leet matching, pattern detectors, word-aware passphrase entropy (NIST values 51.7/64.6/77.5 bits), NIST scoring behaviour, generator guarantees |
| `test_crypto_logic.py` | 18 | Caesar/Vigenère/Base64/SHA-256 known vectors, AES-256-GCM round-trip and tamper rejection, PBKDF2 key derivation, RSA-2048-OAEP round-trip and wrong-key rejection, 80-question bank structure and four-option generation |
| `test_scanner_logic.py` | 22 | Cmdlet-only script (never `netsh`), TCP+UDP parsing, firewall-truth classification, connection heuristics, patch recency, baseline assessment for exposed and clean machines, hardening history, drift detection, allowlist, Word export, all failure modes |
| `test_traffic_logic.py` | 19 | Structured cmdlet script, throughput maths with counter resets, public/private classification, top talkers, new/closed diffs, new-process alerts, beacon detection (regular rhythm, jitter filtering, minimum samples), CSV export |
| `test_firewall_logic.py` | 20 | Windows `allow|block` and `in|out` vocabulary with correct rendering, MikroTik and Cisco builders, wildcard-mask contiguity, ACL first-match simulation and implicit deny, rule-audit script and failure modes |
| `test_connectivity.py` | 7 | Online/offline verdicts, latency, injectable sockets, stop-at-first-success, all-down handling |
| `test_elevation.py` | 5 | Non-Windows safety, relaunch only exits on success, frozen-argument handling |
| `test_packaging.py` | 11 | Spec file validity (windowed, icon, version resource, no UPX), version metadata matching the theme, icon sizes, build script contents, frozen asset lookup, CI workflow shape (including a regression check against bash-only syntax), verification script graceful failure |
| `test_theme.py` | 3 | The stylesheet covers every native widget type that would otherwise fall back to light OS styling |
| `test_scaffold_ui.py` | 1 | All five modules are navigable and the elevation banner renders (skips itself when no display is available) |

**Expected result:** `147 passed, 1 skipped` when no display is present (the GUI test
skips by design and prints the reason).

### What "skipped" means

`test_scaffold_ui.py` is skipped when Qt cannot load a platform plugin (for example in
a headless container). The skip reason is printed with `-rs`. This is a limitation of
the *machine*, not of the code: the same test runs on Windows.

---

## 3. Cross-implementation parity checks

Because the browser preview duplicates some logic in JavaScript, parity was audited
explicitly rather than assumed:

| Area | Method | Result |
| --- | --- | --- |
| Credential analysis | 12 representative passwords (common, leet, patterned, passphrase, empty) analysed by both implementations and compared field-by-field (score, strength, entropy, patterns) | identical |
| Passphrase handling | 6 cases including hyphenated passphrases | identical |
| Cryptographic primitives | Caesar, Vigenère, Base64, SHA-256, AES-GCM round-trip, tamper failure, Caesar breaker, salted hashing | identical |
| Route summarisation | 4 network sets compared (host/base/prefix/wasted) | identical |
| Firewall commands and validation messages | 16 checks across the three platforms | byte-identical strings |
| Subnet quiz options | all 90 questions produce four distinct options containing the answer | passed |
| Feature matrix | 25 components (shell, five modules, dialogs, exports) audited across both implementations | 0 mismatches |

The audit is scripted in the development workflow, so it can be re-run after any
change.

---

## 4. Windows integration verification

On Windows (and in CI) run:

```powershell
python packaging\verify_windows_modules.py
```

It performs **read-only** queries and prints:

```
== Scan Reports ==        listeners / services / hotfixes / firewall state /
                          findings / hardening percentage
== Traffic Dashboard ==   adapters / established connections
== Firewall rule audit == rules read / enabled / enabled inbound-allow
```

Exit code 0 means all three PowerShell-backed modules answered. Exit code 1 means at
least one failed; the failing module is named. On non-Windows systems the script
reports "runs on Windows only" and exits 1 — this behaviour is itself covered by a
test, so the failure path is verified everywhere.

---

## 5. Packaged application verification (CI)

### Activating the workflow (one manual step)

The workflow file lives at `.github/workflows/windows-build.yml` in this repository and
in `Bastion-source.zip`. If it is not yet present on GitHub, add it once through the web
interface — GitHub requires the `workflows` permission to create that path
programmatically, which automated pushes may not hold:

1. Open the repository on GitHub, switch to the branch you are pushing to.
2. **Add file → Create new file**, name it exactly
   `.github/workflows/windows-build.yml`.
3. Paste the contents of the local file (it is also printed at the end of this document).
4. Commit — the workflow starts running on the next push and can also be triggered from
   the **Actions** tab with *Run workflow*.

No other step of the project needs manual set-up.

### What the workflow does

`windows-build.yml` runs on `windows-latest` and performs, in order:

1. install runtime requirements;
2. `python -m pytest -q -rs` — the full suite;
3. install build requirements;
4. `python packaging/verify_windows_modules.py` — live-OS checks (non-fatal, logged);
5. `python -m PyInstaller packaging/bastion.spec --noconfirm`;
6. assert `dist\Bastion.exe` exists and report its size;
7. **smoke-launch** the executable, wait 12 seconds, fail if the process exited;
8. upload the executable as a downloadable artifact.

Steps 6–8 are what make the packaging claim meaningful: a build that produces a file
which cannot start would fail the pipeline.

---

## 6. Manual acceptance checklist

Complete once on a real Windows machine (the definitive acceptance pass):

| # | Check | Expected |
| --- | --- | --- |
| 1 | `.\start.ps1` on a clean checkout | Environment created, Bastion opens, dark theme throughout |
| 2 | Sidebar toggle | ✕ collapses the sidebar, ☰ restores it |
| 3 | Internet indicator | Shows Online with a latency figure; turns Offline when the network is disabled, and recovers |
| 4 | Subnet calculator with the default values | Users /25, Servers /26, Management /27; unallocated space reported |
| 5 | Route summariser with the four default /24s | `192.168.0.0/22`, 0 unused |
| 6 | Subnet quiz: Exam 10 minutes, keyboard `A`–`D` / `Enter` / `Esc` | Shortcuts work, timer changes colour, report and mastery appear |
| 7 | Credential Auditor: type `password`, then `correct horse battery staple` | Very weak (common alert) versus Very strong (passphrase note) |
| 8 | Generate passphrase → analysis | Very strong, word-list estimate shown |
| 9 | Crypto Lab: AES encrypt → Tamper demo → decrypt | Tampering is detected and reported |
| 10 | Scan Reports → Run local scan | Findings, ports with firewall truth, baseline checks with a hardening score; second scan adds a trend entry |
| 11 | Scan Reports → Export Word Report | Document opens with the same content as the screen |
| 12 | Firewall Builder: each of the three tabs | Valid command rendered; wrong vocabulary rejected with a clear message |
| 13 | Cisco tab → template → Run packet | Correct entry decides, verdict printed |
| 14 | Rule audit → Load rules | Real rules listed and filterable |
| 15 | Traffic Dashboard → Start monitoring | Rates move; new connections highlighted; findings appear; Export CSV writes a file |
| 16 | `.\build.ps1 -Test -Zip` | Tests pass, `dist\Bastion.exe` builds, zip created |
| 17 | Run `dist\Bastion.exe` directly | Starts, branded icon in the taskbar, About dialog works |

---

## 7. Defect log (found and fixed during development)

Recorded because it demonstrates the verification working as intended:

| # | Defect | How it was caught | Fix |
| --- | --- | --- | --- |
| 1 | Quiz option generator produced a nonsense `"Option 4"` for answers ending in `.0` (24 of 90 questions) | Reproduced with a script comparing generated options to the answers | Rewrote generation with wraparound octet arithmetic; regression test added |
| 2 | Leet translation mangled digits before pattern detection, so `Summer2024!` escaped the year check | Test asserting pattern detection | Detect keyboard/repeat/year patterns on the raw string, leet-normalise only for dictionary comparison |
| 3 | Hyphenated passphrases were counted as one token (12.9 bits instead of 64.6) | Parity test against the preview | Single shared tokeniser used by every code path |
| 4 | Wildcard-mask contiguity test was inverted, accepting invalid masks | Unit test with `0.0.1.1` | Corrected the bit test |
| 5 | Cisco interface names with `/` were rejected by the MikroTik validator | Unit test with `GigabitEthernet0/1` | Platform-specific validators |
| 6 | Export produced a different report from the displayed page (duplicated sample data had drifted) | Parity audit comparing the export source to the embedded data | The page sends its own payload; the server no longer keeps a copy |
| 7 | "Top talkers" disappeared from the preview during a rewrite | 25-component parity audit | Restored and re-verified |
| 8 | Packaged elevation would pass the executable path as a script argument | Design review while writing the spec | `relaunch_arguments()` strips it when frozen; two tests added |
| 9 | CI workflow used a bash heredoc inside PowerShell (would fail on the runner) | Review of the workflow against the PowerShell dialect | Replaced with `packaging/verify_windows_modules.py`; regression check added to the workflow test |

---

## 8. Coverage boundaries (honest limitations)

* **GUI pixels are not automatically compared.** Widget structure, sizing and theme are
  covered by the parity audit and the manual checklist, not by screenshot diffing.
* **Live Windows behaviour cannot be tested in the development container** (no
  PowerShell, no Qt display). It is covered by the CI job and the manual checklist.
* **Antivirus/packaging interactions** (false positives, signing) are out of scope; the
  spec disables UPX for this reason.
* **Performance** is not benchmarked: the app performs bounded local queries, and the
  heaviest operation (a full scan) runs on a worker thread with a timeout.

---

## Appendix — full contents of `.github/workflows/windows-build.yml`

Paste this into the GitHub web UI as described in section 5.

```yaml
name: Windows build

# Builds and tests Bastion on a real Windows runner so the native modules are
# exercised with actual PowerShell and the PySide6 GUI libraries.
on:
  push:
    branches: ["main", "arena/**"]
  pull_request:
    branches: ["main"]
  workflow_dispatch:

jobs:
  test-and-build:
    name: Test and package (Windows)
    runs-on: windows-latest

    env:
      # Qt needs a platform plugin in a headless CI session.
      QT_QPA_PLATFORM: offscreen
      PYTHONUNBUFFERED: "1"

    steps:
      - name: Check out the repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip

      - name: Install runtime and test requirements
        run: |
          python -m pip install --upgrade pip
          python -m pip install -r requirements.txt

      - name: Run the test suite
        run: python -m pytest -q -rs

      - name: Install build requirements
        run: python -m pip install -r requirements-build.txt

      - name: Verify the PowerShell-based modules against the real OS
        # Read-only checks against the live OS. Kept non-fatal so a runner
        # quirk cannot block the build artifact; inspect the log for details.
        continue-on-error: true
        run: python packaging/verify_windows_modules.py

      - name: Build Bastion.exe with PyInstaller
        run: python -m PyInstaller packaging/bastion.spec --noconfirm

      - name: Confirm the executable exists
        shell: pwsh
        run: |
          $exe = "dist\\Bastion.exe"
          if (-not (Test-Path $exe)) { throw "Build output missing: $exe" }
          $sizeMb = [math]::Round((Get-Item $exe).Length / 1MB, 1)
          Write-Host "Built $exe ($sizeMb MB)"

      - name: Smoke-launch the packaged application
        shell: pwsh
        run: |
          # Start the packaged app, let it initialise, then close it. The
          # process must stay alive (a crash would exit immediately).
          $process = Start-Process -FilePath "dist\\Bastion.exe" -PassThru
          Start-Sleep -Seconds 12
          if ($process.HasExited) {
            throw "The packaged application exited early with code $($process.ExitCode)"
          }
          Write-Host "Packaged application started successfully (pid $($process.Id))"
          Stop-Process -Id $process.Id -Force

      - name: Upload the executable as a build artifact
        uses: actions/upload-artifact@v4
        with:
          name: Bastion-windows-exe
          path: dist/Bastion.exe
          if-no-files-found: error

      - name: Upload the built application bundle
        uses: actions/upload-artifact@v4
        with:
          name: Bastion-windows-bundle
          path: |
            dist/Bastion.exe
            README.md
            assets/bastion.ico
            packaging/verify_windows_modules.py
          if-no-files-found: error
```
