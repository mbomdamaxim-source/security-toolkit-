# Bastion — Architecture

**Learn your system. Secure your system.**

Bastion is a Windows desktop application built with Python 3.11+ and PySide6. It
helps a user understand and improve the security of **the device it runs on**. It is
not a scanner for remote targets.

---

## 1. Design principles

| Principle | How it is enforced in the code |
| --- | --- |
| **Local only** | Every system query is a local PowerShell call or a local socket query. No telemetry, no uploads. The only outbound traffic is the user-initiated connectivity probe and the opt-in hostname lookup. |
| **Read-only by default** | Inspection uses `Get-*` cmdlets and never parses localized text output. Nothing is changed on the machine without explicit confirmation. |
| **Generate before apply** | The Firewall Builder validates and renders commands for review; applying is a separate, administrator-gated step. |
| **Fail closed** | Unreadable state is reported as *unknown* rather than assumed good. Input validation raises clear errors instead of guessing. |
| **Pure logic, thin UI** | All decision-making lives in testable `logic.py` modules with no Qt imports. UI modules only render. This is why 147 tests run without a display. |
| **Educational by design** | Findings carry a *why* explanation; rules explain their parameters; quizzes explain every answer. |

---

## 2. Layered structure

```
┌──────────────────────────────────────────────────────────────────┐
│ app.py            application shell: sidebar, stack, header       │
│                   (internet indicator, About), elevation banner   │
├──────────────────────────────────────────────────────────────────┤
│ modules/<name>/ui.py         PySide6 presentation per module      │
│ modules/<name>/<helpers>.py  dialogs, Word/CSV reports, learn UI  │
├──────────────────────────────────────────────────────────────────┤
│ modules/<name>/logic.py      deterministic, side-effect-free      │
│ core/*.py                    theme, elevation, history, probing   │
└──────────────────────────────────────────────────────────────────┘
```

### Shared core (`core/`)

| Module | Responsibility |
| --- | --- |
| `theme.py` | Single source of visual truth: palette, spacing, typography, `APP_NAME`/`APP_TAGLINE`/`APP_VERSION`, and the global Qt stylesheet (including native-widget rules for tabs, tables, scrollbars, menus). |
| `context.py` | Frozen `AppContext` (administrator state, version) passed to every module. |
| `elevation.py` | Administrator detection and safe UAC relaunch. Exits only when Windows accepted the request; `relaunch_arguments()` handles the packaged-executable case. |
| `status_widgets.py` | Reusable, content-sized `StatusBanner`, `SeverityBadge`, `EmptyState`, `ModuleHeader`. |
| `quiz_history.py` | Generic JSON quiz-attempt store (last 20 summaries, fail-closed on corrupt files). |
| `connectivity.py` | Internet-connectivity probing: TCP connects to well-known public endpoints with latency, injectable sockets for tests. |
| `branding.py` | Resolves bundled assets from source or from the PyInstaller bundle (`sys._MEIPASS`). |

### Module anatomy

Each of the five feature modules follows the same three-part shape:

* **`logic.py`** — the domain: validation, parsing, analysis. No Qt, no I/O beyond
  a single well-defined PowerShell/socket boundary that is injectable for tests.
* **`ui.py`** — the native interface. Runs any slow work on a `QThread` worker and
  renders results into a fixed-size, internally scrolling content area.
* **Helper modules** — `report.py` (`.docx`/`.csv` export), `summary_dialog.py`,
  `crypto_ui.py`, `learn.py` (learning overlays).

---

## 3. The five modules

### Block 1 — Subnet and VLSM (`modules/subnet/`)
* `allocate_vlsm()` — largest-first allocation with alignment, fit checking,
  uniqueness and positive-integer validation.
* `find_summary_route()` — smallest supernet covering a set of networks, with
  wasted-address reporting (route summarisation practice).
* `cidr_to_mask()`, `quiz_choices()`, `verify_quiz_bank()` — a fixed bank of
  **90 questions in 6 categories**, every answer independently verified with the
  `ipaddress` module at import time.
* `aggregate_mastery()` — per-category mastery from stored attempt summaries.
* `summary_dialog.py` — the Route summariser overlay; `report.py` — Word export.

### Block 2 — Credential Auditor + Crypto Lab (`modules/credentials/`)
* `analyze_password()` — word-aware, pattern-aware strength analysis:
  keyboard walks, repeats, sequences, years, embedded common words, personal
  context, leet-normalised matching against a **2,033-entry** curated bank.
* Passphrase handling uses the word-list model (`words × log2(7776)`) per
  NIST SP 800-63B instead of raw entropy.
* `generate_password()` / `generate_passphrase()` — OS-secure randomness; the
  passphrase list holds 1,228 curated words.
* `crypto_logic.py` — Caesar, Vigenère, Base64, SHA-256, PBKDF2, AES-256-GCM and
  RSA-2048-OAEP; classic ciphers are labelled educational; real crypto uses the
  audited `cryptography` library. Includes a verified **80-question** quiz bank.
* `crypto_ui.py` — the Crypto Lab overlay (8 tools + quiz).

### Block 3 — Scan Reports (`modules/scanner/`)
* One PowerShell script (UTF-16LE, `-EncodedCommand`) queries
  `Get-NetTCPConnection`, `Get-NetUDPEndpoint`, `Get-Process`, `Get-CimInstance`,
  `Get-NetFirewallProfile`, `Get-NetFirewallRule`, `Get-Service`, `Get-HotFix`.
* `analyze_ports()` classifies **firewall truth**: exposed / blocked / loopback /
  unknown — a listener on `0.0.0.0` that the firewall blocks is *not* reported as
  a hole.
* `analyze_connections()` flags suspicious outbound behaviour;
  `analyze_services()` checks Defender/Update/BITS; `analyze_patches()` grades
  update recency.
* `assess_baseline()` + `baseline_summary()` — CIS Level-1-style hardening checks
  with pass/fail/not-verifiable states and a hardening percentage;
  `append_hardening_score()` keeps a 30-scan trend.
* `diff_reports()` — drift detection against the previous scan.
* `exposure_summary()` — severity counts, 0–100 exposure score, posture verdict.

### Block 4 — Firewall Builder (`modules/firewall/`)
* Three validated command builders: **Windows Defender** (`New-NetFirewallRule`,
  `allow|block`, `in|out`), **MikroTik RouterOS** (`/ip firewall filter add`,
  `accept|drop`), **Cisco IOS** (named extended ACL, `permit|deny`).
* `simulate_acl()` — first-match evaluation for teaching, returning the deciding
  entry, the per-ACE trace and the implicit-deny outcome.
* `read_firewall_rules()` + `parse_windows_rules()` — live rule audit view.
* Teaching content: WAN-hardening recipe, ACL templates, port/attack reference.
* `learn.py` — Practice labs (3 scenarios) and a 12-question concepts quiz.

### Block 5 — Traffic Dashboard (`modules/traffic/`)
* `run_snapshot()` — adapter byte counters (`Get-NetAdapterStatistics`) and
  established connections with process paths.
* `compute_rates()` — throughput between two samples, clamping counter resets.
* `diff_connections()` — new/closed highlighting; `new_process_alerts()` — processes
  that started talking; `detect_beacons()` + `beacon_anomalies()` — regular-interval
  beacon candidates with a jitter score.
* `top_talkers()`, `summarize()`, `is_public_remote()`, `is_suspicious_path()`.
* `report.py` — CSV snapshot export.

---

## 4. Data flow (example: a scan)

```
UI (Scan Reports)                 logic.py                  Windows
─────────────────                 ─────────                 ───────
"Run local scan" ──► ScanWorker (QThread)
                        │
                        ├─► run_local_scan() ──── PowerShell -EncodedCommand ──► cmdlets
                        │        ◄──────────────────── JSON ──────────────────────┘
                        ├─► build_report(payload)         (parsing + analysis)
                        ├─► diff_reports(previous, current)
                        ├─► assess_baseline() / baseline_summary()
                        ├─► append_hardening_score() ──► %LOCALAPPDATA%\Bastion\
                        └─► signal ──► UI renders cards, tables, findings
```

Nothing is written outside `%LOCALAPPDATA%\Bastion\`, and only summaries — never
passwords, keys or packet data.

---

## 5. Concurrency model

Long-running work never blocks the interface. Each module owns a `QThread`
subclass that performs one unit of work and emits a signal:

| Worker | Module | Work |
| --- | --- | --- |
| `ScanWorker` | Scan Reports | one full local scan |
| `SnapshotWorker` | Traffic Dashboard | one traffic sample (timer-driven) |
| `ResolveWorker` | Traffic Dashboard | batched reverse DNS for visible remotes |
| `FirewallRulesWorker` | Firewall Builder | read existing firewall rules |
| `ConnectivityWorker` | Shell (`app.py`) | internet probe (auto-refresh 30 s) |

Results are rendered on the GUI thread in the signal slot.

---

## 6. Browser preview and parity

`ui_preview.html` (with `preview_server.py`) is a self-contained interactive model of
all five modules using generated sample data. It exists because the visual layer is
easier to review and iterate in a browser and because the sandbox used during
development cannot render Qt.

Parity is treated as a first-class requirement:

* Data banks (common passwords, subnet quiz, crypto quiz, passphrase words,
  incident reference) are generated from the Python sources into the page, so the
  two cannot drift.
* Command rendering and validation messages were compared case-by-case between the
  JavaScript mirror and `logic.py` (identical strings).
* A 25-component parity audit across shell, all five modules, dialogs and reports
  currently reports **0 mismatches**.

The preview never performs security actions; it is labelled as a preview in the UI
and in the footer notice.

---

## 7. Packaging

| Piece | File |
| --- | --- |
| PyInstaller specification (windowed, icon, version metadata) | `packaging/bastion.spec` |
| Windows version resource | `packaging/version_info.txt` |
| Brand assets | `assets/bastion.ico` (7 sizes), `assets/bastion-icon.png` |
| One-click build | `build.ps1` (`-Test`, `-Zip`, `-Clean`) |
| Build-only dependencies | `requirements-build.txt` |
| Live-OS integration check | `packaging/verify_windows_modules.py` |
| Continuous integration | `.github/workflows/windows-build.yml` (windows-latest) |

The CI pipeline runs the tests, exercises the PowerShell-backed modules against the
real OS, builds the executable, smoke-launches it and uploads it as an artifact.

---

## 8. Known limitations

* **Windows-only system features** — Scan Reports, Traffic Dashboard and the
  firewall audit require Windows PowerShell; elsewhere they report a clear error.
* **No packet capture** — throughput is derived from adapter byte counters and
  connection listings, which keeps the tool lightweight and permission-light but
  cannot show payloads.
* **Baseline checks are best-effort** — registry-only controls (SMBv1, RDP NLA,
  print spooler) are reported as *not verifiable* rather than guessed.
* **Beacon detection is heuristic** — regular update checkers legitimately match the
  pattern, so candidates are labelled as candidates, never verdicts.
* **GUI rendering is verified on Windows** — the development sandbox cannot open a
  Qt window, so the visual layer is verified by the parity audit and the Windows
  smoke test.
