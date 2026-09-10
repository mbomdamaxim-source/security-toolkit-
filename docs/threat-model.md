# Bastion — Threat Model

This document describes what Bastion defends against, what it deliberately does not,
and the threats to Bastion itself.

---

## 1. Assets Bastion protects

| Asset | Why it matters | How Bastion helps |
| --- | --- | --- |
| **The device's network exposure** | An unnecessary listening port is a way in | Scan Reports maps listeners with firewall truth; Firewall Builder closes what is not needed |
| **The user's credentials** | Weak or reused passwords are the most common initial access | Credential Auditor scores strength honestly and generates strong alternatives |
| **The user's understanding** | A user who does not understand *why* cannot maintain security | Every module explains its findings; labs and quizzes teach the reasoning |
| **The device's network behaviour** | Malware and unwanted software reveal themselves through connections | Traffic Dashboard surfaces new talkers, unusual ports and regular beaconing rhythms |

---

## 2. Adversaries and threats in scope

| Threat | Typical real-world form | Bastion's countermeasure |
| --- | --- | --- |
| **Exposed remote services** | RDP (3389) or SMB (445) reachable from the network; EternalBlue/BlueKeep-class exploitation | Scan Reports classifies *reachability* (listener + firewall rule), not just "port open"; Firewall Builder produces the blocking rule |
| **Guessable credentials** | Common passwords, mangled words (`P@ssw0rd`), personal data, reused passwords | 2,033-entry bank with leet-aware matching, pattern detection, personal-context check, honest crack-time estimates, secure generator |
| **Human error in configuration** | A firewall rule typed with the wrong direction, action or mask | Validated builders reject wrong vocabulary (`deny` on Windows), check wildcard contiguity, and explain each parameter |
| **Unnoticed change** | A new listener or a stopped security service after an update, install or compromise | Drift detection between scans; per-scan hardening trend |
| **Malware communication** | New process talking to a public address, especially from AppData/Temp; periodic beaconing | Connection heuristics, new-process alerts, beacon candidates with jitter scoring |
| **Patch lag** | Exploits target already-patched vulnerabilities | Update recency grading and an explicit Windows Update reminder (including the `Get-HotFix` blind spot) |
| **Silent exposure of user-writable folders** | Dropped executables in Temp/Downloads that then reach the internet | Path-based scoring in Scan Reports and Traffic Dashboard |

---

## 3. Trust boundaries

```
   USER
     │  types a password, presses buttons
     ▼
┌──────────────────────────────────────────────┐
│ Bastion process (user privileges by default) │
│  • analysis in memory                        │
│  • writes only summaries under %LOCALAPPDATA%│
└───────┬───────────────────────┬──────────────┘
        │ read-only cmdlets     │ outbound TCP (probe; opt-in DNS)
        ▼                       ▼
┌──────────────────┐   ┌───────────────────────┐
│ Local Windows OS │   │ Public endpoints      │
│ (ports, firewall │   │ (1.1.1.1, 8.8.8.8,    │
│  services, fixes)│   │  example.com)         │
└──────────────────┘   └───────────────────────┘
```

**Trust decisions:**

* The local operating system is queried but never modified automatically; system
  changes require an explicit user action and (for firewall rules) administrator rights.
* Public endpoints are contacted only for the connectivity probe (which sends nothing)
  and, optionally, for hostname resolution. No data about the device is transmitted.
* **User input is never trusted**: it is validated before being rendered into a
  command, and commands are displayed for review rather than executed silently.

---

## 4. Threats to Bastion itself

| Threat | Risk | Mitigation |
| --- | --- | --- |
| **Command injection through user input** | A crafted rule name/comment could break out of a generated command | Input is validated (names, ports, addresses, interfaces, characters) and quoted for the target shell before rendering; invalid input is refused with a message |
| **Localized output parsing** | Parsing translated text would silently break on non-English Windows | Only structured cmdlets and JSON are used; `netsh` is avoided entirely (asserted by tests) |
| **Storing secrets** | A password or key written to disk could be stolen later | Nothing sensitive is ever persisted; leaving the Credential Auditor clears the field; history stores only scores |
| **Excessive privilege** | Running elevated all the time widens the blast radius | The app runs unelevated by default; elevation is offered only when needed, and the current state is always visible |
| **Self-inflicted denial of service** | A wrong firewall rule could cut off the machine's network | The app generates but does not auto-apply rules; rule names are unique and reviewable; the audit tab shows what exists |
| **Malicious or accidental data tampering** | A corrupted state file could crash the app or mislead the user | All state files are read defensively (corrupt → treated as empty) and writes never raise |
| **False reassurance** | A tool that over-reports safety is worse than none | Limitations are stated in the UI (unknown firewall state, unverifiable registry checks, `Get-HotFix` blind spot, "candidates not verdicts") |
| **Supply chain** | A compromised dependency could undermine everything | Dependencies are pinned; cryptography uses the audited `cryptography` library rather than home-grown primitives; no network installs at runtime |
| **Antivirus false positives** | Packaged security tools are often flagged | UPX compression is disabled in the spec; version metadata and an icon are embedded; the binary is built from visible source |
| **Shoulder surfing / logs** | Sensitive input visible on screen or in logs | Password fields are masked with an explicit reveal toggle; no plaintext is logged; the scan report exports only derived findings |

---

## 5. Explicitly out of scope

* **Remote scanning or exploitation** — Bastion never targets another machine.
* **Packet capture and payload inspection** — only counters and connection metadata.
* **Malware removal or quarantine** — it reports suspicious behaviour, it does not
  clean it.
* **Full CIS/STIG compliance assessment** — the baseline checks are Level-1-style
  indicators, not a certified audit.
* **Protecting against an attacker who already has administrator rights** — at that
  point the operating system itself is untrusted.
* **Network-level protection** — a host firewall is one layer; routers, segmentation
  and monitoring are separate concerns.

---

## 6. Residual risk statement

After using Bastion, the following risks remain and should be stated honestly:

1. **Larger breach corpora exist.** The 2,033-entry bank and the pattern detectors
   catch common cases; a password absent from the bank but present in a multi-million
   entry breach list will be scored optimistically.
2. **Beacon detection is behavioural and heuristic.** Legitimate updaters match the
   pattern; absence of candidates does not prove absence of compromise.
3. **Firewall truth depends on readable policy state.** Where the firewall cannot be
   queried, exposure is reported as *unknown*, which is the safe direction but not a
   guarantee.
4. **Baseline registry controls are not inspected.** SMBv1, RDP NLA and spooler state
   are reported as *not verifiable* rather than guessed.
5. **The tool cannot see traffic it does not generate.** Connections that open and
   close between samples are invisible.

These limitations are documented in the application itself (not only here), so the
user is never told they are safer than the evidence supports.
