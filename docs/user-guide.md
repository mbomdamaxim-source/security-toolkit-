# Bastion — User Guide

**Learn your system. Secure your system.**

This guide explains what Bastion does, how to start it, and how to use each module
to actually improve the security of your Windows device.

---

## 1. What Bastion is (and is not)

**It is** a local, educational security toolkit for the computer it runs on: it maps
your exposure, checks your credentials, helps you build firewall rules, and watches
your network activity.

**It is not** a remote scanner, a penetration-testing tool, or a replacement for
antivirus. Bastion never attacks anything and never scans other people's machines.

---

## 2. Installing and starting

### Run from source

```powershell
cd path\to\security-toolkit-
.\start.ps1
```

The script creates a virtual environment, installs the requirements and launches the
app. Options: `-Test` (run the test suite first), `-Preview` (open the browser preview
instead), `-NoLaunch` (set up only).

Manual alternative:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

### Build a standalone executable

```powershell
.\build.ps1 -Test -Zip
```

Produces `dist\Bastion.exe` (double-click to run; no Python needed) and
`Bastion-windows.zip`.

### Administrator rights

Bastion starts **without** elevation and says so in the banner at the top. Only
actions that change system settings need administrator rights, and the banner offers
a button to restart elevated. Never run it as administrator "just in case".

---

## 3. The window

```
┌───────────────────────────────────────────────────────────────────────┐
│ ☰/✕   Bastion 0.1.0 — Learn your system. Secure your system.          │
│                          Internet: Online (12 ms)  [Check]  [About]   │
├───────────────────────────────────────────────────────────────────────┤
│ Administrator privileges are not active. … [Restart with admin]        │
├──────────────┬────────────────────────────────────────────────────────┤
│ Subnet       │                                                        │
│ Credential   │   module content (scrolls inside this area)            │
│ Scan Reports │                                                        │
│ Firewall     │                                                        │
│ Traffic      │                                                        │
└──────────────┴────────────────────────────────────────────────────────┘
```

* **☰ / ✕** collapses or expands the sidebar.
* **Internet: Online/Offline** is a live read-only probe; **Check** retries.
* **About** shows the version, purpose and module list.
* The content area scrolls internally, so the navigation never disappears.

---

## 4. Module 1 — Subnet and VLSM

**Purpose:** plan address space and practise the fundamentals.

**Calculator tab**
1. Enter a base network (default `192.168.10.0/24`).
2. Set host requirements for Users / Servers / Management, or add your own rows.
3. Press **Calculate VLSM allocation** — each row shows network, CIDR, mask, usable
   range, broadcast, capacity and unused addresses, plus the unallocated remainder.
4. Use **Copy allocation summary** or **Export Word Report** for documentation.

**Route summariser** (button, top right) — paste the networks you manage, one CIDR
per line, and press **Find summary route**. Bastion returns the smallest single
summary route, its block size and the number of unused addresses inside it (an exact
or inexact summarisation).

**Quiz tab** — choose a study mode (Practice, or Exam 10/20/30 minutes) and a
category. During a quiz: `A`–`D` select an answer, `Enter` checks or advances,
`Esc` returns to setup. Afterwards you get a per-category report, a review of missed
questions, and a **Category mastery** panel built from your previous attempts.

---

## 5. Module 2 — Credential Auditor

**Purpose:** find weak passwords *before* an attacker does, and learn what makes a
password strong.

1. Type a password. Nothing is stored, logged or transmitted — the analysis happens
   in memory on your device.
2. Read the verdict: score out of 100, strength label, entropy estimates
   (random-choice and pattern-aware), and estimated cracking time for an offline
   attacker (1 billion guesses/second) and an online attacker (1,000/second).
3. The checklist tells you exactly what is missing. Detected patterns (keyboard
   walks, repeats, years, embedded common words, your own personal context) are
   named, and a warning appears if the password is in the 2,033-entry common bank.
4. **Generate strong password** creates a random password; **Generate passphrase
   (4 words)** creates a NIST-style word sequence (~51.7 bits). **Copy** puts it on
   the clipboard. Leaving the module clears the field.

**Crypto Lab** (button, top right) — eight hands-on tools: Caesar (with a brute-force
breaker), Vigenère, Base64, SHA-256, AES-256-GCM (including a tamper demo that proves
integrity protection) and RSA-2048 key pairs. A **Quiz** tab tests the concepts with
80 verified questions and an explanation for every answer.

---

## 6. Module 3 — Scan Reports

**Purpose:** see exactly how your device is exposed.

Press **Run local scan**. The scan is read-only and uses PowerShell cmdlets. You get:

| Section | What to look for |
| --- | --- |
| **Security posture + exposure score** | A quick 0–100 summary and severity counts. |
| **Hardening baseline (CIS Level-1 style)** | Eight checks with pass/fail/not-verifiable states, a hardening percentage, a trend line across your last scans, and a *why* line for each check. |
| **What changed since the last scan** | New listeners and stopped services — drift is often more interesting than a static list. |
| **Findings** | Severity-ordered issues. A port listening on `0.0.0.0` that the firewall **blocks** is reported as *info*, not as a hole — the report tells the truth about reachability. |
| **Listening ports (TCP/UDP)** | Each row shows the owning process and the firewall truth: *Exposed - firewall allows*, *Blocked by firewall*, *Loopback only*, or *Firewall unknown*. |
| **Active connections** | Outbound connections flagged when the process runs from a user-writable folder or uses an unusual port. |
| **Services / Hotfixes** | Running state of security services and update recency. |

Press **Export Word Report** to save everything as a `.docx` document.

---

## 7. Module 4 — Firewall Builder

**Purpose:** create correct firewall rules for three platforms without breaking
anything. Bastion **generates and validates** commands; you decide what to run.

**Windows Defender tab** — fill the form (name, action Allow/Block, direction
Inbound/Outbound, protocol, port, profile, optional remote address, program,
description). The exact `New-NetFirewallRule` command appears as you type, with an
explanation of every parameter. Three one-click templates are provided (Allow HTTPS,
Block RDP, Block SMB outbound). **Copy command**, then run it in an **elevated**
PowerShell.

**MikroTik RouterOS tab** — build a filter rule (chain, accept/drop, protocol, port,
addresses, interface, connection state, comment) or press **Generate WAN hardening
recipe** to get the classic seven-rule protection sequence for your WAN interface.

**Cisco IOS ACL tab** — add access-control entries (permit/deny, protocol, source,
destination, port operator, log) and apply the ACL to an interface. Two templates are
included (block risky inbound, SSH from a management host). Use the **first-match
simulator** to send a test packet through your ACL and see which entry decides — the
best way to understand top-down evaluation and the implicit deny.

**Rule audit tab** — **Load rules** reads your existing Windows firewall rules
(searchable, filterable by direction/action/state) so you can review what is already
allowed. The tips panel reminds you to verify changes from another host, enable
firewall logging, and review Inbound+Allow+Public rules first.

**Practice & Quiz** (button, top right) — three scenario labs and a concepts quiz.

---

## 8. Module 5 — Traffic Dashboard

**Purpose:** understand what your device is talking to, right now.

1. Press **Start monitoring** and choose an interval (3/5/10 seconds).
2. **Throughput** shows live download/upload rates per adapter.
3. **What changed since the last sample** highlights new and closed connections —
   a new process starting to talk is the single most interesting event.
4. **Findings** flag new processes (especially from AppData/Temp), unusual outbound
   ports and user-writable executables.
5. **Beacon candidates** lists connections that reappear on a very regular rhythm
   with a jitter score. This pattern matches command-and-control software — and also
   legitimate update checkers, so it is a prompt to look, not a verdict.
6. **Top talkers** and the **Established connections** table show who is busiest.
   Tick **Resolve hostnames** to turn addresses into names (opt-in; it uses the
   network).
7. **Export CSV** saves the current snapshot.

Monitoring stops automatically when you leave the module.

---

## 9. Privacy and data

Bastion keeps nothing sensitive:

* Passwords, keys and plaintexts are never written to disk, logged or exported.
* Under `%LOCALAPPDATA%\Bastion\` it stores only quiz summaries, an allowlist of
  listener ports you marked as expected, the previous scan (for drift) and the
  hardening-score history.
* The internet probe and hostname resolution are the only outbound operations; the
  probe sends nothing, and hostname resolution is off by default.

Delete that folder at any time to reset Bastion's local state.

---

## 10. Troubleshooting

| Symptom | Explanation |
| --- | --- |
| Scan Reports or Traffic Dashboard reports "PowerShell was not found" | Those modules need Windows PowerShell (included with Windows). |
| A baseline check says "not verifiable" | That control (SMBv1, RDP NLA, print spooler) needs registry access Bastion does not use; verify it manually. |
| Internet shows Offline while pages load | A firewall or proxy may block the probe endpoints; this does not affect the other modules. |
| The app cannot display a window ("libGL"/platform plugin) | On Linux, install the Qt/OpenGL system libraries; Windows is the supported platform. |
| Some tests are skipped | The GUI test skips itself when no display is available — this is expected. |
