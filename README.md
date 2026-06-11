# WinSpector

A modular Windows process and driver activity monitor — a mini-EDR built from scratch in Python. WinSpector watches running processes, scans loaded drivers against a known-malicious-driver database, mines Windows event logs in real time, scores everything against a custom detection rule set, and exports alerts to an Elastic SIEM.

It was built and tested against a real meterpreter payload, a masquerading binary running reconnaissance commands, and an EICAR test file — all caught live.

## What it does

WinSpector runs as a single Python process on a Windows 10 host and continuously:

- **Watches every running process** — hashes each executable (SHA-256), checks Authenticode signatures, and tracks process creation/termination including PID reuse detection
- **Scans every loaded driver** — checks each `.sys` file against a local copy of the [LOLDrivers](https://www.loldrivers.io/) database of known-vulnerable and known-malicious drivers, with integrity verification on the database itself
- **Mines Windows event logs in real time** — Sysmon (process create, network connection, image load, process injection, file create) and native Windows Security/System logs (process creation, service installs)
- **Scores everything** against 17 detection rules covering masquerading, living-off-the-land execution, C2 callbacks, LOLDriver matches, and reconnaissance behaviour
- **Displays a live terminal dashboard** — five-panel Rich TUI showing alerts, process diffs, event stream, and driver scan status in real time
- **Exports scored alerts to Elasticsearch** — for SIEM-style querying and investigation in Kibana

## Architecture

```
+----------------  +  +------------------ +  +-------------------- +
¦ Process Watcher  ¦  ¦  Driver Scanner   ¦  ¦  Event Log Miner    ¦
¦ (psutil + WMI)   ¦  ¦  (LOLDrivers DB)  ¦  ¦ (Sysmon + Security) ¦
+------------------+  +-------------------+  +---------- ----------+
         ¦                      ¦                        ¦
         +----------------------+------------------------+
                                ¦
                         +------?-------- +
                         ¦  Alert Scorer  ¦
                         ¦  (17 rules,    ¦
                         ¦   0-100 score)  ¦
                         +---------------- +
                                 ¦
                  +----------------------------- +
                  ¦                              ¦
          +-------?-------- +           +--------?--------- +
          ¦ Rich Dashboard  ¦           ¦ Elastic Exporter  ¦
          ¦ (live terminal) ¦           ¦ (Bulk API ? ES)   ¦
          +-----------------+           +-------------------+
```

Each module is independent and testable on its own. The alert scorer is the only component that knows about detection logic — process watcher, driver scanner, and event miner only collect and normalise data.

## Detection rules

17 additive scoring rules, 0–100 scale, alert threshold =30:

| Rule | Trigger | Score |
|---|---|---|
| RULE-001 | `svchost.exe` with non-`services.exe` parent | +70 |
| RULE-002 | `svchost.exe` with no `-k` flag | +60 |
| RULE-003 | shell spawned by `cmd.exe` | +35 |
| RULE-004 | unsigned binary in `%TEMP%`/`%APPDATA%` | +55 |
| RULE-005 | unsigned binary (any location) | +30 |
| RULE-006 | shell spawned by non-standard parent | +40 |
| RULE-007 | `cmd.exe` spawned from `%TEMP%`/`%APPDATA%` binary | +60 |
| RULE-008 | blank PE metadata (FileVersion/Description/Company) | +35 |
| RULE-009 | `.exe` dropped to `%TEMP%` by a shell | +55 |
| RULE-010 | outbound TCP from `%TEMP%`/`%APPDATA%` binary | +70 |
| RULE-011 | non-standard high port from unknown process | +25 |
| RULE-012 | LOLDrivers hash match | +100 (critical) |
| RULE-013 | unsigned driver loaded | +60 |
| RULE-014 | driver loaded from non-standard path | +50 |
| RULE-015 | recon tool (`whoami`, `ipconfig`, etc.) spawned by suspicious-path binary | +50 |
| RULE-SVCINSTALL | new service installed | +30 |
| RULE-SVCINSTALL-SUSPPATH | new service binary in suspicious path | +45 |

Two of these rules have been published as [Sigma rules](sigma_rules/) — the open, SIEM-agnostic detection format.

## Real detections

WinSpector was tested against real and simulated attacker behaviour in an isolated lab (Win10 target, Kali attacker, Ubuntu Elastic backend, Flare VM for malware analysis — all on host-only networks, no internet access for the attack/analysis VMs).

**Meterpreter reverse_tcp payload** — a `windows/x64/meterpreter/reverse_tcp` payload was downloaded via PowerShell and executed. WinSpector flagged it within seconds:

- `RULE-004`: unsigned binary in `%TEMP%` — score 55 (MEDIUM)
- Sysmon corroboration: process create (EID 1), outbound connection to attacker on port 4444 (EID 3), file write (EID 11), termination after Defender quarantine (EID 5)
- Static analysis confirmed: single import (`VirtualProtect`), entry point in an RWX section, `CLD` + PEB-walking shellcode signature.

**Masquerading binary running reconnaissance** — `calc.exe` copied to `%TEMP%\svchost32.exe` and used to run `whoami`:

- `RULE-004`: process image in suspicious path — score 40 (LOW)
- `RULE-015` (added as a direct result of this test): recon tool spawned by suspicious-path binary — score 50 (MEDIUM)
- Both Sysmon (EID 1) and Windows Security (EID 4688) corroborated the same chain

**EICAR test file** — written to `%TEMP%` via PowerShell:

- `RULE-009`: executable dropped to temp by `powershell.exe` — score 55 (MEDIUM)
- Detection latency: under 5 seconds

## Tech stack

- **Python 3.12**, hash-pinned dependencies (`pip install --require-hashes`)
- **psutil** + **pywin32** for process and WMI access
- **win32evtlog** (EvtQuery/EvtNext/EvtRender) for event log mining — XML-based, works across Sysmon and native channels uniformly
- **Rich** for the terminal dashboard
- **SQLite** (WAL mode) for event persistence and cursor tracking
- **Elasticsearch + Kibana** for SIEM export and querying
- **Sigma** for portable detection rules

## Security hardening

This project takes its own security seriously — it's a security tool, so it shouldn't introduce vulnerabilities of its own:

- All subprocess calls (PowerShell signature checks) use strict path validation against an injection-safe regex — no `shell=True`, no string interpolation into commands
- LOLDrivers database integrity verified via SHA-256 manifest on every startup; 7-day staleness warning
- Snapshot output files are hashed and recorded in an append-only manifest for tamper evidence
- Signature verification results cached with a 10-minute TTL to prevent stale trust after binary swaps
- PID reuse detected via process creation time comparison — prevents a 5-second poll window from missing a spawn+exit+respawn sequence
- Dependencies installed via `pip install --require-hashes -r requirements-pinned.txt`

## Running it

Requires Windows 10/11, Python 3.12, and Sysmon installed with a process-creation/network/file-create logging configuration.

```powershell
git clone https://github.com/Shantanu0001/winspector.git
cd winspector
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements-pinned.txt

# Download the LOLDrivers database
Invoke-WebRequest -Uri "https://www.loldrivers.io/api/drivers.json" -OutFile "data\loldrivers\drivers.json"

# Run as Administrator (required for driver scanning and Security log access)
python main.py
```

Optional — point alerts at an Elasticsearch instance by editing the `ElasticExporter` URL in `main.py`.

## Project structure

```
winspector/
+-- main.py                    # entry point, dashboard loop
+-- requirements-pinned.txt    # hash-pinned dependencies
+-- winspector/
¦   +-- models.py              # shared dataclasses
¦   +-- process_watcher.py     # Module 1
¦   +-- driver_scanner.py      # Module 2
¦   +-- event_log_miner.py     # Module 3
¦   +-- alert_scorer.py        # Module 4
¦   +-- dashboard.py           # Module 5a
¦   +-- elastic_exporter.py    # Module 5b
+-- sigma_rules/                # portable detection rules
+-- data/loldrivers/manifest.json  # LOLDrivers DB integrity anchor
```