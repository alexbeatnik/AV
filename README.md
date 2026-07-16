# AV

<p align="center">
  <img src="logo.png" width="128" alt="AV Logo" />
</p>

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows_10_/_11-0078d7.svg)](https://www.microsoft.com/windows)
[![Framework](https://img.shields.io/badge/.NET_Framework-4.8-purple.svg)](https://dotnet.microsoft.com/download/dotnet-framework/net48)
[![Latest release](https://img.shields.io/github/v/release/alexbeatnik/AV?label=release)](../../releases/latest)
[![Downloads](https://img.shields.io/github/downloads/alexbeatnik/AV/total?color=success)](../../releases)
[![Tests](https://img.shields.io/github/actions/workflow/status/alexbeatnik/AV/tests.yml?label=tests)](../../actions/workflows/tests.yml)
![UI languages](https://img.shields.io/badge/UI-English%20%7C%20%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D1%81%D1%8C%D0%BA%D0%B0-green)

A lightweight **multi-engine antivirus for Windows** — three layers of
detection under one portable dashboard:

1. **ClamAV** — the classic signature engine (official, unmodified binaries);
2. **YARA rules** — community heuristics from [YARA Forge](https://yarahq.github.io/)
   that catch malware families and fresh threats signatures miss;
3. **VirusTotal** — suspicious files are checked by hash against 70+ engines,
   so one false alarm from a heuristic rule doesn't scare you for nothing.

The app itself is a single ~290 KB exe; the engines it orchestrates are
fetched automatically on first run (ClamAV with its signature database
~220 MB, YARA with its rules ~15 MB) and kept updated. Interface in
**English** and **Ukrainian**. Idle in the tray it uses under 15 MB of RAM;
nothing is installed system-wide and admin rights are never required.

<p align="center">
  <img src="screenshots/dashboard.png" width="400" alt="Dashboard" />
  <img src="screenshots/logs.png" width="400" alt="Logs" />
</p>
<p align="center">
  <img src="screenshots/quarantine.png" width="400" alt="Quarantine" />
  <img src="screenshots/settings.png" width="400" alt="Settings" />
</p>

## Quick start

1. Download `AV.exe` from the [latest release](../../releases/latest).
2. Run it. The first start asks: install per-user (shortcuts, "Apps" entry,
   no admin rights) or stay portable — a single folder you can carry around.
3. That's it. ClamAV with its signature database (~220 MB) and the YARA
   engine + rules (~15 MB) are downloaded automatically; the app keeps them
   updated and updates itself from GitHub Releases.

To get the VirusTotal layer, paste a free API key from
[virustotal.com](https://www.virustotal.com/) into **Settings →
DETECTION ENGINES…** — by default only file hashes are checked; uploading
unknown files is a separate opt-in toggle.

### "Windows protected your PC" warning

Downloading a release may trigger a SmartScreen / browser warning: the
executable is not code-signed, so every new release is an unknown file with
zero reputation for Windows. This is a reputation notice, not a detection —
each release is built from this repository by the public
[Release workflow](.github/workflows/release.yml). To run it anyway:
**More info → Run anyway**.

On Windows 11 with **Smart App Control** enabled the app is blocked
outright — Smart App Control allows only signed or well-known binaries and
has no per-app exceptions. It can only be switched off entirely (Windows
Security → App & browser control → Smart App Control; one-way — a Windows
reset is needed to re-enable it).

## What it can do

- Scan a file, a folder, or the **whole PC**; **Scan RAM** (live process
  memory — catches injected code masked on disk); **quick scan** of common
  infection points; scheduled quick scans (daily/weekly); or just
  **drag & drop** files onto the window
- **Auto-check of new files**: Downloads, Desktop, Program Files, Temp,
  AppData… are monitored, and new files are scanned by all engines
  automatically
- **Threat handling your way**: per-file choice of quarantine / delete /
  exclude — or silent auto-quarantine
- **Neutralized quarantine**: captured files are XOR-transformed `.quar`
  blobs that can't run and don't trip other antiviruses; everything is
  reversible from the Quarantine page
- **Smart false-positive handling**: a file flagged only by a heuristic rule
  is held untouched until VirusTotal confirms or clears it
- One-click database updates, a stale-database warning, app self-update,
  USB scan offer, exclusions, scan performance modes, color-coded log with
  per-phase progress

## Why this project?

Windows Defender is excellent, and this project is not intended to replace
it. It is a lightweight power-tool demonstrating how distinct, decoupled
detection systems — local signatures, local heuristic rules, and cloud
reputation — can be orchestrated under a single portable dashboard entirely
built in C#.

## For developers

The whole app builds with the `csc.exe` compiler already present in Windows —
no toolchain, no NuGet, one command:

```powershell
.\build.ps1
```

Architecture, the engine pipeline, trust tiers, project structure, and
contributor constraints live in **[README.DEV.md](README.DEV.md)** (and
`AGENTS.md` for AI-agent specifics).

## License

[Apache License 2.0](LICENSE). ClamAV® is a registered trademark of Cisco
Systems, Inc. (GPLv2, run as separate unmodified processes); YARA is ©
VirusTotal (BSD-3); rules by [YARA Forge](https://github.com/YARAHQ/yara-forge)
(licenses of the bundled rule sets apply); VirusTotal is used via its public
API under its terms of service. This project is an independent open-source UI
affiliated with none of them.
