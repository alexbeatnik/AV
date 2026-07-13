# Antivirus AV

A lightweight **multi-engine antivirus for Windows**. Three layers of detection
in one ~250 KB portable exe with **zero dependencies and zero toolchains** —
builds with the `csc.exe` compiler already built into Windows (.NET Framework
4.8, present on Win10/11):

1. **ClamAV** — the classic signature engine (official, unmodified binaries,
   downloaded automatically);
2. **YARA rules** — a second detection engine running community rules from
   [YARA Forge](https://yarahq.github.io/) (plus your own custom `.yar` files)
   over every scan, catching malware families and fresh threats the signature
   database misses;
3. **VirusTotal** — suspicious and unknown files are checked by SHA256 hash
   against 70+ engines; files VirusTotal has never seen can (opt-in) be
   uploaded for analysis.

Based on [ClamAV-WindowsUI](https://github.com/alexbeatnik/ClamAV-WindowsUI).
The interface is available in **English** (default) and **Ukrainian**,
switchable anytime from Settings.


## How the three engines work together

Every scan (manual, quick, full, RAM, and the automatic new-file monitor) runs
in phases over the exact same file list:

1. **ClamAV** scans the files (via the fast `clamd` daemon with parallel
   workers, falling back to `clamscan` automatically).
2. **YARA** re-checks the same list — including the dumped process memory —
   with `yara64 --scan-list`. Matches are reported as `YARA:<rule>` threats and
   go through the same threat dialog / auto-quarantine pipeline as ClamAV
   detections.
3. **VirusTotal**: files flagged only by YARA (i.e. unknown to the signature
   database) and new files caught by the folder monitor are queued for a
   SHA256 hash lookup (throttled to the free-tier 4 requests/minute). If 3 or
   more engines flag a file, it's treated as a threat — alert, threat dialog,
   or straight to quarantine when auto-quarantine is on. Files unknown to
   VirusTotal are uploaded for analysis **only** if the upload toggle is
   explicitly enabled (files uploaded to VT become visible to researchers
   worldwide — the default is hash-only, nothing leaves the PC).

The YARA engine (`yara64.exe`, from the official
[VirusTotal/yara](https://github.com/VirusTotal/yara) releases) and the YARA
Forge *core* rule set are downloaded automatically on first run and the rules
are refreshed weekly. Custom rules go into `yara\rules\custom\`.

Everything is configured in **Settings → ENGINES: YARA / VIRUSTOTAL…** — the
YARA toggle and rules maintenance, and the VirusTotal API key (free account at
[virustotal.com](https://www.virustotal.com/)) with the hash-check and upload
toggles. The quarantine **Properties** dialog and the **threat dialog** also
have a VIRUSTOTAL button that opens the file's public VT page in the browser —
that works without any API key.

## Features (inherited from ClamAV-WindowsUI)

- Scan a file, a folder, or the **whole PC**; **Scan RAM** (live process
  memory — catches injected/unpacked code masked on disk); **quick scan** of
  common infection points; **fast full scan** (risky file types only, toggle
  in Settings); scheduled quick scans (weekly/daily)
- **clamd engine while scanning**: parallel scanning with the database loaded
  in memory, resident only for the scan's duration
- **Auto-check for new files**: folder monitoring (Downloads, Desktop, Program
  Files, Temp, AppData…) — new files are scanned by all engines automatically
- **Threat handling**: per-file choice of quarantine / delete / exclude, or
  silent auto-quarantine
- **Neutralized quarantine** (XOR-transformed `.quar` files that can't run and
  don't trip other AVs), with search, sorting, properties incl. SHA256
- **Exclusions**, **USB scan offer**, **scan performance modes**, readable
  color-coded log with progress and ETA, statistics
- One-click signature updates, daily auto-checks, app **self-update** from this
  repo's GitHub Releases
- **Portable or installed per-user** (no admin rights) — the first run asks
  once; tray icon, autostart, single instance, dark theme

## Building

```powershell
.\build.ps1   # builds AV.exe with the csc.exe built into Windows
.\test.ps1    # builds and runs the unit tests (AVUI.Tests.exe)
```

Nothing needs to be installed. See `AGENTS.md` for the contributor/agent guide
(hard constraints: C# 5, .NET Framework 4.8 BCL only, no NuGet).

## Installing on a new PC

Copy the single `AV.exe` anywhere and run it. The first start asks: install
per-user to `%LocalAppData%\Programs\AV` (no admin rights, shortcuts, "Apps"
entry) or stay portable. ClamAV (~220 MB with the database) and the YARA
engine + rules (~15 MB) are downloaded automatically.

## Structure

```
src/                       — the application (WinForms, C# 5), one portable exe
  MainForm.Yara.cs         — YARA engine: download, Forge rules, scan phase
  MainForm.VirusTotal.cs   — VT hash lookups, opt-in uploads, rate limiting
  MainForm.Engines.cs      — the engines settings dialog
  MainForm.Scan.cs         — scans, progress/ETA, clamd engine
  MainForm.*.cs            — monitor, quarantine, updates, install, USB, UI…
  Lang.cs                  — English/Ukrainian string table
tests/                     — unit tests + zero-dependency test runner
build.ps1 / test.ps1       — zero-toolchain build scripts
app.ico / logo.png         — placeholder shield icon (temporary branding)
clamav/                    — portable ClamAV (not in git, downloaded)
yara/                      — yara64.exe + rules (not in git, downloaded)
quarantine/                — neutralized (.quar) files + index
```

## License

[Apache License 2.0](LICENSE). ClamAV® is a registered trademark of Cisco
Systems, Inc. (GPLv2, run as separate unmodified processes); YARA is ©
VirusTotal (BSD-3); rules by [YARA Forge](https://github.com/YARAHQ/yara-forge)
(licenses of the bundled rule sets apply); VirusTotal is used via its public
API under its terms of service. This project is an independent open-source UI
affiliated with none of them.
