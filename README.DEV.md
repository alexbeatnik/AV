# AV — developer guide

Technical documentation for contributors. The user-facing overview and
quick start live in [README.md](README.md); AI-agent-specific rules and hard
constraints are in [AGENTS.md](AGENTS.md).

## Building

```powershell
.\build.ps1   # builds AV.exe with the csc.exe built into Windows
.\test.ps1    # builds and runs the unit tests (AVUI.Tests.exe)
```

Nothing needs to be installed: the app targets .NET Framework 4.8 and builds
with the C# 5 compiler (`v4.0.30319\csc.exe`) that ships inside Windows.
That imposes the project's hard constraints — **C# 5 syntax only, .NET 4.8
BCL only, no NuGet, no third-party libraries, no image assets** (icons are
GDI+ vector glyphs). There is no `.sln`/`.csproj` and there must not be one:
both scripts glob `src\*.cs`, and CI (`.github/workflows/tests.yml`) runs
exactly these two scripts on every PR. Releases are published by
`.github/workflows/release.yml` whenever the version in
`src/AssemblyInfo.cs` changes on `main`.

## Resource & performance profile

* **Executable size:** ~280 KB (single portable EXE, zero dependencies)
* **Downloads footprint:** ClamAV binary assets and database (~220 MB total)
  + YARA core ruleset (~15 MB total)
* **Typical memory profile:**
  * **While idle:** < 15 MB RAM (in system tray)
  * **While scanning:** ~80 MB RAM for the coordinator UI (`AV.exe`).
    Scanning spawns sub-processes that allocate on demand: the ClamAV
    resident database backend (`clamd`) uses ~1.2 GB RAM (loaded only for
    the active scan duration), and the `yara64` heuristic process typically
    uses ~150 MB RAM while evaluating rules.

## Scan architecture & flow

```
               Scan Input (Disk / RAM / New File Event)
                                 │
                        ┌────────┴────────┐
                        ▼                 ▼
                     ClamAV              YARA
                   Signatures         Heuristics
                        │                 │
                        └────────┬────────┘
                                 ▼
                             Suspicion
                                 │
                                 ▼
                            VirusTotal
                            Arbitration
                                 │
                                 ▼
                          Threat Decision
                        ┌────────┴────────┐
                        ▼                 ▼
                     Quarantine         Exclusion
```

## How the three engines work together

Every scan (manual, quick, full, RAM, and the automatic new-file monitor)
runs in phases over the exact same file list. The status bar labels them —
**Phase 1 of 3: ClamAV**, **Phase 2 of 3: YARA**, **Phase 3 of 3:
VirusTotal** (of 2 when no VT key is set) — and each phase has its own
progress: ClamAV counts scanned files, YARA tracks the bytes its process has
actually read (yara64 prints nothing per file), VirusTotal counts verdicts
received.

1. **ClamAV** scans the files (manual scans use the fast `clamd` daemon with
   parallel workers, falling back to `clamscan` automatically; the small
   new-file batches from the monitor go straight to `clamscan`).
2. **YARA** re-checks the same list — including the dumped process memory —
   with `yara64 --scan-list`. A ClamAV detection is a *verdict*; a single
   community-rule match is only a *suspicion* (YARA Forge rules do hit
   legitimate packers and installers), so the two are trusted differently —
   see the tiers below.
3. **VirusTotal** arbitrates the suspicions: files flagged only by YARA and
   new files caught by the folder monitor are queued for a SHA256 hash lookup
   (throttled to the free-tier 4 requests/minute). Files unknown to
   VirusTotal are uploaded for analysis **only** if the upload toggle is
   explicitly enabled (files uploaded to VT become visible to researchers
   worldwide — the default is hash-only, nothing leaves the PC).

### Trust tiers — how conflicting results are resolved

| Signal | Treated as | What happens |
|--------|-----------|--------------|
| ClamAV signature match | threat | threat dialog / auto-quarantine, immediately |
| YARA match, VirusTotal confirms (≥ 3 engines) | threat | threat dialog / auto-quarantine, named `YARA:<rule> + VirusTotal x/y` |
| YARA match, VirusTotal clean (0 flags from 20+ engines) | likely false positive | file left in place, noted in the log |
| YARA match, VT inconclusive / unknown / unreachable | suspicion | user's call via the threat dialog (or quietly quarantined when auto-quarantine is on — reversible from the Quarantine page) |
| YARA match, no VT key configured | suspicion | classic flow: threat dialog / auto-quarantine |

While a file awaits its VirusTotal verdict nothing touches it, and the scan
does not pretend to be over: it stays in **Phase 3** (busy shield, progress
driven by verdicts received) until the last verdict arrives. Each verdict
lands in the log as it comes in, and the final one closes the scan with a
single tray notification reporting the actual outcome ("scan complete: no
threats found" or "X of N need attention") — quarantine records keep the scan
the suspicion actually came from, even if another scan ran in between. YARA
matches on dumped process memory skip the waiting step — the dump files are
deleted when the scan ends, so they go straight to the threat flow.

The YARA engine (`yara64.exe`, from the official
[VirusTotal/yara](https://github.com/VirusTotal/yara) releases) and the YARA
Forge *core* rule set are downloaded automatically on first run and the rules
are refreshed weekly. Custom rules go into `yara\rules\custom\`.

Everything is configured in **Settings → DETECTION ENGINES…** — the
YARA toggle and rules maintenance, and the VirusTotal API key with the
hash-check and upload toggles. The quarantine **Properties** dialog and the
**threat dialog** also have a VIRUSTOTAL button that opens the file's public
VT page in the browser — that works without any API key.

## Security design pipeline

Every scanned file follows a multi-stage defense-in-depth pipeline to isolate
and eliminate threats efficiently while minimizing performance impact and
preventing false positives on clean files:

```
          [ Threat Sources (Disk / RAM / Folder Monitor) ]
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │ 1. Signature Engine   │ ──(Threat Found)──► [ Auto-Quarantine / Alert ]
                     │    (ClamAV CVD/CLD)   │
                     └───────────────────────┘
                                 │
                            (No matches)
                                 ▼
                     ┌───────────────────────┐
                     │ 2. Heuristics Engine  │ ──(No matches)────► [ Target Allowed (Clean) ]
                     │    (YARA ruleset)     │
                     └───────────────────────┘
                                 │
                            (Suspicious)
                                 ▼
                     ┌───────────────────────┐
                     │ 3. Cloud Reputation   │ ──(Clean / 0 flags)► [ Left in Place (False Pos.)]
                     │  (VirusTotal Hash API)│
                     └───────────────────────┘
                                 │
                           (≥ 3 Engines)
                                 ▼
                     [ Threat Verdict Confirmed ]
                                 │
                                 ▼
                     [ Neutralized Quarantine / XOR ]
```

## Project structure

```
src/                       — the application (WinForms, C# 5), one portable exe
  MainForm.Yara.cs         — YARA engine: download, Forge rules, scan phase
  MainForm.VirusTotal.cs   — VT hash lookups, opt-in uploads, rate limiting
  MainForm.Engines.cs      — the engines settings dialog
  MainForm.Scan.cs         — scans, progress/ETA, clamd engine
  MainForm.*.cs            — monitor, quarantine, updates, install, USB, UI…
  ScanSession.cs           — per-scan state (counters, phases, cancel flag)
  Lang.cs                  — English/Ukrainian string table
tests/                     — unit tests + zero-dependency test runner
build.ps1 / test.ps1       — zero-toolchain build scripts
app.ico / logo.png         — placeholder shield icon (temporary branding)
clamav/                    — portable ClamAV (not in git, downloaded)
yara/                      — yara64.exe + rules (not in git, downloaded)
quarantine/                — neutralized (.quar) files + index
```

A more detailed per-file architecture map (which partial class owns which
concern, threading rules, settings-key conventions, localization rules) is
maintained in [AGENTS.md](AGENTS.md).
