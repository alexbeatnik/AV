# AGENTS.md — guide for AI coding agents (and new contributors)

A WinForms multi-engine antivirus for Windows: ClamAV + YARA rules +
VirusTotal hash checks. One ~280 KB portable exe,
**zero dependencies, zero toolchains**: it builds with the `csc.exe` compiler
that ships inside Windows (.NET Framework 4.8). Keep it that way.
Licensed under Apache 2.0 (`LICENSE`).

## Build & test

```powershell
.\build.ps1   # builds AV.exe with C:\Windows\Microsoft.NET\...\csc.exe
.\test.ps1    # compiles src\ + tests\ into AVUI.Tests.exe and runs it
```

Run **both** after every change. There is no .sln/.csproj and there must not
be one — both scripts glob `src\*.cs` (+ `tests\*.cs`); a new framework
reference means editing the `/r:` lists in **both** scripts. CI
(`.github/workflows/tests.yml`) runs exactly these two scripts on every PR.

## Hard constraints

- **C# 5 only** — the built-in compiler (v4.0.30319) rejects anything newer.
  No `$"..."` interpolation, no `?.`/`??=`, no `nameof`, no expression-bodied
  members, no `out var`, no pattern matching, no tuples, no auto-property
  initializers. `async/await` is available but the codebase mostly uses
  threads + `BeginInvoke`; anonymous callbacks use `delegate(...) { }` syntax.
- **.NET Framework 4.8 BCL only** — no NuGet, no third-party libraries,
  no image assets (icons are GDI+ vector glyphs in `src/Icons.cs`).
- **UTF-8 sources** (`/codepage:65001`); Ukrainian literals are normal.
- The app always runs **non-elevated**. Install/uninstall are per-user
  (`%LocalAppData%\Programs\AV`, HKCU, per-user shortcuts) and need no admin;
  the only admin action (`--fix-wintemp`) is a separate short-lived relaunch
  with `Verb = "runas"` (see `MainForm.Install.cs`).
- Never commit build outputs, `clamav/`, `yara/`, `settings.ini`, `scans.log`,
  `vt.key`, or `quarantine/` (all gitignored).

## Architecture

One `MainForm` class split into partial files by concern:

| File | Concern |
|------|---------|
| `src/MainForm.cs` | state fields, `Main()`, process plumbing, log rendering, autostart |
| `src/MainForm.Ui.cs` | all UI construction, pages, dialogs, `ApplyLanguage()` |
| `src/MainForm.Scan.cs` | scans, progress/ETA, clamd engine, scheduled quick scan |
| `src/MainForm.MemScan.cs` | quick-scan process-memory dumping (RAM regions → temp files → clamd) |
| `src/MainForm.Updates.cs` | DB updates, ClamAV download, app self-update |
| `src/MainForm.Settings.cs` | locating ClamAV, `settings.ini` load/save |
| `src/MainForm.Quarantine.cs` | neutralized `.quar` storage, index, threat dialog |
| `src/MainForm.Monitor.cs` | FileSystemWatcher monitoring, exclusions |
| `src/MainForm.Install.cs` | per-user install/uninstall, ACL fixes |
| `src/MainForm.Usb.cs` | USB volume-arrival prompt |
| `src/MainForm.Yara.cs` | YARA engine: yara64/Forge-rules download, the post-ClamAV scan phase (`OnScanExit` → `RunYaraPhase` → `FinishScan`) |
| `src/MainForm.VirusTotal.cs` | VT API v3: throttled SHA256 lookups, opt-in uploads, trust tiers (`VtClassify`/`ResolvePendingYara` — YARA-only matches are held untouched until the VT verdict decides quarantine / release / user decision) |
| `src/MainForm.Engines.cs` | the Settings → engines dialog (YARA toggle, VT key) |
| `src/Controls.cs`, `src/Icons.cs`, `src/Theme.cs` | custom-drawn controls, glyphs, dark palette |
| `src/Lang.cs` | the English/Ukrainian string table |

UI is built in code; the main window is fixed-size (`FixedSingle`, no
maximize — pages are hand-tuned layouts) and the settings card uses absolute
positions. All state lives on the UI thread — background work goes through `ThreadPool`/threads
and marshals back with `BeginInvoke` (wrapped in `try/catch` for the
form-already-closed case). Child processes set `SynchronizingObject = this`.

Quick scan, full scan, and the dedicated **Scan RAM** dashboard button all dump
running processes' executable RAM (`MainForm.MemScan.cs`): best-effort
`OpenProcess`/`VirtualQueryEx`/`ReadProcessMemory` P/Invoke on the background
listing thread, writing the executable non-image regions to a temp folder so
clamd scans code that is masked or absent on disk. The three entry points share
`BeginListScan(roots, riskyOnly, dumpMemory)` — Scan RAM (`RunMemoryScan`) passes
empty roots so only the dumps are scanned. Inaccessible (protected /
higher-integrity) processes are silently skipped; dumps are capped (per-region
and total) and cleaned up on every scan-exit path and on form close
(`CleanupMemDumps`).

Scan size limits are centralized in `ScanLimitsArg(bool skipBig)` (clamscan
args) and mirrored in `WriteClamdConf()` (clamd.conf) — keep the two in sync.
The per-file/scan-size cap is user-controlled by the "skip large files"
toggle (`chkSkipBig`, `skipbig=` in settings.ini, on by default): 200 MB when
on, `0` = unlimited when off. The other limits (recursion, file count, and
especially `--max-scantime=10000` — 10 s per object) always apply and are
what keep even a multi-GB file from hanging a scan; don't remove them.

## Working rules

Follow the matching rule whenever a change touches one of these areas:

- **`localization`** — every user-visible string goes through `Lang.T("key")`,
  added in `src/Lang.cs` with **both** English and Ukrainian; persistent
  controls are re-texted in `ApplyLanguage()`.
- **`settings-key`** — a `settings.ini` key needs a parser line in
  `LoadSettings()`, a writer in `SaveSettings()`, and graceful degradation
  when missing from old files. Exception: the VirusTotal API key lives in its
  own `vt.key` file (`SaveVtKey`), written only when the user changes the key —
  so a fresh download's default `settings.ini` can never wipe it on install
  (`CarryOverFile` in `MainForm.Install.cs` also never overwrites existing
  destination files).
- **`testing`** — testable logic is exposed as `internal static` members of
  `MainForm` and covered in `tests/*.cs` (zero-dependency reflection runner).
- **`release`** — the version lives in `src/AssemblyInfo.cs`; merging a bump
  to `main` publishes the GitHub Release the app self-updates from.
- **`verify`** — launching the built exe for a manual check: single-instance
  tray app, both languages, and the Defender-eats-EICAR gotcha.
