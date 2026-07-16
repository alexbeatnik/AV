# Copilot instructions — AV

WinForms multi-engine antivirus app compiled with the `csc.exe` built into
Windows (.NET Framework 4.8, compiler v4.0.30319). One portable exe, zero
dependencies, zero toolchains. `AGENTS.md` is the full contributor guide
(localization, settings-key, testing, release and verify rules).
License: Apache 2.0.

## Environment constraints — do NOT flag these as issues

The compiler only supports **C# 5**, so the following are deliberate and
must not be "modernized" in suggestions or review comments:

- No `$"..."` interpolation (`string.Format`/concatenation is correct here).
- No `?.`, `??=`, `nameof`, expression-bodied members, `out var`, pattern
  matching, tuples, auto-property initializers, or C# 6+ features of any kind.
- Anonymous callbacks use `delegate(...) { }` syntax — not lambdas converted
  to expression trees or newer idioms (plain lambdas do exist and are fine).
- Threads + `BeginInvoke` instead of `async/await` in most places.
- No NuGet packages, no third-party libraries, no `.csproj`/`.sln` (file
  lists live in `build.ps1`/`test.ps1`), no image assets (icons are GDI+
  code in `src/Icons.cs`).
- The main window is fixed-size by design (`FixedSingle`, minimize/maximize
  boxes dropped, ✕ hides to the tray; pages are hand-tuned layouts) — don't
  suggest making it resizable/responsive or restoring the caption buttons.
- The settings page uses absolute pixel positions by design.
- UI strings live in `src/Lang.cs`, built in code — no resx, no designer.
- Quick scan, full scan, and Scan RAM read other processes' memory via `kernel32` P/Invoke
  (`OpenProcess`/`VirtualQueryEx`/`ReadProcessMemory` in `src/MainForm.MemScan.cs`)
  to scan executable RAM regions — this is intentional (malware detection),
  best-effort, and runs non-elevated: failing to open a protected process is
  expected and swallowed, not a bug.
- `src/MainForm.Yara.cs` polls its own child process with
  `GetProcessIoCounters` (kernel32 P/Invoke) to estimate the YARA phase's
  progress — yara64 prints nothing per file, so bytes-read is the only
  signal. The estimate is deliberately capped at 99%; only the process exit
  completes the phase. Don't suggest replacing it with output parsing.

## What TO check in review

- **C# 6+ syntax sneaking in** — it breaks the build on a stock machine.
- **Hardcoded user-visible strings** — every UI/log/tray/dialog string must
  go through `Lang.T("key")` with **both** English and Ukrainian entries
  (`A(key, en, uk)` in `src/Lang.cs`); persistent controls must be re-texted
  in `ApplyLanguage()` (`src/MainForm.Ui.cs`). Format placeholders (`{0}`…)
  must match between both translations and the call site.
- **settings.ini keys**: a new key needs a parser line in `LoadSettings()`,
  a writer line in `SaveSettings()` (`src/MainForm.Settings.cs`), and must
  degrade gracefully when missing from an old settings file. Corrupt values
  must not throw during startup — timestamps go through the range-checked
  `TryParseTicks`, never a bare `new DateTime(ticks)`.
- **Threading**: background work must marshal to the UI thread via
  `BeginInvoke` wrapped in `try/catch` (the form may already be closed);
  child `Process` objects set `SynchronizingObject = this`; no UI-thread
  blocking waits on child processes.
- **Per-scan state**: anything that lives and dies with one scan (a counter,
  a phase flag, cancel-related state) belongs in `src/ScanSession.cs`, not in
  a new `MainForm` field — `ResetScanState` replaces the session wholesale,
  which is what guarantees no state leaks between scans. Background workers
  must capture the session they were started for (`var ses = scan;`) and
  check *its* `Cancel` flag instead of reading the live `scan` field. State
  that must outlive the scan (e.g. `vtPendingYara`, cumulative stats) stays
  on `MainForm`.
- **Scan limits**: `ScanLimitsArg(bool skipBig)` (clamscan) and
  `WriteClamdConf()` (clamd.conf) must stay in sync. The file/scan-size cap is
  user-controlled by the "skip large files" toggle (`chkSkipBig`, `skipbig=`,
  default on): `200M` when on, `0` = unlimited when off — don't flag the `0`
  as a bug. The other limits, especially `--max-scantime=10000` (10 s/object),
  must stay: they, not a size cap, are what prevent a huge file from hanging a
  scan.
- **Elevation**: the main app must never require admin. Install, uninstall and
  self-update are per-user and unelevated; only `--fix-wintemp` elevates, via a
  separate short-lived relaunch (`src/MainForm.Install.cs`).
- **Tests**: new pure logic should be an `internal static` member of
  `MainForm` with a test in `tests/` (zero-dependency runner; classes named
  `*Tests`, methods `Test*`). CI runs `build.ps1` + `test.ps1` on every PR.
- **Self-update safety**: releases are consumed by the app's self-updater —
  changes to `.github/workflows/release.yml`, asset names, or versioning in
  `src/AssemblyInfo.cs` must keep the `AV.exe` asset name and strictly
  increasing versions.
- Committed artifacts: `AV*.exe`, `clamav/`, `yara/`, `settings.ini`,
  `scans.log`, `vt.key`, `quarantine/` must never appear in a PR.

## Review tone

Prefer a few high-confidence findings over volume. Skip style nitpicks that
conflict with the constraints above.
