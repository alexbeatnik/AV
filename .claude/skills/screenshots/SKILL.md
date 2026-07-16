---
name: screenshots
description: Retake the four README screenshots (dashboard, logs, quarantine, settings) by driving the running AV app through UI Automation. Use when asked for new/updated README screenshots or to capture the app's pages.
---

# README screenshots

Run the ready-made script — it drives the app end-to-end and writes the four
PNGs to `screenshots\` (the paths README.md embeds):

```powershell
# full flow: clear log → real quick scan (~3-5 min) → capture all four pages
& .claude\skills\screenshots\capture.ps1

# just capture the pages as they are (no scan)
& .claude\skills\screenshots\capture.ps1 -NoScan
```

Run it **in the background** (it takes minutes and moves the mouse) and check
its output for `MISS:` lines (a UIA name lookup failed) and `saved:` lines.
Warn the user first that the mouse will move on its own. Review every PNG
with the Read tool before calling the job done — a stray modal (threat
dialog, MessageBox) photobombs silently.

## Preconditions

- The UI must be in **English** (`lang=en` in `settings.ini` next to the exe
  that runs) — the script clicks controls by their UIA Name, which is the
  visible English text.
- Display scaling must be 100% (`AppliedDPI` 96 in
  `HKCU:\Control Panel\Desktop\WindowMetrics`) for crisp 1:1 pixels.
- Prefer the **installed instance** (`%LOCALAPPDATA%\Programs\AV\AV.exe`,
  usually already running in the tray): it has the real `vt.key`, scan
  history, and staged quarantine entries, so pages look lived-in. The script
  auto-detects the running instance and uses its folder's `scans.log`.

## How it works — hard-won facts, don't rediscover them

- **Single instance**: launching `AV.exe` again does NOT start a second copy —
  it broadcasts a "show yourself" message to the running one and exits. That
  is exactly how the script summons the window from the tray.
- **`Process.MainWindowHandle` lies**: it stays `0` for a form restored from
  the tray. The script finds the window by `EnumWindows` — the visible
  top-level window with caption text `AV` owned by an `AV.exe` pid.
- **Custom controls have no UIA Invoke pattern** (they're owner-drawn
  `Control` subclasses), but every WinForms control has its own HWND, so its
  `Text` shows up as the UIA `Name`. Click targets: nav tabs `Dashboard`,
  `Logs`, `Quarantine`, `Settings`; buttons `QUICK SCAN`, `CLEAR`. Clicks are
  real mouse events at the element's center (`SetCursorPos` + `mouse_event`).
- **Scan completion** is detected by a new `quick scan` summary line appended
  to `scans.log`; after that the script waits 90 s so held-back VirusTotal
  verdicts (16 s each, free tier) drain and the hero returns to "Protected".
- **Capture** = `DwmGetWindowAttribute(DWMWA_EXTENDED_FRAME_BOUNDS)` +
  `Graphics.CopyFromScreen` from a DPI-aware process — window-only pixels, no
  drop shadow. `PrintWindow` is not needed.
- **The monitor watches `%TEMP%`** (and Downloads/Desktop/…): any file another
  tool writes there mid-run becomes an `auto-check of new files` line in the
  log page being photographed. The script clears the log right before the
  scan; don't run other commands while it works.
- **Don't plant a live EICAR file** to stage a detection — Defender's
  real-time protection eats it before AV sees it. The staged quarantine
  entries already in the installed copy are what the quarantine page shows.
