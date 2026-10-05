# Captures the four README screenshots (dashboard, logs, quarantine, settings)
# by driving the running AV instance through UI Automation. See SKILL.md for
# the gotchas this script already encodes.
#
#   -NoScan   capture the pages as they are, without running a quick scan
#   -OutDir   where the PNGs go (default: <repo>\screenshots)
param(
    [switch]$NoScan,
    [string]$OutDir = ''
)
$ErrorActionPreference = 'Stop'
if ($OutDir -eq '') {
    $OutDir = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path 'screenshots'
}

Add-Type -AssemblyName System.Drawing, System.Windows.Forms, UIAutomationClient, UIAutomationTypes, WindowsBase
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Native {
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, UIntPtr e);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h, int attr, out RECT r, int size);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }

    // Process.MainWindowHandle reports 0 for a form restored from the tray —
    // find the visible top-level window titled "AV" by enumeration instead.
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr lp);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern int GetWindowText(IntPtr h, System.Text.StringBuilder sb, int n);
    delegate bool EnumProc(IntPtr h, IntPtr lp);
    public static IntPtr FindAvWindow(uint targetPid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr h, IntPtr lp) {
            uint pid; GetWindowThreadProcessId(h, out pid);
            if (pid != targetPid || !IsWindowVisible(h)) return true;
            var t = new System.Text.StringBuilder(64); GetWindowText(h, t, 64);
            if (t.ToString() == "AV") { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
"@
[Native]::SetProcessDPIAware() | Out-Null

# Prefer the already-running instance; otherwise start the installed copy,
# falling back to the repo build. A second launch of the same exe only pings
# the running instance to show its window (single-instance broadcast) and exits.
$proc = Get-Process AV -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $proc) {
    $exe = Join-Path $env:LOCALAPPDATA 'Programs\AV\AV.exe'
    if (-not (Test-Path $exe)) { $exe = Join-Path (Split-Path $OutDir -Parent) 'AV.exe' }
    Start-Process $exe
    Start-Sleep 6   # engines init on a cold start
    $proc = Get-Process AV -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $proc) { throw 'AV.exe did not start' }
} else {
    Start-Process $proc.Path   # ping: tells the running instance to show its window
    Start-Sleep 3
}
$avDir = Split-Path $proc.Path -Parent
$log = Join-Path $avDir 'scans.log'

$hwnd = [IntPtr]::Zero
for ($i = 0; $i -lt 10 -and $hwnd -eq [IntPtr]::Zero; $i++) {
    foreach ($p in @(Get-Process AV -ErrorAction SilentlyContinue)) {
        $hwnd = [Native]::FindAvWindow([uint32]$p.Id)
        if ($hwnd -ne [IntPtr]::Zero) { break }
    }
    if ($hwnd -eq [IntPtr]::Zero) { Start-Sleep 1 }
}
if ($hwnd -eq [IntPtr]::Zero) { throw 'AV window not found (is the app running and shown?)' }
[Native]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep 1

$root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)

function Click-Point([int]$x, [int]$y) {
    [Native]::SetCursorPos($x, $y) | Out-Null
    Start-Sleep -Milliseconds 150
    [Native]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)   # left down
    Start-Sleep -Milliseconds 80
    [Native]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)   # left up
    Start-Sleep -Milliseconds 400
}

# Custom-drawn WinForms controls have no UIA Invoke pattern, but each has its
# own HWND, so its Text surfaces as the UIA Name — click its center instead.
function Click-El([string]$name) {
    $c = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::NameProperty, $name)
    $e = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c)
    if ($null -eq $e) { Write-Host "MISS: $name"; return }
    $r = $e.Current.BoundingRectangle
    Click-Point ([int]($r.X + $r.Width / 2)) ([int]($r.Y + $r.Height / 2))
    Write-Host "clicked: $name"
}

function Capture([string]$file) {
    $r = New-Object Native+RECT
    [Native]::DwmGetWindowAttribute($hwnd, 9, [ref]$r, 16) | Out-Null  # extended frame bounds: no shadow
    $w = $r.R - $r.L; $h = $r.B - $r.T
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($r.L, $r.T, 0, 0, (New-Object System.Drawing.Size($w, $h)))
    $g.Dispose()
    $bmp.Save((Join-Path $OutDir $file), [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "saved: $file ($w x $h)"
}

# Activate the window with a click on the empty part of the header
$wr = $root.Current.BoundingRectangle
Click-Point ([int]($wr.X + 350)) ([int]($wr.Y + 45))

if (-not $NoScan) {
    # Clean log, then a real quick scan so the logs page shows the phase flow
    Click-El 'Logs'
    Click-El 'CLEAR'
    Click-El 'Dashboard'
    $base = @(Get-Content $log -ErrorAction SilentlyContinue).Count
    Click-El 'QUICK SCAN'

    # The summary line lands in scans.log when the scan finishes (up to 10 min)
    $done = $false
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep 10
        $lines = @(Get-Content $log -ErrorAction SilentlyContinue)
        if ($lines.Count -gt $base) {
            $new = $lines[$base..($lines.Count - 1)]
            if ($new -match 'quick scan') { $done = $true; break }
        }
    }
    Write-Host "scan finished: $done (waited $(($i + 1) * 10)s)"

    # Held-back VirusTotal verdicts drain at 16 s per lookup (free tier)
    Start-Sleep 90
}

[Native]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep 1
Click-El 'Logs';       Start-Sleep 1; Capture 'logs.png'
Click-El 'Dashboard';  Start-Sleep 1; Capture 'dashboard.png'
Click-El 'Quarantine'; Start-Sleep 1; Capture 'quarantine.png'
Click-El 'Settings';   Start-Sleep 1; Capture 'settings.png'
Click-El 'Dashboard'
Write-Host 'ALL DONE'
