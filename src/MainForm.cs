// MainForm: constants, state fields, entry point, process launching, autostart.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Microsoft.Win32;

namespace AVUI
{
    public partial class MainForm : Form
    {
        // Display name only. Technical identifiers (AV.exe, %LocalAppData%\Programs\AV,
        // the Run/uninstall registry names, the mutex, the release asset name) stay "AV"
        // so installed copies and self-update keep working.
        const string AppName = "AV";
        static readonly string AppVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString(3);
        const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        const string RunValueName = "AV";

        string clamDir;      // folder containing clamscan.exe / freshclam.exe
        string dbDir;        // signature database folder
        string settingsPath; // settings.ini next to the exe
        string quarDir;      // quarantine folder next to the exe
        string quarIndex;    // quarantine\index.txt: "file|original path|date"
        string clamVersion = "—";
        string lastScanInfo = ""; // empty = never scanned yet
        Process currentProc; // running clamscan or freshclam
        long totalScans, totalFound, totalMoved, totalFilesScanned; // cumulative statistics
        bool updateRunning;
        bool reallyClose;    // true = exit, false = minimize to tray
        bool autostartInitialized; // whether autostart was already auto-enabled on first run
        bool modeAsked;            // first-run "portable vs installed" question already answered
        int perfMode = 1;    // scan performance: 0 = low, 1 = normal, 2 = high (see Perf* helpers)

        // The current (or last finished) scan's state — counters, phases, cancel
        // flag. Replaced wholesale by ResetScanState; see ScanSession.cs for the
        // lifecycle rules. Starts as an idle instance so reads never need a null check.
        ScanSession scan = new ScanSession();
        // Generation counter spanning scans: BeginInvoke callbacks and background
        // walkers compare their captured value against it to detect supersession
        int countGen;
        Timer scanHeartbeat;         // logs progress every N seconds even when clamscan is silent
        string scanLogPath;   // scans.log next to the exe
        Timer autoUpdateTimer;
        bool autoUpdateFirstTick = true;

        // Scheduled quick scan: 0 = off, 1 = daily, 2 = weekly (the default)
        int schedMode = 2;
        DateTime lastScheduledScan; // when the last scheduled quick scan started (persisted)
        Timer schedTimer;           // periodically checks whether a scheduled scan is due

        // Exclusions: paths that are not scanned
        readonly List<string> exclusions = new List<string>();

        // Windows paths are case-insensitive: "C:\Temp" and "c:\temp" are the
        // same folder, and storing both means duplicate watchers and repeated
        // monitor scans. Every watch/exclusion addition goes through here.
        internal static void AddPathOnce(List<string> list, string path)
        {
            foreach (string p in list)
                if (string.Equals(p, path, StringComparison.OrdinalIgnoreCase)) return;
            list.Add(path);
        }

        // New-file monitoring
        readonly List<string> watchDirs = new List<string>();
        readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
        readonly Dictionary<string, int> pendingFiles = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        Timer debounceTimer;
        bool watchInitialized; // whether the default monitored folders were already set up
        bool watchDefaultsV2;  // whether the v2 defaults (Temp, Roaming) were already added
        bool watchDefaultsV3;  // whether C:\Windows\Temp was already dropped (v2 mistake — unwatchable non-elevated)
        static readonly string[] TempExtensions = new string[]
            { ".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload" };

        // Potentially dangerous types: executables, scripts, installers, archives,
        // and documents with macros — where real-world malware actually shows up.
        internal static readonly HashSet<string> RiskyExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // executables and libraries
            ".exe", ".dll", ".sys", ".com", ".scr", ".cpl", ".ocx", ".drv", ".efi",
            ".msi", ".msix", ".msp", ".mst", ".appx",
            // scripts and shortcuts
            ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
            ".wsh", ".hta", ".lnk", ".scf", ".reg", ".jar", ".py", ".ahk",
            // documents with macros / exploits
            ".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".xlsb", ".xlm",
            ".ppt", ".pptm", ".potm", ".rtf", ".pdf",
            // archives and disk images (can contain anything)
            ".zip", ".rar", ".7z", ".cab", ".arj", ".gz", ".tar", ".iso", ".img", ".vhd"
        };

        // UI
        ModernButton btnStop, btnUpdate, btnWatchDirs, btnScanLog, btnClearLog;
        ModernButton btnGetYara, btnEnterVtKey; // engine call-to-action buttons on the dashboard strip
        ModernButton dashQuick, dashStop, dashScanFile, dashScanFolder, dashScanAll, dashScanRam, btnInstall, btnLangEn, btnLangUk, btnFixWinTemp, btnAbout, btnEngines;
        ModernButton btnPerfLow, btnPerfNormal, btnPerfHigh;
        Label perfLabel, perfHint;
        ModernButton btnSchedOff, btnSchedDaily, btnSchedWeekly;
        Label schedLabel;
        Label installedBadge;                  // green "✓ Installed" badge
        Label setStatusHeader;                 // STATUS block on the settings page
        Label[] setStatusCaps, setStatusVals;  // engine / database / monitoring / quarantine / scheduler
        ModernButton btnQuarDelete, btnQuarRestore, btnQuarToExcl, btnQuarOpenFolder, btnQuarExclusions;
        ListView quarList;
        StatStrip quarStrip;          // files / total size / last detection above the list
        TextBox quarSearch;           // filters by name, origin path, and threat name
        EmptyState quarEmpty;         // shown instead of an empty list
        ContextMenuStrip quarMenu;
        ToolStripMenuItem quarMenuRestore, quarMenuRestoreExcl, quarMenuDelete, quarMenuOpen, quarMenuProps;
        int quarSortCol = 4;          // default sort: newest first
        bool quarSortAsc = false;
        readonly List<ModernButton> scanButtons = new List<ModernButton>(); // all buttons that start a scan (both pages)
        RichTextBox log;
        Label statusLabel, heroTitle, heroSub, langLabel, lastActivityLabel, activityCaption, scanProgressLabel;
        ShieldIndicator shield;
        Toggle chkAutostart, chkMonitor, chkQuarantine, chkAutoUpdate, chkRiskyOnly, chkFullRisky, chkUsbPrompt, chkLogDetails, chkSkipBig;
        Toggle chkNotify; // tray notifications; threat alerts are shown regardless (see Notify)
        SlimMarquee progress;
        NotifyIcon tray;
        ToolStripItem trayOpenItem, trayExitItem;
        StatusBanner statusBanner, activityRow;
        StatStrip statStrip, dbStrip;
        CardPanel cardQuar, cardScan, cardSettingsPanel;
        Panel[] pages;
        NavTab[] navs;
        static Image logoImage;
        static Icon appIcon;

        // Logo and icon are embedded in the exe as resources (see build.ps1)
        static Image LogoImage
        {
            get
            {
                if (logoImage == null)
                {
                    try
                    {
                        var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("logo.png");
                        if (s != null) logoImage = Image.FromStream(s);
                    }
                    catch { }
                }
                return logoImage;
            }
        }

        static Icon AppIcon
        {
            get
            {
                if (appIcon == null)
                {
                    try
                    {
                        var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico");
                        if (s != null) appIcon = new Icon(s);
                    }
                    catch { }
                }
                return appIcon ?? SystemIcons.Shield;
            }
        }

        // One instance per user session + a "show window" message to the existing instance
        static System.Threading.Mutex singleInstanceMutex;
        internal static readonly int WmShow = NativeMethods.RegisterWindowMessage("AV_Show_7f3a1c");

        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            bool startInTray = false;
            foreach (string a in args)
            {
                if (a == "--tray") startInTray = true;
                if (a == "--install") { RunInstallMode(); return; }
                if (a == "--uninstall") { RunUninstallMode(); return; }
                if (a == "--fix-wintemp") { RunFixWinTempMode(); return; }
            }

            // Single instance only: if already running, ask that instance to show itself and exit
            bool createdNew;
            singleInstanceMutex = new System.Threading.Mutex(true, "Local\\AV_SingleInstance_v1", out createdNew);
            if (!createdNew)
            {
                // The broadcast reaches the instance while its window is visible or
                // plainly minimized, but a tray-hidden window is OWNED (that's how
                // ShowInTaskbar=false hides it) and HWND_BROADCAST skips owned
                // windows — so the running instance must also get the message
                // posted straight to its windows (unknown windows just ignore it).
                NativeMethods.PostMessage((IntPtr)NativeMethods.HWND_BROADCAST, WmShow, IntPtr.Zero, IntPtr.Zero);
                PostShowToRunningInstance();
                return;
            }

            try { Application.Run(new MainForm(startInTray)); }
            finally { GC.KeepAlive(singleInstanceMutex); }
        }

        // Posts WmShow directly to every top-level window of the already-running
        // instance (same process name, other PID). EnumWindows, unlike
        // HWND_BROADCAST, also lists owned windows — including the tray-hidden
        // main form. Extra hits (a message box, the IME window) ignore the
        // registered message, so precision beyond the PID doesn't matter.
        static void PostShowToRunningInstance()
        {
            var pids = new HashSet<uint>();
            try
            {
                using (var self = Process.GetCurrentProcess())
                    foreach (Process p in Process.GetProcessesByName(self.ProcessName))
                    {
                        try { if (p.Id != self.Id) pids.Add((uint)p.Id); }
                        catch { }
                        finally { try { p.Dispose(); } catch { } }
                    }
            }
            catch { }
            if (pids.Count == 0) return;
            try
            {
                NativeMethods.EnumWindows(delegate(IntPtr h, IntPtr lp)
                {
                    uint pid;
                    NativeMethods.GetWindowThreadProcessId(h, out pid);
                    if (pids.Contains(pid))
                        NativeMethods.PostMessage(h, WmShow, IntPtr.Zero, IntPtr.Zero);
                    return true;
                }, IntPtr.Zero);
            }
            catch { }
        }

        // ---------- Process launching ----------

        void StartProcess(string exe, string args, Action<string> onLine, Action<int> onExit)
        {
            StartProcess(exe, args, onLine, onExit, Encoding.UTF8);
        }

        // enc — how the child's output is decoded: ClamAV talks UTF-8, but yara64
        // is an ANSI program (paths go through the system code page, see RunYaraPhase)
        void StartProcess(string exe, string args, Action<string> onLine, Action<int> onExit, Encoding enc)
        {
            var psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = enc;
            psi.StandardErrorEncoding = enc;
            psi.WorkingDirectory = clamDir;

            var p = new Process();
            p.StartInfo = psi;
            p.EnableRaisingEvents = true;
            p.SynchronizingObject = this; // events fire on the UI thread
            // The process is finished only when all three signals are in: Exited
            // plus EOF on stdout AND stderr (the null line is guaranteed to be a
            // stream's last event). Exited alone can overtake the tail of the
            // output — finalizing there could run FinishScan before the last
            // "FOUND"/"OK" lines were counted, dropping a threat from the dialog.
            // All three callbacks arrive on the UI thread, so plain bools suffice.
            bool exited = false, outEof = false, errEof = false;
            Action tryFinish = delegate
            {
                if (!exited || !outEof || !errEof) return;
                int code = 0;
                try { code = p.ExitCode; } catch { }
                currentProc = null;
                onExit(code);
                p.Dispose();
            };
            p.OutputDataReceived += delegate(object s, DataReceivedEventArgs e)
            {
                if (e.Data == null) { outEof = true; tryFinish(); } else onLine(e.Data);
            };
            p.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e)
            {
                if (e.Data == null) { errEof = true; tryFinish(); } else onLine(e.Data);
            };
            p.Exited += delegate { exited = true; tryFinish(); };

            try
            {
                p.Start();
                ApplyScanPriority(p);
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                currentProc = p;
            }
            catch (Exception ex)
            {
                AppendLog(string.Format(Lang.T("log.processStartFailed"), Path.GetFileName(exe), ex.Message), Theme.Danger);
                scan.Running = false;
                scan.Monitor = false;
                updateRunning = false;
                SetBusy(false, Lang.T("status.startError"));
            }
        }

        void StopCurrent()
        {
            cancelUpdate = true; // interrupts a database download in progress, if any
            scan.Cancel = true;  // the scan-wide stop flag: every phase exit and background walker checks it
            var wc = clamZipClient;
            if (wc != null) { try { wc.CancelAsync(); } catch { } }
            foreach (var sp in scanProcs.ToArray()) { try { sp.Kill(); } catch { } }
            var p = currentProc;
            if (p == null) return;
            try { p.Kill(); } catch { }
        }

        void SetBusy(bool busy, string status)
        {
            SetScanEnabled(!busy && DbExists());
            btnUpdate.Enabled = !busy; // without ClamAV this button triggers its installation
            btnStop.Enabled = busy;
            // in the dashboard hero, STOP swaps in where QUICK SCAN sits, so the
            // running scan/update can be stopped without leaving the dashboard
            if (dashStop != null)
            {
                dashStop.Visible = busy;
                dashQuick.Visible = !busy;
            }
            if (scanProgressLabel != null) scanProgressLabel.Text = ""; // fresh readout per scan
            if (busy)
            {
                progress.Start();
                if (scan.Running) SetHero(ShieldState.Busy, Lang.T("hero.scanningTitle"), Lang.T("hero.scanningSub"));
                if (scan.Running && !scan.Monitor)
                {
                    // stay on the dashboard: the hero shows the busy state and STOP,
                    // the detailed output is one click away on the Logs tab
                    scan.LastOutput = DateTime.Now;
                    scanHeartbeat.Start();
                }
            }
            else { progress.Stop(); scanHeartbeat.Stop(); }
            if (status != null) statusLabel.Text = status;
        }

        // ---------- Log rendering ----------
        // Entries are kept in a list so the view can be re-rendered when the Details
        // toggle changes. Every visible line gets a timestamp and a colored [TAG]
        // prefix; "detail" entries (path lists, raw scanner chatter) are hidden
        // unless the toggle is on.

        sealed class LogEntry
        {
            public DateTime Time;
            public string Text;
            public Color Color;
            public string Tag;   // null = inferred from Color
            public bool Detail;  // hidden unless the Details toggle is on
            public bool Section; // stage banner instead of a normal line
        }

        readonly List<LogEntry> logEntries = new List<LogEntry>();
        static readonly Color StampColor = Color.FromArgb(100, 106, 122); // dimmer than Muted

        // A tray-resident session with a chatty monitor would otherwise grow the
        // list (and the rendered RichTextBox) forever. Trimmed in chunks of 500
        // so the full re-render runs once per ~500 appends, not on every line.
        const int MaxLogEntries = 5000;

        void TrimLogEntries()
        {
            if (logEntries.Count <= MaxLogEntries + 500) return;
            logEntries.RemoveRange(0, logEntries.Count - MaxLogEntries);
            RebuildLog();
        }

        void AppendLog(string text, Color color)
        {
            AppendLog(text, color, null, false);
        }

        void AppendLog(string text, Color color, string tag, bool detail)
        {
            var e = new LogEntry();
            e.Time = DateTime.Now;
            e.Text = text;
            e.Color = color;
            e.Tag = tag;
            e.Detail = detail;
            logEntries.Add(e);
            if (!e.Detail || chkLogDetails.Checked) RenderEntry(e);
            TrimLogEntries();
        }

        // Stage banner ("════ QUICK SCAN ════") — makes scan phases easy to spot
        void AppendSection(string title)
        {
            var e = new LogEntry();
            e.Time = DateTime.Now;
            e.Text = title;
            e.Color = Theme.Accent;
            e.Section = true;
            logEntries.Add(e);
            RenderEntry(e);
            TrimLogEntries();
        }

        void ClearLog()
        {
            logEntries.Clear();
            log.Clear();
        }

        // Re-renders the whole view (after toggling Details)
        void RebuildLog()
        {
            log.Clear();
            foreach (LogEntry e in logEntries)
                if (e.Section || !e.Detail || chkLogDetails.Checked) RenderEntry(e);
            log.SelectionStart = log.TextLength;
            log.ScrollToCaret();
        }

        static string TagFor(LogEntry e)
        {
            if (e.Tag != null) return e.Tag;
            if (e.Color == Theme.Good) return "OK";
            if (e.Color == Theme.Warn) return "WARN";
            if (e.Color == Theme.Danger) return "ERROR";
            return "INFO";
        }

        static Color TagColor(string tag)
        {
            switch (tag)
            {
                case "OK": return Theme.Good;
                case "WARN": return Theme.Warn;
                case "SCAN": return Theme.Accent;
                case "ERROR":
                case "INFECTED": return Theme.Danger;
                default: return Theme.Muted;
            }
        }

        void RenderEntry(LogEntry e)
        {
            bool follow = LogAtBottom(); // don't yank the view if the user scrolled up
            if (e.Section)
            {
                AppendRt((log.TextLength > 0 ? "\r\n" : "") + "═══════════  ", StampColor);
                AppendRt(e.Text.ToUpperInvariant(), Theme.Accent);
                AppendRt("  ═══════════\r\n", StampColor);
            }
            else
            {
                string tag = TagFor(e);
                string stamp = e.Time.ToString("HH:mm:ss") + "  ";
                string pad = ("[" + tag + "]").PadRight(11); // [INFECTED] is the widest tag
                // texts arrive with embedded newlines — prefix every non-empty line
                string[] lines = e.Text.Split(new string[] { "\r\n" }, StringSplitOptions.None);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (lines[i].Length == 0)
                    {
                        if (i < lines.Length - 1) AppendRt("\r\n", e.Color); // blank spacer line
                        continue;
                    }
                    AppendRt(stamp, StampColor);
                    AppendRt(pad, TagColor(tag));
                    AppendRt(lines[i] + "\r\n", e.Color);
                }
            }
            if (follow)
            {
                log.SelectionStart = log.TextLength;
                log.ScrollToCaret();
            }
        }

        void AppendRt(string text, Color color)
        {
            log.SelectionStart = log.TextLength;
            log.SelectionColor = color;
            log.AppendText(text);
            log.SelectionColor = log.ForeColor;
        }

        // True when the view is scrolled to (or near) the last line
        bool LogAtBottom()
        {
            if (log.TextLength == 0) return true;
            int lastVisible = log.GetLineFromCharIndex(log.GetCharIndexFromPosition(
                new Point(3, log.ClientSize.Height - 1)));
            int lastLine = log.GetLineFromCharIndex(log.TextLength);
            return lastVisible >= lastLine - 2;
        }

        // Text progress bar for the Logs page ("██████░░░░░░")
        internal static string ProgressBarText(double f)
        {
            const int cells = 18;
            int full = (int)Math.Floor(Math.Max(0, Math.Min(1, f)) * cells);
            return new string('█', full) + new string('░', cells - full);
        }

        // ---------- Autostart ----------

        bool IsAutostartEnabled()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(RunKeyPath))
            {
                return key != null && key.GetValue(RunValueName) != null;
            }
        }

        void SetAutostart(bool enable)
        {
            using (var key = Registry.CurrentUser.CreateSubKey(RunKeyPath))
            {
                if (enable)
                    key.SetValue(RunValueName, "\"" + Application.ExecutablePath + "\" --tray");
                else
                    key.DeleteValue(RunValueName, false);
            }
            statusLabel.Text = enable ? Lang.T("status.autostartOn") : Lang.T("status.autostartOff");
        }

        // Autostart is enabled automatically on first run. A flag is set so that if the
        // user later disables it, we don't turn it back on.
        void EnsureAutostartFirstRun()
        {
            if (autostartInitialized) return;
            autostartInitialized = true;
            if (!IsAutostartEnabled())
                chkAutostart.Checked = true; // the CheckedChanged handler will write the registry
            SaveSettings();
        }
    }
}
