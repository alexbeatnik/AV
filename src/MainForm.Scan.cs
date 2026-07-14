// Scanning: manual scans, progress/ETA, file listing, clamd engine, scan results.
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
        // ---------- Manual scanning ----------

        void PickAndScan(bool folder)
        {
            string target = null;
            if (folder)
            {
                using (var dlg = new FolderBrowserDialog())
                {
                    dlg.Description = Lang.T("dlg.pickFolder");
                    if (dlg.ShowDialog(this) == DialogResult.OK) target = dlg.SelectedPath;
                }
            }
            else
            {
                using (var dlg = new OpenFileDialog())
                {
                    dlg.Title = Lang.T("dlg.pickFile");
                    if (dlg.ShowDialog(this) == DialogResult.OK) target = dlg.FileName;
                }
            }
            if (target != null) RunClamscan(target);
        }

        void RunClamscan(string target)
        {
            if (scanRunning || updateRunning) return;
            ResetScanState(target);
            ClearLog();
            AppendSection(Lang.T("section.scan"));
            AppendLog(string.Format(Lang.T("log.scanning"), target), Theme.Text, "SCAN", false);
            AppendLog(Lang.T("log.buildingList"), Theme.Muted);
            SetBusy(true, Lang.T("status.scanning"));
            BeginListScan(new List<string> { target }, false);
        }

        string MoveArg()
        {
            return chkQuarantine.Checked ? " --move=" + Quote(quarDir) : "";
        }

        // Limits so clamscan doesn't bog down on large files and deep archives. The
        // per-file/scan size cap is user-controlled (the "skip large files" toggle):
        // 200 MB when on, unlimited when off. 200 MB scans typical installers, DLLs
        // and archives while skipping the multi-hundred-MB files (VM images, media,
        // caches) that dominate scan time — malware ClamAV catches is almost always
        // small. The rest always apply; max-scantime caps time per object.
        internal static string ScanLimitsArg(bool skipBig)
        {
            string size = skipBig ? "200M" : "0"; // 0 = unlimited in ClamAV
            return " --max-filesize=" + size + " --max-scansize=" + size
                 + " --max-recursion=6 --max-files=5000"
                 + " --max-scantime=10000"; // no more than 10s per object — a few heavy files (big archives, raw memory) used to eat 20s each and dominate a quick scan
        }

        // ---------- Scan performance (Settings → Low / Normal / High) ----------
        // Low keeps the PC responsive during a scan (single scanner process at reduced
        // OS priority); High trades CPU for speed (more clamd threads + parallel
        // clamdscan processes at elevated priority). Normal is the pre-0.0.4 behavior.

        internal static int PerfMaxThreads(int mode)
        {
            return mode == 0 ? 2 : mode == 2 ? 16 : 8; // clamd worker threads
        }

        // Upper bound on parallel clamdscan processes (capped by CPU count at the call site)
        internal static int PerfMaxProcs(int mode)
        {
            return mode == 0 ? 1 : mode == 2 ? 8 : 4;
        }

        internal static ProcessPriorityClass PerfPriority(int mode)
        {
            return mode == 0 ? ProcessPriorityClass.BelowNormal
                 : mode == 2 ? ProcessPriorityClass.AboveNormal
                 : ProcessPriorityClass.Normal;
        }

        void ApplyScanPriority(Process p)
        {
            try { p.PriorityClass = PerfPriority(perfMode); } catch { } // process may have exited already
        }

        // ---------- Progress, log, auto-update ----------

        internal static string FormatSpan(TimeSpan t)
        {
            if (t.TotalHours >= 1) return string.Format(Lang.T("time.hm"), Math.Floor(t.TotalHours), t.Minutes);
            if (t.TotalMinutes >= 1) return string.Format(Lang.T("time.ms"), Math.Floor(t.TotalMinutes), t.Seconds);
            return string.Format(Lang.T("time.s"), t.TotalSeconds);
        }

        void UpdateScanProgress()
        {
            if (totalToScan <= 0 || scannedCount <= 0) return;
            double f = Math.Min(1.0, (double)scannedCount / totalToScan);
            progress.SetFraction(f);
            shield.SetProgress(f); // the busy shield shows the percent instead of dots
            // ETA via a moving window (rate over the last ~seconds), not the whole elapsed
            // time — otherwise a slow start (loading the DB + counting files on C:\, which
            // hammers the disk) inflates the estimate to hundreds of hours.
            string eta = "";
            if (scannedCount < totalToScan)
            {
                if (rateWinTime == DateTime.MinValue) { rateWinTime = DateTime.Now; rateWinCount = scannedCount; }
                double winElapsed = (DateTime.Now - rateWinTime).TotalSeconds;
                int winScanned = scannedCount - rateWinCount;
                if (winElapsed >= 5 && winScanned >= 20)
                {
                    double rate = winScanned / winElapsed; // files/s over the last window
                    double sec = (totalToScan - scannedCount) / rate;
                    lastEta = "~" + FormatSpan(TimeSpan.FromSeconds(sec));
                }
                // window not mature yet — keep the previous estimate, no "estimating…" flicker
                eta = lastEta.Length > 0 ? Lang.T("eta.remainingPrefix") + lastEta : Lang.T("eta.estimating");
                if (winElapsed >= 30) { rateWinTime = DateTime.Now; rateWinCount = scannedCount; } // shift the window
            }
            statusLabel.Text = string.Format(Lang.T("status.progress"),
                scannedCount, totalToScan, f * 100, eta, foundCount);
            scanProgressLabel.Text = ProgressBarText(f)
                + string.Format("  {0} / {1}  ({2:0}%)", scannedCount, totalToScan, f * 100);

            if (monitorScan) return;
            if (!loggedTotal)
            {
                loggedTotal = true;
                AppendLog(string.Format(Lang.T("log.filesToCheck"), totalToScan) + "\r\n", Theme.Text, "SCAN", false);
            }
        }
        string lastEta = ""; // last time estimate ("~5m"), also shown by the heartbeat

        // Called by a timer every 10s during a scan — guarantees a log line even when
        // clamscan is stuck for a long time on a large file and prints nothing.
        void ScanHeartbeatTick()
        {
            if (!scanRunning || monitorScan) return;
            string elapsed = FormatSpan(DateTime.Now - scanStart);
            if (listingFiles)
            {
                AppendLog(string.Format(Lang.T("log.hbListing"), DateTime.Now, listedCount, elapsed), Theme.Muted, "SCAN", false);
                return;
            }
            if (startingEngine)
            {
                AppendLog(string.Format(Lang.T("log.hbEngineLoading"), DateTime.Now, elapsed), Theme.Muted, "SCAN", false);
                return;
            }
            if (yaraRunning)
            {
                AppendLog(string.Format(Lang.T("log.hbYara"), DateTime.Now, elapsed), Theme.Muted, "SCAN", false);
                return;
            }
            bool stalled = (DateTime.Now - lastScanOutput).TotalSeconds >= 9; // no new output
            if (totalToScan <= 0)
            {
                AppendLog(string.Format(Lang.T("log.hbRunning"), DateTime.Now, scannedCount, elapsed), Theme.Muted, "SCAN", false);
                return;
            }
            double f = Math.Min(1.0, (double)scannedCount / totalToScan);
            int left = Math.Max(0, totalToScan - scannedCount);
            if (stalled)
                AppendLog(string.Format(Lang.T("log.hbBigFile"), DateTime.Now, scannedCount, totalToScan, f * 100, elapsed), Theme.Muted, "SCAN", false);
            else
                AppendLog(string.Format(Lang.T("log.hbProgress"), DateTime.Now, scannedCount, totalToScan, f * 100, left,
                    lastEta.Length > 0 ? " (" + lastEta + ")" : "",
                    foundCount > 0 ? string.Format(Lang.T("log.threatsSuffix"), foundCount) : ""), Theme.Muted, "SCAN", false);
        }

        void AppendScanLog()
        {
            try
            {
                File.AppendAllText(scanLogPath, string.Format(
                    "{0:yyyy-MM-dd HH:mm}  {1}  scanned: {2}, threats: {3}, quarantined: {4}, duration: {5}\r\n",
                    DateTime.Now, currentScanDesc, scannedCount, foundCount, movedCount,
                    FormatSpan(DateTime.Now - scanStart)), new UTF8Encoding(false));
            }
            catch { }
            if (pages != null && pages[0].Visible) RefreshHistory();
        }

        void OpenScanLog()
        {
            if (File.Exists(scanLogPath)) Process.Start("notepad.exe", Quote(scanLogPath));
            else statusLabel.Text = Lang.T("log.emptyLogFile");
        }

        // Once a day, quietly checks database versions (3 requests of 512 bytes). If a
        // newer database is out, shows the "Update Database" button, notifies via the
        // tray, and if auto-update is on, downloads right away — nothing for the user to click.
        void MaybeAutoUpdate()
        {
            if (scanRunning || updateRunning || clamDir == null) return;
            if (DateTime.Now < dbCooldownUntil) return; // server asked for a pause (429)
            if (!DbExists()) { if (chkAutoUpdate.Checked) RunFreshclam(true); return; }
            if (checkingDb || (DateTime.Now - lastDbCheck).TotalHours < 24) return;
            checkingDb = true;
            System.Threading.ThreadPool.QueueUserWorkItem(delegate
            {
                bool newer = false, reachedServer = false;
                foreach (string url in DbUrls)
                {
                    string dest = Path.Combine(dbDir, url.Substring(url.LastIndexOf('/') + 1));
                    long local = LocalCvdVersion(dest);
                    long remote = 0;
                    try { remote = RemoteCvdVersion(url); } catch { }
                    if (remote > 0) reachedServer = true;
                    if (remote > 0 && remote > local) { newer = true; break; }
                }
                bool fresh = newer, checkedOk = reachedServer;
                try
                {
                    BeginInvoke((Action)delegate
                    {
                        checkingDb = false;
                        lastDbCheck = DateTime.Now;
                        SaveSettings();
                        // the server couldn't be reached (offline / transient failure):
                        // don't claim "up to date", and don't clear an update flag a
                        // previous successful check may have set — try again tomorrow
                        if (!checkedOk) return;
                        updateAvailable = fresh;
                        RefreshDbStatus(); // shows/hides the update button
                        if (!fresh)
                        {
                            statusLabel.Text = Lang.T("status.dbUpToDate");
                            return;
                        }
                        if (chkAutoUpdate.Checked)
                        {
                            Notify(5000, Lang.T("tray.dbUpdateDownloading"), ToolTipIcon.Info);
                            AppendLog(string.Format(Lang.T("log.dbNewerAutoDownload"), DateTime.Now), Theme.Muted);
                            RunFreshclam(true);
                        }
                        else
                        {
                            heroSub.Text = Lang.T("hero.dbUpdateAvailable");
                            statusLabel.Text = Lang.T("status.dbUpdateAvailablePress");
                            Notify(5000, Lang.T("tray.dbUpdateAvailablePress"), ToolTipIcon.Info);
                        }
                    });
                }
                catch { checkingDb = false; } // the form is already closed
            });
        }
        bool checkingDb;       // a version check is already running
        DateTime lastDbCheck;  // time of the last daily check (persisted)
        bool updateAvailable;  // the server has a newer database — show the update button

        // ---------- Scheduled quick scan ----------

        // Timer-driven: when the configured period (a day / a week) has passed since
        // the last scheduled run, a normal quick scan starts on its own. A PC that was
        // off past the due time catches up a few minutes after the next start. Skipped
        // while anything else runs, and while a modal dialog is open — starting a scan
        // would ClearLog() and reset foundFiles under the threat dialog.
        void MaybeRunScheduledScan()
        {
            if (!ScheduledScanDue(schedMode, lastScheduledScan, DateTime.Now)) return;
            if (scanRunning || updateRunning || startingEngine || clamDir == null || !DbExists()) return;
            if (!NativeMethods.IsWindowEnabled(Handle)) return; // a dialog is open — retry on a later tick
            RunQuickScan();
            if (!scanRunning) return; // didn't start — stays due, retried on the next tick
            lastScheduledScan = DateTime.Now;
            SaveSettings();
            AppendLog(Lang.T("log.scheduledScanStart"), Theme.Muted);
            Notify(4000, Lang.T("tray.scheduledScan"), ToolTipIcon.Info);
        }

        // Pure due-time rule (unit-tested). mode: 0 = off, 1 = daily, 2 = weekly.
        // A never-anchored MinValue counts as long overdue; a last-run in the future
        // (clock set back) is NOT due — it self-heals once real time catches up.
        internal static bool ScheduledScanDue(int mode, DateTime last, DateTime now)
        {
            if (mode != 1 && mode != 2) return false;
            return (now - last).TotalHours >= (mode == 1 ? 24 : 168);
        }

        // Quotes a command-line argument; a trailing \ before the quote must be doubled
        internal static string Quote(string path)
        {
            if (path.EndsWith("\\")) path += "\\";
            return "\"" + path + "\"";
        }

        // --exclude/--exclude-dir built from user exclusions + quarantine + ClamAV's own folder
        string ExcludeArg()
        {
            var all = new List<string>(exclusions);
            if (quarDir != null) all.Add(quarDir);
            if (clamDir != null) all.Add(clamDir);
            var sb = new StringBuilder();
            foreach (string d in all)
            {
                string rx = ExcludePathRegex(d);
                sb.Append(" --exclude-dir=\"").Append(rx).Append("\"");
                sb.Append(" --exclude=\"").Append(rx).Append("\"");
            }
            return sb.ToString();
        }

        // (\\|$): matches only the path itself or what's inside it,
        // otherwise ^C:\...\quarantine would also match C:\...\quarantine2
        internal static string ExcludePathRegex(string dir)
        {
            return "(?i)^" + Regex.Escape(dir.TrimEnd('\\')) + "(\\\\|$)";
        }

        // True if path is root itself or lies inside it. A plain StartsWith would not
        // work: "C:\Program Files" would also match "C:\Program Files (x86)".
        internal static bool IsUnder(string path, string root)
        {
            root = root.TrimEnd('\\');
            if (root.Length == 0) return false;
            if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return false;
            return path.Length == root.Length || path[root.Length] == '\\';
        }

        bool IsExcluded(string path)
        {
            foreach (string d in exclusions)
                if (IsUnder(path, d)) return true;
            if (quarDir != null && IsUnder(path, quarDir)) return true;
            // ClamAV's own folder (database, binaries) — don't scan ourselves
            if (clamDir != null && IsUnder(path, clamDir)) return true;
            if (IsUnder(path, YaraDir)) return true; // yara64 + rule files
            return false;
        }

        void RunFullScan()
        {
            if (scanRunning || updateRunning) return;
            var targets = new List<string>();
            foreach (DriveInfo d in DriveInfo.GetDrives())
                if (d.DriveType == DriveType.Fixed && d.IsReady) targets.Add(d.RootDirectory.FullName);
            if (targets.Count == 0) return;
            string drives = string.Join(", ", targets.ToArray());
            bool risky = chkFullRisky.Checked;
            string warn = string.Format(risky ? Lang.T("msg.fullScanRiskyWarn") : Lang.T("msg.fullScanAllWarn"), drives);
            if (MessageBox.Show(this, warn, Lang.T("title.fullScan"),
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

            ResetScanState(string.Format(Lang.T("desc.fullScan"), drives));
            ClearLog();
            AppendSection(Lang.T("title.fullScan"));
            AppendLog(string.Format(risky ? Lang.T("log.fullScanRisky") : Lang.T("log.fullScanAll"), drives), Theme.Text, "SCAN", false);
            AppendLog(Lang.T("log.quickScanMemory"), Theme.Muted, null, true); // full scan also dumps process RAM
            AppendLog(Lang.T("log.buildingList"), Theme.Muted);
            SetBusy(true, Lang.T("status.fullScanRunning"));
            BeginListScan(targets, risky, true);
        }

        // RAM-only scan: dumps the executable memory of every running process and
        // scans just those — no disk walk. Catches injected/unpacked code that's
        // masked or absent on disk, in seconds rather than a full file scan.
        void RunMemoryScan()
        {
            if (scanRunning || updateRunning || clamDir == null || !DbExists()) return;
            ResetScanState(Lang.T("desc.memScan"));
            ClearLog();
            AppendSection(Lang.T("btn.scanRam"));
            AppendLog(Lang.T("log.memScanHeader"), Theme.Text, "SCAN", false);
            AppendLog(Lang.T("log.buildingList"), Theme.Muted);
            SetBusy(true, Lang.T("status.memScanRunning"));
            BeginListScan(new List<string>(), true, true); // no disk roots — memory only
        }

        // Shared counter reset before a manual scan
        void ResetScanState(string desc)
        {
            scanRunning = true;
            monitorScan = false;
            cancelScanListing = false; // a Stop from a previous scan must not leak into this one
            scannedCount = 0;
            foundCount = 0;
            movedCount = 0;
            foundFiles.Clear();
            scanStart = DateTime.Now;
            loggedTotal = false;
            lastEta = "";
            rateWinTime = DateTime.MinValue;
            currentScanDesc = desc;
        }

        // Quick scan: risky file types in common infection points (downloads, desktop,
        // temp, AppData, startup) + running processes' executables. Minutes instead of
        // the hours a full scan takes.
        void RunQuickScan()
        {
            if (scanRunning || updateRunning || clamDir == null || !DbExists()) return;
            ResetScanState(Lang.T("desc.quickScan"));
            ClearLog();
            var roots = QuickScanRoots();
            AppendSection(Lang.T("btn.quickScan"));
            AppendLog(Lang.T("log.quickScanHeader"), Theme.Text, "SCAN", false);
            foreach (string r in roots) AppendLog("  " + r + "\r\n", Theme.Muted, null, true);
            AppendLog(Lang.T("log.quickScanProcesses"), Theme.Muted, null, true);
            AppendLog(Lang.T("log.quickScanMemory"), Theme.Muted, null, true);
            AppendLog(Lang.T("log.buildingList"), Theme.Muted);
            roots.AddRange(RunningProcessFiles());
            SetBusy(true, Lang.T("status.quickScanRunning"));
            BeginListScan(roots, true, true);
        }

        // Common places malware ends up. Nested paths are merged so the same
        // location isn't scanned twice (e.g. Temp inside AppData\Local).
        List<string> QuickScanRoots()
        {
            var list = new List<string>();
            Action<string> add = delegate(string p)
            {
                if (string.IsNullOrEmpty(p)) return;
                try { p = Path.GetFullPath(p); } catch { return; }
                if (!Directory.Exists(p)) return;
                MergeScanRoot(list, p);
            };
            add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));       // Roaming
            add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));  // Local (contains Temp)
            add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)); // ProgramData
            add(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
            add(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
            add(Path.GetTempPath());
            add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
            add(Environment.GetEnvironmentVariable("PUBLIC"));
            return list;
        }

        // Adds a scan root unless a broader root already covers it, and drops any
        // narrower roots the new one covers — each location ends up scanned once
        internal static void MergeScanRoot(List<string> list, string path)
        {
            foreach (string e in list)
                if (IsUnder(path, e)) return;
            list.RemoveAll(delegate(string e) { return IsUnder(e, path); });
            list.Add(path);
        }

        // Paths of running processes' executables — checks what's currently running
        static List<string> RunningProcessFiles()
        {
            var res = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Process p in Process.GetProcesses())
            {
                try
                {
                    string f = p.MainModule.FileName;
                    if (seen.Add(f) && File.Exists(f)) res.Add(f);
                }
                catch { } // system/protected processes — no access
                finally { try { p.Dispose(); } catch { } }
            }
            return res;
        }

        volatile bool cancelScanListing; // "Stop" pressed while building the file list
        volatile int listedCount;        // how many files are in the list so far (for the heartbeat)
        volatile bool listingFiles;      // the list is being built, clamscan hasn't started yet

        // Builds the file list in the background (applying type filters and exclusions)
        // and starts clamscan with --file-list. This way the scanner doesn't waste time
        // on gigabyte-sized videos/images, and progress knows the exact workload upfront.
        void BeginListScan(List<string> roots, bool riskyOnly)
        {
            BeginListScan(roots, riskyOnly, false);
        }

        void BeginListScan(List<string> roots, bool riskyOnly, bool dumpMemory)
        {
            int gen = ++countGen;
            cancelScanListing = false;
            listedCount = 0;
            listingFiles = true;
            // snapshot of exclusions: the background thread must not read the live list
            var skip = new List<string>(exclusions);
            if (quarDir != null) skip.Add(quarDir);
            if (clamDir != null) skip.Add(clamDir);
            skip.Add(YaraDir);
            var rootsCopy = new List<string>(roots);

            var th = new System.Threading.Thread(delegate()
            {
                Func<string, bool> excluded = delegate(string p)
                {
                    foreach (string s in skip)
                        if (IsUnder(p, s)) return true;
                    return false;
                };
                var files = new List<string>();
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var stack = new Stack<string>();
                foreach (string r in rootsCopy)
                {
                    if (File.Exists(r)) { if (!excluded(r) && seen.Add(r)) files.Add(r); }
                    // roots are followed even when they are junctions/symlinks — a folder
                    // the user explicitly picked must be scanned. A root is entered once,
                    // and every child link below is skipped, so no cycle can form.
                    else if (Directory.Exists(r)) stack.Push(r);
                }
                DateTime lastUi = DateTime.MinValue;
                while (stack.Count > 0 && gen == countGen && !cancelScanListing)
                {
                    string d = stack.Pop();
                    if (excluded(d)) continue;
                    try
                    {
                        foreach (string f in Directory.GetFiles(d))
                        {
                            if (excluded(f)) continue;
                            if (riskyOnly && !RiskyExtensions.Contains(Path.GetExtension(f))) continue;
                            if (seen.Add(f)) files.Add(f);
                        }
                        foreach (string sub in Directory.GetDirectories(d))
                        {
                            // don't follow junctions/symlinks: cyclic links (the legacy
                            // "Application Data" junctions, mklink loops) would spin the
                            // walk forever and list the same content twice
                            try
                            {
                                if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0) continue;
                            }
                            catch { continue; }
                            stack.Push(sub);
                        }
                    }
                    catch { } // no access — skip
                    listedCount = files.Count;
                    if ((DateTime.Now - lastUi).TotalMilliseconds > 500)
                    {
                        lastUi = DateTime.Now;
                        int n = files.Count;
                        try
                        {
                            BeginInvoke((Action)delegate
                            {
                                if (gen == countGen && listingFiles)
                                    statusLabel.Text = string.Format(Lang.T("status.buildingListFound"), n);
                            });
                        }
                        catch { }
                    }
                }
                // Dump running processes' executable RAM (injected/masked code) and
                // add those temp files to the scan — done after the disk walk so the
                // slow part reports its own status line.
                if (dumpMemory && !cancelScanListing && gen == countGen)
                {
                    try
                    {
                        BeginInvoke((Action)delegate
                        {
                            if (gen == countGen) statusLabel.Text = Lang.T("status.memScanning");
                        });
                    }
                    catch { }
                    int mp, mr; long mb;
                    foreach (string f in DumpRunningProcessMemory(gen, out mp, out mr, out mb))
                        if (seen.Add(f)) files.Add(f);
                    int fMp = mp, fMr = mr; long fMb = mb;
                    try
                    {
                        BeginInvoke((Action)delegate
                        {
                            if (gen == countGen)
                                AppendLog(string.Format(Lang.T("log.memScanDone"),
                                    fMr, fMp, FormatSize(fMb)), Theme.Muted, "SCAN", false);
                        });
                    }
                    catch { }
                }
                // Smallest files first: fast, visible early progress; the few heavy
                // files (which can each hit the per-object time limit) fall to the tail.
                if (!cancelScanListing && files.Count > 1)
                    SortPathsBySize(files, delegate(string p)
                    {
                        try { return new FileInfo(p).Length; } catch { return 0; }
                    });
                bool cancelled = cancelScanListing;
                try
                {
                    BeginInvoke((Action)delegate
                    {
                        if (gen != countGen) return; // a different scan started — this UI update is stale
                        listingFiles = false;
                        if (cancelled)
                        {
                            scanRunning = false;
                            SetBusy(false, Lang.T("status.scanCancelled"));
                            AppendLog(Lang.T("log.cancelled"), Theme.Warn);
                            RefreshDbStatus();
                            CleanupMemDumps();
                            return;
                        }
                        if (files.Count == 0)
                        {
                            scanRunning = false;
                            SetBusy(false, Lang.T("status.noFiles"));
                            AppendLog(Lang.T("log.noFiles"), Theme.Text);
                            RefreshDbStatus();
                            CleanupMemDumps();
                            return;
                        }
                        totalToScan = files.Count;
                        initialFilesToScan = files.Count;
                        loggedTotal = true;
                        AppendLog(string.Format(Lang.T("log.filesToCheck"), files.Count) + "\r\n\r\n", Theme.Text, "SCAN", false);
                        StartDaemonScan(files);
                    });
                }
                catch { } // the form is already closed
            });
            th.IsBackground = true;
            th.Start();
        }

        // ---------- clamd engine: resident in memory only while scanning ----------

        const int ClamdPort = 3310;
        const string CancelledMarker = "__CANCELLED__"; // language-independent internal sentinel
        Process clamdProc;                 // the daemon we started
        volatile bool clamdStopping;       // the daemon is still shutting down (releasing the port)
        volatile bool startingEngine;      // clamd is loading the database, the scan hasn't started yet
        readonly List<Process> scanProcs = new List<Process>(); // parallel clamdscan processes
        int scanProcsLeft;                 // how many clamdscan processes are still running
        int scanAggExit;                   // aggregated exit code across chunks

        // skipBig is read on the UI thread and passed in — this runs on the
        // EnsureClamd background thread, which must not touch controls
        void WriteClamdConf(bool skipBig)
        {
            // same size cap as ScanLimitsArg: 200 MB when "skip large files" is on, else 0 = unlimited
            string size = skipBig ? "200M" : "0";
            File.WriteAllText(Path.Combine(clamDir, "clamd.conf"),
                "TCPSocket " + ClamdPort + "\r\n" +
                "TCPAddr 127.0.0.1\r\n" +
                "MaxThreads " + PerfMaxThreads(perfMode) + "\r\n" +
                "DatabaseDirectory \"" + dbDir + "\"\r\n" +
                "MaxScanSize " + size + "\r\nMaxFileSize " + size + "\r\nMaxRecursion 6\r\n" +
                "MaxFiles 5000\r\nMaxScanTime 10000\r\n" +
                "IdleTimeout 300\r\nForeground yes\r\n",
                new UTF8Encoding(false));
        }

        // clamd only opens its port AFTER loading the database,
        // so PING→PONG is a reliable readiness signal
        static bool ClamdPing()
        {
            return ClamdCommand("PING").StartsWith("PONG");
        }

        static string ClamdCommand(string cmd)
        {
            try
            {
                using (var c = new System.Net.Sockets.TcpClient())
                {
                    c.Connect("127.0.0.1", ClamdPort);
                    using (var s = c.GetStream())
                    {
                        byte[] b = Encoding.ASCII.GetBytes("n" + cmd + "\n");
                        s.Write(b, 0, b.Length);
                        s.ReadTimeout = 3000;
                        var buf = new byte[64];
                        int n = s.Read(buf, 0, buf.Length);
                        return n > 0 ? Encoding.ASCII.GetString(buf, 0, n) : "";
                    }
                }
            }
            catch { return ""; }
        }

        // Starts clamd and waits for it to become ready in the background;
        // onReady/onFail are invoked on the UI thread
        void EnsureClamd(Action onReady, Action<string> onFail)
        {
            startingEngine = true;
            bool skipBig = chkSkipBig.Checked; // snapshot on the UI thread for the worker
            var th = new System.Threading.Thread(delegate()
            {
                string err = null;
                try
                {
                    // a previous daemon is still shutting down — give it time to free the port
                    DateTime stopWait = DateTime.Now.AddSeconds(10);
                    while (clamdStopping && DateTime.Now < stopWait)
                        System.Threading.Thread.Sleep(300);
                    WriteClamdConf(skipBig);
                    if (cancelScanListing) err = CancelledMarker;
                    else if (!ClamdPing())
                    {
                        var psi = new ProcessStartInfo(Path.Combine(clamDir, "clamd.exe"),
                            "-c " + Quote(Path.Combine(clamDir, "clamd.conf")));
                        psi.UseShellExecute = false;
                        psi.CreateNoWindow = true;
                        psi.RedirectStandardOutput = true;
                        psi.RedirectStandardError = true;
                        psi.WorkingDirectory = clamDir;
                        var p = Process.Start(psi);
                        ApplyScanPriority(p); // clamd does the actual scanning work
                        string lastLine = "";
                        p.OutputDataReceived += delegate(object s, DataReceivedEventArgs e)
                            { if (!string.IsNullOrEmpty(e.Data)) lastLine = e.Data; };
                        p.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e)
                            { if (!string.IsNullOrEmpty(e.Data)) lastLine = e.Data; };
                        p.BeginOutputReadLine();
                        p.BeginErrorReadLine();
                        clamdProc = p;
                        DateTime deadline = DateTime.Now.AddSeconds(180);
                        bool ready = false;
                        while (DateTime.Now < deadline)
                        {
                            if (cancelScanListing) { err = CancelledMarker; break; }
                            if (p.HasExited)
                            {
                                err = Lang.T("err.daemonExited")
                                    + (lastLine.Length > 0 ? ": " + lastLine : "");
                                break;
                            }
                            if (ClamdPing()) { ready = true; break; }
                            System.Threading.Thread.Sleep(1000);
                        }
                        if (err == null && !ready) err = Lang.T("err.daemonTimeout");
                    }
                }
                catch (Exception ex) { err = ex.Message; }
                string fe = err;
                try
                {
                    BeginInvoke((Action)delegate
                    {
                        startingEngine = false;
                        if (fe == null) onReady(); else onFail(fe);
                    });
                }
                catch { }
            });
            th.IsBackground = true;
            th.Start();
        }

        // Gracefully stops the daemon (SHUTDOWN), falling back to Kill if needed — in the
        // background, so the UI isn't blocked. A foreign clamd on the same port is left alone.
        void StopClamd()
        {
            var p = clamdProc;
            clamdProc = null;
            if (p == null) return;
            clamdStopping = true;
            System.Threading.ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    if (!p.HasExited)
                    {
                        ClamdCommand("SHUTDOWN");
                        if (!p.WaitForExit(5000)) p.Kill();
                    }
                }
                catch { try { p.Kill(); } catch { } }
                try { p.Dispose(); } catch { }
                clamdStopping = false;
            });
        }

        // Synchronous kill for app exit: the queued StopClamd worker dies with the
        // process before it gets to run, which would leave clamd.exe (hundreds of MB
        // of RAM) running forever. Kill is fine here — clamd holds no state to flush.
        void KillClamdNow()
        {
            var p = clamdProc;
            clamdProc = null;
            if (p == null) return;
            try { if (!p.HasExited) p.Kill(); } catch { }
            try { p.Dispose(); } catch { }
        }

        // Writes the full list + chunks, starts clamd, and launches parallel clamdscan
        // processes. If clamd is missing or fails to start, falls back to plain clamscan.
        void StartDaemonScan(List<string> files)
        {
            CleanupBatchLists();
            string tmp = Path.GetTempPath();
            string fullList = Path.Combine(tmp, "av-list-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllLines(fullList, files.ToArray(), new UTF8Encoding(false));
                batchListPaths.Add(fullList);
                yaraListPath = fullList;  // the YARA phase reuses the exact same list
                yaraPhasePending = true;
            }
            catch (Exception ex)
            {
                scanRunning = false;
                SetBusy(false, Lang.T("status.listCreateFailed"));
                AppendLog(string.Format(Lang.T("log.listCreateFailed"), ex.Message), Theme.Danger);
                RefreshDbStatus();
                CleanupMemDumps();
                return;
            }

            bool haveDaemon = File.Exists(Path.Combine(clamDir, "clamd.exe"))
                && File.Exists(Path.Combine(clamDir, "clamdscan.exe"));
            if (!haveDaemon)
            {
                StartProcess(Path.Combine(clamDir, "clamscan.exe"),
                    "--stdout -d " + Quote(dbDir) + MoveArg() + ScanLimitsArg(chkSkipBig.Checked)
                    + " --file-list=" + Quote(fullList), OnScanLine, OnScanExit);
                return;
            }

            // as many list chunks as parallel clamdscan processes (perf mode sets the cap)
            int maxProcs = Math.Min(PerfMaxProcs(perfMode), Environment.ProcessorCount);
            int n = files.Count >= 200 && maxProcs >= 2 ? Math.Max(2, maxProcs) : 1;
            var chunks = new List<string>();
            if (n > 1)
            {
                // Round-robin (stripe) the list across the N processes instead of
                // handing each a contiguous block. The file list is ordered by the
                // directory walk, so heavy folders (AppData\Local) and the memory
                // dumps — all appended at the tail — would otherwise pile into the
                // last chunk(s), collapsing parallelism to 1 core partway through.
                // Striping gives every process an even mix, keeping all cores busy
                // to the end (and smoothing the ETA).
                var slices = StripeFiles(files, n);
                for (int i = 0; i < n; i++)
                {
                    if (slices[i].Count == 0) continue;
                    string cp = Path.Combine(tmp, "av-list-" + (i + 1) + "-" + Guid.NewGuid().ToString("N") + ".txt");
                    try { File.WriteAllLines(cp, slices[i].ToArray(), new UTF8Encoding(false)); }
                    catch { chunks.Clear(); break; } // failed — fall back to a single process
                    chunks.Add(cp);
                    batchListPaths.Add(cp);
                }
            }
            if (chunks.Count == 0) chunks.Add(fullList);

            statusLabel.Text = Lang.T("status.engineStarting");
            AppendLog(Lang.T("log.engineStarting"), Theme.Muted);
            EnsureClamd(
                delegate { StartClamdscanChunks(chunks); },
                delegate(string msg)
                {
                    StopClamd();
                    if (msg == CancelledMarker)
                    {
                        scanRunning = false;
                        SetBusy(false, Lang.T("status.scanCancelled"));
                        AppendLog(Lang.T("log.cancelled"), Theme.Warn);
                        RefreshDbStatus();
                        CleanupBatchLists();
                        CleanupMemDumps();
                        return;
                    }
                    AppendLog(string.Format(Lang.T("log.daemonFallback"), msg), Theme.Warn);
                    StartProcess(Path.Combine(clamDir, "clamscan.exe"),
                        "--stdout -d " + Quote(dbDir) + MoveArg() + ScanLimitsArg(chkSkipBig.Checked)
                        + " --file-list=" + Quote(fullList), OnScanLine, OnScanExit);
                });
        }

        // Sorts paths by size, smallest first, using a caller-supplied size lookup
        // (so it's testable without touching the disk). Sizes are read once up front —
        // never from inside the comparator — so it stays O(n log n), not O(n log n)
        // stat calls. Combined with StripeFiles, each clamdscan process then scans
        // small files first (fast, visible early progress) and the few heavy files
        // (each capped at max-scantime) fall to the tail, where a slowing "finishing
        // up" reads far better than a scan that sits at 0-7 % for minutes.
        internal static void SortPathsBySize(List<string> files, Func<string, long> sizeOf)
        {
            var size = new Dictionary<string, long>(files.Count);
            foreach (string f in files) if (!size.ContainsKey(f)) size[f] = sizeOf(f);
            files.Sort(delegate(string a, string b) { return size[a].CompareTo(size[b]); });
        }

        // Distributes files round-robin across n buckets (stripe): file j goes to
        // bucket j % n. The file list is ordered by the directory walk, so heavy
        // folders and the appended memory dumps cluster at the tail; a contiguous
        // split would dump all of that on one clamdscan process. Striping spreads it
        // so every process finishes around the same time. Every file lands in exactly
        // one bucket, order within a bucket preserved.
        internal static List<List<string>> StripeFiles(List<string> files, int n)
        {
            var slices = new List<List<string>>(n);
            for (int i = 0; i < n; i++) slices.Add(new List<string>());
            for (int j = 0; j < files.Count; j++) slices[j % n].Add(files[j]);
            return slices;
        }

        void StartClamdscanChunks(List<string> chunks)
        {
            if (chunks.Count > 1)
                AppendLog(string.Format(Lang.T("log.scanningThreads"), chunks.Count), Theme.Muted);
            lastScanOutput = DateTime.Now;
            scanProcsLeft = chunks.Count;
            scanAggExit = 0;
            string conf = Quote(Path.Combine(clamDir, "clamd.conf"));
            foreach (string cp in chunks)
                StartScanChild(Path.Combine(clamDir, "clamdscan.exe"),
                    "-c " + conf + " --stdout --no-summary" + MoveArg() + " --file-list=" + Quote(cp));
        }

        // One of the parallel clamdscan processes; OnScanExit fires when the last one finishes
        void StartScanChild(string exe, string args)
        {
            var psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = Encoding.UTF8;
            psi.StandardErrorEncoding = Encoding.UTF8;
            psi.WorkingDirectory = clamDir;

            var p = new Process();
            p.StartInfo = psi;
            p.EnableRaisingEvents = true;
            p.SynchronizingObject = this; // events and counters run on the UI thread
            p.OutputDataReceived += delegate(object s, DataReceivedEventArgs e) { OnScanLine(e.Data); };
            p.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e) { OnScanLine(e.Data); };
            p.Exited += delegate
            {
                int code = 2;
                try { code = p.ExitCode; } catch { }
                scanProcs.Remove(p);
                try { p.Dispose(); } catch { }
                OnScanChildDone(code);
            };
            try
            {
                p.Start();
                ApplyScanPriority(p);
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                scanProcs.Add(p);
            }
            catch (Exception ex)
            {
                AppendLog(string.Format(Lang.T("log.clamdscanStartFailed"), ex.Message), Theme.Danger);
                OnScanChildDone(2);
            }
        }

        void OnScanChildDone(int code)
        {
            // 1 (threats found) outranks 2 (error); 0 only if everything came back clean
            if (code == 1) scanAggExit = 1;
            else if (code != 0 && scanAggExit != 1) scanAggExit = 2;
            scanProcsLeft--;
            if (scanProcsLeft <= 0) OnScanExit(scanAggExit);
        }

        void OnScanLine(string line)
        {
            if (line == null) return;
            lastScanOutput = DateTime.Now; // clamscan produced output — it's not stuck
            if (line.Contains(": moved to '"))
            {
                RecordQuarantineMove(line);
                AppendLog(line + "\r\n", Theme.Warn, "INFECTED", false);
                return;
            }
            if (line.EndsWith(" FOUND"))
            {
                foundCount++;
                scannedCount++;
                int sep = line.LastIndexOf(": ");
                if (sep > 0)
                {
                    string path = line.Substring(0, sep);
                    string sig = line.Substring(sep + 2, line.Length - sep - 2 - 6); // strip " FOUND"
                    foundFiles.Add(new string[] { path, sig });
                }
                AppendLog(line + "\r\n", Theme.Danger, "INFECTED", false);
                if (totalToScan > 0) UpdateScanProgress();
                else statusLabel.Text = string.Format(Lang.T("status.scannedFound"), scannedCount, foundCount);
            }
            else if (line.EndsWith(": OK"))
            {
                scannedCount++;
                if (monitorScan) AppendLog(line + "\r\n", Theme.Muted, "OK", true);
                if (scannedCount % 10 == 0 || scannedCount == totalToScan)
                {
                    if (totalToScan > 0) UpdateScanProgress();
                    else statusLabel.Text = string.Format(Lang.T("status.scannedFound"), scannedCount, foundCount);
                }
            }
            else if (line.EndsWith(" ERROR"))
            {
                scannedCount++;
                if (monitorScan) AppendLog(line + "\r\n", Theme.Muted, "ERROR", true);
                else AppendLog(line + "\r\n", Theme.Danger, "ERROR", true);
                if (scannedCount % 10 == 0 || scannedCount == totalToScan)
                {
                    if (totalToScan > 0) UpdateScanProgress();
                    else statusLabel.Text = string.Format(Lang.T("status.scannedFound"), scannedCount, foundCount);
                }
            }
            else if (!monitorScan && line.Trim().Length > 0)
            {
                // raw scanner chatter (access-denied warnings etc.) — details only
                if (line.IndexOf("warning", StringComparison.OrdinalIgnoreCase) >= 0)
                    AppendLog(line + "\r\n", Theme.Warn, "WARN", true);
                else
                    AppendLog(line + "\r\n", Theme.Muted, null, true);
            }
        }

        // Parses a clamscan line "C:\path: moved to 'C:\quarantine\file'"
        void RecordQuarantineMove(string line)
        {
            int idx = line.LastIndexOf(": moved to '");
            if (idx < 0 || !line.EndsWith("'")) return;
            string original = line.Substring(0, idx);
            string moved = line.Substring(idx + 12, line.Length - idx - 13);
            movedCount++;
            totalMoved++; // every other quarantine path goes through QuarantineFile, which counts itself
            // clamscan dropped the raw infected file into quarantine — neutralize it
            // right away (see QuarExt); if that fails, the reload sweep retries later
            string finalName = Path.GetFileName(moved);
            try
            {
                string dest = UniqueQuarPath(quarDir, finalName);
                XorCopy(moved, dest);
                File.Delete(moved);
                finalName = Path.GetFileName(dest);
            }
            catch { }
            // the FOUND line for this file arrived just before the move — take its signature
            string threat = "";
            foreach (string[] ff in foundFiles)
                if (string.Equals(ff[0], original, StringComparison.OrdinalIgnoreCase)) { threat = ff[1]; break; }
            try
            {
                File.AppendAllText(quarIndex,
                    finalName + "|" + original + "|" + DateTime.Now.ToString("yyyy-MM-dd HH:mm")
                    + "|" + threat + "|" + currentScanDesc + "\r\n",
                    new UTF8Encoding(false));
            }
            catch { }
        }

        // Final scan wrap-up. Reached via OnScanExit (MainForm.Yara.cs), which
        // may first run the YARA phase over the same file list.
        void FinishScan(int exitCode)
        {
            bool wasMonitor = monitorScan;
            // new files the monitor just cleared are still worth a VirusTotal hash
            // check — fresh malware is often unknown to the signature databases
            if (wasMonitor && VtActive && yaraListPath != null)
            {
                try
                {
                    string[] scanned = File.ReadAllLines(yaraListPath);
                    for (int i = 0; i < scanned.Length && i < 20; i++)
                        if (File.Exists(scanned[i])) VtQueueFile(scanned[i], null);
                }
                catch { }
            }
            yaraListPath = null;
            scanRunning = false;
            monitorScan = false;
            countGen++; // stop the background file counter
            totalToScan = 0;
            initialFilesToScan = 0;
            StopClamd(); // the daemon lives only for the duration of the scan
            CleanupBatchLists();
            if (movedCount > 0) NeutralizeQuarantineFolder(); // safety net for --move drops
            SetBusy(false, null);
            if (!wasMonitor && (exitCode == 0 || exitCode == 1))
            {
                AppendSection(Lang.T("section.summary"));
                AppendLog(string.Format(Lang.T("log.summary"),
                    scannedCount, FormatSpan(DateTime.Now - scanStart), foundCount),
                    foundCount > 0 ? Theme.Danger : Theme.Text,
                    foundCount > 0 ? "INFECTED" : "SCAN", false);
                if (scannedCount < initialFilesToScan)
                {
                    int skipped = initialFilesToScan - scannedCount;
                    AppendLog(string.Format(Lang.T("log.skippedExplanation"), skipped), Theme.Muted, null, false);
                }
            }
            if (exitCode == 0 || exitCode == 1)
            {
                totalScans++;
                totalFilesScanned += scannedCount;
                totalFound += foundCount;
                // totalMoved is counted at each actual move (QuarantineFile /
                // RecordQuarantineMove) — adding movedCount here would double-count
                // the YARA-phase auto-quarantines
                lastScanInfo = DateTime.Now.ToString("dd.MM.yyyy HH:mm");
                SaveSettings();
                UpdateStatsUi();
                AppendScanLog();
            }
            if (exitCode == 0)
            {
                statusLabel.Text = string.Format(Lang.T("status.doneClean"), scannedCount);
                RefreshDbStatus(); // returns to the green "Protected" state
                if (vtPendingYara.Count > 0)
                {
                    // suspicious files are still awaiting the VirusTotal verdict —
                    // don't announce a clean result that may flip in a minute
                    AppendLog(string.Format(Lang.T("log.donePendingVt"), vtPendingYara.Count), Theme.Warn, "WARN", false);
                    Notify(5000, string.Format(Lang.T("tray.donePendingVt"), vtPendingYara.Count), ToolTipIcon.Info);
                }
                else if (wasMonitor)
                {
                    AppendLog(Lang.T("log.newFilesClean"), Theme.Good);
                    Notify(4000, string.Format(Lang.T("tray.newFilesClean"), scannedCount), ToolTipIcon.Info);
                }
                else
                {
                    AppendLog(Lang.T("log.noThreatsFound"), Theme.Good);
                    Notify(4000, Lang.T("tray.scanDoneClean"), ToolTipIcon.Info);
                }
            }
            else if (exitCode == 1)
            {
                string movedInfo = movedCount > 0
                    ? string.Format(Lang.T("status.quarantinedSuffix"), movedCount) : "";
                statusLabel.Text = string.Format(Lang.T("status.threatsFound"),
                    scannedCount, foundCount, movedInfo);
                SetHero(ShieldState.Danger, Lang.T("hero.threatsFoundTitle"),
                    string.Format(Lang.T("hero.threatsFoundSub"), foundCount, movedInfo));
                AppendLog(string.Format(Lang.T("log.threatsFound"), foundCount, movedInfo), Theme.Danger, "INFECTED", false);
                tray.ShowBalloonTip(8000, AppName,
                    string.Format(Lang.T("tray.threatsFoundWarn"), foundCount, movedInfo), ToolTipIcon.Warning);
                RestoreFromTray();
                ShowThreatDialog(); // shows nothing if every file was already quarantined
            }
            else
            {
                statusLabel.Text = string.Format(Lang.T("status.scanInterrupted"), exitCode);
                RefreshDbStatus();
            }
            CleanupMemDumps(); // after the (modal) threat dialog, so found dumps stayed listable
            // New files may have appeared while the scan was running
            if (pendingFiles.Count > 0) { debounceTimer.Stop(); debounceTimer.Start(); }
        }

    }
}
