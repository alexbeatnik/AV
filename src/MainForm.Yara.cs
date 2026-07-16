// YARA engine: a second detection engine that runs community/custom rules over
// the exact same file list as every ClamAV scan (including the RAM dumps), via
// yara64.exe --scan-list. Rules catch malware families and fresh threats the
// signature database may miss; matches are reported as "YARA:<rule>" threats
// and go through the same threat dialog / auto-quarantine pipeline.
// The official yara64.exe comes from the VirusTotal/yara GitHub releases; the
// curated rule set is the YARA Forge "core" package (refreshed weekly). Users
// can drop their own .yar files into yara\rules\custom\.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace AVUI
{
    public partial class MainForm : Form
    {
        bool yaraEnabled = true;          // settings: yara=0 turns the engine off
        DateTime lastYaraRulesCheck;      // when the Forge rules were last downloaded (persisted)
        volatile bool yaraSetupRunning;   // an engine/rules download is already in flight
        int yaraSetupFails;               // consecutive download failures (see EnsureYaraSetup)
        // The per-scan YARA phase state (list path, pending/expected flags, match
        // map, progress counters) lives in ScanSession — note in particular that
        // YaraPhaseExpected only drives the "Phase 1 of N" label; the phase itself
        // is re-decided live in OnScanExit, so an engine that finishes downloading
        // mid-scan still gets its pass (just without the label).
        Timer yaraProgressTimer;          // polls yara64's IO counters for the progress bar

        // yara64 prints nothing per file, so unlike the ClamAV phase there is no
        // output to count. Progress is instead estimated from how many bytes the
        // process has actually read (charged to it by the OS, including
        // memory-mapped page-ins) out of the total size of the files on its list.
        [StructLayout(LayoutKind.Sequential)]
        struct IO_COUNTERS
        {
            public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
            public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
        }
        [DllImport("kernel32.dll")]
        static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS counters);

        const string YaraApiUrl = "https://api.github.com/repos/VirusTotal/yara/releases/latest";
        // known-good pin if the GitHub API is unreachable (same pattern as the ClamAV download)
        const string YaraFallbackZip = "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip";
        // "latest/download" resolves without an API call; the asset name is stable
        const string YaraForgeZip = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";

        static string YaraDir { get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "yara"); } }
        static string YaraExe { get { return Path.Combine(YaraDir, "yara64.exe"); } }
        static string YaraRulesDir { get { return Path.Combine(YaraDir, "rules"); } }
        static string YaraForgeRules { get { return Path.Combine(YaraRulesDir, "forge-core.yar"); } }
        static string YaraCustomDir { get { return Path.Combine(YaraRulesDir, "custom"); } }

        // Forge rules first, then any user-supplied .yar/.yara files
        static List<string> YaraRuleFiles()
        {
            var list = new List<string>();
            if (File.Exists(YaraForgeRules)) list.Add(YaraForgeRules);
            try
            {
                if (Directory.Exists(YaraCustomDir))
                    foreach (string f in Directory.GetFiles(YaraCustomDir))
                    {
                        string ext = Path.GetExtension(f);
                        if (ext.Equals(".yar", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".yara", StringComparison.OrdinalIgnoreCase))
                            list.Add(f);
                    }
            }
            catch { }
            return list;
        }

        bool YaraReady()
        {
            return yaraEnabled && File.Exists(YaraExe) && YaraRuleFiles().Count > 0;
        }

        // ---------- Engine + rules download ----------

        // Fetches whatever part of the YARA setup is missing (engine exe, Forge
        // rules) in the background. Called on startup when the engine is enabled,
        // from the engines dialog when it gets enabled, and by the weekly rules
        // refresh (force=true re-downloads the rules even if present).
        void EnsureYaraSetup(bool forceRules)
        {
            if (!yaraEnabled || yaraSetupRunning) return;
            bool needExe = !File.Exists(YaraExe);
            bool needRules = forceRules || !File.Exists(YaraForgeRules);
            if (!needExe && !needRules) return;
            yaraSetupRunning = true;
            var th = new System.Threading.Thread(delegate()
            {
                string err = null;
                try
                {
                    const System.Net.SecurityProtocolType Tls13 = (System.Net.SecurityProtocolType)12288;
                    System.Net.ServicePointManager.SecurityProtocol |= System.Net.SecurityProtocolType.Tls12 | Tls13;
                    Directory.CreateDirectory(YaraRulesDir);
                    Directory.CreateDirectory(YaraCustomDir);
                    if (needExe) DownloadYaraEngine();
                    else if (forceRules)
                    {
                        // the weekly rules refresh also keeps the engine current:
                        // yara64 releases a few times a year, and without this the
                        // exe installed on day one would never be updated. Any
                        // doubt (either version unreadable) means no re-download.
                        if (YaraVersionIsNewer(LatestYaraTag(), InstalledYaraVersion()))
                            DownloadYaraEngine();
                    }
                    if (needRules) DownloadYaraForgeRules();
                }
                catch (Exception ex) { err = ex.Message; }
                string fe = err;
                try
                {
                    BeginInvoke((Action)delegate
                    {
                        yaraSetupRunning = false;
                        if (fe != null)
                        {
                            // The hourly auto-update timer retries a due download until it
                            // succeeds; offline that used to print a warning every hour.
                            // Only the first failure is a visible warning — repeats go to
                            // the details view until a download succeeds again.
                            yaraSetupFails++;
                            AppendLog(string.Format(Lang.T("log.yaraSetupFailed"), fe), Theme.Warn, "WARN", yaraSetupFails > 1);
                            return;
                        }
                        yaraSetupFails = 0;
                        lastYaraRulesCheck = DateTime.Now;
                        SaveSettings();
                        AppendLog(string.Format(Lang.T("log.yaraReady"), YaraRuleFiles().Count), Theme.Good);
                        UpdateStatsUi(); // the dashboard YARA cell flips to ✓
                    });
                }
                catch { }
            });
            th.IsBackground = true;
            th.Start();
        }

        void DownloadYaraEngine()
        {
            UiLog(Lang.T("log.yaraDownloadingEngine"), Theme.Muted);
            string url = null;
            try
            {
                using (var api = new System.Net.WebClient())
                {
                    api.Headers.Add("User-Agent", "AV");
                    string json = api.DownloadString(YaraApiUrl);
                    var m = Regex.Match(json, "\"browser_download_url\"\\s*:\\s*\"([^\"]+win64\\.zip)\"");
                    if (m.Success) url = m.Groups[1].Value;
                }
            }
            catch { } // API unavailable — use the pinned release
            if (url == null) url = YaraFallbackZip;
            string zip = Path.Combine(YaraDir, "yara-download.zip");
            using (var wc = new System.Net.WebClient())
            {
                wc.Headers.Add("User-Agent", "AV");
                wc.DownloadFile(url, zip);
            }
            string tmp = Path.Combine(YaraDir, "yara-tmp");
            if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
            System.IO.Compression.ZipFile.ExtractToDirectory(zip, tmp);
            string exe = FindFileUnder(tmp, "yara64.exe");
            if (exe == null) throw new Exception(Lang.T("err.noYaraInArchive"));
            File.Copy(exe, YaraExe, true);
            try { Directory.Delete(tmp, true); } catch { }
            try { File.Delete(zip); } catch { }
        }

        void DownloadYaraForgeRules()
        {
            UiLog(Lang.T("log.yaraDownloadingRules"), Theme.Muted);
            string zip = Path.Combine(YaraDir, "rules-download.zip");
            using (var wc = new System.Net.WebClient())
            {
                wc.Headers.Add("User-Agent", "AV");
                wc.DownloadFile(YaraForgeZip, zip);
            }
            string tmp = Path.Combine(YaraDir, "rules-tmp");
            if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
            System.IO.Compression.ZipFile.ExtractToDirectory(zip, tmp);
            // the package contains packages/core/yara-rules-core.yar — take the
            // biggest .yar in the archive so a layout change doesn't break us
            string best = null;
            long bestSize = 0;
            foreach (string f in Directory.GetFiles(tmp, "*.yar", SearchOption.AllDirectories))
            {
                long len = new FileInfo(f).Length;
                if (len > bestSize) { best = f; bestSize = len; }
            }
            if (best == null) throw new Exception(Lang.T("err.noRulesInArchive"));
            PromoteDownloadedFile(best, YaraForgeRules);
            try { Directory.Delete(tmp, true); } catch { }
            try { File.Delete(zip); } catch { }
        }

        static string FindFileUnder(string dir, string name)
        {
            foreach (string f in Directory.GetFiles(dir, name, SearchOption.AllDirectories))
                return f;
            return null;
        }

        // ---------- Engine version check (piggybacks on the weekly refresh) ----------

        // "yara64.exe --version" prints a bare "4.5.2"; null when the exe is
        // missing/broken or prints nothing in time. Called on the setup thread.
        string InstalledYaraVersion()
        {
            try
            {
                var psi = new ProcessStartInfo(YaraExe, "--version");
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                using (var p = Process.Start(psi))
                {
                    // bounded wait — a broken exe that prints nothing must not
                    // hang the setup thread (same pattern as FetchClamVersion)
                    var read = p.StandardOutput.ReadLineAsync();
                    string line = read.Wait(3000) ? read.Result : null;
                    p.WaitForExit(3000);
                    return line;
                }
            }
            catch { return null; }
        }

        // Latest release tag ("v4.5.2") from the GitHub API; null when offline
        // or rate-limited — the caller then simply skips the engine update.
        static string LatestYaraTag()
        {
            try
            {
                using (var api = new System.Net.WebClient())
                {
                    api.Headers.Add("User-Agent", "AV");
                    string json = api.DownloadString(YaraApiUrl);
                    var m = Regex.Match(json, "\"tag_name\"\\s*:\\s*\"([^\"]+)\"");
                    return m.Success ? m.Groups[1].Value : null;
                }
            }
            catch { return null; }
        }

        // True only when both sides parse and the remote release is strictly
        // newer — any doubt means no re-download (a needless engine swap risks
        // racing a scan for nothing).
        internal static bool YaraVersionIsNewer(string remoteTag, string localVersion)
        {
            Version remote = ParseYaraVersion(remoteTag);
            Version local = ParseYaraVersion(localVersion);
            return remote != null && local != null && remote > local;
        }

        // Tolerates a leading "v" and surrounding chatter: "v4.5.2", "4.5.2",
        // "yara 4.5.2 (build)" all yield 4.5.2; null when nothing version-like.
        internal static Version ParseYaraVersion(string s)
        {
            if (s == null) return null;
            var m = Regex.Match(s, "(\\d+)\\.(\\d+)(?:\\.(\\d+))?");
            if (!m.Success) return null;
            try
            {
                return new Version(int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value),
                    m.Groups[3].Success ? int.Parse(m.Groups[3].Value) : 0);
            }
            catch { return null; } // digits too long for int — treat as unparsable
        }

        // Weekly rules refresh, piggybacking on the hourly auto-update timer
        void MaybeUpdateYaraRules()
        {
            if (!yaraEnabled || yaraSetupRunning || scan.Running || updateRunning) return;
            if (!File.Exists(YaraExe)) { EnsureYaraSetup(false); return; }
            if ((DateTime.Now - lastYaraRulesCheck).TotalDays < 7) return;
            EnsureYaraSetup(true);
        }

        // ---------- The YARA scan phase ----------

        // Every scan path (manual, monitor batch) funnels its ClamAV exit through
        // here: when YARA is ready and a file list exists, the same list gets a
        // second pass with yara64 before the scan is finalized.
        void OnScanExit(int exitCode)
        {
            // scan.Cancel doubles as the scan-wide cancel flag (StopCurrent sets
            // it): a stopped scan must not continue into the YARA phase
            if (!scan.YaraPhasePending || scan.Cancel || !YaraReady() || scan.YaraListPath == null || !File.Exists(scan.YaraListPath))
            {
                scan.YaraPhasePending = false;
                FinishScan(exitCode);
                return;
            }
            scan.YaraPhasePending = false;
            StopClamd(); // release the daemon's memory before the second engine runs
            RunYaraPhase(exitCode);
        }

        // Filters out paths the given ANSI code page cannot represent (they'd be
        // unopenable for yara64 anyway) — the survivors round-trip losslessly, so
        // yara's output maps back to the exact original path strings.
        internal static List<string> AnsiSafePaths(List<string> paths, Encoding ansi, out int skipped)
        {
            var res = new List<string>(paths.Count);
            skipped = 0;
            foreach (string p in paths)
            {
                if (ansi.GetString(ansi.GetBytes(p)) == p) res.Add(p);
                else skipped++;
            }
            return res;
        }

        void RunYaraPhase(int clamCode)
        {
            scan.YaraClamCode = clamCode;
            scan.YaraPhaseStart = DateTime.Now;
            scan.YaraMatches.Clear();
            scan.YaraErrLines = 0;
            scan.YaraLastFraction = 0;
            if (!scan.Monitor) AppendSection(Lang.T("section.yara"));

            // On Windows, yara64.exe expects the --scan-list file to be encoded in
            // UTF-16 LE (Unicode without BOM) and writes match results to stdout
            // in UTF-8. Re-encode our temporary file list to UTF-16 LE.
            //
            // Additionally, yara64.exe opens files via the ANSI code page (fopen), so
            // we filter out paths that cannot round-trip through the default ANSI encoding,
            // otherwise they cannot be opened anyway and would cause unreadable error logs.
            string scanList = scan.YaraListPath;
            int unsupported = 0;
            List<string> safePaths = null; // kept for the progress total below
            try
            {
                var unicodeWithoutBom = new UnicodeEncoding(false, false);
                var raw = File.ReadAllLines(scan.YaraListPath);
                var safe = AnsiSafePaths(new List<string>(raw), Encoding.Default, out unsupported);
                if (safe.Count == 0)
                {
                    // nothing yara can even open — don't spawn it just to fail
                    AppendLog(string.Format(Lang.T("log.yaraPathsSkipped"), unsupported), Theme.Warn, "WARN", true);
                    FinishScan(clamCode);
                    return;
                }
                // kept before the list-file write: if that throws, the scan falls
                // back to the shared UTF-8 list but the progress total still works
                safePaths = safe;
                string unicodeList = Path.Combine(Path.GetTempPath(), "av-yara-" + Guid.NewGuid().ToString("N") + ".txt");
                File.WriteAllLines(unicodeList, safe.ToArray(), unicodeWithoutBom);
                batchListPaths.Add(unicodeList); // cleaned with the other scan lists
                scanList = unicodeList;
                if (unsupported > 0)
                    AppendLog(string.Format(Lang.T("log.yaraPathsSkipped"), unsupported), Theme.Warn, "WARN", true);
            }
            catch { } // fall back to the shared UTF-8 list — worst case is the old behavior

            // Total workload for the progress estimate, summed off the UI thread
            // (metadata-only reads; the OS cache is still warm from the ClamAV
            // phase). Until it's done the bar just sits at 0%.
            scan.YaraTotalBytes = 0;
            if (!scan.Monitor && safePaths != null)
            {
                bool skipBig = chkSkipBig.Checked;
                string[] sizePaths = safePaths.ToArray();
                var ses = scan; // a slow sizing pass must not write into a newer scan's session
                System.Threading.ThreadPool.QueueUserWorkItem(delegate
                {
                    long sum = YaraWorkloadBytes(sizePaths, skipBig);
                    System.Threading.Interlocked.Exchange(ref ses.YaraTotalBytes, sum);
                });
            }

            AppendLog(Lang.T("log.yaraScanning"), scan.Monitor ? Theme.Muted : Theme.Text, "SCAN", scan.Monitor);
            statusLabel.Text = PhasePrefix(2) + Lang.T("status.yaraScanning");

            var args = new StringBuilder();
            args.Append("-w -f -p ").Append(Math.Min(PerfMaxThreads(perfMode), Environment.ProcessorCount));
            if (chkSkipBig.Checked) args.Append(" --skip-larger=209715200"); // same 200 MB cap as ClamAV
            int ns = 0;
            foreach (string rf in YaraRuleFiles())
            {
                // each file gets its own namespace so a duplicate rule name in a
                // custom file doesn't abort the whole compile
                ns++;
                args.Append(" r").Append(ns).Append(":").Append(Quote(rf));
            }
            args.Append(" --scan-list ").Append(Quote(scanList));
            scan.YaraRunning = true;
            // yara64 outputs in UTF-8 (handled by standard StartProcess overload)
            StartProcess(YaraExe, args.ToString(), OnYaraLine, OnYaraExit);
            if (currentProc == null)
            {
                // yara64 failed to launch (deleted/blocked since the YaraReady
                // check): OnYaraExit will never fire, so close the scan with the
                // ClamAV result instead of leaving it half-open — a stale
                // scan.YaraRunning would mislabel the next scan's heartbeat, and the
                // RAM dumps/list files would never be cleaned up
                scan.YaraRunning = false;
                FinishScan(clamCode);
                return;
            }
            if (!scan.Monitor)
            {
                // the bar restarts from 0 for this phase (the ClamAV part just
                // showed 100%) and climbs again as yara reads through the files
                progress.SetFraction(0);
                shield.SetProgress(0);
                scanProgressLabel.Text = ProgressBarText(0);
                if (yaraProgressTimer == null)
                {
                    yaraProgressTimer = new Timer();
                    yaraProgressTimer.Interval = 1000;
                    yaraProgressTimer.Tick += delegate { YaraProgressTick(); };
                }
                yaraProgressTimer.Start();
            }
        }

        // Bytes the YARA phase is expected to read: the size of every file on
        // its list, minus files over the 200 MB cap when "skip large files" is
        // on (--skip-larger means yara never opens them). Missing/unreadable
        // files count as 0 — the estimate errs toward finishing early.
        internal static long YaraWorkloadBytes(IEnumerable<string> paths, bool skipBig)
        {
            long sum = 0;
            foreach (string p in paths)
            {
                try
                {
                    long len = new FileInfo(p).Length;
                    if (!skipBig || len <= 209715200) sum += len;
                }
                catch { }
            }
            return sum;
        }

        // Progress fraction for the YARA phase. Rule compilation reads a few
        // extra MB, so the value is capped below 100% — only the real process
        // exit completes the phase. 0 while the total isn't known yet.
        internal static double YaraProgressFraction(long readBytes, long totalBytes)
        {
            if (totalBytes <= 0 || readBytes <= 0) return 0;
            if (readBytes > totalBytes) readBytes = totalBytes;
            return Math.Min(0.99, (double)readBytes / totalBytes);
        }

        // Drives the progress bar during the YARA phase: bytes the yara64
        // process has read vs the list's total size.
        void YaraProgressTick()
        {
            if (!scan.YaraRunning) { yaraProgressTimer.Stop(); return; }
            long total = System.Threading.Interlocked.Read(ref scan.YaraTotalBytes);
            Process p = currentProc;
            if (total <= 0 || p == null) return;
            IO_COUNTERS io;
            try { if (!GetProcessIoCounters(p.Handle, out io)) return; }
            catch { return; } // the process just exited under us
            long read = io.ReadTransferCount > long.MaxValue ? long.MaxValue : (long)io.ReadTransferCount;
            if (read > total) read = total;
            double f = YaraProgressFraction(read, total);
            scan.YaraLastFraction = f;
            progress.SetFraction(f);
            shield.SetProgress(f);
            string eta = "";
            double elapsed = (DateTime.Now - scan.YaraPhaseStart).TotalSeconds;
            if (elapsed > 15 && read > 0)
                eta = Lang.T("eta.remainingPrefix")
                    + "~" + FormatSpan(TimeSpan.FromSeconds((total - read) / (read / elapsed)));
            statusLabel.Text = PhasePrefix(2) + string.Format(Lang.T("status.yaraProgress"), f * 100, eta);
            scanProgressLabel.Text = ProgressBarText(f)
                + string.Format("  {0} / {1}  ({2:0}%)", FormatSize(read), FormatSize(total), f * 100);
        }

        // Match lines look like "RuleName C:\path\file"; anything else (compile
        // warnings, "error scanning ..." chatter) is not a match.
        internal static bool ParseYaraMatch(string line, out string rule, out string path)
        {
            rule = path = null;
            if (string.IsNullOrEmpty(line)) return false;
            int sp = line.IndexOf(' ');
            if (sp <= 0 || sp >= line.Length - 1) return false;
            string r = line.Substring(0, sp);
            string p = line.Substring(sp + 1);
            if (r.IndexOf('\\') >= 0 || r.IndexOf('/') >= 0) return false; // not a rule identifier
            if (p.Length < 3 || p[1] != ':' || p[2] != '\\') return false; // not an absolute Windows path
            rule = r;
            path = p;
            return true;
        }

        void OnYaraLine(string line)
        {
            if (string.IsNullOrEmpty(line)) return;
            scan.LastOutput = DateTime.Now;
            string rule, path;
            if (ParseYaraMatch(line, out rule, out path))
            {
                if (!scan.YaraMatches.ContainsKey(path)) scan.YaraMatches[path] = rule;
            }
            else
            {
                // rule warnings / unreadable files: show a few, then just count —
                // a folder of locked files must not flood the log with error lines
                scan.YaraErrLines++;
                if (scan.YaraErrLines <= 3) AppendLog(line + "\r\n", Theme.Warn, "WARN", true);
            }
        }

        void OnYaraExit(int code)
        {
            scan.YaraRunning = false;
            if (yaraProgressTimer != null) yaraProgressTimer.Stop();
            // Stop pressed mid-phase (StopCurrent set the cancel flag and killed
            // yara64): the match list is partial — acting on it would quarantine
            // or hold back files from a scan the user abandoned. Finish as
            // interrupted, the same way a stop during the ClamAV phase does.
            if (scan.Cancel)
            {
                AppendLog(Lang.T("log.cancelled"), Theme.Warn);
                FinishScan(2);
                return;
            }
            int extra = 0, pending = 0;
            foreach (KeyValuePair<string, string> kv in scan.YaraMatches)
            {
                string path = kv.Key;
                string threat = "YARA:" + kv.Value;
                bool known = false;
                foreach (string[] ff in scan.FoundFiles)
                    if (string.Equals(ff[0], path, StringComparison.OrdinalIgnoreCase)) { known = true; break; }
                if (known) continue; // ClamAV already reported this file
                bool isMemDump = memDumpDir != null && IsUnder(path, memDumpDir);
                // Cheap readability probe only — the actual SHA256 is computed by
                // the lookup worker off the UI thread (VtQueueFile accepts a null
                // hash): hashing a multi-GB match here used to freeze the UI.
                bool readable = false;
                if (VtActive && !isMemDump)
                {
                    try { using (File.OpenRead(path)) { } readable = true; } catch { }
                }
                // One community-rule match is a suspicion, not a verdict — Forge
                // rules do hit legitimate packers/installers. When VirusTotal can
                // arbitrate, hold the file untouched until the hash verdict arrives
                // (ResolvePendingYara). RAM dumps can't wait: their temp files are
                // deleted right after the scan, so they take the immediate path;
                // so does a file we can't even read (locked — hashing would fail).
                if (readable && VtQueueFile(path, null))
                {
                    pending++;
                    vtPendingYara[path] = new string[] { threat, scan.Desc };
                    AppendLog(string.Format(Lang.T("log.yaraSuspiciousPending"), path, threat), Theme.Warn, "WARN", false);
                    continue;
                }
                extra++;
                scan.Found++;
                AppendLog(path + ": " + threat + " FOUND\r\n", Theme.Danger, "INFECTED", false);
                if (chkQuarantine.Checked)
                {
                    if (QuarantineFile(path, threat, scan.Desc)) scan.Moved++;
                }
                scan.FoundFiles.Add(new string[] { path, threat }); // threat dialog skips files already moved
            }
            if (scan.YaraErrLines > 3)
                AppendLog(string.Format(Lang.T("log.yaraMoreErrors"), scan.YaraErrLines - 3), Theme.Warn, "WARN", true);
            if (extra == 0 && pending == 0)
            {
                if (code != 0) AppendLog(string.Format(Lang.T("log.yaraExitCode"), code), Theme.Warn, "WARN", true);
                AppendLog(Lang.T("log.yaraClean"), scan.Monitor ? Theme.Muted : Theme.Good, "OK", scan.Monitor);
            }
            else if (extra > 0)
                AppendLog(string.Format(Lang.T("log.yaraFound"), extra), Theme.Danger, "INFECTED", false);
            if (pending > 0)
                AppendLog(string.Format(Lang.T("log.yaraPendingCount"), pending), Theme.Warn, "WARN", false);
            int final = scan.YaraClamCode;
            if (extra > 0 && final == 0) final = 1; // YARA findings surface the threat flow
            FinishScan(final);
        }
    }
}
