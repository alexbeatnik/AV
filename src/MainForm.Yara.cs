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
        string yaraListPath;              // file list of the current scan, reused for the YARA phase
        bool yaraPhasePending;            // a scan is running and YARA should follow the ClamAV part
        int yaraClamCode;                 // ClamAV exit code, held while the YARA phase runs
        volatile bool yaraRunning;        // the yara64 process is scanning (heartbeat message)
        readonly Dictionary<string, string> yaraMatches
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); // path → rule

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
                            AppendLog(string.Format(Lang.T("log.yaraSetupFailed"), fe), Theme.Warn);
                            return;
                        }
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

        // Weekly rules refresh, piggybacking on the hourly auto-update timer
        void MaybeUpdateYaraRules()
        {
            if (!yaraEnabled || yaraSetupRunning || scanRunning || updateRunning) return;
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
            // cancelScanListing doubles as the scan-wide cancel flag (StopCurrent sets
            // it): a stopped scan must not continue into the YARA phase
            if (!yaraPhasePending || cancelScanListing || !YaraReady() || yaraListPath == null || !File.Exists(yaraListPath))
            {
                yaraPhasePending = false;
                FinishScan(exitCode);
                return;
            }
            yaraPhasePending = false;
            StopClamd(); // release the daemon's memory before the second engine runs
            RunYaraPhase(exitCode);
        }

        void RunYaraPhase(int clamCode)
        {
            yaraClamCode = clamCode;
            yaraMatches.Clear();
            if (!monitorScan) AppendSection(Lang.T("section.yara"));
            AppendLog(Lang.T("log.yaraScanning"), monitorScan ? Theme.Muted : Theme.Text, "SCAN", monitorScan);
            statusLabel.Text = Lang.T("status.yaraScanning");

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
            args.Append(" --scan-list ").Append(Quote(yaraListPath));
            yaraRunning = true;
            StartProcess(YaraExe, args.ToString(), OnYaraLine, OnYaraExit);
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
            lastScanOutput = DateTime.Now;
            string rule, path;
            if (ParseYaraMatch(line, out rule, out path))
            {
                if (!yaraMatches.ContainsKey(path)) yaraMatches[path] = rule;
            }
            else
                AppendLog(line + "\r\n", Theme.Warn, "WARN", true); // rule warnings / scan errors
        }

        void OnYaraExit(int code)
        {
            yaraRunning = false;
            int extra = 0, pending = 0;
            foreach (KeyValuePair<string, string> kv in yaraMatches)
            {
                string path = kv.Key;
                string threat = "YARA:" + kv.Value;
                bool known = false;
                foreach (string[] ff in foundFiles)
                    if (string.Equals(ff[0], path, StringComparison.OrdinalIgnoreCase)) { known = true; break; }
                if (known) continue; // ClamAV already reported this file
                string hash = null;
                try { hash = Sha256OfQuarFile(path); } catch { }
                // One community-rule match is a suspicion, not a verdict — Forge
                // rules do hit legitimate packers/installers. When VirusTotal can
                // arbitrate, hold the file untouched until the hash verdict arrives
                // (ResolvePendingYara). RAM dumps can't wait: their temp files are
                // deleted right after the scan, so they take the immediate path.
                bool isMemDump = memDumpDir != null && IsUnder(path, memDumpDir);
                if (VtActive && hash != null && !isMemDump && VtQueueFile(path, hash))
                {
                    pending++;
                    vtPendingYara[path] = threat;
                    AppendLog(string.Format(Lang.T("log.yaraSuspiciousPending"), path, threat), Theme.Warn, "WARN", false);
                    continue;
                }
                extra++;
                foundCount++;
                AppendLog(path + ": " + threat + " FOUND\r\n", Theme.Danger, "INFECTED", false);
                if (chkQuarantine.Checked)
                {
                    if (QuarantineFile(path, threat, currentScanDesc)) movedCount++;
                }
                foundFiles.Add(new string[] { path, threat }); // threat dialog skips files already moved
            }
            if (extra == 0 && pending == 0)
            {
                if (code != 0) AppendLog(string.Format(Lang.T("log.yaraExitCode"), code), Theme.Warn, "WARN", true);
                AppendLog(Lang.T("log.yaraClean"), monitorScan ? Theme.Muted : Theme.Good, "OK", monitorScan);
            }
            else if (extra > 0)
                AppendLog(string.Format(Lang.T("log.yaraFound"), extra), Theme.Danger, "INFECTED", false);
            if (pending > 0)
                AppendLog(string.Format(Lang.T("log.yaraPendingCount"), pending), Theme.Warn, "WARN", false);
            int final = yaraClamCode;
            if (extra > 0 && final == 0) final = 1; // YARA findings surface the threat flow
            FinishScan(final);
        }
    }
}
