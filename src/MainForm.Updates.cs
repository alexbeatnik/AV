// Updates: app self-update, ClamAV download/install, signature database updates.
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
        // ---------- Self-update: check GitHub Releases for a newer AV.exe ----------

        const string UpdateApiUrl = "https://api.github.com/repos/alexbeatnik/AV/releases/latest";
        // On every launch plus once a day while running. One tiny GitHub API
        // request — the 60 unauthenticated requests/hour limit is nowhere near
        // (unlike the ClamAV database CDN, see dbCooldownUntil, which does 429).
        const int AppUpdateCheckHours = 24;
        DateTime lastAppUpdateCheck; // time of the last check (persisted)
        bool checkingAppUpdate;      // a check/download is already in flight
        bool startupAppCheckDone;    // this launch already ran its unconditional check

        // Pure due-time rule (unit-tested): the first check of a launch always
        // fires; after that the daily period applies.
        internal static bool AppUpdateDue(bool startupChecked, DateTime last, DateTime now, int periodHours)
        {
            return !startupChecked || (now - last).TotalHours >= periodHours;
        }

        void MaybeCheckAppUpdate()
        {
            if (checkingAppUpdate || scan.Running || updateRunning) return;
            if (!AppUpdateDue(startupAppCheckDone, lastAppUpdateCheck, DateTime.Now, AppUpdateCheckHours)) return;
            startupAppCheckDone = true; // set only when a check actually launches
            checkingAppUpdate = true;
            System.Threading.ThreadPool.QueueUserWorkItem(delegate { AppUpdateWorker(); });
        }

        // Checks the latest GitHub release and, if it's newer than AppVersion, downloads
        // its AV.exe asset next to the current one. Runs entirely off the UI thread;
        // network failures are silent (retried on the next scheduled check).
        void AppUpdateWorker()
        {
            string downloadedExe = null, version = null;
            bool success = false;
            try
            {
                const System.Net.SecurityProtocolType Tls13 = (System.Net.SecurityProtocolType)12288;
                System.Net.ServicePointManager.SecurityProtocol |= System.Net.SecurityProtocolType.Tls12 | Tls13;
                string json;
                using (var api = new System.Net.WebClient())
                {
                    api.Headers.Add("User-Agent", "AV");
                    json = api.DownloadString(UpdateApiUrl);
                }
                var vm = Regex.Match(json, "\"tag_name\"\\s*:\\s*\"[vV]?([\\d.]+)\"");
                var um = Regex.Match(json, "\"browser_download_url\"\\s*:\\s*\"([^\"]*AV\\.exe)\"");
                if (vm.Success && um.Success)
                {
                    success = true;
                    if (new Version(vm.Groups[1].Value) > new Version(AppVersion))
                    {
                        version = vm.Groups[1].Value;
                        // %TEMP% is always writable, wherever the app itself lives
                        string updatePath = Path.Combine(Path.GetTempPath(), "AV.update.exe");
                        TryDelete(updatePath); // leftover from an earlier interrupted attempt
                        using (var wc = new System.Net.WebClient())
                        {
                            wc.Headers.Add("User-Agent", "AV");
                            wc.DownloadFile(um.Groups[1].Value, updatePath);
                        }
                        // sanity check: a real build is ~300 KB, an error page/HTML redirect is not
                        if (File.Exists(updatePath) && new FileInfo(updatePath).Length > 50 * 1024)
                            downloadedExe = updatePath;
                        else
                            TryDelete(updatePath);
                    }
                }
            }
            catch { } // offline, rate-limited, or no releases yet — try again tomorrow

            string fp = downloadedExe, fv = version;
            bool s = success;
            try { BeginInvoke((Action)delegate { OnAppUpdateChecked(fp, fv, s); }); }
            catch { }
        }

        void OnAppUpdateChecked(string updatePath, string version, bool success)
        {
            checkingAppUpdate = false;
            if (success)
            {
                lastAppUpdateCheck = DateTime.Now;
                SaveSettings();
            }
            if (updatePath == null) return;
            // busy — retried tomorrow. Held-back VirusTotal verdicts count as busy
            // too: vtPendingYara lives only in memory, so restarting mid-phase-3
            // would silently drop the suspicious files awaiting their verdict.
            // A modal dialog open (threat dialog, engines, quarantine props) is the
            // same hazard: swapping the exe and restarting under it would tear down
            // an in-memory decision (scan.FoundFiles for a non-auto-quarantine scan
            // is dropped on restart) — defer it exactly like the scheduled scan and
            // monitor batch do (IsWindowEnabled).
            if (scan.Running || updateRunning || vtPhaseRunning || vtPendingYara.Count > 0
                || !NativeMethods.IsWindowEnabled(Handle))
            { TryDelete(updatePath); return; }
            ApplyAppUpdate(updatePath, version);
        }

        // Swaps in the downloaded build and relaunches: a detached cmd.exe helper waits
        // for this process to exit (so the exe file is no longer locked), moves the new
        // build over the current one, then starts it again in the same tray state.
        void ApplyAppUpdate(string updatePath, string version)
        {
            try
            {
                Notify(4000, string.Format(Lang.T("tray.appUpdateInstalling"), version), ToolTipIcon.Info);
            }
            catch { }
            string exePath = Application.ExecutablePath;
            bool trayNext = WindowState == FormWindowState.Minimized || !ShowInTaskbar;
            var psi = new ProcessStartInfo("cmd.exe",
                "/c timeout /t 3 /nobreak >nul & move /y \"" + updatePath + "\" \"" + exePath + "\""
                + " & start \"\" \"" + exePath + "\"" + (trayNext ? " --tray" : ""));
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            try
            {
                Process.Start(psi);
                reallyClose = true;
                Close(); // releases the exe file lock so the helper script can replace it
            }
            catch { TryDelete(updatePath); }
        }

        // ---------- Database updates ----------

        void RunFreshclam()
        {
            RunFreshclam(false);
        }

        // ---------- Automatic ClamAV installation (for a clean PC) ----------

        void OfferClamAVDownload()
        {
            if (!IsInstalled)
            {
                DialogResult r = MessageBox.Show(this,
                    Lang.T("msg.offerInstallChoice"),
                    AppName, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
                if (r == DialogResult.Yes) LaunchInstaller();
                else if (r == DialogResult.No) StartClamAVDownload();
                return;
            }
            if (MessageBox.Show(this,
                Lang.T("msg.offerPortableDownload"),
                AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                StartClamAVDownload();
        }

        void LaunchInstaller()
        {
            try
            {
                // per-user install (%LocalAppData%\Programs) — no elevation needed
                Process.Start(Application.ExecutablePath, "--install");
                reallyClose = true;
                Close(); // the installed copy will launch itself after copying
            }
            catch
            {
                statusLabel.Text = Lang.T("status.installCancelled");
            }
        }

        void StartClamAVDownload()
        {
            if (scan.Running || updateRunning) return;
            updateRunning = true;

            // If the archive was already downloaded (interrupted install), extract it instead of re-downloading
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string existingZip = Path.Combine(baseDir, "clamav-download.zip");
            if (File.Exists(existingZip) && new FileInfo(existingZip).Length > 50 * 1048576)
            {
                SetBusy(true, Lang.T("status.foundArchiveExtracting"));
                SetHero(ShieldState.Busy, Lang.T("hero.installingClamAV"), Lang.T("hero.extractingArchive"));
                System.Threading.ThreadPool.QueueUserWorkItem(delegate { ExtractClamZip(baseDir, existingZip); });
                return;
            }

            SetBusy(true, Lang.T("status.findingLatestClamAV"));
            SetHero(ShieldState.Busy, Lang.T("hero.installingClamAV"), Lang.T("hero.findingLatestRelease"));
            const System.Net.SecurityProtocolType Tls13 = (System.Net.SecurityProtocolType)12288;
            System.Net.ServicePointManager.SecurityProtocol |= System.Net.SecurityProtocolType.Tls12 | Tls13;

            System.Threading.ThreadPool.QueueUserWorkItem(delegate
            {
                string url = null;
                try
                {
                    using (var api = new System.Net.WebClient())
                    {
                        api.Headers.Add("User-Agent", "AV");
                        string json = api.DownloadString(
                            "https://api.github.com/repos/Cisco-Talos/clamav/releases/latest");
                        var m = Regex.Match(json, "\"browser_download_url\"\\s*:\\s*\"([^\"]+win\\.x64\\.zip)\"");
                        if (m.Success) url = m.Groups[1].Value;
                    }
                }
                catch { } // API unavailable — fall back to a known version below
                if (url == null)
                    url = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.3/clamav-1.5.3.win.x64.zip";
                try { BeginInvoke((Action<string>)DownloadClamZip, url); }
                catch { }
            });
        }

        void DownloadClamZip(string url)
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string zipPath = Path.Combine(baseDir, "clamav-download.zip");
            AppendLog(string.Format(Lang.T("log.downloading"), url), Theme.Muted);

            var wc = new System.Net.WebClient();
            clamZipClient = wc; // so "Stop" can cancel the download
            wc.Headers.Add("User-Agent", "AV");
            wc.DownloadProgressChanged += delegate(object s, System.Net.DownloadProgressChangedEventArgs e)
            {
                if (e.TotalBytesToReceive > 0)
                {
                    progress.SetFraction((double)e.BytesReceived / e.TotalBytesToReceive);
                    statusLabel.Text = string.Format(Lang.T("status.downloadingClamAV"),
                        e.BytesReceived / 1048576, e.TotalBytesToReceive / 1048576);
                }
            };
            wc.DownloadFileCompleted += delegate(object s, System.ComponentModel.AsyncCompletedEventArgs e)
            {
                clamZipClient = null;
                wc.Dispose();
                if (e.Cancelled)
                {
                    updateRunning = false;
                    TryDelete(zipPath); // a partial archive isn't usable for recovery
                    SetBusy(false, Lang.T("status.clamAVDownloadCancelled"));
                    SetHero(ShieldState.Warning, Lang.T("hero.installCancelled"),
                        Lang.T("hero.pressUpdateRetry"));
                    return;
                }
                if (e.Error != null)
                {
                    updateRunning = false;
                    SetBusy(false, string.Format(Lang.T("status.clamAVDownloadFailed"), e.Error.Message));
                    SetHero(ShieldState.Danger, Lang.T("hero.downloadError"),
                        Lang.T("hero.checkConnectionRetry"));
                    return;
                }
                statusLabel.Text = Lang.T("status.extractingClamAV");
                SetHero(ShieldState.Busy, Lang.T("hero.installingClamAV"), Lang.T("hero.extractingArchive"));
                System.Threading.ThreadPool.QueueUserWorkItem(delegate { ExtractClamZip(baseDir, zipPath); });
            };
            wc.DownloadFileAsync(new Uri(url), zipPath);
        }

        void ExtractClamZip(string baseDir, string zipPath)
        {
            string err = null;
            try
            {
                string tmp = Path.Combine(baseDir, "clamav-tmp");
                if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
                System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, tmp);
                // inside the zip is a clamav-x.y.z.win.x64 folder
                string src = tmp;
                if (!File.Exists(Path.Combine(src, "clamscan.exe")))
                    foreach (string d in Directory.GetDirectories(tmp))
                        if (File.Exists(Path.Combine(d, "clamscan.exe"))) { src = d; break; }
                string dst = Path.Combine(baseDir, "clamav");
                if (!File.Exists(Path.Combine(src, "clamscan.exe")))
                    throw new Exception(Lang.T("err.noClamscanInArchive"));
                // The official zip unpacks to ~900 MB, ~760 MB of which is
                // build-time artifacts the scanner never reads at runtime
                // (.pdb debug symbols, clamav_rust.lib) — drop them so the
                // install keeps only the ~140 MB that actually runs
                foreach (string f in Directory.GetFiles(src))
                {
                    string ext = Path.GetExtension(f);
                    if (ext.Equals(".pdb", StringComparison.OrdinalIgnoreCase)
                        || ext.Equals(".lib", StringComparison.OrdinalIgnoreCase))
                        TryDelete(f);
                }
                PromoteExtractedFolder(src, dst);
                if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
                File.Delete(zipPath);
            }
            catch (Exception ex)
            {
                err = ex.Message;
                // clean up a corrupt/partial archive, otherwise every retry just trips
                // over it again instead of re-downloading
                if (ex is InvalidDataException) TryDelete(zipPath);
            }

            try
            {
                BeginInvoke((Action)delegate
                {
                    updateRunning = false;
                    if (err != null)
                    {
                        SetBusy(false, string.Format(Lang.T("status.clamAVInstallError"), err));
                        SetHero(ShieldState.Danger, Lang.T("hero.installError"), err);
                        return;
                    }
                    SetBusy(false, Lang.T("status.clamAVInstalled"));
                    AppendLog(Lang.T("log.clamAVInstalled"), Theme.Good);
                    LocateClamAV();
                    RefreshDbStatus();
                    if (clamDir != null && !DbExists()) RunFreshclam(); // fetch the database right away
                });
            }
            catch { }
        }

        // Downloads the database directly instead of via freshclam: its libcurl reliably
        // hangs when fetching main.cvd from Cloudflare, while .NET downloads it fine.
        static readonly string[] DbUrls = new string[]
        {
            "https://database.clamav.net/main.cvd",
            "https://database.clamav.net/daily.cvd",
            "https://database.clamav.net/bytecode.cvd"
        };
        volatile bool cancelUpdate;
        System.Net.WebClient clamZipClient; // the active ClamAV archive download
        DateTime dbCooldownUntil;           // the CDN returned 429 — don't hit the server again until this time
        int cooldown429Sec;                 // Retry-After from the 429 response (for the UI thread)

        void RunFreshclam(bool auto)
        {
            if (scan.Running || updateRunning) return;
            if (clamDir == null) { StartClamAVDownload(); return; } // clean PC
            // the server rate-limited us (429) — don't hammer it, that would extend the block
            if (DateTime.Now < dbCooldownUntil)
            {
                if (auto) return;
                if (MessageBox.Show(this,
                    string.Format(Lang.T("msg.cooldownWarn"), dbCooldownUntil.ToString("HH:mm")),
                    AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            }
            updateRunning = true;
            cancelUpdate = false;
            if (!auto)
            {
                ClearLog();
                AppendSection(Lang.T("btn.updateDb"));
                AppendLog(Lang.T("log.updatingDbFirstTime"), Theme.Text);
            }
            else
            {
                AppendSection(Lang.T("btn.updateDb"));
                AppendLog(string.Format(Lang.T("log.autoUpdating"), DateTime.Now), Theme.Muted);
            }
            SetBusy(true, auto ? Lang.T("status.autoUpdatingDb") : Lang.T("status.updatingDb"));
            SetHero(ShieldState.Busy, Lang.T("hero.updatingDb"), Lang.T("hero.downloadingSignatures"));

            System.Threading.ThreadPool.QueueUserWorkItem(delegate { DbUpdateWorker(); });
        }

        void DbUpdateWorker()
        {
            const System.Net.SecurityProtocolType Tls13 = (System.Net.SecurityProtocolType)12288;
            System.Net.ServicePointManager.SecurityProtocol |= System.Net.SecurityProtocolType.Tls12 | Tls13;
            string err = null;
            int updated = 0;
            try
            {
                foreach (string url in DbUrls)
                {
                    if (cancelUpdate) throw new Exception(CancelledMarker);
                    string name = url.Substring(url.LastIndexOf('/') + 1);
                    string dest = Path.Combine(dbDir, name);
                    long localVer = LocalCvdVersion(dest);
                    long remoteVer = RemoteCvdVersion(url); // Let it throw
                    if (localVer > 0 && remoteVer > 0 && localVer >= remoteVer)
                    {
                        UiLog(string.Format(Lang.T("log.dbAlreadyCurrent"), name, localVer), Theme.Muted);
                        continue;
                    }
                    if (remoteVer > 0 || localVer == 0)
                    {
                        DownloadCvd(url, dest, name);
                        updated++;
                    }
                    else
                        // the server responded but the header isn't a CVD — surface an
                        // error instead of silently reporting "already up to date"
                        throw new Exception(string.Format(Lang.T("err.versionCheckFailed"), name));
                }
            }
            catch (Exception ex)
            {
                err = ex.Message;
                // 429 Too Many Requests: the CDN rate-limited our address — back off
                var we = ex as System.Net.WebException;
                var resp = we != null ? we.Response as System.Net.HttpWebResponse : null;
                if (resp != null && (int)resp.StatusCode == 429)
                {
                    int waitSec = 6 * 3600; // if the server didn't say how long — 6 hours
                    string ra = resp.Headers["Retry-After"];
                    int v;
                    if (!string.IsNullOrEmpty(ra) && int.TryParse(ra, out v) && v > 0)
                        waitSec = Math.Max(900, Math.Min(v, 24 * 3600));
                    cooldown429Sec = waitSec;
                    err = "429";
                }
            }

            string fe = err;
            int fu = updated;
            try { BeginInvoke((Action)delegate { OnDbUpdateDone(fe, fu); }); }
            catch { }
        }

        void OnDbUpdateDone(string err, int updated)
        {
            updateRunning = false;
            SetBusy(false, null);
            FetchClamVersion();
            if (err == null) updateAvailable = false; // updated — the button is no longer needed
            if (ShouldClearDbCooldown(err == null, dbCooldownUntil, DateTime.Now))
            {
                dbCooldownUntil = DateTime.MinValue;
                SaveSettings();
            }
            RefreshDbStatus();
            if (err == null)
            {
                statusLabel.Text = updated > 0 ? Lang.T("status.dbUpdated") : Lang.T("status.dbAlreadyCurrent2");
                AppendLog(updated > 0 ? Lang.T("log.dbUpdated") : Lang.T("log.dbAlreadyCurrentLog"), Theme.Good);
            }
            else if (err == CancelledMarker)
            {
                statusLabel.Text = Lang.T("status.updateCancelled");
                AppendLog(Lang.T("log.updateCancelled"), Theme.Warn);
            }
            else if (err == "429")
            {
                dbCooldownUntil = DateTime.Now.AddSeconds(cooldown429Sec);
                SaveSettings();
                statusLabel.Text = Lang.T("status.serverRateLimited");
                AppendLog(Lang.T("log.rateLimitedExplain")
                    + string.Format(Lang.T("log.nextAttempt"), dbCooldownUntil),
                    Theme.Warn);
            }
            else
            {
                statusLabel.Text = Lang.T("status.updateError");
                AppendLog(string.Format(Lang.T("log.updateErrorDetail"), err), Theme.Danger);
            }
        }

        // Pure rule (unit-tested): a download that succeeded while a 429
        // cooldown was still pending proves the block is over ("try anyway") —
        // a stale deadline must not keep the daily auto-check blocked after
        // the server is clearly serving us again.
        internal static bool ShouldClearDbCooldown(bool updateSucceeded, DateTime cooldownUntil, DateTime now)
        {
            return updateSucceeded && now < cooldownUntil;
        }

        // Database version from the 512-byte CVD header ("ClamAV-VDB:date:version:...")
        internal static long CvdVersionFromHeader(byte[] head, int len)
        {
            return CvdFieldFromHeader(head, len, 2);
        }

        // The CVD header is colon-separated: "ClamAV-VDB:<build date>:<version>:<signatures>:…"
        internal static long CvdFieldFromHeader(byte[] head, int len, int field)
        {
            try
            {
                string s = Encoding.ASCII.GetString(head, 0, Math.Min(len, 512));
                string[] parts = s.Split(':');
                if (parts.Length > field) { long v; if (long.TryParse(parts[field], out v)) return v; }
            }
            catch { }
            return 0;
        }

        internal static long LocalCvdVersion(string path)
        {
            return LocalCvdField(path, 2);
        }

        internal static long LocalCvdField(string path, int field)
        {
            if (!File.Exists(path)) return 0;
            try
            {
                using (var fs = File.OpenRead(path))
                {
                    var buf = new byte[512];
                    int n = fs.Read(buf, 0, 512);
                    return CvdFieldFromHeader(buf, n, field);
                }
            }
            catch { return 0; }
        }

        // Fills the dashboard engines strip: one cell per ClamAV database file
        // (freshclam may have converted a .cvd to .cld — whichever is present wins),
        // the total signature count, and the status of the two other detection
        // layers — YARA rules and the VirusTotal hash check.
        // The engines strip: ClamAV, its database, signature count, YARA, and
        // VirusTotal — every engine's state in one compact row (see UpdateStatsUi).
        // Five cells on purpose: the call-to-action buttons dock on the right of
        // this strip, and the row must stay readable next to them at the default
        // window width. Per-file cvd versions live in the ClamAV card (Engines).
        void DbStripData(out string[] caps, out string[] vals, out Color[] colors)
        {
            caps = new string[5];
            vals = new string[5];
            colors = new Color[5];

            // ClamAV: the core engine's version, green once it's present with a database
            caps[0] = Lang.T("stat.clamav");
            vals[0] = clamVersion;
            colors[0] = clamDir != null && DbExists() ? Theme.Good : Theme.Warn;

            // Database: the daily.cvd version (the file that actually changes every
            // day); the database date is already in the hero. Signature count sums
            // all three files.
            long sigs = 0, dailyVer = 0;
            string[] names = { "main", "daily", "bytecode" };
            foreach (string name in names)
            {
                if (dbDir == null) break;
                string file = Path.Combine(dbDir, name + ".cvd");
                long ver = LocalCvdVersion(file);
                if (ver == 0)
                {
                    string cld = Path.Combine(dbDir, name + ".cld");
                    long cldVer = LocalCvdVersion(cld);
                    if (cldVer > 0) { file = cld; ver = cldVer; }
                }
                if (ver > 0) sigs += LocalCvdField(file, 3);
                if (name == "daily") dailyVer = ver;
            }
            caps[1] = Lang.T("stat.database");
            vals[1] = dailyVer > 0 ? "v" + dailyVer : "—";
            if (dailyVer == 0) colors[1] = Theme.Warn;
            caps[2] = Lang.T("stat.signatures");
            vals[2] = sigs > 0 ? sigs.ToString("#,0") : "—";

            // YARA: ✓ + rules date when ready, otherwise why it isn't
            caps[3] = Lang.T("stat.yara");
            if (!yaraEnabled)
            {
                vals[3] = Lang.T("sval.disabled");
                colors[3] = Theme.Muted;
            }
            else if (YaraReady())
            {
                string when = File.Exists(YaraForgeRules)
                    ? File.GetLastWriteTime(YaraForgeRules).ToString("dd.MM.yyyy") : "";
                vals[3] = ("✓ " + when).TrimEnd();
                colors[3] = Theme.Good;
            }
            else
            {
                vals[3] = yaraSetupRunning ? Lang.T("sval.downloading") : "—";
                colors[3] = Theme.Warn;
            }

            // VirusTotal: enabled with a key / no key yet / switched off / offline
            caps[4] = Lang.T("stat.virustotal");
            if (vtApiKey.Length == 0)
            {
                vals[4] = Lang.T("sval.vtNoKey");
                colors[4] = Theme.Warn;
            }
            else if (!vtCheckEnabled)
            {
                vals[4] = Lang.T("sval.disabled");
                colors[4] = Theme.Muted;
            }
            else if (!NetOnline())
            {
                vals[4] = Lang.T("sval.vtOffline");
                colors[4] = Theme.Warn;
            }
            else
            {
                vals[4] = "✓ " + Lang.T("sval.enabled");
                colors[4] = Theme.Good;
            }
        }

        // "Is there any network at all?" — cheap local check (no probe request).
        // Can stay true behind a captive portal or with virtual adapters up, but
        // catches the common cases: Wi-Fi off, cable unplugged, airplane mode.
        internal static bool NetOnline()
        {
            try { return System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable(); }
            catch { return true; } // if the check itself fails, don't cry offline
        }

        static long RemoteCvdVersion(string url)
        {
            var req = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(url);
            req.UserAgent = "ClamAV/1.5.3";
            req.Timeout = 30000;
            req.AddRange(0, 511);
            using (var resp = req.GetResponse())
            using (var rs = resp.GetResponseStream())
            {
                var buf = new byte[512];
                int total = 0, r;
                while (total < 512 && (r = rs.Read(buf, total, 512 - total)) > 0) total += r;
                return CvdVersionFromHeader(buf, total);
            }
        }

        void DownloadCvd(string url, string dest, string name)
        {
            var req = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(url);
            req.UserAgent = "ClamAV/1.5.3";
            req.Timeout = 30000;
            string part = dest + ".part";
            try
            {
                using (var resp = (System.Net.HttpWebResponse)req.GetResponse())
                using (var rs = resp.GetResponseStream())
                using (var fs = new FileStream(part, FileMode.Create, FileAccess.Write))
                {
                    rs.ReadTimeout = 45000; // abort a stalled connection instead of waiting forever
                    long total = resp.ContentLength;
                    long got = 0;
                    var buf = new byte[65536];
                    int read;
                    DateTime lastUi = DateTime.MinValue;
                    while ((read = rs.Read(buf, 0, buf.Length)) > 0)
                    {
                        if (cancelUpdate) throw new Exception(CancelledMarker);
                        fs.Write(buf, 0, read);
                        got += read;
                        if ((DateTime.Now - lastUi).TotalMilliseconds > 250)
                        {
                            lastUi = DateTime.Now;
                            long g = got, t = total;
                            try
                            {
                                BeginInvoke((Action)delegate
                                {
                                    if (t > 0) progress.SetFraction((double)g / t);
                                    statusLabel.Text = string.Format(Lang.T("status.downloadingDb"),
                                        name, g / 1048576.0, t / 1048576.0, t > 0 ? g * 100.0 / t : 0);
                                });
                            }
                            catch { }
                        }
                    }
                }
                // the server might have returned an error page instead of the database — check the CVD header
                if (LocalCvdVersion(part) <= 0)
                {
                    TryDelete(part);
                    throw new Exception(string.Format(Lang.T("err.notADatabaseFile"), name));
                }
                PromoteDownloadedFile(part, dest);
                UiLog(string.Format(Lang.T("log.dbFileDownloaded"), name), Theme.Good);
            }
            catch
            {
                TryDelete(part);
                throw;
            }
        }

        // Promotes a fully downloaded .part file to the live database file.
        // Replace, not Delete+Move: a failure between those two would leave no
        // working database at all. File.Replace (Win32 ReplaceFile) swaps in
        // place — at every moment either the old or the new file exists at dest.
        // The null backup argument is valid on .NET Framework: no backup is kept.
        internal static void PromoteDownloadedFile(string part, string dest)
        {
            if (File.Exists(dest)) File.Replace(part, dest, null);
            else File.Move(part, dest);
        }

        // Same loss-safety rule for the extracted ClamAV folder. Directories
        // have no ReplaceFile, so: rename the old install aside, move the new
        // one in, drop the old. A lock/AV/disk failure at any step leaves the
        // old working install in place (or rolls it back) — never Delete+Move,
        // which would destroy the scanner before the replacement is in place.
        internal static void PromoteExtractedFolder(string src, string dst)
        {
            string old = dst + "-old";
            if (Directory.Exists(dst))
            {
                if (Directory.Exists(old)) Directory.Delete(old, true); // stale leftover from an interrupted install
                Directory.Move(dst, old);
            }
            // else: a previous run died between the two moves and old (if present)
            // is the only working install — keep it as the rollback copy below
            try { Directory.Move(src, dst); }
            catch
            {
                if (Directory.Exists(old) && !Directory.Exists(dst))
                    try { Directory.Move(old, dst); } catch { }
                throw;
            }
            try { if (Directory.Exists(old)) Directory.Delete(old, true); } catch { }
        }

        // Thread-safe logging from a background thread
        void UiLog(string text, Color color)
        {
            try { BeginInvoke((Action)delegate { AppendLog(text, color); }); }
            catch { }
        }

    }
}
