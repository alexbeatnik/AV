// Locating ClamAV, database status, settings load/save, default watch folders.
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
        // ---------- Locating ClamAV ----------

        void LocateClamAV()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string[] candidates = new string[]
            {
                Path.Combine(baseDir, "clamav"),
                baseDir,
                Path.Combine(baseDir, @"..\clamav"),
                @"C:\Program Files\ClamAV"
            };
            foreach (string c in candidates)
            {
                string full = Path.GetFullPath(c);
                if (File.Exists(Path.Combine(full, "clamscan.exe")))
                {
                    clamDir = full;
                    break;
                }
            }
            if (clamDir == null)
            {
                // clean up remnants of an interrupted extraction (keep the zip itself for recovery)
                try
                {
                    string tmp = Path.Combine(baseDir, "clamav-tmp");
                    if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
                }
                catch { }
                AppendLog(Lang.T("log.clamscanNotFound"), Theme.Warn);
                SetScanEnabled(false);
                return; // btnUpdate stays enabled: it will trigger the install
            }
            dbDir = Path.Combine(clamDir, "database");
            try
            {
                // must not crash startup: clamDir can be read-only for us (e.g. the
                // official ClamAV MSI in Program Files, found by the candidate list
                // above, with the app running non-elevated)
                if (!Directory.Exists(dbDir)) Directory.CreateDirectory(dbDir);
                EnsureFreshclamConf();
            }
            catch (Exception ex)
            {
                AppendLog(string.Format(Lang.T("log.clamDirNotWritable"), ex.Message), Theme.Warn);
            }
            FetchClamVersion();
            AppendLog(string.Format(Lang.T("log.clamAVPath"), clamDir), Theme.Muted);
        }

        void FetchClamVersion()
        {
            try
            {
                var psi = new ProcessStartInfo(Path.Combine(clamDir, "clamscan.exe"), "--version");
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                using (var p = Process.Start(psi))
                {
                    // ReadLine() would block the UI forever if the exe is broken and
                    // prints nothing — bounded wait instead
                    var read = p.StandardOutput.ReadLineAsync(); // "ClamAV 1.5.3/27710/..."
                    string line = read.Wait(3000) ? read.Result : null;
                    p.WaitForExit(3000);
                    if (!string.IsNullOrEmpty(line))
                        clamVersion = line.Replace("ClamAV ", "").Split('/')[0];
                }
            }
            catch { }
        }

        void EnsureFreshclamConf()
        {
            string conf = Path.Combine(clamDir, "freshclam.conf");
            if (File.Exists(conf)) return;
            // the path must be quoted: unquoted "C:\Program Files\..." breaks on the space
            File.WriteAllText(conf,
                "DatabaseDirectory \"" + dbDir + "\"\r\n" +
                "DatabaseMirror database.clamav.net\r\n",
                new UTF8Encoding(false));
        }

        bool DbExists()
        {
            if (dbDir == null || !Directory.Exists(dbDir)) return false;
            return Directory.GetFiles(dbDir, "*.cvd").Length > 0
                || Directory.GetFiles(dbDir, "*.cld").Length > 0;
        }

        string DbDateString()
        {
            if (!DbExists()) return "—";
            DateTime newest = DateTime.MinValue;
            foreach (string f in Directory.GetFiles(dbDir))
            {
                // only real database files — a leftover .part download or a stray file
                // must not pass for "the database is fresh"
                string ext = Path.GetExtension(f);
                if (!ext.Equals(".cvd", StringComparison.OrdinalIgnoreCase)
                    && !ext.Equals(".cld", StringComparison.OrdinalIgnoreCase)) continue;
                DateTime t = File.GetLastWriteTime(f);
                if (t > newest) newest = t;
            }
            return newest == DateTime.MinValue ? "—" : newest.ToString("dd.MM.yyyy HH:mm");
        }

        void RefreshDbStatus()
        {
            if (clamDir == null)
            {
                btnUpdate.Visible = true; // here the button triggers ClamAV installation
                SetHero(ShieldState.Danger, Lang.T("hero.clamAVNotFound"),
                    Lang.T("hero.putPortableClamAV"));
                return;
            }
            if (DbExists())
            {
                // the update button is visible only when the server actually has a newer database
                btnUpdate.Visible = updateAvailable;
                SetHero(ShieldState.Ok, Lang.T("hero.protected"), string.Format(Lang.T("hero.dbFrom"), DbDateString()));
                SetScanEnabled(!scanRunning && !updateRunning);
            }
            else
            {
                btnUpdate.Visible = true;
                SetHero(ShieldState.Warning, Lang.T("hero.dbNeeded"),
                    Lang.T("hero.pressUpdateFirstTime"));
                SetScanEnabled(false);
            }
            UpdateStatsUi();
        }

        // ---------- Settings ----------

        bool loadingSettings;

        void LoadSettings()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            settingsPath = Path.Combine(baseDir, "settings.ini");
            scanLogPath = Path.Combine(baseDir, "scans.log");
            quarDir = Path.Combine(baseDir, "quarantine");
            quarIndex = Path.Combine(quarDir, "index.txt");
            // an unwritable exe folder must not crash startup; quarantine operations
            // will surface their own errors when actually used
            try { if (!Directory.Exists(quarDir)) Directory.CreateDirectory(quarDir); } catch { }
            NeutralizeQuarantineFolder(); // migrate a pre-0.0.3 quarantine to the .quar form

            loadingSettings = true;
            bool monitor = false, quarantine = false, autoUpdate = true, riskyOnly = true, fullRisky = true;
            bool usbPrompt = true, logDetails = false, notify = true, skipBig = true;
            bool hadSettings = File.Exists(settingsPath), modeAskedSeen = false;
            // an unreadable/corrupt settings.ini must not take down startup:
            // fall back to defaults; SaveSettings() at the end rewrites the file
            string[] lines = null;
            if (hadSettings)
                try { lines = File.ReadAllLines(settingsPath); } catch { }
            if (lines != null)
            {
                foreach (string line in lines)
                {
                    string t = line.Trim();
                    if (t.StartsWith("watch=", StringComparison.OrdinalIgnoreCase))
                    {
                        string d = t.Substring(6).Trim();
                        if (d.Length > 0) AddPathOnce(watchDirs, d);
                    }
                    else if (t.StartsWith("exclude=", StringComparison.OrdinalIgnoreCase))
                    {
                        string d = t.Substring(8).Trim();
                        if (d.Length > 0) AddPathOnce(exclusions, d);
                    }
                    else if (t == "monitor=1") monitor = true;
                    else if (t == "quarantine=1") quarantine = true;
                    else if (t == "autoupdate=0") autoUpdate = false;
                    else if (t == "riskyonly=0") riskyOnly = false;
                    else if (t == "fullrisky=0") fullRisky = false;
                    else if (t == "usbprompt=0") usbPrompt = false;
                    else if (t == "logdetails=1") logDetails = true;
                    else if (t == "notify=0") notify = false;
                    else if (t == "skipbig=0") skipBig = false;
                    else if (t == "perf=low") perfMode = 0;
                    else if (t == "perf=high") perfMode = 2;
                    else if (t == "sched=off") schedMode = 0;
                    else if (t == "sched=daily") schedMode = 1; // weekly is the field default
                    else if (t.StartsWith("lastsched="))
                    {
                        long ticks;
                        if (long.TryParse(t.Substring(10), out ticks) && ticks > 0)
                            lastScheduledScan = new DateTime(ticks);
                    }
                    else if (t == "yara=0") yaraEnabled = false;
                    // legacy (pre-0.0.3): the key used to live in settings.ini;
                    // it's migrated to vt.key below and never written here again
                    else if (t.StartsWith("vtkey=")) vtApiKey = t.Substring(6).Trim();
                    else if (t == "vtcheck=0") vtCheckEnabled = false;
                    else if (t == "vtupload=1") vtUploadEnabled = true; // opt-in, off unless explicitly enabled
                    else if (t.StartsWith("lastyararules="))
                    {
                        long ticks;
                        if (long.TryParse(t.Substring(14), out ticks) && ticks > 0)
                            lastYaraRulesCheck = new DateTime(ticks);
                    }
                    else if (t == "autostartinit=1") autostartInitialized = true;
                    else if (t == "modeasked=1") { modeAsked = true; modeAskedSeen = true; }
                    else if (t == "modeasked=0") modeAskedSeen = true;
                    else if (t == "watchinit=1") watchInitialized = true;
                    else if (t == "watchinit=2") { watchInitialized = true; watchDefaultsV2 = true; }
                    else if (t == "watchinit=3") { watchInitialized = true; watchDefaultsV2 = true; watchDefaultsV3 = true; }
                    else if (t == "lang=uk") Lang.Current = Lang.Language.Ukrainian;
                    else if (t.StartsWith("lastscan="))
                    {
                        string v = t.Substring(9);
                        lastScanInfo = v == "ще не було" ? "" : v; // legacy sentinel from older versions
                    }
                    else if (t.StartsWith("dbcooldown="))
                    {
                        long ticks;
                        if (long.TryParse(t.Substring(11), out ticks) && ticks > 0)
                            dbCooldownUntil = new DateTime(ticks);
                    }
                    else if (t.StartsWith("lastdbcheck="))
                    {
                        long ticks;
                        if (long.TryParse(t.Substring(12), out ticks) && ticks > 0)
                            lastDbCheck = new DateTime(ticks);
                    }
                    else if (t.StartsWith("lastappcheck="))
                    {
                        long ticks;
                        if (long.TryParse(t.Substring(13), out ticks) && ticks > 0)
                            lastAppUpdateCheck = new DateTime(ticks);
                    }
                    else if (t.StartsWith("totalScans=")) long.TryParse(t.Substring(11), out totalScans);
                    else if (t.StartsWith("totalFiles=")) long.TryParse(t.Substring(11), out totalFilesScanned);
                    else if (t.StartsWith("totalFound=")) long.TryParse(t.Substring(11), out totalFound);
                    else if (t.StartsWith("totalMoved=")) long.TryParse(t.Substring(11), out totalMoved);
                }
            }
            // The VirusTotal key lives in vt.key, NOT in settings.ini: a freshly
            // downloaded exe writes a default settings.ini on its very first run,
            // and installing that copy used to clobber the installed settings —
            // taking the key with it. vt.key is created only when the user actually
            // enters a key, so a fresh download has nothing to overwrite it with.
            vtKeyPath = Path.Combine(baseDir, "vt.key");
            try
            {
                if (File.Exists(vtKeyPath))
                {
                    string k = File.ReadAllText(vtKeyPath).Trim();
                    if (k.Length > 0) vtApiKey = k;
                }
                else if (vtApiKey.Length > 0)
                    SaveVtKey(); // migrate a legacy settings.ini key into its own file
            }
            catch { }
            // Pre-0.0.6 settings have no modeasked flag: that setup already exists and
            // works — don't spring the first-run mode question on an existing user
            if (hadSettings && !modeAskedSeen) modeAsked = true;
            // Scheduler anchor: on a fresh install (or an upgrade from a version
            // without the scheduler) count from "now", so the first automatic scan
            // happens one full period from today instead of right at startup
            if (lastScheduledScan == DateTime.MinValue) lastScheduledScan = DateTime.Now;
            // First run: add default folders (Downloads, Desktop, Program Files) and
            // enable monitoring right away. Done only once — if the user changes it
            // afterwards, we don't force it back on.
            if (!watchInitialized)
            {
                watchInitialized = true;
                foreach (string d in DefaultWatchDirs())
                    AddPathOnce(watchDirs, d);
                monitor = true;
            }
            else if (!watchDefaultsV2)
            {
                // migrating older settings: add only the new folders (Temp, Roaming)
                // once, without restoring anything the user has since removed
                foreach (string d in TempWatchDirs())
                    AddPathOnce(watchDirs, d);
            }
            if (!watchDefaultsV3)
            {
                // v2 added C:\Windows\Temp unconditionally, but a non-elevated process
                // can't watch it on a hardened system (FileSystemWatcher fails there).
                // Self-healing check instead of a blanket removal: keep/add it if it's
                // actually watchable (stock Windows default, or already fixed via
                // --install / the "Fix" button), drop it otherwise.
                string winTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
                if (CanWatchDirectory(winTemp)) AddPathOnce(watchDirs, winTemp);
                else watchDirs.RemoveAll(delegate(string d) { return string.Equals(d, winTemp, StringComparison.OrdinalIgnoreCase); });
            }
            watchDefaultsV2 = true;
            watchDefaultsV3 = true;
            if (watchDirs.Count == 0)
                foreach (string d in DefaultWatchDirs())
                    AddPathOnce(watchDirs, d);
            chkQuarantine.Checked = quarantine;
            chkAutoUpdate.Checked = autoUpdate;
            chkRiskyOnly.Checked = riskyOnly;
            chkFullRisky.Checked = fullRisky;
            chkUsbPrompt.Checked = usbPrompt;
            chkLogDetails.Checked = logDetails;
            chkNotify.Checked = notify;
            chkSkipBig.Checked = skipBig;
            UpdatePerfButtons();  // reflect the loaded perf mode
            UpdateSchedButtons(); // reflect the loaded schedule
            chkMonitor.Checked = monitor; // CheckedChanged will start the watchers itself
            loadingSettings = false;
            ApplyLanguage(); // picks up the loaded language setting and re-texts the UI
            SaveSettings(); // persist the default migration
        }

        // Default monitored folders: typical infection vectors
        List<string> DefaultWatchDirs()
        {
            var list = new List<string>();
            Action<string> add = delegate(string p)
            {
                if (!string.IsNullOrEmpty(p) && Directory.Exists(p) && !list.Contains(p)) list.Add(p);
            };
            add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            add(Environment.GetEnvironmentVariable("ProgramFiles(x86)"));
            foreach (string d in TempWatchDirs()) add(d);
            return list;
        }

        // Hot spots added in defaults v2: temp folders and Roaming — the places
        // droppers get extracted to and where malware commonly persists. C:\Windows\Temp
        // is only included if it's actually watchable (see CanWatchDirectory) — on some
        // hardened machines a non-elevated process can't even list it; --install fixes
        // the ACL automatically, or the user can run the fix from Settings.
        static List<string> TempWatchDirs()
        {
            var list = new List<string>();
            Action<string> add = delegate(string p)
            {
                if (!string.IsNullOrEmpty(p) && Directory.Exists(p) && !list.Contains(p)) list.Add(p);
            };
            try { add(Path.GetTempPath().TrimEnd('\\')); } catch { }        // the user's %TEMP%
            add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)); // Roaming
            string winTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
            if (CanWatchDirectory(winTemp)) add(winTemp);
            return list;
        }

        void SaveSettings()
        {
            if (loadingSettings) return;
            var sb = new StringBuilder();
            sb.AppendLine("monitor=" + (chkMonitor.Checked ? "1" : "0"));
            sb.AppendLine("quarantine=" + (chkQuarantine.Checked ? "1" : "0"));
            sb.AppendLine("autoupdate=" + (chkAutoUpdate.Checked ? "1" : "0"));
            sb.AppendLine("riskyonly=" + (chkRiskyOnly.Checked ? "1" : "0"));
            sb.AppendLine("fullrisky=" + (chkFullRisky.Checked ? "1" : "0"));
            sb.AppendLine("usbprompt=" + (chkUsbPrompt.Checked ? "1" : "0"));
            sb.AppendLine("logdetails=" + (chkLogDetails.Checked ? "1" : "0"));
            sb.AppendLine("notify=" + (chkNotify.Checked ? "1" : "0"));
            sb.AppendLine("skipbig=" + (chkSkipBig.Checked ? "1" : "0"));
            sb.AppendLine("perf=" + (perfMode == 0 ? "low" : perfMode == 2 ? "high" : "normal"));
            sb.AppendLine("yara=" + (yaraEnabled ? "1" : "0"));
            // the VT API key is deliberately NOT here — it lives in vt.key (see LoadSettings)
            sb.AppendLine("vtcheck=" + (vtCheckEnabled ? "1" : "0"));
            sb.AppendLine("vtupload=" + (vtUploadEnabled ? "1" : "0"));
            sb.AppendLine("lastyararules=" + lastYaraRulesCheck.Ticks);
            sb.AppendLine("sched=" + (schedMode == 0 ? "off" : schedMode == 1 ? "daily" : "weekly"));
            sb.AppendLine("lastsched=" + lastScheduledScan.Ticks);
            sb.AppendLine("autostartinit=" + (autostartInitialized ? "1" : "0"));
            sb.AppendLine("modeasked=" + (modeAsked ? "1" : "0"));
            sb.AppendLine("watchinit=" + (watchInitialized ? "3" : "0"));
            sb.AppendLine("lang=" + (Lang.Current == Lang.Language.Ukrainian ? "uk" : "en"));
            sb.AppendLine("lastscan=" + lastScanInfo);
            sb.AppendLine("dbcooldown=" + dbCooldownUntil.Ticks);
            sb.AppendLine("lastdbcheck=" + lastDbCheck.Ticks);
            sb.AppendLine("lastappcheck=" + lastAppUpdateCheck.Ticks);
            sb.AppendLine("totalScans=" + totalScans);
            sb.AppendLine("totalFiles=" + totalFilesScanned);
            sb.AppendLine("totalFound=" + totalFound);
            sb.AppendLine("totalMoved=" + totalMoved);
            foreach (string d in watchDirs) sb.AppendLine("watch=" + d);
            foreach (string d in exclusions) sb.AppendLine("exclude=" + d);
            try { File.WriteAllText(settingsPath, sb.ToString(), new UTF8Encoding(false)); }
            catch (Exception ex) { AppendLog("Failed to save settings: " + ex.Message + "\r\n", Theme.Danger); }
        }

        // Writes (or removes, when the key was cleared) vt.key. Called only when
        // the user actually changes the key in the engines dialog, plus the one-time
        // migration in LoadSettings — not on every SaveSettings.
        void SaveVtKey()
        {
            try
            {
                if (vtApiKey.Length > 0) File.WriteAllText(vtKeyPath, vtApiKey, new UTF8Encoding(false));
                else if (File.Exists(vtKeyPath)) File.Delete(vtKeyPath);
            }
            catch (Exception ex) { AppendLog("Failed to save the API key: " + ex.Message + "\r\n", Theme.Danger); }
        }

    }
}
