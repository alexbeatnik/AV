// Per-user install/uninstall (%LocalAppData%\Programs), C:\Windows\Temp ACL
// fix, shortcuts.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Microsoft.Win32;

namespace AVUI
{
    public partial class MainForm : Form
    {
        // ---------- Install (per-user, no admin rights) ----------

        // Shown as the publisher in Settings → Apps. Read out of AssemblyCompany
        // (src/AssemblyInfo.cs) rather than spelled out again here: the install
        // and the startup sync below wrote it separately and drifted — the Apps
        // list read "AV" while the exe's version resource said the real name.
        // One source, so the two can't disagree again.
        static readonly string PublisherName = AssemblyCompanyName();

        static string AssemblyCompanyName()
        {
            try
            {
                object[] a = Assembly.GetExecutingAssembly()
                    .GetCustomAttributes(typeof(AssemblyCompanyAttribute), false);
                if (a.Length > 0)
                {
                    string c = ((AssemblyCompanyAttribute)a[0]).Company;
                    if (!string.IsNullOrEmpty(c)) return c;
                }
            }
            catch { }
            return AppName; // no readable version resource — never write a null
        }

        // %LocalAppData%\Programs\AV — writable by the owning user only.
        // Binaries can't be tampered with by other local users, and installing
        // and self-updating need no admin rights or UAC prompts. The app never
        // installs to Program Files and never needs elevation for setup.
        static string InstallDir
        {
            get
            {
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    @"Programs\AV");
            }
        }

        static bool IsInstalled
        {
            // IsUnder, not StartsWith: "...\AV Beta" must not count
            get { return IsUnder(Application.ExecutablePath, InstallDir); }
        }

        static bool IsAdmin()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        static void RunInstallMode()
        {
            var f = new Form();
            f.Text = Lang.T("install.title");
            f.FormBorderStyle = FormBorderStyle.FixedDialog;
            f.MinimizeBox = f.MaximizeBox = false;
            f.Size = new Size(440, 130);
            f.StartPosition = FormStartPosition.CenterScreen;
            f.BackColor = Theme.Bg;
            Theme.DarkTitleBar(f);
            var l = new Label();
            l.Dock = DockStyle.Fill;
            l.TextAlign = ContentAlignment.MiddleCenter;
            l.ForeColor = Theme.Text;
            l.Text = Lang.T("install.installing");
            f.Controls.Add(l);
            f.Shown += delegate
            {
                System.Threading.ThreadPool.QueueUserWorkItem(delegate
                {
                    string err = null;
                    try { DoInstall(); }
                    catch (Exception ex) { err = ex.Message; }
                    try
                    {
                        f.BeginInvoke((Action)delegate
                        {
                            f.Hide();
                            if (err != null)
                                MessageBox.Show(Lang.T("install.failed") + err, AppName,
                                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                            else
                            {
                                try { Process.Start(Path.Combine(InstallDir, "AV.exe")); }
                                catch { }
                            }
                            Application.ExitThread();
                        });
                    }
                    catch { }
                });
            };
            Application.Run(f);
        }

        static void DoInstall()
        {
            // the instance that launched --install is still shutting down and holds
            // the single-instance mutex — give it a moment, otherwise the installed
            // copy started below would just signal it and exit
            System.Threading.Thread.Sleep(1500);

            string srcDir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            string dst = InstallDir;
            Directory.CreateDirectory(dst);

            string dstExe = Path.Combine(dst, "AV.exe");
            if (!string.Equals(Application.ExecutablePath, dstExe, StringComparison.OrdinalIgnoreCase))
                File.Copy(Application.ExecutablePath, dstExe, true);

            // carry over whatever is already next to the exe so it isn't downloaded again
            bool samePlace = string.Equals(srcDir, dst, StringComparison.OrdinalIgnoreCase);
            if (!samePlace)
            {
                foreach (string sub in new string[] { "clamav", "quarantine", "yara" })
                {
                    string s = Path.Combine(srcDir, sub);
                    if (Directory.Exists(s)) CopyDir(s, Path.Combine(dst, sub));
                }
                foreach (string fn in new string[] { "settings.ini", "scans.log", "vt.key" })
                    CarryOverFile(Path.Combine(srcDir, fn), Path.Combine(dst, fn));
            }

            // shortcuts: Start Menu and Desktop (both per-user). Non-essential — if
            // Windows Script Host is disabled by group policy, CreateShortcut throws;
            // skip the shortcuts rather than failing an install whose files are done.
            try
            {
                CreateShortcut(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Programs), "AV.lnk"), dstExe, dst);
                CreateShortcut(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "AV.lnk"), dstExe, dst);
            }
            catch { }

            // register in "Apps" (per-user entry)
            using (var k = Registry.CurrentUser.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AV"))
            {
                k.SetValue("DisplayName", "AV");
                k.SetValue("DisplayVersion", AppVersion);
                k.SetValue("Publisher", PublisherName);
                k.SetValue("DisplayIcon", dstExe);
                k.SetValue("InstallLocation", dst);
                k.SetValue("UninstallString", "\"" + dstExe + "\" --uninstall");
                k.SetValue("NoModify", 1, RegistryValueKind.DWord);
                k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                k.SetValue("EstimatedSize", 600000, RegistryValueKind.DWord); // KB, including the database
            }

            // if autostart was enabled from the old location, repoint it to the new one
            using (var k = Registry.CurrentUser.OpenSubKey(RunKeyPath, true))
                if (k != null && k.GetValue(RunValueName) != null)
                    k.SetValue(RunValueName, "\"" + dstExe + "\" --tray");
        }

        // Self-updates swap the exe but the Apps-list entry kept the version from
        // install time — refresh it on startup so Settings → Apps shows what's
        // actually running. The publisher goes through here too: an install made
        // before it was corrected still says "AV", and only a rewrite from a
        // running copy can fix that without a reinstall.
        static void SyncUninstallEntry()
        {
            if (!IsInstalled) return;
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AV", true))
                {
                    if (k == null) return; // installed manually without the registry entry
                    if (!string.Equals(k.GetValue("DisplayVersion") as string, AppVersion))
                        k.SetValue("DisplayVersion", AppVersion);
                    if (!string.Equals(k.GetValue("Publisher") as string, PublisherName))
                        k.SetValue("Publisher", PublisherName);
                }
            }
            catch { }
        }

        static void RunUninstallMode()
        {
            // Everything the app ever creates is per-user (%LocalAppData%, HKCU,
            // per-user shortcuts), so uninstalling needs no elevation and touches
            // nothing outside the current user's profile.
            if (MessageBox.Show(
                Lang.T("uninstall.confirm"),
                AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            try
            {
                TryDelete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "AV.lnk"));
                TryDelete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "AV.lnk"));
                Registry.CurrentUser.DeleteSubKeyTree(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AV", false);
                using (var k = Registry.CurrentUser.OpenSubKey(RunKeyPath, true))
                    if (k != null) k.DeleteValue(RunValueName, false);
                MessageBox.Show(Lang.T("uninstall.done"), AppName);
                // The folder itself is removed after exit, since our exe is still
                // running from it. Launched AFTER the MessageBox: otherwise rd
                // runs while the window is still open and can't delete the locked exe.
                var rm = new ProcessStartInfo("cmd.exe",
                    "/c timeout /t 3 /nobreak >nul & rd /s /q \"" + InstallDir + "\"");
                rm.CreateNoWindow = true;
                rm.UseShellExecute = false;
                Process.Start(rm);
            }
            catch (Exception ex)
            {
                MessageBox.Show(Lang.T("uninstall.error") + ex.Message, AppName,
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }

        // Carries a data file into the install dir only when it isn't there yet.
        // Never overwrites: a freshly downloaded exe writes a default settings.ini
        // on its very first run, and blindly copying that over an existing install
        // used to wipe the user's real settings (VT key, watch folders, stats).
        internal static void CarryOverFile(string src, string dst)
        {
            if (File.Exists(src) && !File.Exists(dst)) File.Copy(src, dst);
        }

        // ---------- C:\Windows\Temp access fix ----------
        // On some hardened machines Users can't even list C:\Windows\Temp (a Group
        // Policy/security baseline strips the normally-default read permission), so
        // FileSystemWatcher on it fails for our always-non-elevated process. Rather than
        // running the whole app elevated (bigger attack surface, breaks non-admin users,
        // fights autostart), we fix the one thing that actually needs admin: the ACL
        // itself, once, via a UAC prompt — the app stays unprivileged afterwards.

        static void RunFixWinTempMode()
        {
            if (!IsAdmin())
            {
                try
                {
                    var psi = new ProcessStartInfo(Application.ExecutablePath, "--fix-wintemp");
                    psi.UseShellExecute = true;
                    psi.Verb = "runas";
                    Process.Start(psi);
                }
                catch { } // user declined the UAC prompt
                return;
            }
            FixWinTempAcl();
        }

        // Written through .NET's own ACL API rather than by shelling out to icacls:
        // two hidden console processes rewriting permissions under C:\Windows is a
        // shape heuristics recognise malware by, and this app is already losing that
        // argument over its own exe (see the Defender exclusion below). Same result,
        // no child process.
        static void FixWinTempAcl()
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
            var di = new DirectoryInfo(dir);
            DirectorySecurity sec = di.GetAccessControl(AccessControlSections.Access);
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            // strip any explicit Deny for Users/Everyone first — an Allow we add below
            // can't override a Deny, so without this the grant could silently no-op.
            // RemoveAccessRuleAll ignores the rights of the rule it is handed and
            // drops every Deny for that identity, which is what /remove:d did.
            sec.RemoveAccessRuleAll(new FileSystemAccessRule(users, FileSystemRights.FullControl, AccessControlType.Deny));
            sec.RemoveAccessRuleAll(new FileSystemAccessRule(everyone, FileSystemRights.FullControl, AccessControlType.Deny));
            // this folder only, no inheritance — exactly what
            // `icacls <dir> /grant *S-1-5-32-545:(RX)` granted. We need to list the
            // directory, not to read what other users dropped in it.
            sec.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute,
                InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
            di.SetAccessControl(sec);
        }

        // Cheap capability probe: FileSystemWatcher needs at least list access to the
        // directory. Used both to decide whether C:\Windows\Temp is worth adding to the
        // default watch list, and to check whether FixWinTempAcl actually took effect.
        internal static bool CanWatchDirectory(string dir)
        {
            try { Directory.GetFiles(dir); return true; }
            catch { return false; }
        }

        // ---------- Windows Defender exclusion for the app's own folder ----------
        // Two of this app's own files read as malware to a resident scanner, for
        // reasons that have nothing to do with what they contain or do.
        //
        // (1) A YARA rule file is by construction tens of thousands of literal
        // malware strings, so Defender reads our own rule set as malware and
        // deletes it (Trojan:HTML/Sonbokli.A!cl), silently leaving the engine with
        // nothing to compile. Storing the rules neutralized (MainForm.Yara.cs)
        // covers them at rest, but yara64 has to read real text at some point.
        //
        // (2) The released exe is unsigned and has no download reputation, and
        // Defender's cloud has repeatedly issued a verdict on that basis alone —
        // Trojan:Win32/Bearfoos.B!ml, then Trojan:Win32/Sonbokli.A!cl. Verified:
        // the release binary is quarantined within seconds of download while the
        // same source built locally scans clean, so the verdict rides on the file's
        // hash and reputation, not on anything in it. Remediation takes AV.exe, both
        // shortcuts, the Run value and the Uninstall key together — it uninstalls
        // the app out from under the user.
        //
        // One exclusion covers both, so an install excludes the install folder
        // rather than just yara\. Same shape as the C:\Windows\Temp fix: a single
        // UAC prompt for the one thing that needs admin, after which the app goes
        // on running unprivileged.

        // Portable runs deliberately keep the narrow yara-only scope. The app's
        // "own folder" is then whatever the user dropped the exe into — Downloads,
        // a USB stick, the desktop — and excluding that would be a real hole in
        // Defender's coverage rather than a fix for ours. Installed, the folder is
        // %LocalAppData%\Programs\AV: our binaries, our rules and a quarantine
        // whose contents are already XOR-neutralized, and nothing the user opens
        // documents from.
        internal static string DefenderExclusionDirFor(bool installed, string installDir, string yaraDir)
        {
            return (installed ? installDir : yaraDir).TrimEnd('\\');
        }

        // The install-scope folder is taken from where THIS exe actually sits,
        // not from InstallDir: the two are the same folder for an installed copy,
        // but InstallDir resolves %LocalAppData% for whoever is running — and the
        // elevated --defender-exclude instance can be a DIFFERENT account (a
        // standard user typing an admin's credentials at the UAC prompt). See the
        // argument constants below for why the wide/narrow choice travels too.
        static string DefenderExclusionDirFor(bool wide)
        {
            return DefenderExclusionDirFor(wide, AppDomain.CurrentDomain.BaseDirectory, YaraDir);
        }

        // The scope is decided by the non-elevated instance and carried on the
        // command line. Recomputing IsInstalled inside the elevated copy asked
        // "does this exe live under the CURRENT user's %LocalAppData%?", which is
        // false whenever the UAC prompt was answered with another account — so an
        // install silently got the narrow yara-only exclusion while the UI said it
        // had excluded the whole app folder, and AV.exe stayed exposed. Only these
        // two fixed tokens travel; no directory is ever taken from the argument.
        const string DefenderExcludeAppArg = "--defender-exclude-app";
        const string DefenderExcludeYaraArg = "--defender-exclude-yara";

        static void RunDefenderExcludeMode(bool wide)
        {
            if (!IsAdmin())
            {
                try
                {
                    var psi = new ProcessStartInfo(Application.ExecutablePath,
                        wide ? DefenderExcludeAppArg : DefenderExcludeYaraArg);
                    psi.UseShellExecute = true;
                    psi.Verb = "runas";
                    Process.Start(psi);
                }
                catch { } // user declined the UAC prompt
                return;
            }
            // the caller waits on this process and reads its exit code — Tamper
            // Protection and managed-endpoint policy both refuse exclusion changes,
            // and reporting success there would be a lie
            try { AddDefenderExclusion(DefenderExclusionDirFor(wide)); }
            catch { Environment.ExitCode = 1; }
        }

        // Calls Defender's own WMI provider — the one Add-MpPreference drives —
        // instead of shelling out to `powershell -ExecutionPolicy Bypass -Command
        // Add-MpPreference` in a hidden window. Identical result, but a hidden
        // script host spawned by an unsigned binary to add an antivirus exclusion
        // is textbook "malware switching off its own detection", and this app is
        // already fighting heuristic verdicts on its exe. No reason to hand the
        // model that pattern as well.
        static void AddDefenderExclusion(string dir)
        {
            Directory.CreateDirectory(dir);
            using (var cls = new ManagementClass(@"\\.\root\Microsoft\Windows\Defender:MSFT_MpPreference"))
            using (ManagementBaseObject args = cls.GetMethodParameters("Add"))
            {
                args["ExclusionPath"] = new string[] { dir };
                using (ManagementBaseObject result = cls.InvokeMethod("Add", args, null))
                    ThrowIfWmiFailed(result);
            }
        }

        // MSFT_MpPreference::Add is declared `uint32 Add(...)`, so a refusal
        // (Tamper Protection, managed-endpoint policy) can come back as a
        // non-zero ReturnValue instead of an exception. Ignoring it made
        // --defender-exclude exit 0 and the UI report an exclusion that was
        // never written. Anything but 0 is a failure; a build that returns no
        // ReturnValue at all keeps the old "no throw = success" reading.
        static void ThrowIfWmiFailed(ManagementBaseObject result)
        {
            object rv = null;
            try { if (result != null) rv = result["ReturnValue"]; }
            catch { return; } // no such out-parameter — nothing to judge it by
            if (rv == null) return;
            long code;
            try { code = Convert.ToInt64(rv); }
            catch { return; }
            if (code != 0)
                throw new Exception("MSFT_MpPreference::Add returned 0x" + code.ToString("x8"));
        }

        bool defenderExclusionOffered;   // already asked in this run
        bool yaraExclusionAsked;         // yara-folder scope, asked in an earlier run (settings.ini)
        // Install-folder scope, tracked separately: installs that already answered
        // the narrow yara question in 0.1.7/0.1.8 must still be asked once about the
        // wider exclusion, since only that one keeps AV.exe itself alive.
        bool appExclusionAsked;

        bool DefenderExclusionAsked
        {
            get { return IsInstalled ? appExclusionAsked : yaraExclusionAsked; }
        }

        // The exclusion is not a nicety: yara64 has to read real rule text, and
        // Defender takes a plain .yar off the disk within about a second of it
        // being written — measured, not assumed — while the exe itself is taken on
        // whatever day the cloud decides. So the offer is made once, proactively.
        //
        // proactive=false means the rules were actually taken during a scan, so
        // the engine has visibly failed; that is worth asking again once per run
        // even when an earlier run's answer was no. Declining an install-wide
        // exclusion costs the YARA pass and leaves the exe exposed; declining the
        // portable one costs only the YARA pass — ClamAV and VirusTotal are
        // unaffected either way.
        void OfferDefenderExclusion(bool proactive)
        {
            if (defenderExclusionOffered) return;
            if (proactive && DefenderExclusionAsked) return;
            defenderExclusionOffered = true;
            bool wide = IsInstalled;
            if (wide) appExclusionAsked = true; else yaraExclusionAsked = true;
            SaveSettings(); // asked once, whatever the answer turns out to be
            if (MessageBox.Show(this,
                string.Format(Lang.T(wide ? "msg.defenderExcludeAppConfirm" : "msg.defenderExcludeConfirm"),
                    DefenderExclusionDirFor(wide)),
                AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
            {
                statusLabel.Text = Lang.T(wide ? "status.defenderExcludeAppCancelled" : "status.defenderExcludeCancelled");
                return;
            }
            int code;
            try
            {
                // the scope goes with it: the elevated copy must not re-derive it
                var psi = new ProcessStartInfo(Application.ExecutablePath,
                    wide ? DefenderExcludeAppArg : DefenderExcludeYaraArg);
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                using (var p = Process.Start(psi)) { p.WaitForExit(); code = p.ExitCode; }
            }
            catch
            {
                statusLabel.Text = Lang.T(wide ? "status.defenderExcludeAppCancelled" : "status.defenderExcludeCancelled");
                return;
            }
            if (code != 0)
            {
                statusLabel.Text = Lang.T("status.defenderExcludeFailed");
                return;
            }
            statusLabel.Text = Lang.T(wide ? "status.defenderExcludeAppDone" : "status.defenderExcludeDone");
            yaraRulesTaken = false;
            // Only the reactive case has actually lost its rules; re-fetching
            // 8 MB when they are sitting right there would be for nothing.
            if (!File.Exists(YaraForgeRules)) EnsureYaraSetup(true);
        }

        // Same never-overwrite rule as CarryOverFile: existing files at the
        // destination (a fresher database, the installed quarantine) win.
        static void CopyDir(string src, string dst)
        {
            Directory.CreateDirectory(dst);
            foreach (string f in Directory.GetFiles(src))
                CarryOverFile(f, Path.Combine(dst, Path.GetFileName(f)));
            foreach (string d in Directory.GetDirectories(src))
                CopyDir(d, Path.Combine(dst, Path.GetFileName(d)));
        }

        // .lnk via WScript.Shell (COM, no extra dependencies)
        static void CreateShortcut(string lnkPath, string target, string workDir)
        {
            Type t = Type.GetTypeFromProgID("WScript.Shell");
            object shell = Activator.CreateInstance(t);
            object sc = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell,
                new object[] { lnkPath });
            Type st = sc.GetType();
            st.InvokeMember("TargetPath", BindingFlags.SetProperty, null, sc, new object[] { target });
            st.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, sc, new object[] { workDir });
            st.InvokeMember("IconLocation", BindingFlags.SetProperty, null, sc, new object[] { target + ",0" });
            st.InvokeMember("Save", BindingFlags.InvokeMethod, null, sc, null);
        }
    }
}
