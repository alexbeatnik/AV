// Per-user install/uninstall (%LocalAppData%\Programs), C:\Windows\Temp ACL
// fix, shortcuts.
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
        // ---------- Install (per-user, no admin rights) ----------

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
                k.SetValue("Publisher", "AV");
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
        // actually running.
        static void SyncUninstallVersion()
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

        static void FixWinTempAcl()
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
            // strip any explicit Deny for Users/Everyone first — an Allow we add below
            // can't override a Deny, so without this the grant could silently no-op
            RunHidden("icacls", "\"" + dir + "\" /remove:d *S-1-5-32-545 *S-1-1-0");
            RunHidden("icacls", "\"" + dir + "\" /grant *S-1-5-32-545:(RX)");
        }

        // Cheap capability probe: FileSystemWatcher needs at least list access to the
        // directory. Used both to decide whether C:\Windows\Temp is worth adding to the
        // default watch list, and to check whether FixWinTempAcl actually took effect.
        internal static bool CanWatchDirectory(string dir)
        {
            try { Directory.GetFiles(dir); return true; }
            catch { return false; }
        }

        static void RunHidden(string exe, string args)
        {
            var psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            using (var p = Process.Start(psi)) p.WaitForExit(30000);
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
