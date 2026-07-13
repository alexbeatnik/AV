// Path lists, exclusions dialog, new-file monitoring (FileSystemWatcher + debounce).
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
        // ---------- Path lists ----------

        void UpdateMonitorLabel()
        {
            chkMonitor.Text = string.Format(Lang.T("settings.monitorLabel"), watchDirs.Count);
            RefreshSettingsStatus(); // folder count shows in the STATUS block too
        }

        void EditWatchDirs()
        {
            if (EditPathList(Lang.T("watch.editTitle"), watchDirs, true))
            {
                UpdateMonitorLabel();
                SaveSettings();
                if (chkMonitor.Checked) StartWatchers();
            }
        }

        // Restores read access to C:\Windows\Temp (see FixWinTempAcl) so it can be
        // monitored, then adds it to the watch list. No UAC prompt at all if it's
        // already accessible (e.g. stock Windows, or already fixed via --install).
        void FixWinTempAccess()
        {
            string winTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
            if (!CanWatchDirectory(winTemp))
            {
                if (MessageBox.Show(this, Lang.T("msg.fixWinTempConfirm"), AppName,
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                try
                {
                    var psi = new ProcessStartInfo(Application.ExecutablePath, "--fix-wintemp");
                    psi.UseShellExecute = true;
                    psi.Verb = "runas";
                    using (var p = Process.Start(psi)) p.WaitForExit();
                }
                catch
                {
                    statusLabel.Text = Lang.T("status.fixWinTempCancelled");
                    return;
                }
            }
            if (!CanWatchDirectory(winTemp))
            {
                statusLabel.Text = Lang.T("status.fixWinTempFailed");
                return;
            }
            AddPathOnce(watchDirs, winTemp);
            UpdateMonitorLabel();
            SaveSettings();
            if (chkMonitor.Checked) StartWatchers();
            btnFixWinTemp.Visible = false;
            statusLabel.Text = Lang.T("status.fixWinTempDone");
        }

        void EditExclusions()
        {
            using (var dlg = new Form())
            {
                dlg.Text = Lang.T("excl.title");
                dlg.Size = new Size(760, 440);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.MinimizeBox = dlg.MaximizeBox = false;
                dlg.BackColor = Theme.Bg;
                dlg.ForeColor = Theme.Text;
                dlg.Font = Font;
                Theme.DarkTitleBar(dlg);

                var list = MakeList();
                list.Columns.Add(Lang.T("col.path"), 520);
                list.Columns.Add(Lang.T("col.type"), 120);

                Action reload = delegate
                {
                    list.Items.Clear();
                    foreach (string p in exclusions)
                    {
                        string kind = File.Exists(p) ? Lang.T("type.file") : (Directory.Exists(p) ? Lang.T("type.folder") : Lang.T("type.missing"));
                        var item = new ListViewItem(new string[] { p, kind });
                        item.Tag = p;
                        list.Items.Add(item);
                    }
                };

                var buttons = new FlowLayoutPanel();
                buttons.Dock = DockStyle.Bottom;
                buttons.FlowDirection = FlowDirection.RightToLeft;
                buttons.Height = 50;
                buttons.Padding = new Padding(8);
                buttons.BackColor = Theme.Bg;

                var close = MakeButton(Lang.T("btn.close"), 90, Theme.Card, Theme.Bg, Ico.Close);
                close.DialogResult = DialogResult.Cancel;
                var delFile = MakeButton(Lang.T("btn.deleteFile"), 140, Theme.Danger, Theme.DangerHot, Ico.Trash);
                var toQuar = MakeButton(Lang.T("btn.toQuarantine"), 110, Theme.Accent, Theme.AccentHot, Ico.ShieldIcon);
                var remove = MakeButton(Lang.T("btn.removeFromList"), 165, Theme.Card, Theme.Bg, Ico.Close);
                var addFile = MakeButton(Lang.T("btn.addFile"), 135, Theme.Card, Theme.Bg, Ico.FilePlus);
                var addDir = MakeButton(Lang.T("btn.addFolder"), 140, Theme.Card, Theme.Bg, Ico.FolderPlus);

                remove.Click += delegate
                {
                    foreach (ListViewItem it in list.SelectedItems)
                        exclusions.Remove((string)it.Tag);
                    SaveSettings();
                    reload();
                };

                toQuar.Click += delegate
                {
                    foreach (ListViewItem it in list.SelectedItems)
                    {
                        string p = (string)it.Tag;
                        if (!File.Exists(p))
                        {
                            MessageBox.Show(dlg, string.Format(Lang.T("msg.onlyExistingToQuarantine"), p), Lang.T("quarantine.title"));
                            continue;
                        }
                        if (QuarantineFile(p, "", Lang.T("quarantine.reasonManual"))) exclusions.Remove(p);
                    }
                    SaveSettings();
                    UpdateStatsUi();
                    reload();
                };

                delFile.Click += delegate
                {
                    if (list.SelectedItems.Count == 0) return;
                    if (MessageBox.Show(dlg,
                        string.Format(Lang.T("msg.deleteFromDiskConfirm"), list.SelectedItems.Count),
                        Lang.T("title.deletion"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
                    foreach (ListViewItem it in list.SelectedItems)
                    {
                        string p = (string)it.Tag;
                        try
                        {
                            if (File.Exists(p)) File.Delete(p);
                            exclusions.Remove(p);
                        }
                        catch (Exception ex) { MessageBox.Show(dlg, ex.Message, Lang.T("title.error")); }
                    }
                    SaveSettings();
                    reload();
                };

                addFile.Click += delegate
                {
                    using (var f = new OpenFileDialog())
                        if (f.ShowDialog(dlg) == DialogResult.OK) { AddExclusion(f.FileName); SaveSettings(); reload(); }
                };
                addDir.Click += delegate
                {
                    using (var f = new FolderBrowserDialog())
                        if (f.ShowDialog(dlg) == DialogResult.OK) { AddExclusion(f.SelectedPath); SaveSettings(); reload(); }
                };

                buttons.Controls.Add(close);
                buttons.Controls.Add(delFile);
                buttons.Controls.Add(toQuar);
                buttons.Controls.Add(remove);
                buttons.Controls.Add(addFile);
                buttons.Controls.Add(addDir);

                dlg.Controls.Add(list);
                dlg.Controls.Add(buttons);
                dlg.CancelButton = close;

                reload();
                dlg.ShowDialog(this);
            }
            statusLabel.Text = string.Format(Lang.T("status.exclusionsCount"), exclusions.Count);
            UpdateStatsUi();
        }

        // Generic path-list editor; returns true if OK was pressed
        bool EditPathList(string title, List<string> target, bool requireDir)
        {
            using (var dlg = new Form())
            {
                dlg.Text = title;
                dlg.Size = new Size(560, 340);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.MinimizeBox = dlg.MaximizeBox = false;
                dlg.BackColor = Theme.Bg;
                dlg.ForeColor = Theme.Text;
                dlg.Font = Font;
                Theme.DarkTitleBar(dlg);

                var box = new TextBox();
                box.Multiline = true;
                box.ScrollBars = ScrollBars.Vertical;
                box.Dock = DockStyle.Fill;
                box.Font = new Font("Consolas", 9.5f);
                box.BackColor = Theme.LogBg;
                box.ForeColor = Theme.Text;
                box.BorderStyle = BorderStyle.None;
                box.Text = string.Join(Environment.NewLine, target.ToArray());

                var boxWrap = new Panel();
                boxWrap.Dock = DockStyle.Fill;
                boxWrap.Padding = new Padding(12);
                boxWrap.BackColor = Theme.Bg;
                boxWrap.Controls.Add(box);

                var buttons = new FlowLayoutPanel();
                buttons.Dock = DockStyle.Bottom;
                buttons.FlowDirection = FlowDirection.RightToLeft;
                buttons.Height = 48;
                buttons.Padding = new Padding(8);
                buttons.BackColor = Theme.Bg;
                var ok = MakeButton("OK", 90, Theme.Accent, Theme.AccentHot, Ico.Check);
                ok.DialogResult = DialogResult.OK;
                var cancel = MakeButton(Lang.T("btn.cancel"), 100, Theme.Card, Theme.Bg, Ico.Close);
                cancel.DialogResult = DialogResult.Cancel;
                buttons.Controls.Add(ok);
                buttons.Controls.Add(cancel);

                dlg.Controls.Add(boxWrap);
                dlg.Controls.Add(buttons);
                dlg.AcceptButton = ok;
                dlg.CancelButton = cancel;

                if (dlg.ShowDialog(this) != DialogResult.OK) return false;

                target.Clear();
                foreach (string line in box.Lines)
                {
                    string d = line.Trim();
                    if (d.Length == 0) continue;
                    if (requireDir && !Directory.Exists(d))
                    {
                        AppendLog(string.Format(Lang.T("log.folderNotFound"), d), Theme.Warn);
                        continue;
                    }
                    if (!requireDir && !Directory.Exists(d) && !File.Exists(d))
                    {
                        AppendLog(string.Format(Lang.T("log.pathNotFound"), d), Theme.Warn);
                        continue;
                    }
                    AddPathOnce(target, d);
                }
                return true;
            }
        }

        // ---------- New-file monitoring ----------

        void OnMonitorToggled()
        {
            if (chkMonitor.Checked) StartWatchers();
            else StopWatchers();
            SaveSettings();
            RefreshSettingsStatus();
            statusLabel.Text = chkMonitor.Checked
                ? Lang.T("status.monitorOn")
                : Lang.T("status.monitorOff");
        }

        void StartWatchers()
        {
            StopWatchers();
            foreach (string d in watchDirs)
            {
                if (!Directory.Exists(d)) continue;
                var w = new FileSystemWatcher(d);
                w.IncludeSubdirectories = true;
                w.NotifyFilter = NotifyFilters.FileName;
                w.InternalBufferSize = 65536; // large trees (Program Files) during installs
                w.SynchronizingObject = this; // events fire on the UI thread
                w.Created += delegate(object s, FileSystemEventArgs e) { QueueNewFile(e.FullPath); };
                w.Renamed += delegate(object s, RenamedEventArgs e) { QueueNewFile(e.FullPath); };
                try { w.EnableRaisingEvents = true; watchers.Add(w); }
                catch (Exception ex)
                {
                    AppendLog(string.Format(Lang.T("log.watchFailed"), d, ex.Message), Theme.Danger);
                    w.Dispose();
                }
            }
            AppendLog(string.Format(Lang.T("log.watchingFolders"), watchers.Count), Theme.Muted);
        }

        void StopWatchers()
        {
            foreach (var w in watchers) w.Dispose();
            watchers.Clear();
            debounceTimer.Stop();
            pendingFiles.Clear();
        }

        void QueueNewFile(string path)
        {
            // FileSystemWatcher can raise on a worker thread when the form handle isn't
            // created yet (SynchronizingObject is a no-op then, and InvokeRequired is
            // false without a handle) — marshal to the UI thread before touching
            // pendingFiles/debounceTimer; pre-handle events are dropped by the catch
            if (!IsHandleCreated || InvokeRequired)
            {
                try { BeginInvoke((Action<string>)QueueNewFile, path); } catch { }
                return;
            }
            if (Directory.Exists(path)) return; // files inside it will arrive as separate events
            if (IsExcluded(path)) return;
            // by default only potentially dangerous types are checked
            if (chkRiskyOnly != null && chkRiskyOnly.Checked
                && !RiskyExtensions.Contains(Path.GetExtension(path))) return;
            if (HasTempDownloadExtension(path)) return; // still downloading: wait for the rename
            pendingFiles[path] = 0;
            debounceTimer.Stop();
            debounceTimer.Start(); // restart: scan once the stream of new files settles down
        }

        void OnDebounceTick(object sender, EventArgs e)
        {
            if (scanRunning || updateRunning || !DbExists()) return; // try again on the next tick
            var ready = new List<string>();
            var stillLocked = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, int> kvp in pendingFiles)
            {
                string f = kvp.Key;
                int retries = kvp.Value;
                if (!File.Exists(f)) continue;
                if (IsFileLocked(f))
                {
                    if (retries < 10) // max 10 retries (~30 seconds)
                        stillLocked[f] = retries + 1;
                    continue;
                }
                ready.Add(f);
            }
            pendingFiles.Clear();
            foreach (KeyValuePair<string, int> kvp in stillLocked)
                pendingFiles[kvp.Key] = kvp.Value;
            if (pendingFiles.Count == 0) debounceTimer.Stop();
            if (ready.Count > 0) ScanFileBatch(ready);
        }

        // In-progress browser/downloader files (.crdownload, .part, …): scanning them
        // is pointless — the monitor waits for the rename to the final name instead
        internal static bool HasTempDownloadExtension(string path)
        {
            string ext = Path.GetExtension(path).ToLowerInvariant();
            foreach (string t in TempExtensions)
                if (ext == t) return true;
            return false;
        }

        internal static bool IsFileLocked(string path)
        {
            try
            {
                using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    return false;
            }
            catch (IOException) { return true; }
            catch (UnauthorizedAccessException) { return false; } // not locked, just inaccessible
        }

        void ScanFileBatch(List<string> files)
        {
            ResetScanState(Lang.T("desc.autoCheck"));
            monitorScan = true;
            countGen++; // the total is known upfront, no background counting needed
            totalToScan = files.Count;
            initialFilesToScan = files.Count;
            AppendSection(Lang.T("desc.autoCheck"));
            AppendLog(string.Format(Lang.T("log.newFilesHeader"), DateTime.Now, files.Count), Theme.Text, "SCAN", false);
            SetBusy(true, string.Format(Lang.T("status.autoCheck"), files.Count));

            // Paths are passed via --file-list: hundreds of files on the command line
            // (e.g. installing to Program Files) exceed the ~32K character limit and Process.Start fails
            var args = new StringBuilder();
            args.Append("-r --stdout -d ").Append(Quote(dbDir)).Append(MoveArg()).Append(ExcludeArg()).Append(ScanLimitsArg(chkSkipBig.Checked));
            try
            {
                string lp = Path.Combine(Path.GetTempPath(), "av-batch-" + Guid.NewGuid().ToString("N") + ".txt");
                File.WriteAllLines(lp, files.ToArray(), new UTF8Encoding(false));
                batchListPaths.Add(lp);
                args.Append(" --file-list=").Append(Quote(lp));
                yaraListPath = lp;  // new files get the YARA pass too
                yaraPhasePending = true;
            }
            catch (Exception ex)
            {
                AppendLog(string.Format(Lang.T("log.listCreateFailedInline"), ex.Message), Theme.Warn);
                foreach (string f in files)
                    args.Append(" ").Append(Quote(f));
            }
            StartProcess(Path.Combine(clamDir, "clamscan.exe"), args.ToString(), OnScanLine, OnScanExit);
        }
        readonly List<string> batchListPaths = new List<string>(); // temporary lists for --file-list

        void CleanupBatchLists()
        {
            foreach (string p in batchListPaths) TryDelete(p);
            batchListPaths.Clear();
        }

    }
}
