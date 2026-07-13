// Quarantine: neutralized .quar storage, index, statistics, threat dialog.
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
        // ---------- Quarantine and statistics ----------

        // One quarantined file as shown in the list; Tag of every ListViewItem
        sealed class QuarRow
        {
            public string Path;     // full path of the .quar file on disk
            public string Name;     // original file name (without .quar)
            public string Threat;   // signature name ("" = unknown, pre-0.0.4 entry)
            public string Origin;   // original full path ("" = unknown)
            public string Reason;   // what put it here (scan description / "Manual")
            public string WhenText; // index date string ("yyyy-MM-dd HH:mm")
            public DateTime When;   // parsed date (MinValue if unparsable)
            public long Size;       // bytes (equals the original size — XOR keeps length)
        }
        readonly List<QuarRow> quarRows = new List<QuarRow>();

        // Quarantined files are stored transformed (every byte XOR 0xFF) with a ".quar"
        // extension. The bytes on disk are no longer the malware body, so a resident AV
        // (e.g. Windows Defender) doesn't detect and "steal" files out of our quarantine,
        // and the file can't be launched accidentally. The same XOR restores the original.
        internal const string QuarExt = ".quar";

        internal static void XorCopy(string src, string dst)
        {
            using (var fin = File.OpenRead(src))
            using (var fout = new FileStream(dst, FileMode.CreateNew, FileAccess.Write))
            {
                var buf = new byte[81920];
                int n;
                while ((n = fin.Read(buf, 0, buf.Length)) > 0)
                {
                    for (int i = 0; i < n; i++) buf[i] ^= 0xFF;
                    fout.Write(buf, 0, n);
                }
            }
        }

        // Recreates the parent folder of a path about to be written (no-op when it
        // already exists) — quarantine restores must work even after the user has
        // deleted the folder the file originally lived in.
        internal static void EnsureParentDir(string path)
        {
            string dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        }

        // A free "name.quar" (or "name(2).quar") slot inside the quarantine folder
        internal static string UniqueQuarPath(string dir, string originalName)
        {
            string dest = Path.Combine(dir, originalName + QuarExt);
            int i = 1;
            while (File.Exists(dest))
            {
                dest = Path.Combine(dir, originalName + "(" + i + ")" + QuarExt);
                i++;
            }
            return dest;
        }

        // Converts any raw file sitting in quarantine into the neutralized .quar form:
        // legacy quarantines (v0.0.2 and older stored files as-is) and files that
        // clamscan --move just dropped there. Index entries follow the rename.
        void NeutralizeQuarantineFolder()
        {
            if (quarDir == null || !Directory.Exists(quarDir)) return;
            var renames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string f in Directory.GetFiles(quarDir))
            {
                string name = Path.GetFileName(f);
                if (string.Equals(name, "index.txt", StringComparison.OrdinalIgnoreCase)) continue;
                if (name.EndsWith(QuarExt, StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    string dest = UniqueQuarPath(quarDir, name);
                    XorCopy(f, dest);
                    File.Delete(f);
                    renames[name] = Path.GetFileName(dest);
                }
                catch { } // locked/unreadable — retried on the next reload
            }
            if (renames.Count == 0 || !File.Exists(quarIndex)) return;
            try
            {
                var lines = new List<string>();
                foreach (string line in File.ReadAllLines(quarIndex))
                {
                    int p = line.IndexOf('|');
                    string key = p > 0 ? line.Substring(0, p) : null;
                    string renamed;
                    if (key != null && renames.TryGetValue(key, out renamed))
                        lines.Add(renamed + line.Substring(p));
                    else
                        lines.Add(line);
                }
                File.WriteAllLines(quarIndex, lines.ToArray());
            }
            catch { }
        }

        int QuarantineCount()
        {
            if (quarDir == null || !Directory.Exists(quarDir)) return 0;
            int n = 0;
            foreach (string f in Directory.GetFiles(quarDir))
                if (!string.Equals(Path.GetFileName(f), "index.txt", StringComparison.OrdinalIgnoreCase)) n++;
            return n;
        }

        void UpdateStatsUi()
        {
            int q = QuarantineCount();
            statStrip.Captions = new string[]
            {
                Lang.T("stat.clamav"), Lang.T("stat.lastScan"), Lang.T("stat.scans"),
                Lang.T("stat.files"), Lang.T("stat.threats"), Lang.T("stat.quarantined")
            };
            statStrip.Values = new string[]
            {
                clamVersion,
                lastScanInfo.Length == 0 ? Lang.T("stats.neverScanned") : lastScanInfo,
                totalScans.ToString(), totalFilesScanned.ToString(),
                totalFound.ToString(), q.ToString()
            };
            statStrip.ValueColors = new Color[]
            {
                Color.Empty, Color.Empty, Color.Empty, Color.Empty,
                totalFound > 0 ? Theme.Danger : Color.Empty,
                q > 0 ? Theme.Warn : Color.Empty
            };
            statStrip.Invalidate();
            if (dbStrip != null)
            {
                string[] caps, vals;
                Color[] colors;
                DbStripData(out caps, out vals, out colors);
                dbStrip.Captions = caps;
                dbStrip.Values = vals;
                dbStrip.ValueColors = colors;
                dbStrip.Invalidate();
            }
        }

        // Moves a file into quarantine manually (without clamscan --move) in the
        // neutralized .quar form, and writes the index.
        // Index line format: file|origin|date|threat|source (older lines have 3 fields).
        bool QuarantineFile(string path, string threat, string reason)
        {
            try
            {
                string dest = UniqueQuarPath(quarDir, Path.GetFileName(path));
                XorCopy(path, dest);
                try { File.Delete(path); }
                catch { TryDelete(dest); throw; } // source still there — don't leave two copies
                File.AppendAllText(quarIndex,
                    Path.GetFileName(dest) + "|" + path + "|" + DateTime.Now.ToString("yyyy-MM-dd HH:mm")
                    + "|" + (threat ?? "") + "|" + (reason ?? "") + "\r\n",
                    new UTF8Encoding(false));
                totalMoved++;
                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, string.Format(Lang.T("msg.quarantineMoveFailed"), ex.Message), Lang.T("quarantine.title"));
                return false;
            }
        }

        // SHA256 of the ORIGINAL file content: .quar files are XOR-ed back on the fly,
        // so the hash matches what the file was before quarantining (VirusTotal-ready)
        internal static string Sha256OfQuarFile(string path)
        {
            bool xor = path.EndsWith(QuarExt, StringComparison.OrdinalIgnoreCase);
            using (var sha = System.Security.Cryptography.SHA256.Create())
            using (var fin = File.OpenRead(path))
            {
                var buf = new byte[81920];
                int n;
                while ((n = fin.Read(buf, 0, buf.Length)) > 0)
                {
                    if (xor) for (int i = 0; i < n; i++) buf[i] ^= 0xFF;
                    sha.TransformBlock(buf, 0, n, null, 0);
                }
                sha.TransformFinalBlock(buf, 0, 0);
                var sb = new StringBuilder(64);
                foreach (byte b in sha.Hash) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        // "2.3 MB", "145 KB" — human-readable size for the quarantine list
        internal static string FormatSize(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            double v = bytes / 1024.0;
            string[] units = { "KB", "MB", "GB", "TB" };
            int i = 0;
            while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
            return v.ToString(v >= 100 ? "0" : "0.0", System.Globalization.CultureInfo.InvariantCulture)
                + " " + units[i];
        }

        void AddExclusion(string path)
        {
            AddPathOnce(exclusions, path);
        }

        // Asks the user what to do with each detected threat
        void ShowThreatDialog()
        {
            using (var dlg = new Form())
            {
                dlg.Text = Lang.T("threat.title");
                dlg.Size = new Size(760, 420);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.MinimizeBox = dlg.MaximizeBox = false;
                dlg.BackColor = Theme.Bg;
                dlg.ForeColor = Theme.Text;
                dlg.Font = Font;
                Theme.DarkTitleBar(dlg);

                var list = MakeList();
                list.Columns.Add(Lang.T("col.file"), 400);
                list.Columns.Add(Lang.T("col.threat"), 280);

                foreach (string[] f in foundFiles)
                {
                    if (!File.Exists(f[0])) continue; // already moved or gone
                    var item = new ListViewItem(new string[] { f[0], f[1] });
                    item.Tag = f; // {path, threat name}
                    list.Items.Add(item);
                }
                if (list.Items.Count == 0) return;

                var hint = new Label();
                hint.Dock = DockStyle.Top;
                hint.Height = 30;
                hint.Padding = new Padding(10, 8, 10, 0);
                hint.ForeColor = Theme.Muted;
                hint.Text = Lang.T("threat.hint");

                var buttons = new FlowLayoutPanel();
                buttons.Dock = DockStyle.Bottom;
                buttons.FlowDirection = FlowDirection.RightToLeft;
                buttons.Height = 50;
                buttons.Padding = new Padding(8);
                buttons.BackColor = Theme.Bg;

                var close = MakeButton(Lang.T("btn.close"), 90, Theme.Card, Theme.Bg, Ico.Close);
                close.DialogResult = DialogResult.Cancel;
                var vt = MakeButton("VIRUSTOTAL", 130, Theme.Card, Theme.Bg, Ico.Radar);
                var excl = MakeButton(Lang.T("btn.toExclusions"), 125, Theme.Card, Theme.Bg, Ico.Ban);
                var del = MakeButton(Lang.T("btn.delete"), 100, Theme.Danger, Theme.DangerHot, Ico.Trash);
                var quar = MakeButton(Lang.T("btn.toQuarantine"), 110, Theme.Accent, Theme.AccentHot, Ico.ShieldIcon);

                Func<List<ListViewItem>> picked = delegate
                {
                    var items = new List<ListViewItem>();
                    if (list.SelectedItems.Count > 0)
                        foreach (ListViewItem it in list.SelectedItems) items.Add(it);
                    else
                        foreach (ListViewItem it in list.Items) items.Add(it);
                    return items;
                };
                Action maybeClose = delegate { if (list.Items.Count == 0) dlg.Close(); };

                quar.Click += delegate
                {
                    foreach (var it in picked())
                    {
                        string[] meta = (string[])it.Tag;
                        if (QuarantineFile(meta[0], meta[1], currentScanDesc)) { movedCount++; list.Items.Remove(it); }
                    }
                    SaveSettings();
                    UpdateStatsUi();
                    maybeClose();
                };
                del.Click += delegate
                {
                    var items = picked();
                    if (MessageBox.Show(dlg, string.Format(Lang.T("msg.deleteConfirm"), items.Count),
                        Lang.T("title.deletion"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
                    foreach (var it in items)
                    {
                        try { File.Delete(((string[])it.Tag)[0]); list.Items.Remove(it); }
                        catch (Exception ex) { MessageBox.Show(dlg, ex.Message, Lang.T("title.error")); }
                    }
                    maybeClose();
                };
                excl.Click += delegate
                {
                    foreach (var it in picked())
                    {
                        AddExclusion(((string[])it.Tag)[0]);
                        list.Items.Remove(it);
                    }
                    SaveSettings();
                    statusLabel.Text = string.Format(Lang.T("status.exclusionsCount"), exclusions.Count);
                    maybeClose();
                };

                // opens the public VirusTotal page for the selected files' hashes —
                // a quick second opinion before deciding what to do with them
                vt.Click += delegate
                {
                    int opened = 0;
                    foreach (var it in picked())
                    {
                        if (opened >= 5) break; // don't open a wall of browser tabs
                        string p = ((string[])it.Tag)[0];
                        try { VtOpenInBrowser(Sha256OfQuarFile(p)); opened++; }
                        catch { }
                    }
                };

                buttons.Controls.Add(close);
                buttons.Controls.Add(vt);
                buttons.Controls.Add(excl);
                buttons.Controls.Add(del);
                buttons.Controls.Add(quar);

                dlg.Controls.Add(list);
                dlg.Controls.Add(hint);
                dlg.Controls.Add(buttons);
                dlg.CancelButton = close;
                dlg.ShowDialog(this);
            }
            UpdateStatsUi();
        }

        internal static Dictionary<string, string[]> ReadQuarIndex(string indexPath)
        {
            var map = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            if (!File.Exists(indexPath)) return map;
            foreach (string line in File.ReadAllLines(indexPath))
            {
                string[] parts = line.Split('|');
                if (parts.Length < 3) continue;
                if (parts.Length < 5)
                {
                    // pre-0.0.4 entries lack threat/source — pad so callers can index freely
                    var full = new string[5];
                    for (int i = 0; i < 5; i++) full[i] = i < parts.Length ? parts[i] : "";
                    parts = full;
                }
                map[parts[0]] = parts;
            }
            return map;
        }

        internal static void RemoveQuarIndexEntry(string indexPath, string fileName)
        {
            if (!File.Exists(indexPath)) return;
            var keep = new List<string>();
            foreach (string line in File.ReadAllLines(indexPath))
                if (!line.StartsWith(fileName + "|", StringComparison.OrdinalIgnoreCase))
                    keep.Add(line);
            File.WriteAllLines(indexPath, keep.ToArray());
        }



    }
}
