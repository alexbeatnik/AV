// The "Detection engines" dialog (Settings → YARA / VIRUSTOTAL…): the YARA
// toggle with rules maintenance, and the VirusTotal API key + privacy toggles.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace AVUI
{
    public partial class MainForm : Form
    {
        void ShowEnginesDialog()
        {
            using (var dlg = new Form())
            {
                dlg.Text = Lang.T("engines.title");
                dlg.ClientSize = new Size(640, 520);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.MinimizeBox = dlg.MaximizeBox = false;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.BackColor = Theme.Bg;
                dlg.ForeColor = Theme.Text;
                dlg.Font = Font;
                Theme.DarkTitleBar(dlg);

                Func<string, int, Label> header = delegate(string text, int y)
                {
                    var l = new Label();
                    l.Text = text.ToUpperInvariant();
                    l.Font = new Font("Segoe UI Semibold", 9f);
                    l.ForeColor = Theme.Accent;
                    l.BackColor = Theme.Bg;
                    l.AutoSize = true;
                    l.Location = new Point(24, y);
                    return l;
                };

                // ---- YARA ----
                var yaraHead = header("YARA", 18);

                var tglYara = new Toggle(Lang.T("settings.yaraEnabled"));
                tglYara.BackColor = Theme.Bg;
                tglYara.Location = new Point(24, 46);
                tglYara.Checked = yaraEnabled;

                var yaraStatus = new Label();
                yaraStatus.AutoSize = true;
                yaraStatus.BackColor = Theme.Bg;
                yaraStatus.Location = new Point(24, 82);
                Action refreshYaraStatus = delegate
                {
                    bool exe = File.Exists(YaraExe);
                    int rules = YaraRuleFiles().Count;
                    string rulesDate = File.Exists(YaraForgeRules)
                        ? File.GetLastWriteTime(YaraForgeRules).ToString("dd.MM.yyyy") : "—";
                    if (exe && rules > 0)
                    {
                        yaraStatus.Text = string.Format(Lang.T("engines.yaraStatusReady"), rules, rulesDate);
                        yaraStatus.ForeColor = Theme.Good;
                    }
                    else if (yaraSetupRunning)
                    {
                        yaraStatus.Text = Lang.T("engines.yaraStatusDownloading");
                        yaraStatus.ForeColor = Theme.Warn;
                    }
                    else
                    {
                        yaraStatus.Text = Lang.T("engines.yaraStatusMissing");
                        yaraStatus.ForeColor = Theme.Warn;
                    }
                };
                refreshYaraStatus();

                var btnRules = MakeButton(Lang.T("btn.updateYaraRules"), 220, Theme.Card, Theme.CardLine, Ico.Refresh);
                btnRules.Location = new Point(24, 112);
                btnRules.Click += delegate
                {
                    yaraEnabled = true;
                    tglYara.Checked = true;
                    EnsureYaraSetup(true);
                    refreshYaraStatus();
                    statusLabel.Text = Lang.T("status.yaraUpdating");
                };
                var btnCustom = MakeButton(Lang.T("btn.customRules"), 260, Theme.Card, Theme.CardLine, Ico.FolderIcon);
                btnCustom.Location = new Point(254, 112);
                btnCustom.Click += delegate
                {
                    try
                    {
                        Directory.CreateDirectory(YaraCustomDir);
                        Process.Start("explorer.exe", "\"" + YaraCustomDir + "\"");
                    }
                    catch { }
                };

                var yaraHint = new Label();
                yaraHint.Text = Lang.T("engines.yaraHint");
                yaraHint.ForeColor = Theme.Muted;
                yaraHint.BackColor = Theme.Bg;
                yaraHint.SetBounds(24, 152, dlg.ClientSize.Width - 48, 46);

                // ---- VirusTotal ----
                var vtHead = header("VirusTotal", 212);

                var keyLabel = new Label();
                keyLabel.Text = Lang.T("engines.vtKeyLabel");
                keyLabel.AutoSize = true;
                keyLabel.ForeColor = Theme.Text;
                keyLabel.BackColor = Theme.Bg;
                keyLabel.Location = new Point(24, 242);

                var keyBox = new TextBox();
                keyBox.SetBounds(24, 264, 450, 26);
                keyBox.BorderStyle = BorderStyle.FixedSingle;
                keyBox.BackColor = Theme.LogBg;
                keyBox.ForeColor = Theme.Text;
                keyBox.Font = new Font("Consolas", 9.5f);
                keyBox.Text = vtApiKey;

                var keyLink = new LinkLabel();
                keyLink.Text = Lang.T("engines.vtGetKey");
                keyLink.AutoSize = true;
                keyLink.Location = new Point(482, 268);
                keyLink.BackColor = Theme.Bg;
                keyLink.LinkColor = Theme.Accent;
                keyLink.ActiveLinkColor = Theme.AccentHot;
                keyLink.LinkBehavior = LinkBehavior.HoverUnderline;
                keyLink.LinkClicked += delegate
                {
                    try { Process.Start("https://www.virustotal.com/gui/my-apikey"); } catch { }
                };

                var tglVtCheck = new Toggle(Lang.T("settings.vtCheck"));
                tglVtCheck.BackColor = Theme.Bg;
                tglVtCheck.Location = new Point(24, 304);
                tglVtCheck.Checked = vtCheckEnabled;

                var tglVtUpload = new Toggle(Lang.T("settings.vtUpload"));
                tglVtUpload.BackColor = Theme.Bg;
                tglVtUpload.Location = new Point(24, 340);
                tglVtUpload.Checked = vtUploadEnabled;

                var vtHint = new Label();
                vtHint.Text = Lang.T("engines.vtHint");
                vtHint.ForeColor = Theme.Muted;
                vtHint.BackColor = Theme.Bg;
                vtHint.SetBounds(24, 380, dlg.ClientSize.Width - 48, 78);

                var buttons = new FlowLayoutPanel();
                buttons.Dock = DockStyle.Bottom;
                buttons.FlowDirection = FlowDirection.RightToLeft;
                buttons.Height = 52;
                buttons.Padding = new Padding(10);
                buttons.BackColor = Theme.Bg;
                var cancel = MakeButton(Lang.T("btn.cancel"), 100, Theme.Card, Theme.Bg, Ico.Close);
                cancel.DialogResult = DialogResult.Cancel;
                var ok = MakeButton("OK", 90, Theme.Accent, Theme.AccentHot, Ico.Check);
                ok.DialogResult = DialogResult.OK;
                buttons.Controls.Add(cancel);
                buttons.Controls.Add(ok);

                dlg.Controls.Add(yaraHead);
                dlg.Controls.Add(tglYara);
                dlg.Controls.Add(yaraStatus);
                dlg.Controls.Add(btnRules);
                dlg.Controls.Add(btnCustom);
                dlg.Controls.Add(yaraHint);
                dlg.Controls.Add(vtHead);
                dlg.Controls.Add(keyLabel);
                dlg.Controls.Add(keyBox);
                dlg.Controls.Add(keyLink);
                dlg.Controls.Add(tglVtCheck);
                dlg.Controls.Add(tglVtUpload);
                dlg.Controls.Add(vtHint);
                dlg.Controls.Add(buttons);
                dlg.AcceptButton = ok;
                dlg.CancelButton = cancel;

                if (dlg.ShowDialog(this) != DialogResult.OK) return;

                bool wasEnabled = yaraEnabled;
                yaraEnabled = tglYara.Checked;
                vtApiKey = keyBox.Text.Trim();
                vtCheckEnabled = tglVtCheck.Checked;
                vtUploadEnabled = tglVtUpload.Checked;
                SaveSettings();
                if (yaraEnabled && (!wasEnabled || !YaraReady())) EnsureYaraSetup(false);
                UpdateStatsUi(); // the dashboard engine cells reflect the new state
                statusLabel.Text = Lang.T("status.enginesSaved");
            }
        }
    }
}
