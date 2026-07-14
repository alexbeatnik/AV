// The "Detection engines" dialog (Settings → ENGINES…): three uniform cards —
// ClamAV (core engine, status only), YARA (toggle + rules maintenance), and
// VirusTotal (API key with a TEST KEY probe + privacy toggles). Every card
// leads with a colored ● status line so the state of each engine is obvious.
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
                dlg.ClientSize = new Size(640, 676);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.MinimizeBox = dlg.MaximizeBox = false;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.BackColor = Theme.Bg;
                dlg.ForeColor = Theme.Text;
                dlg.Font = Font;
                Theme.DarkTitleBar(dlg);

                // Labels on a card surface share the same setup
                Func<int, int, Label> mkLabel = delegate(int x, int y)
                {
                    var l = new Label();
                    l.AutoSize = true;
                    l.BackColor = Theme.Card;
                    l.ForeColor = Theme.Text;
                    l.Location = new Point(x, y);
                    return l;
                };

                // ---- Card 1: ClamAV (the core engine — no toggle, status only) ----
                var cardClam = new CardPanel("ClamAV");
                cardClam.SetBounds(24, 16, 592, 96);

                var clamStatus = mkLabel(16, 42);
                bool haveDb = DbExists();
                if (clamDir != null && haveDb)
                {
                    clamStatus.Text = "● " + string.Format(Lang.T("engines.clamavReady"), clamVersion, DbDateString());
                    clamStatus.ForeColor = Theme.Good;
                }
                else if (clamDir != null)
                {
                    clamStatus.Text = "● " + Lang.T("engines.clamavNoDb");
                    clamStatus.ForeColor = Theme.Warn;
                }
                else
                {
                    clamStatus.Text = "● " + Lang.T("engines.clamavMissing");
                    clamStatus.ForeColor = Theme.Warn;
                }

                var clamNote = mkLabel(16, 64);
                clamNote.Text = Lang.T("engines.clamavCore");
                clamNote.ForeColor = Theme.Muted;

                cardClam.Controls.Add(clamStatus);
                cardClam.Controls.Add(clamNote);

                // ---- Card 2: YARA ----
                var cardYara = new CardPanel("YARA");
                cardYara.SetBounds(24, 124, 592, 180);

                var yaraStatus = mkLabel(16, 42);
                Action refreshYaraStatus = delegate
                {
                    bool exe = File.Exists(YaraExe);
                    int rules = YaraRuleFiles().Count;
                    string rulesDate = File.Exists(YaraForgeRules)
                        ? File.GetLastWriteTime(YaraForgeRules).ToString("dd.MM.yyyy") : "—";
                    if (exe && rules > 0)
                    {
                        yaraStatus.Text = "● " + string.Format(Lang.T("engines.yaraStatusReady"), rules, rulesDate);
                        yaraStatus.ForeColor = Theme.Good;
                    }
                    else if (yaraSetupRunning)
                    {
                        yaraStatus.Text = "● " + Lang.T("engines.yaraStatusDownloading");
                        yaraStatus.ForeColor = Theme.Warn;
                    }
                    else
                    {
                        yaraStatus.Text = "● " + Lang.T("engines.yaraStatusMissing");
                        yaraStatus.ForeColor = Theme.Warn;
                    }
                };
                refreshYaraStatus();

                var tglYara = new Toggle(Lang.T("settings.yaraEnabled"));
                tglYara.BackColor = Theme.Card;
                tglYara.Location = new Point(16, 68);
                tglYara.Checked = yaraEnabled;

                var btnRules = MakeLightButton(Lang.T("btn.updateYaraRules"), Ico.Refresh);
                btnRules.BackColor = Theme.Card; // corners show the card surface through them
                btnRules.SetBounds(16, 102, 220, 30);
                btnRules.Click += delegate
                {
                    yaraEnabled = true;
                    tglYara.Checked = true;
                    EnsureYaraSetup(true);
                    refreshYaraStatus();
                    statusLabel.Text = Lang.T("status.yaraUpdating");
                };
                var btnCustom = MakeLightButton(Lang.T("btn.customRules"), Ico.FolderIcon);
                btnCustom.BackColor = Theme.Card;
                btnCustom.SetBounds(246, 102, 240, 30);
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
                yaraHint.BackColor = Theme.Card;
                yaraHint.SetBounds(16, 140, 560, 32);

                cardYara.Controls.Add(yaraStatus);
                cardYara.Controls.Add(tglYara);
                cardYara.Controls.Add(btnRules);
                cardYara.Controls.Add(btnCustom);
                cardYara.Controls.Add(yaraHint);

                // ---- Card 3: VirusTotal ----
                var cardVt = new CardPanel("VirusTotal");
                cardVt.SetBounds(24, 316, 592, 296);

                var vtStatus = mkLabel(16, 42);
                if (vtApiKey.Length == 0)
                {
                    vtStatus.Text = "● " + Lang.T("engines.vtStatusNoKey");
                    vtStatus.ForeColor = Theme.Warn;
                }
                else if (!vtCheckEnabled)
                {
                    vtStatus.Text = "● " + Lang.T("sval.disabled");
                    vtStatus.ForeColor = Theme.Muted;
                }
                else
                {
                    vtStatus.Text = "● " + Lang.T("engines.vtStatusOn");
                    vtStatus.ForeColor = Theme.Good;
                }

                var keyLabel = mkLabel(16, 70);
                keyLabel.Text = Lang.T("engines.vtKeyLabel");

                var keyBox = new TextBox();
                keyBox.SetBounds(16, 92, 400, 26);
                keyBox.BorderStyle = BorderStyle.FixedSingle;
                keyBox.BackColor = Theme.LogBg;
                keyBox.ForeColor = Theme.Text;
                keyBox.Font = new Font("Consolas", 9.5f);
                keyBox.Text = vtApiKey;

                var keyLink = new LinkLabel();
                keyLink.Text = Lang.T("engines.vtGetKey");
                keyLink.AutoSize = true;
                keyLink.Location = new Point(428, 96);
                keyLink.BackColor = Theme.Card;
                keyLink.LinkColor = Theme.Accent;
                keyLink.ActiveLinkColor = Theme.AccentHot;
                keyLink.LinkBehavior = LinkBehavior.HoverUnderline;
                keyLink.LinkClicked += delegate
                {
                    try { Process.Start("https://www.virustotal.com/gui/my-apikey"); } catch { }
                };

                var btnTest = MakeLightButton(Lang.T("btn.testKey"), Ico.Radar);
                btnTest.BackColor = Theme.Card;
                btnTest.SetBounds(16, 128, 180, 30);
                var testResult = mkLabel(208, 135);
                testResult.ForeColor = Theme.Muted;
                btnTest.Click += delegate
                {
                    string k = keyBox.Text.Trim();
                    if (k.Length == 0)
                    {
                        testResult.Text = Lang.T("engines.vtKeyEmpty");
                        testResult.ForeColor = Theme.Warn;
                        return;
                    }
                    testResult.Text = Lang.T("engines.vtTesting");
                    testResult.ForeColor = Theme.Muted;
                    btnTest.Enabled = false;
                    VtTestKey(k, delegate(bool ok, string msg, Color color)
                    {
                        if (dlg.IsDisposed) return; // dialog closed before the probe returned
                        btnTest.Enabled = true;
                        testResult.Text = msg;
                        testResult.ForeColor = color;
                        // a proven-good key must not sit out an old bad-key backoff
                        if (ok) vtPauseUntil = DateTime.MinValue;
                    });
                };

                var tglVtCheck = new Toggle(Lang.T("settings.vtCheck"));
                tglVtCheck.BackColor = Theme.Card;
                tglVtCheck.Location = new Point(16, 168);
                tglVtCheck.Checked = vtCheckEnabled;

                var tglVtUpload = new Toggle(Lang.T("settings.vtUpload"));
                tglVtUpload.BackColor = Theme.Card;
                tglVtUpload.Location = new Point(16, 200);
                tglVtUpload.Checked = vtUploadEnabled;

                var vtHint = new Label();
                vtHint.Text = Lang.T("engines.vtHint");
                vtHint.ForeColor = Theme.Muted;
                vtHint.BackColor = Theme.Card;
                vtHint.SetBounds(16, 234, 560, 56);

                cardVt.Controls.Add(vtStatus);
                cardVt.Controls.Add(keyLabel);
                cardVt.Controls.Add(keyBox);
                cardVt.Controls.Add(keyLink);
                cardVt.Controls.Add(btnTest);
                cardVt.Controls.Add(testResult);
                cardVt.Controls.Add(tglVtCheck);
                cardVt.Controls.Add(tglVtUpload);
                cardVt.Controls.Add(vtHint);

                var buttons = new FlowLayoutPanel();
                buttons.Dock = DockStyle.Bottom;
                buttons.FlowDirection = FlowDirection.RightToLeft;
                buttons.Height = 52;
                buttons.Padding = new Padding(10);
                buttons.BackColor = Theme.Bg;
                var cancel = MakeButton(Lang.T("btn.cancel"), 100, Theme.Card, Theme.Bg, Ico.Close);
                cancel.DialogResult = DialogResult.Cancel;
                var ok2 = MakeButton("OK", 90, Theme.Accent, Theme.AccentHot, Ico.Check);
                ok2.DialogResult = DialogResult.OK;
                buttons.Controls.Add(cancel);
                buttons.Controls.Add(ok2);

                dlg.Controls.Add(cardClam);
                dlg.Controls.Add(cardYara);
                dlg.Controls.Add(cardVt);
                dlg.Controls.Add(buttons);
                dlg.AcceptButton = ok2;
                dlg.CancelButton = cancel;

                if (dlg.ShowDialog(this) != DialogResult.OK) return;

                bool wasEnabled = yaraEnabled;
                bool keyChanged = !string.Equals(vtApiKey, keyBox.Text.Trim());
                yaraEnabled = tglYara.Checked;
                vtApiKey = keyBox.Text.Trim();
                vtCheckEnabled = tglVtCheck.Checked;
                vtUploadEnabled = tglVtUpload.Checked;
                // a fresh key must not inherit the previous key's 401/403 backoff
                if (keyChanged) vtPauseUntil = DateTime.MinValue;
                SaveSettings();
                if (yaraEnabled && (!wasEnabled || !YaraReady())) EnsureYaraSetup(false);
                UpdateStatsUi(); // the dashboard engine cells reflect the new state
                statusLabel.Text = Lang.T("status.enginesSaved");
            }
        }
    }
}
