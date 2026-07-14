// UI construction: pages, dashboard, quarantine/settings pages, language switching.
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

        public MainForm(bool startInTray)
        {
            Text = AppName; // stays "AV" for the taskbar/Alt+Tab; the visible caption text is hidden below
            Icon = AppIcon;
            // Fixed-size window: the pages are hand-tuned layouts (the settings card
            // uses absolute positions), so resizing and maximizing are disabled.
            // Both caption boxes are dropped so only ✕ remains — Windows can't show
            // minimize+close without a grayed maximize placeholder between them, and
            // ✕ already minimizes to the tray instead of exiting (see OnFormClosing),
            // so a separate minimize button adds nothing.
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            MinimizeBox = false;
            Size = new Size(940, 720);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Font = new Font("Segoe UI", 9.5f);
            Theme.DarkTitleBar(this, true); // caption text hidden — the in-window header is the branding

            BuildUi();
            LocateClamAV();
            LoadSettings();
            SyncUninstallVersion(); // a self-updated exe must show its real version in Settings → Apps
            RefreshDbStatus();
            ShowPage(0);
            EnsureAutostartFirstRun();

            if (startInTray)
            {
                WindowState = FormWindowState.Minimized;
                ShowInTaskbar = false;
            }

            // The first normal start decides where the app lives (portable vs
            // per-user install) BEFORE anything is downloaded, so ClamAV, the database
            // and quarantine land in the right place. After that, a clean PC gets
            // the ClamAV download offer as before.
            Shown += delegate
            {
                if (startInTray) return;
                if (!modeAsked && !IsInstalled)
                {
                    modeAsked = true; // one-time question, even if UAC is declined later
                    SaveSettings();
                    if (MessageBox.Show(this,
                        string.Format(Lang.T("msg.firstRunModeChoice"), AppDomain.CurrentDomain.BaseDirectory, InstallDir),
                        AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                    {
                        LaunchInstaller(); // copies everything to the per-user folder and relaunches from there
                        return;
                    }
                    // portable mode: the current folder stays the root for ClamAV,
                    // the database, quarantine and settings — just fetch ClamAV if
                    // it isn't sitting next to the exe yet
                    if (clamDir == null && MessageBox.Show(this, Lang.T("msg.offerPortableDownload"),
                            AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                        StartClamAVDownload();
                    return;
                }
                if (clamDir == null) OfferClamAVDownload();
            };
        }

        // ---------- UI construction ----------

        void BuildUi()
        {
            // Header: the AV mark on the left, horizontal nav tabs on the right.
            // (Not a left icon rail — see the note on NavTab for why.)
            var title = new Panel();
            title.Dock = DockStyle.Top;
            title.Height = 78;
            title.BackColor = Theme.Bg;
            // Just the textless shield: the app name already sits in the window title
            // bar right above — repeating it next to the logo read as "AV AV AV"
            var logo = new PictureBox();
            logo.Image = LogoImage;
            logo.SizeMode = PictureBoxSizeMode.Zoom;
            logo.Size = new Size(64, 64);
            logo.Location = new Point(24, 7);
            logo.BackColor = Color.Transparent;
            var verText = new Label();
            verText.Text = "v" + AppVersion;
            verText.Font = new Font("Segoe UI", 8f); // small and quiet — it's a detail, not a headline
            verText.ForeColor = Theme.Muted;
            verText.AutoSize = true;
            verText.Location = new Point(96, 33); // vertically centered on the shield
            title.Controls.Add(logo);
            title.Controls.Add(verText);

            var navBar = new FlowLayoutPanel();
            navBar.Dock = DockStyle.Right;
            navBar.FlowDirection = FlowDirection.LeftToRight;
            navBar.WrapContents = false;
            navBar.AutoSize = true;
            navBar.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            navBar.BackColor = Theme.Bg;
            navBar.Padding = new Padding(0, 17, 24, 0);
            string[] navLabelKeys = { "nav.dashboard", "nav.logs", "nav.quarantine", "nav.settings" };
            IconDraw[] navIcons = { Ico.ShieldIcon, Ico.LogIcon, Ico.Radiation, Ico.Gear };
            navs = new NavTab[4];
            for (int i = 0; i < 4; i++)
            {
                navs[i] = new NavTab(Lang.T(navLabelKeys[i]), navIcons[i]);
                int idx = i;
                navs[i].Click += delegate { ShowPage(idx); };
                navBar.Controls.Add(navs[i]);
            }
            title.Controls.Add(navBar);

            // Status bar at the bottom
            var statusBar = new Panel();
            statusBar.Dock = DockStyle.Bottom;
            statusBar.Height = 26;
            statusBar.BackColor = Theme.Card;
            statusLabel = new Label();
            statusLabel.Dock = DockStyle.Fill;
            statusLabel.ForeColor = Theme.Muted;
            statusLabel.TextAlign = ContentAlignment.MiddleLeft;
            statusLabel.Padding = new Padding(12, 0, 0, 0);
            statusLabel.Text = Lang.T("status.ready");
            statusBar.Controls.Add(statusLabel);

            progress = new SlimMarquee();
            progress.Dock = DockStyle.Bottom;

            // Page area (full width now that navigation lives in the header)
            var content = new Panel();
            content.Dock = DockStyle.Fill;
            content.Padding = new Padding(20, 8, 20, 12);
            content.BackColor = Theme.Bg;

            pages = new Panel[4];
            pages[0] = BuildDashboardPage();
            pages[1] = BuildLogsPage();
            pages[2] = BuildQuarantinePage();
            pages[3] = BuildSettingsPage();
            foreach (var p in pages) { p.Visible = false; content.Controls.Add(p); }

            Controls.Add(content);
            Controls.Add(progress);
            Controls.Add(statusBar);
            Controls.Add(title);

            // Debounce timer: wait for a file to finish being written, then scan as a batch
            debounceTimer = new Timer();
            debounceTimer.Interval = 3000;
            debounceTimer.Tick += OnDebounceTick;

            // Auto-update: first check 15s after startup, then the timer ticks hourly.
            // The actual checks are throttled further: database versions once a day
            // (the CDN rate-limits); app releases on GitHub are checked on every
            // launch (the first tick ignores the persisted timestamp) and then daily
            autoUpdateTimer = new Timer();
            autoUpdateTimer.Interval = 15000;
            autoUpdateTimer.Tick += delegate
            {
                if (autoUpdateFirstTick) { autoUpdateFirstTick = false; autoUpdateTimer.Interval = 3600000; }
                MaybeAutoUpdate();
                MaybeCheckAppUpdate();
                MaybeUpdateYaraRules(); // first tick also installs the engine if it's enabled but missing
            };
            autoUpdateTimer.Start();

            // Scheduled quick scan: a cheap due-time check every 5 minutes. The periods
            // are coarse (a day / a week), so minute precision is plenty, and the first
            // tick lands after startup has settled instead of joining the boot storm.
            schedTimer = new Timer();
            schedTimer.Interval = 300000;
            schedTimer.Tick += delegate { MaybeRunScheduledScan(); };
            schedTimer.Start();

            // Scan heartbeat: guarantees a progress line every 10s even when clamscan
            // is stuck for a long time on a large file/archive and prints nothing.
            scanHeartbeat = new Timer();
            scanHeartbeat.Interval = 10000;
            scanHeartbeat.Tick += delegate { ScanHeartbeatTick(); };

            // Tray
            tray = new NotifyIcon();
            tray.Icon = AppIcon;
            tray.Text = AppName;
            tray.Visible = true;
            tray.DoubleClick += delegate { RestoreFromTray(); };
            var menu = new ContextMenuStrip();
            menu.Renderer = new ToolStripProfessionalRenderer(new DarkMenuColors());
            menu.ForeColor = Theme.Text;
            trayOpenItem = menu.Items.Add(Lang.T("tray.open"), null, delegate { RestoreFromTray(); });
            trayExitItem = menu.Items.Add(Lang.T("tray.exit"), null, delegate { reallyClose = true; Close(); });
            tray.ContextMenuStrip = menu;

            Resize += delegate
            {
                if (WindowState == FormWindowState.Minimized)
                    ShowInTaskbar = false; // hide to tray
            };
            FormClosing += OnFormClosing;
        }

        Panel BuildDashboardPage()
        {
            var page = new Panel();
            page.Dock = DockStyle.Fill;
            page.BackColor = Theme.Bg;

            // Top mosaic (Zillya-style, in our dark card idiom): a large QUICK SCAN
            // tile on the left, and the protection-status tile with the glowing
            // shield on the right. While a scan/update runs, a red STOP tile swaps
            // in where QUICK SCAN was (see SetBusy).
            var topGrid = new TableLayoutPanel();
            topGrid.Dock = DockStyle.Top;
            topGrid.Height = 204;
            topGrid.BackColor = Theme.Bg;
            topGrid.ColumnCount = 2;
            topGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58f));
            topGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42f));
            topGrid.RowCount = 1;
            topGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

            dashQuick = MakeCardButton(Lang.T("btn.quickScan"), Theme.Accent, Theme.AccentHot, Theme.Text, Ico.Radar);
            dashQuick.Dock = DockStyle.Fill;
            dashQuick.Font = new Font("Segoe UI Semibold", 11f);
            dashQuick.Click += delegate { RunQuickScan(); };
            dashStop = MakeCardButton(Lang.T("btn.stop"), Theme.Danger, Theme.DangerHot, Theme.Text, Ico.StopIcon);
            dashStop.Dock = DockStyle.Fill;
            dashStop.Font = dashQuick.Font;
            dashStop.Visible = false;
            dashStop.Click += delegate { StopCurrent(); };
            var quickCell = new Panel();
            quickCell.Dock = DockStyle.Fill;
            quickCell.Margin = new Padding(0, 4, 7, 8);
            quickCell.BackColor = Theme.Bg;
            quickCell.Controls.Add(dashQuick);
            quickCell.Controls.Add(dashStop);
            scanButtons.Add(dashQuick);

            statusBanner = new StatusBanner();
            statusBanner.Dock = DockStyle.Fill;
            statusBanner.Margin = new Padding(7, 4, 0, 8);
            shield = new ShieldIndicator();
            shield.Size = new Size(72, 72);
            shield.BackColor = Theme.Card;
            heroTitle = new Label();
            heroTitle.Font = new Font("Segoe UI Semibold", 14f);
            heroTitle.ForeColor = Theme.Text;
            heroTitle.BackColor = Theme.Card;
            heroTitle.TextAlign = ContentAlignment.MiddleCenter;
            heroSub = new Label();
            heroSub.Font = Font;
            heroSub.ForeColor = Theme.Muted;
            heroSub.BackColor = Theme.Card;
            heroSub.TextAlign = ContentAlignment.MiddleCenter;
            heroSub.AutoEllipsis = true;
            statusBanner.Controls.Add(shield);
            statusBanner.Controls.Add(heroTitle);
            statusBanner.Controls.Add(heroSub);
            statusBanner.Resize += delegate { LayoutHeroTile(); };
            LayoutHeroTile();

            topGrid.Controls.Add(quickCell, 0, 0);
            topGrid.Controls.Add(statusBanner, 1, 0);

            // Secondary action tiles: four equal columns stretching the full row width
            var scanBar = new TableLayoutPanel();
            scanBar.Dock = DockStyle.Top;
            scanBar.Height = 128;
            scanBar.BackColor = Theme.Bg;
            scanBar.ColumnCount = 4;
            for (int i = 0; i < 4; i++)
                scanBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25f));
            scanBar.RowCount = 1;
            scanBar.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            dashScanFile = MakeCardButton(Lang.T("btn.scanFileDash"), Theme.Card, Theme.CardLine, Theme.Text, Ico.FileIcon);
            dashScanFile.SubText = Lang.T("btn.scanFileSub");
            dashScanFile.Click += delegate { PickAndScan(false); };
            dashScanFolder = MakeCardButton(Lang.T("btn.scanFolderDash"), Theme.Card, Theme.CardLine, Theme.Text, Ico.FolderIcon);
            dashScanFolder.SubText = Lang.T("btn.scanFolderSub");
            dashScanFolder.Click += delegate { PickAndScan(true); };
            dashScanAll = MakeCardButton(Lang.T("btn.scanAll"), Theme.Card, Theme.CardLine, Theme.Text, Ico.Stack);
            dashScanAll.SubText = Lang.T("btn.scanAllSub");
            dashScanAll.Click += delegate { RunFullScan(); };
            dashScanRam = MakeCardButton(Lang.T("btn.scanRam"), Theme.Card, Theme.CardLine, Theme.Text, Ico.Memory);
            dashScanRam.SubText = Lang.T("btn.scanRamSub");
            dashScanRam.Click += delegate { RunMemoryScan(); };
            var rowTiles = new ModernButton[] { dashScanFile, dashScanFolder, dashScanAll, dashScanRam };
            for (int i = 0; i < rowTiles.Length; i++)
            {
                rowTiles[i].Dock = DockStyle.Fill;
                rowTiles[i].Margin = new Padding(i == 0 ? 0 : 6, 0, i == rowTiles.Length - 1 ? 0 : 6, 8);
                scanBar.Controls.Add(rowTiles[i], i, 0);
            }
            scanButtons.Add(dashScanFile);
            scanButtons.Add(dashScanFolder); scanButtons.Add(dashScanAll); scanButtons.Add(dashScanRam);

            // Compact stat strip + the (conditionally visible) update button — one
            // slim row instead of the old tall SYSTEM card, which ate half the
            // dashboard for a handful of numbers (the DB date lives in the hero)
            statStrip = new StatStrip();
            statStrip.Dock = DockStyle.Top;
            statStrip.Height = 66;
            statStrip.Margin = new Padding(6, 4, 6, 4);
            statStrip.Padding = new Padding(0, 10, 12, 14);
            btnUpdate = MakeLightButton(Lang.T("btn.updateDb"), Ico.Refresh);
            btnUpdate.BackColor = Theme.Card;
            btnUpdate.Width = 190;
            btnUpdate.Dock = DockStyle.Right;
            btnUpdate.Click += delegate { RunFreshclam(); };
            statStrip.Controls.Add(btnUpdate);

            // Database strip: per-file signature versions + total signature count —
            // fills the formerly empty band between the action tiles and the activity row
            dbStrip = new StatStrip();
            dbStrip.Dock = DockStyle.Top;
            dbStrip.Height = 66;
            dbStrip.Padding = new Padding(0, 10, 12, 14);

            // One-click fixes for engines that need the user's help, right next to
            // the engine cells that show the problem (the user shouldn't have to
            // find Settings → Engines). Visibility is managed by UpdateStatsUi.
            btnGetYara = MakeLightButton(Lang.T("btn.getYara"), Ico.Download);
            btnGetYara.BackColor = Theme.Card;
            btnGetYara.Width = 250;
            btnGetYara.Dock = DockStyle.Right;
            btnGetYara.Visible = false;
            btnGetYara.Click += delegate
            {
                yaraEnabled = true;
                SaveSettings();
                EnsureYaraSetup(false);
                statusLabel.Text = Lang.T("status.yaraUpdating");
                UpdateStatsUi(); // hides the button while the download runs
            };
            btnEnterVtKey = MakeLightButton(Lang.T("btn.enterVtKey"), Ico.Radar);
            btnEnterVtKey.BackColor = Theme.Card;
            btnEnterVtKey.Width = 250;
            btnEnterVtKey.Dock = DockStyle.Right;
            btnEnterVtKey.Visible = false;
            btnEnterVtKey.Click += delegate { ShowVtKeyDialog(); };
            dbStrip.Controls.Add(btnGetYara);
            dbStrip.Controls.Add(btnEnterVtKey);

            // Last-activity strip: one line instead of a scrollable log card — the
            // full history is one click away via "Open Log File", so the dashboard
            // doesn't need to dedicate a big scrollable panel to it.
            activityRow = new StatusBanner();
            activityRow.Dock = DockStyle.Top;
            activityRow.Height = 56;
            activityRow.Margin = new Padding(6, 4, 6, 4);
            activityRow.Padding = new Padding(20, 2, 10, 8); // bottom inset keeps children off the card shadow
            activityRow.AccentColor = Theme.Accent;
            lastActivityLabel = new Label();
            lastActivityLabel.Dock = DockStyle.Fill;
            lastActivityLabel.AutoEllipsis = true;
            lastActivityLabel.Font = new Font("Consolas", 9f);
            lastActivityLabel.ForeColor = Theme.Muted;
            lastActivityLabel.BackColor = Theme.Card;
            lastActivityLabel.TextAlign = ContentAlignment.MiddleLeft;
            // dark secondary button — a light one here outshines the primary actions above
            btnScanLog = MakeButton(Lang.T("btn.openLog"), 235, Theme.Bg, Theme.CardLine, Ico.LogIcon);
            btnScanLog.BackColor = Theme.Card;
            btnScanLog.Dock = DockStyle.Right;
            btnScanLog.Margin = new Padding(0, 0, 0, 0);
            btnScanLog.Click += delegate { OpenScanLog(); };
            activityRow.Controls.Add(lastActivityLabel);
            activityRow.Controls.Add(btnScanLog);

            // Dock=Top stacks in reverse add order: the big tile mosaic first, then the
            // action tiles, the stat strip, the database strip, and the last-activity strip
            page.Controls.Add(activityRow);
            page.Controls.Add(dbStrip);
            page.Controls.Add(statStrip);
            page.Controls.Add(scanBar);
            page.Controls.Add(topGrid);
            return page;
        }

        // Centers the shield and both text lines inside the protection-status tile
        void LayoutHeroTile()
        {
            int w = statusBanner.Width, h = statusBanner.Height;
            shield.SetBounds((w - shield.Width) / 2, (int)(h * 0.10f), shield.Width, shield.Height);
            heroTitle.SetBounds(8, (int)(h * 0.53f), w - 16, 30);
            heroSub.SetBounds(12, (int)(h * 0.72f), w - 24, 20);
        }

        Panel BuildLogsPage()
        {
            var page = new Panel();
            page.Dock = DockStyle.Fill;
            page.BackColor = Theme.Bg;
            page.Padding = new Padding(6);

            cardScan = new CardPanel(Lang.T("card.scanning"));
            cardScan.Dock = DockStyle.Fill;
            cardScan.Margin = new Padding(6);

            var buttonsRow = new FlowLayoutPanel();
            buttonsRow.Dock = DockStyle.Top;
            buttonsRow.Height = 42;
            buttonsRow.BackColor = Theme.Card;

            btnStop = MakeButton(Lang.T("btn.stop"), 110, Theme.Danger, Theme.DangerHot, Ico.StopIcon);
            btnStop.Enabled = false;
            btnStop.Click += delegate { StopCurrent(); };

            btnClearLog = MakeButton(Lang.T("btn.clearLog"), 120, Theme.Bg, Theme.CardLine, Ico.Trash);
            btnClearLog.BackColor = Theme.Card;
            btnClearLog.Click += delegate { ClearLog(); };

            // hides path lists and raw scanner chatter unless the user wants them
            chkLogDetails = new Toggle(Lang.T("log.showDetails"));
            chkLogDetails.BackColor = Theme.Card;
            chkLogDetails.Margin = new Padding(16, 8, 8, 0);
            chkLogDetails.CheckedChanged += delegate { RebuildLog(); SaveSettings(); };

            // live progress readout ("██████░░░░  3150 / 10091 (31%)") — clamscan itself
            // prints nothing useful, but we know the exact file count upfront
            scanProgressLabel = new Label();
            scanProgressLabel.AutoSize = true;
            scanProgressLabel.Font = new Font("Consolas", 10f);
            scanProgressLabel.ForeColor = Theme.AccentHot;
            scanProgressLabel.BackColor = Theme.Card;
            scanProgressLabel.Margin = new Padding(16, 12, 0, 0);

            buttonsRow.Controls.Add(btnStop);
            buttonsRow.Controls.Add(btnClearLog);
            buttonsRow.Controls.Add(chkLogDetails);
            buttonsRow.Controls.Add(scanProgressLabel);

            log = new RichTextBox();
            log.Dock = DockStyle.Fill;
            log.ReadOnly = true;
            log.BorderStyle = BorderStyle.None;
            log.BackColor = Theme.LogBg;
            log.ForeColor = Theme.Muted;
            log.Font = new Font("Consolas", 9.5f);
            log.HideSelection = false;

            cardScan.Controls.Add(log);
            cardScan.Controls.Add(buttonsRow);

            page.Controls.Add(cardScan);
            return page;
        }

        Panel BuildQuarantinePage()
        {
            var page = new Panel();
            page.Dock = DockStyle.Fill;
            page.BackColor = Theme.Bg;
            page.Padding = new Padding(6);

            // Info strip above the list: file count / total size / last detection,
            // with a search box on the right (filters by name, path, and threat)
            quarStrip = new StatStrip();
            quarStrip.Dock = DockStyle.Top;
            quarStrip.Height = 66;
            quarStrip.Padding = new Padding(0, 10, 12, 14);
            var searchWrap = new Panel();
            searchWrap.Dock = DockStyle.Right;
            searchWrap.Width = 250;
            searchWrap.Padding = new Padding(0, 19, 16, 19);
            searchWrap.BackColor = Theme.Card;
            quarSearch = new TextBox();
            quarSearch.Dock = DockStyle.Fill;
            quarSearch.BorderStyle = BorderStyle.FixedSingle;
            quarSearch.BackColor = Theme.LogBg;
            quarSearch.ForeColor = Theme.Text;
            quarSearch.Font = new Font("Segoe UI", 10f);
            quarSearch.TextChanged += delegate { ApplyQuarFilter(); };
            quarSearch.HandleCreated += delegate { SetQuarSearchCue(); };
            searchWrap.Controls.Add(quarSearch);
            quarStrip.Controls.Add(searchWrap);

            cardQuar = new CardPanel(Lang.T("card.quarantine"));
            cardQuar.Dock = DockStyle.Fill;
            cardQuar.Margin = new Padding(6);

            quarList = MakeList();
            quarList.HeaderStyle = ColumnHeaderStyle.Clickable; // click a header to sort
            quarList.Columns.Add(Lang.T("col.file"), 180);
            quarList.Columns.Add(Lang.T("col.threat"), 170);
            quarList.Columns.Add(Lang.T("col.origin"), 230);
            quarList.Columns.Add(Lang.T("col.size"), 80);
            quarList.Columns.Add(Lang.T("col.when"), 125);
            quarList.ColumnClick += OnQuarColumnClick;
            quarList.Resize += delegate { StretchQuarColumns(); };
            quarList.DoubleClick += delegate { ShowQuarProperties(); };
            quarList.SelectedIndexChanged += delegate
            {
                if (quarList.SelectedItems.Count > 0)
                    statusLabel.Text = string.Format(Lang.T("status.selected"), quarList.SelectedItems.Count);
            };

            quarEmpty = new EmptyState();
            quarEmpty.Dock = DockStyle.Fill;
            quarEmpty.Title = Lang.T("quarantine.emptyTitle");
            quarEmpty.Sub = Lang.T("quarantine.emptySub");
            quarEmpty.Visible = false;

            // Right-click menu mirrors the buttons and adds Properties
            quarMenu = new ContextMenuStrip();
            quarMenu.Renderer = new ToolStripProfessionalRenderer(new DarkMenuColors());
            quarMenu.ForeColor = Theme.Text;
            quarMenuRestore = new ToolStripMenuItem();
            quarMenuRestore.Click += delegate { RestoreSelectedQuarantine(false); };
            quarMenuRestoreExcl = new ToolStripMenuItem();
            quarMenuRestoreExcl.Click += delegate { RestoreSelectedQuarantine(true); };
            quarMenuDelete = new ToolStripMenuItem();
            quarMenuDelete.Click += delegate { DeleteSelectedQuarantine(); };
            quarMenuOpen = new ToolStripMenuItem();
            quarMenuOpen.Click += delegate { OpenQuarOriginFolder(); };
            quarMenuProps = new ToolStripMenuItem();
            quarMenuProps.Click += delegate { ShowQuarProperties(); };
            quarMenu.Items.AddRange(new ToolStripItem[]
            {
                quarMenuRestore, quarMenuRestoreExcl, new ToolStripSeparator(),
                quarMenuOpen, quarMenuProps, new ToolStripSeparator(), quarMenuDelete
            });
            quarMenu.Opening += delegate(object s, System.ComponentModel.CancelEventArgs e)
            {
                if (quarList.SelectedItems.Count == 0) e.Cancel = true;
            };
            quarList.ContextMenuStrip = quarMenu;

            var buttons = new FlowLayoutPanel();
            buttons.Dock = DockStyle.Bottom;
            buttons.FlowDirection = FlowDirection.LeftToRight;
            buttons.Height = 50;
            buttons.Padding = new Padding(8);
            buttons.BackColor = Theme.Card;

            btnQuarRestore = MakeButton(Lang.T("btn.restore"), 130, Theme.Accent, Theme.AccentHot, Ico.Restore);
            btnQuarToExcl = MakeButton(Lang.T("btn.restoreExclude"), 225, Theme.Card, Theme.Bg, Ico.Ban);
            btnQuarDelete = MakeButton(Lang.T("btn.deleteForever"), 120, Theme.Danger, Theme.DangerHot, Ico.Trash);
            btnQuarOpenFolder = MakeButton(Lang.T("btn.openFolder"), 150, Theme.Card, Theme.Bg, Ico.FolderIcon);

            btnQuarRestore.Click += delegate { RestoreSelectedQuarantine(false); };
            btnQuarToExcl.Click += delegate { RestoreSelectedQuarantine(true); };
            btnQuarDelete.Click += delegate { DeleteSelectedQuarantine(); };
            btnQuarOpenFolder.Click += delegate { Process.Start("explorer.exe", "\"" + quarDir + "\""); };

            buttons.Controls.AddRange(new Control[] { btnQuarRestore, btnQuarToExcl, btnQuarDelete, btnQuarOpenFolder });

            cardQuar.Controls.Add(quarList);
            cardQuar.Controls.Add(quarEmpty);
            cardQuar.Controls.Add(buttons);

            page.Controls.Add(cardQuar);
            page.Controls.Add(quarStrip);
            return page;
        }

        void SetQuarSearchCue()
        {
            try
            {
                NativeMethods.SendMessage(quarSearch.Handle, NativeMethods.EM_SETCUEBANNER,
                    (IntPtr)1, Lang.T("quarantine.searchCue"));
            }
            catch { }
        }

        void OnQuarColumnClick(object sender, ColumnClickEventArgs e)
        {
            if (quarSortCol == e.Column) quarSortAsc = !quarSortAsc;
            else { quarSortCol = e.Column; quarSortAsc = e.Column < 3; } // size/date: biggest/newest first
            ApplyQuarFilter();
        }

        void UpdateQuarHeaders()
        {
            string[] keys = { "col.file", "col.threat", "col.origin", "col.size", "col.when" };
            for (int i = 0; i < quarList.Columns.Count; i++)
                quarList.Columns[i].Text = Lang.T(keys[i])
                    + (i == quarSortCol ? (quarSortAsc ? "  ▲" : "  ▼") : "");
            StretchQuarColumns();
        }

        // Widens the Origin column so the columns fill the list and no unpainted
        // (white) header slab shows to the right of the last column
        void StretchQuarColumns()
        {
            if (quarList == null || quarList.Columns.Count < 5) return;
            int other = quarList.Columns[0].Width + quarList.Columns[1].Width
                + quarList.Columns[3].Width + quarList.Columns[4].Width;
            int w = quarList.ClientSize.Width - other - 2;
            if (w > 120) quarList.Columns[2].Width = w;
        }

        int CompareQuarRows(QuarRow a, QuarRow b)
        {
            int c;
            switch (quarSortCol)
            {
                case 0: c = string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); break;
                case 1: c = string.Compare(a.Threat, b.Threat, StringComparison.OrdinalIgnoreCase); break;
                case 2: c = string.Compare(a.Origin, b.Origin, StringComparison.OrdinalIgnoreCase); break;
                case 3: c = a.Size.CompareTo(b.Size); break;
                default: c = a.When.CompareTo(b.When); break;
            }
            return quarSortAsc ? c : -c;
        }

        // Fills the ListView from quarRows honoring the search text and sort order
        void ApplyQuarFilter()
        {
            if (quarList == null) return;
            string q = quarSearch != null ? quarSearch.Text.Trim() : "";
            var rows = new List<QuarRow>();
            foreach (QuarRow r in quarRows)
            {
                if (q.Length > 0
                    && r.Name.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0
                    && r.Origin.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0
                    && r.Threat.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0) continue;
                rows.Add(r);
            }
            rows.Sort(CompareQuarRows);
            quarList.BeginUpdate();
            quarList.Items.Clear();
            foreach (QuarRow r in rows)
            {
                var item = new ListViewItem(new string[]
                {
                    r.Name,
                    r.Threat.Length > 0 ? r.Threat : "—",
                    r.Origin.Length > 0 ? r.Origin : Lang.T("quarantine.unknownOrigin"),
                    FormatSize(r.Size),
                    r.WhenText
                });
                item.Tag = r;
                if (r.Threat.Length > 0)
                {
                    item.UseItemStyleForSubItems = false;
                    item.SubItems[1].ForeColor = Theme.Danger;
                }
                quarList.Items.Add(item);
            }
            quarList.EndUpdate();
            bool empty = quarRows.Count == 0;
            quarEmpty.Visible = empty;
            quarList.Visible = !empty;
            UpdateQuarHeaders();
        }

        void OpenQuarOriginFolder()
        {
            if (quarList.SelectedItems.Count == 0) return;
            var row = (QuarRow)quarList.SelectedItems[0].Tag;
            string dir = null;
            try { if (row.Origin.Length > 0) dir = Path.GetDirectoryName(row.Origin); } catch { }
            if (dir != null && Directory.Exists(dir)) Process.Start("explorer.exe", "\"" + dir + "\"");
            else statusLabel.Text = Lang.T("quarantine.unknownOrigin");
        }

        // Properties dialog: origin, threat, source, date, size, SHA256 (+ copy)
        void ShowQuarProperties()
        {
            if (quarList.SelectedItems.Count == 0) return;
            var row = (QuarRow)quarList.SelectedItems[0].Tag;
            string hash;
            try
            {
                Cursor = Cursors.WaitCursor;
                hash = Sha256OfQuarFile(row.Path);
            }
            catch (Exception ex) { hash = ex.Message; }
            finally { Cursor = Cursors.Default; }

            using (var dlg = new Form())
            {
                dlg.Text = Lang.T("prop.title");
                dlg.Size = new Size(680, 350);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.MinimizeBox = dlg.MaximizeBox = false;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.BackColor = Theme.Bg;
                dlg.ForeColor = Theme.Text;
                dlg.Font = Font;
                Theme.DarkTitleBar(dlg);

                var grid = new TableLayoutPanel();
                grid.Dock = DockStyle.Fill;
                grid.Padding = new Padding(16, 12, 16, 0);
                grid.ColumnCount = 2;
                grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
                grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

                Action<string, string, Color> addRow = delegate(string caption, string value, Color valueColor)
                {
                    var cap = new Label();
                    cap.Text = caption;
                    cap.ForeColor = Theme.Muted;
                    cap.AutoSize = true;
                    cap.Margin = new Padding(0, 6, 8, 6);
                    // read-only borderless TextBox so long values can be selected and copied
                    var val = new TextBox();
                    val.Text = value;
                    val.ReadOnly = true;
                    val.BorderStyle = BorderStyle.None;
                    val.BackColor = Theme.Bg;
                    val.ForeColor = valueColor;
                    val.Dock = DockStyle.Fill;
                    val.Margin = new Padding(0, 6, 0, 6);
                    grid.Controls.Add(cap);
                    grid.Controls.Add(val);
                };
                addRow(Lang.T("prop.file"), row.Name, Theme.Text);
                addRow(Lang.T("prop.threat"), row.Threat.Length > 0 ? row.Threat : "—",
                    row.Threat.Length > 0 ? Theme.Danger : Theme.Text);
                addRow(Lang.T("prop.origin"), row.Origin.Length > 0 ? row.Origin : Lang.T("quarantine.unknownOrigin"), Theme.Text);
                addRow(Lang.T("prop.source"), row.Reason.Length > 0 ? row.Reason : "—", Theme.Text);
                addRow(Lang.T("prop.when"), row.WhenText.Length > 0 ? row.WhenText : "—", Theme.Text);
                addRow(Lang.T("prop.size"), FormatSize(row.Size), Theme.Text);
                addRow("SHA256", hash, Theme.Text);

                var buttons = new FlowLayoutPanel();
                buttons.Dock = DockStyle.Bottom;
                buttons.FlowDirection = FlowDirection.RightToLeft;
                buttons.Height = 52;
                buttons.Padding = new Padding(10);
                buttons.BackColor = Theme.Bg;
                var close = MakeButton(Lang.T("btn.close"), 100, Theme.Card, Theme.Bg, Ico.Close);
                close.DialogResult = DialogResult.Cancel;
                var copy = MakeButton(Lang.T("btn.copyHash"), 170, Theme.Accent, Theme.AccentHot);
                copy.Click += delegate
                {
                    try { Clipboard.SetText(hash); statusLabel.Text = Lang.T("status.hashCopied"); }
                    catch { }
                };
                // opens the public VT page for this hash in the browser — no API key needed
                var vt = MakeButton("VIRUSTOTAL", 150, Theme.Card, Theme.Bg, Ico.Radar);
                vt.Enabled = hash.Length == 64;
                vt.Click += delegate { VtOpenInBrowser(hash); };
                buttons.Controls.Add(close);
                buttons.Controls.Add(copy);
                buttons.Controls.Add(vt);

                dlg.Controls.Add(grid);
                dlg.Controls.Add(buttons);
                dlg.CancelButton = close;
                dlg.ShowDialog(this);
            }
        }

        void ReloadQuarantineList()
        {
            if (quarList == null || quarDir == null) return;
            try { if (!Directory.Exists(quarDir)) Directory.CreateDirectory(quarDir); }
            catch { return; }
            NeutralizeQuarantineFolder(); // pick up legacy/raw files before listing
            quarRows.Clear();
            var map = ReadQuarIndex(quarIndex);
            long totalSize = 0;
            DateTime lastDet = DateTime.MinValue;
            foreach (string f in Directory.GetFiles(quarDir))
            {
                string name = Path.GetFileName(f);
                if (string.Equals(name, "index.txt", StringComparison.OrdinalIgnoreCase)) continue;
                var row = new QuarRow();
                row.Path = f;
                // the list shows the original file name; the .quar suffix is an on-disk detail
                row.Name = name.EndsWith(QuarExt, StringComparison.OrdinalIgnoreCase)
                    ? name.Substring(0, name.Length - QuarExt.Length) : name;
                row.Threat = row.Origin = row.Reason = row.WhenText = "";
                string[] meta;
                if (map.TryGetValue(name, out meta))
                {
                    row.Origin = meta[1];
                    row.WhenText = meta[2];
                    row.Threat = meta[3];
                    row.Reason = meta[4];
                }
                DateTime when;
                if (DateTime.TryParseExact(row.WhenText, "yyyy-MM-dd HH:mm", null,
                    System.Globalization.DateTimeStyles.None, out when)) row.When = when;
                try { row.Size = new FileInfo(f).Length; } catch { }
                totalSize += row.Size;
                if (row.When > lastDet) lastDet = row.When;
                quarRows.Add(row);
            }
            quarStrip.Captions = new string[]
            {
                Lang.T("stat.quarFiles"), Lang.T("stat.totalSize"), Lang.T("stat.lastDetection")
            };
            quarStrip.Values = new string[]
            {
                quarRows.Count.ToString(),
                quarRows.Count > 0 ? FormatSize(totalSize) : "—",
                lastDet > DateTime.MinValue ? lastDet.ToString("dd.MM.yyyy HH:mm") : "—"
            };
            quarStrip.ValueColors = new Color[]
            {
                quarRows.Count > 0 ? Theme.Warn : Color.Empty, Color.Empty, Color.Empty
            };
            quarStrip.Invalidate();
            ApplyQuarFilter();
            UpdateStatsUi();
        }

        void RestoreSelectedQuarantine(bool excludeToo)
        {
            if (quarList.SelectedItems.Count == 0) return;
            if (MessageBox.Show(this,
                Lang.T("msg.restoreConfirm"),
                Lang.T("quarantine.title"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            foreach (ListViewItem it in quarList.SelectedItems)
            {
                var row = (QuarRow)it.Tag;
                if (row.Origin.Length == 0)
                {
                    MessageBox.Show(this, string.Format(Lang.T("msg.unknownOriginPath"), row.Name), Lang.T("quarantine.title"));
                    continue;
                }
                try
                {
                    if (File.Exists(row.Origin))
                    {
                        MessageBox.Show(this, string.Format(Lang.T("msg.fileExists"), row.Origin), Lang.T("quarantine.title"));
                        continue;
                    }
                    // the original folder may have been deleted or renamed since
                    // quarantining — recreate it so the restore doesn't dead-end
                    EnsureParentDir(row.Origin);
                    if (row.Path.EndsWith(QuarExt, StringComparison.OrdinalIgnoreCase))
                    {
                        // neutralized file: XOR back into the original bytes at the origin path
                        XorCopy(row.Path, row.Origin);
                        File.Delete(row.Path);
                    }
                    else
                        File.Move(row.Path, row.Origin); // raw legacy file — plain move
                    RemoveQuarIndexEntry(quarIndex, Path.GetFileName(row.Path));
                    if (excludeToo) AddExclusion(row.Origin);
                }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, Lang.T("title.error")); }
            }
            if (excludeToo) SaveSettings();
            ReloadQuarantineList();
        }

        void DeleteSelectedQuarantine()
        {
            if (quarList.SelectedItems.Count == 0) return;
            if (MessageBox.Show(this,
                string.Format(Lang.T("msg.deleteConfirm"), quarList.SelectedItems.Count),
                Lang.T("quarantine.title"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            foreach (ListViewItem it in quarList.SelectedItems)
            {
                var row = (QuarRow)it.Tag;
                try { File.Delete(row.Path); RemoveQuarIndexEntry(quarIndex, Path.GetFileName(row.Path)); }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, Lang.T("title.error")); }
            }
            ReloadQuarantineList();
        }

        Panel BuildSettingsPage()
        {
            var page = new Panel();
            page.Dock = DockStyle.Fill;
            page.BackColor = Theme.Bg;
            page.Padding = new Padding(6);

            cardSettingsPanel = new CardPanel(Lang.T("card.settings"));
            cardSettingsPanel.Dock = DockStyle.Fill;
            cardSettingsPanel.Margin = new Padding(6);

            chkMonitor = MakeCheck("", 20, 56);
            chkMonitor.CheckedChanged += delegate { OnMonitorToggled(); };

            btnWatchDirs = MakeLightButton(Lang.T("btn.folders"), Ico.FolderIcon);
            btnWatchDirs.BackColor = Theme.Card;
            btnWatchDirs.SetBounds(430, 50, 130, 30);

            btnWatchDirs.Click += delegate { EditWatchDirs(); };

            chkRiskyOnly = MakeCheck(Lang.T("settings.riskyOnly"), 20, 92);
            chkRiskyOnly.Checked = true;
            chkRiskyOnly.CheckedChanged += delegate { SaveSettings(); };

            chkQuarantine = MakeCheck(Lang.T("settings.autoQuarantine"), 20, 128);
            chkQuarantine.Checked = false;
            chkQuarantine.CheckedChanged += delegate { SaveSettings(); };

            chkAutoUpdate = MakeCheck(Lang.T("settings.autoUpdate"), 20, 164);
            chkAutoUpdate.Checked = true;
            chkAutoUpdate.CheckedChanged += delegate { SaveSettings(); };

            chkFullRisky = MakeCheck(Lang.T("settings.fullRisky"), 20, 200);
            chkFullRisky.Checked = true;
            chkFullRisky.CheckedChanged += delegate { SaveSettings(); };

            chkAutostart = MakeCheck(Lang.T("settings.autostart"), 20, 236);
            chkAutostart.Checked = IsAutostartEnabled();
            chkAutostart.CheckedChanged += delegate { SetAutostart(chkAutostart.Checked); };

            chkUsbPrompt = MakeCheck(Lang.T("settings.usbPrompt"), 20, 272);
            chkUsbPrompt.Checked = true;
            chkUsbPrompt.CheckedChanged += delegate { SaveSettings(); };

            // informational tray balloons; threat alerts bypass this (see Notify)
            chkNotify = MakeCheck(Lang.T("settings.notifications"), 20, 308);
            chkNotify.Checked = true;
            chkNotify.CheckedChanged += delegate { SaveSettings(); };

            // caps the per-file scan size at 200 MB (see ScanLimitsArg/WriteClamdConf)
            chkSkipBig = MakeCheck(Lang.T("settings.skipBig"), 20, 344);
            chkSkipBig.Checked = true;
            chkSkipBig.CheckedChanged += delegate { SaveSettings(); };

            langLabel = new Label();
            langLabel.Text = Lang.T("settings.language");
            langLabel.AutoSize = true;
            langLabel.ForeColor = Theme.Text;
            langLabel.BackColor = Theme.Card;
            langLabel.Location = new Point(20, 394);
            btnLangEn = MakeButton("English", 90, Theme.Btn, Theme.BtnHot);
            btnLangEn.TextColor = Theme.BtnText;
            btnLangEn.BackColor = Theme.Card;
            btnLangEn.SetBounds(180, 388, 90, 30);
            btnLangEn.Click += delegate { SetLanguage(Lang.Language.English); };
            btnLangUk = MakeButton("Українська", 110, Theme.Btn, Theme.BtnHot);
            btnLangUk.TextColor = Theme.BtnText;
            btnLangUk.BackColor = Theme.Card;
            btnLangUk.SetBounds(276, 388, 110, 30);
            btnLangUk.Click += delegate { SetLanguage(Lang.Language.Ukrainian); };
            UpdateLangButtons();

            // Scan performance selector — right column, clear of the FOLDERS… button above
            perfLabel = new Label();
            perfLabel.Text = Lang.T("settings.performance");
            perfLabel.AutoSize = true;
            perfLabel.ForeColor = Theme.Text;
            perfLabel.BackColor = Theme.Card;
            perfLabel.Location = new Point(520, 96);
            btnPerfLow = MakeButton(Lang.T("perf.low"), 90, Theme.Btn, Theme.BtnHot);
            btnPerfLow.SetBounds(520, 122, 90, 30);
            btnPerfLow.Click += delegate { SetPerfMode(0); };
            btnPerfNormal = MakeButton(Lang.T("perf.normal"), 110, Theme.Btn, Theme.BtnHot);
            btnPerfNormal.SetBounds(616, 122, 110, 30);
            btnPerfNormal.Click += delegate { SetPerfMode(1); };
            btnPerfHigh = MakeButton(Lang.T("perf.high"), 90, Theme.Btn, Theme.BtnHot);
            btnPerfHigh.SetBounds(732, 122, 90, 30);
            btnPerfHigh.Click += delegate { SetPerfMode(2); };
            foreach (ModernButton b in new ModernButton[] { btnPerfLow, btnPerfNormal, btnPerfHigh })
                b.BackColor = Theme.Card;
            perfHint = new Label();
            perfHint.Text = Lang.T("settings.perfHint");
            perfHint.AutoSize = true;
            perfHint.MaximumSize = new Size(302, 0); // wrap inside the card at the minimum window width
            perfHint.ForeColor = Theme.Muted;
            perfHint.BackColor = Theme.Card;
            perfHint.Location = new Point(520, 160);
            UpdatePerfButtons();

            // Scheduled quick scan — the same radio-style row as the perf selector
            schedLabel = new Label();
            schedLabel.Text = Lang.T("settings.schedule");
            schedLabel.AutoSize = true;
            schedLabel.ForeColor = Theme.Text;
            schedLabel.BackColor = Theme.Card;
            schedLabel.Location = new Point(520, 216);
            btnSchedOff = MakeButton(Lang.T("sched.off"), 70, Theme.Btn, Theme.BtnHot);
            btnSchedOff.SetBounds(520, 242, 70, 30);
            btnSchedOff.Click += delegate { SetSchedMode(0); };
            btnSchedDaily = MakeButton(Lang.T("sched.daily"), 100, Theme.Btn, Theme.BtnHot);
            btnSchedDaily.SetBounds(596, 242, 100, 30);
            btnSchedDaily.Click += delegate { SetSchedMode(1); };
            btnSchedWeekly = MakeButton(Lang.T("sched.weekly"), 110, Theme.Btn, Theme.BtnHot);
            btnSchedWeekly.SetBounds(702, 242, 110, 30);
            btnSchedWeekly.Click += delegate { SetSchedMode(2); };
            foreach (ModernButton b in new ModernButton[] { btnSchedOff, btnSchedDaily, btnSchedWeekly })
                b.BackColor = Theme.Card;
            UpdateSchedButtons();

            // exclusion-list editor lives here now — on the quarantine page it looked
            // like one more action applied to the selected file
            btnQuarExclusions = MakeLightButton(Lang.T("btn.exclusions"), Ico.Ban);
            btnQuarExclusions.BackColor = Theme.Card;
            btnQuarExclusions.SetBounds(520, 288, 260, 30);
            btnQuarExclusions.Click += delegate { EditExclusions(); };

            // STATUS block: engine / database / monitoring / quarantine / scheduler
            setStatusHeader = new Label();
            setStatusHeader.Text = Lang.T("settings.status").ToUpperInvariant();
            setStatusHeader.Font = new Font("Segoe UI Semibold", 8f);
            setStatusHeader.ForeColor = Theme.Muted;
            setStatusHeader.AutoSize = true;
            setStatusHeader.BackColor = Theme.Card;
            setStatusHeader.Location = new Point(520, 344);
            cardSettingsPanel.Controls.Add(setStatusHeader);
            setStatusCaps = new Label[5];
            setStatusVals = new Label[5];
            for (int i = 0; i < 5; i++)
            {
                setStatusCaps[i] = new Label();
                setStatusCaps[i].AutoSize = true;
                setStatusCaps[i].ForeColor = Theme.Muted;
                setStatusCaps[i].BackColor = Theme.Card;
                setStatusCaps[i].Location = new Point(520, 370 + i * 28);
                setStatusVals[i] = new Label();
                setStatusVals[i].AutoSize = true;
                setStatusVals[i].Font = new Font("Segoe UI Semibold", 9.5f);
                setStatusVals[i].BackColor = Theme.Card;
                setStatusVals[i].Location = new Point(660, 370 + i * 28);
                cardSettingsPanel.Controls.Add(setStatusCaps[i]);
                cardSettingsPanel.Controls.Add(setStatusVals[i]);
            }

            btnInstall = MakeLightButton(Lang.T("btn.installPF"), Ico.Download);
            btnInstall.BackColor = Theme.Card;
            btnInstall.SetBounds(20, 434, 290, 30);
            btnInstall.Visible = !IsInstalled;
            btnInstall.Click += delegate
            {
                if (MessageBox.Show(this,
                    string.Format(Lang.T("msg.installConfirm"), InstallDir),
                    AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                    LaunchInstaller();
            };

            // when already installed, a quiet green badge instead of a disabled button
            installedBadge = new Label();
            installedBadge.Text = "✓ " + Lang.T("badge.installedPF");
            installedBadge.Font = new Font("Segoe UI Semibold", 9.5f);
            installedBadge.ForeColor = Theme.Good;
            installedBadge.BackColor = Theme.Card;
            installedBadge.AutoSize = true;
            installedBadge.Location = new Point(20, 440);
            installedBadge.Visible = IsInstalled;
            cardSettingsPanel.Controls.Add(installedBadge);

            // Only relevant if C:\Windows\Temp isn't watchable yet — hidden once fixed
            // (via this button, or automatically after --install elevates and fixes it).
            btnFixWinTemp = MakeLightButton(Lang.T("btn.fixWinTemp"), Ico.Unlock);
            btnFixWinTemp.BackColor = Theme.Card;
            btnFixWinTemp.SetBounds(20, 472, 290, 30);
            btnFixWinTemp.Visible = !CanWatchDirectory(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
            btnFixWinTemp.Click += delegate { FixWinTempAccess(); };

            // About: description, quick-start steps, and project links (star / releases / follow)
            btnAbout = MakeLightButton(Lang.T("btn.about"), Ico.Info);
            btnAbout.BackColor = Theme.Card;
            btnAbout.SetBounds(20, 510, 290, 30);
            btnAbout.Click += delegate { ShowAboutDialog(); };

            // Detection engines: the YARA toggle/rules and VirusTotal key live in
            // their own dialog — the settings card has no room for another column
            btnEngines = MakeLightButton(Lang.T("btn.engines"), Ico.Radar);
            btnEngines.BackColor = Theme.Card;
            btnEngines.SetBounds(330, 510, 260, 30);
            btnEngines.Click += delegate { ShowEnginesDialog(); };

            cardSettingsPanel.Controls.Add(chkMonitor);
            cardSettingsPanel.Controls.Add(btnWatchDirs);
            cardSettingsPanel.Controls.Add(chkRiskyOnly);
            cardSettingsPanel.Controls.Add(chkQuarantine);
            cardSettingsPanel.Controls.Add(chkAutoUpdate);
            cardSettingsPanel.Controls.Add(chkFullRisky);
            cardSettingsPanel.Controls.Add(chkAutostart);
            cardSettingsPanel.Controls.Add(chkUsbPrompt);
            cardSettingsPanel.Controls.Add(chkNotify);
            cardSettingsPanel.Controls.Add(chkSkipBig);
            cardSettingsPanel.Controls.Add(langLabel);
            cardSettingsPanel.Controls.Add(btnLangEn);
            cardSettingsPanel.Controls.Add(btnLangUk);
            cardSettingsPanel.Controls.Add(perfLabel);
            cardSettingsPanel.Controls.Add(btnPerfLow);
            cardSettingsPanel.Controls.Add(btnPerfNormal);
            cardSettingsPanel.Controls.Add(btnPerfHigh);
            cardSettingsPanel.Controls.Add(perfHint);
            cardSettingsPanel.Controls.Add(schedLabel);
            cardSettingsPanel.Controls.Add(btnSchedOff);
            cardSettingsPanel.Controls.Add(btnSchedDaily);
            cardSettingsPanel.Controls.Add(btnSchedWeekly);
            cardSettingsPanel.Controls.Add(btnQuarExclusions);
            cardSettingsPanel.Controls.Add(btnInstall);
            cardSettingsPanel.Controls.Add(btnFixWinTemp);
            cardSettingsPanel.Controls.Add(btnAbout);
            cardSettingsPanel.Controls.Add(btnEngines);

            page.Controls.Add(cardSettingsPanel);
            return page;
        }

        // ---------- About dialog ----------

        const string ProjectUrl = "https://github.com/alexbeatnik/AV";
        const string AuthorUrl = "https://github.com/alexbeatnik";

        // Logo + version, a short description, quick-start steps for first-time
        // users, and project links: star the repo, releases page, follow the author.
        void ShowAboutDialog()
        {
            using (var dlg = new Form())
            {
                dlg.Text = Lang.T("about.title");
                dlg.ClientSize = new Size(600, 596);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.MinimizeBox = dlg.MaximizeBox = false;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.BackColor = Theme.Bg;
                dlg.ForeColor = Theme.Text;
                dlg.Font = Font;
                Theme.DarkTitleBar(dlg);

                var logo = new PictureBox();
                logo.Image = LogoImage;
                logo.SizeMode = PictureBoxSizeMode.Zoom;
                logo.SetBounds(24, 18, 128, 60);
                logo.BackColor = Color.Transparent;

                var name = new Label();
                name.Text = AppName;
                name.Font = new Font("Segoe UI Semibold", 16f);
                name.ForeColor = Theme.Text;
                name.AutoSize = true;
                name.Location = new Point(166, 22);

                var ver = new Label();
                ver.Text = string.Format(Lang.T("about.version"), AppVersion);
                ver.ForeColor = Theme.Muted;
                ver.AutoSize = true;
                ver.Location = new Point(169, 56);

                var desc = new Label();
                desc.Text = Lang.T("about.desc");
                desc.ForeColor = Theme.Text;
                desc.SetBounds(24, 94, dlg.ClientSize.Width - 48, 60);

                var howHeader = new Label();
                howHeader.Text = Lang.T("about.quickStart").ToUpperInvariant();
                howHeader.Font = new Font("Segoe UI Semibold", 8f);
                howHeader.ForeColor = Theme.Muted;
                howHeader.AutoSize = true;
                howHeader.Location = new Point(24, 160);

                var how = new Label();
                how.Text = Lang.T("about.howTo");
                how.ForeColor = Theme.Text;
                how.SetBounds(24, 182, dlg.ClientSize.Width - 48, 168);

                // accent-colored links in place of buttons — opens the default browser
                Func<string, string, int, LinkLabel> link = delegate(string text, string url, int y)
                {
                    var l = new LinkLabel();
                    l.Text = text;
                    l.AutoSize = true;
                    l.Location = new Point(24, y);
                    l.BackColor = Theme.Bg;
                    l.LinkColor = Theme.Accent;
                    l.ActiveLinkColor = Theme.AccentHot;
                    l.VisitedLinkColor = Theme.Accent;
                    l.LinkBehavior = LinkBehavior.HoverUnderline;
                    l.LinkClicked += delegate { try { Process.Start(url); } catch { } };
                    return l;
                };
                var star = link(Lang.T("about.star"), ProjectUrl, 358);
                var releases = link(Lang.T("about.releases"), ProjectUrl + "/releases", 386);
                var follow = link(Lang.T("about.follow"), AuthorUrl, 414);
                var license = link(Lang.T("about.license"), ProjectUrl + "/blob/main/LICENSE", 442);

                var powered = new Label();
                powered.Text = Lang.T("about.powered");
                powered.Font = new Font("Segoe UI", 8f);
                powered.ForeColor = Theme.Muted;
                powered.SetBounds(24, 482, dlg.ClientSize.Width - 48, 40);

                var buttons = new FlowLayoutPanel();
                buttons.Dock = DockStyle.Bottom;
                buttons.FlowDirection = FlowDirection.RightToLeft;
                buttons.Height = 52;
                buttons.Padding = new Padding(10);
                buttons.BackColor = Theme.Bg;
                var close = MakeButton(Lang.T("btn.close"), 100, Theme.Card, Theme.Bg, Ico.Close);
                close.DialogResult = DialogResult.Cancel;
                buttons.Controls.Add(close);

                dlg.Controls.Add(logo);
                dlg.Controls.Add(name);
                dlg.Controls.Add(ver);
                dlg.Controls.Add(desc);
                dlg.Controls.Add(howHeader);
                dlg.Controls.Add(how);
                dlg.Controls.Add(star);
                dlg.Controls.Add(releases);
                dlg.Controls.Add(follow);
                dlg.Controls.Add(license);
                dlg.Controls.Add(powered);
                dlg.Controls.Add(buttons);
                dlg.CancelButton = close;
                dlg.ShowDialog(this);
            }
        }

        void ShowPage(int idx)
        {
            for (int i = 0; i < pages.Length; i++)
            {
                pages[i].Visible = i == idx;
                navs[i].SetActive(i == idx);
            }
            if (idx == 0) { UpdateStatsUi(); RefreshHistory(); }
            if (idx == 2) { ReloadQuarantineList(); }
            if (idx == 3) { RefreshSettingsStatus(); }
        }

        // Shows just the last line of scans.log — the full history is one click
        // away via "Open Log File" (see activityRow in BuildDashboardPage).
        void RefreshHistory()
        {
            if (lastActivityLabel == null) return;
            try
            {
                string last = null;
                if (File.Exists(scanLogPath))
                {
                    string[] lines = File.ReadAllLines(scanLogPath);
                    for (int i = lines.Length - 1; i >= 0; i--)
                        if (lines[i].Trim().Length > 0) { last = lines[i]; break; }
                }
                lastActivityLabel.Text = last ?? Lang.T("history.empty");
            }
            catch { }
        }

        void SetScanEnabled(bool on)
        {
            foreach (ModernButton b in scanButtons) if (b != null) b.Enabled = on;
        }

        ModernButton MakeButton(string text, int width, Color back, Color hover, IconDraw icon = null)
        {
            var b = new ModernButton(text, back, hover, Theme.Text);
            b.Width = width;
            b.Icon = icon;
            return b;
        }

        // Light button with dark text
        ModernButton MakeLightButton(string text, IconDraw icon = null)
        {
            var b = new ModernButton(text, Theme.Btn, Theme.BtnHot, Theme.BtnText);
            b.Icon = icon;
            return b;
        }

        // Big square button with the icon centered above the label — dashboard scan actions
        ModernButton MakeCardButton(string text, Color back, Color hover, Color fore, IconDraw icon)
        {
            var b = new ModernButton(text, back, hover, fore);
            b.Icon = icon;
            b.CardStyle = true;
            b.Width = 152;
            b.Height = 104;
            b.Font = new Font("Segoe UI Semibold", 8.5f);
            return b;
        }

        Toggle MakeCheck(string text, int x, int y)
        {
            var c = new Toggle(text);
            c.Location = new Point(x, y);
            c.BackColor = Theme.Card;
            return c;
        }

        // Dark ListView with custom column headers (the system ones are white)
        static ListView MakeList()
        {
            var list = new ListView();
            list.View = View.Details;
            list.FullRowSelect = true;
            list.Dock = DockStyle.Fill;
            list.BackColor = Theme.LogBg;
            list.ForeColor = Theme.Text;
            list.BorderStyle = BorderStyle.None;
            list.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            list.OwnerDraw = true;
            list.DrawColumnHeader += delegate(object s, DrawListViewColumnHeaderEventArgs e)
            {
                using (var b = new SolidBrush(Theme.Card)) e.Graphics.FillRectangle(b, e.Bounds);
                TextRenderer.DrawText(e.Graphics, " " + e.Header.Text, ((ListView)s).Font,
                    e.Bounds, Theme.Muted, TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
            };
            list.DrawItem += delegate(object s, DrawListViewItemEventArgs e) { e.DrawDefault = true; };
            list.DrawSubItem += delegate(object s, DrawListViewSubItemEventArgs e) { e.DrawDefault = true; };
            return list;
        }

        void SetHero(ShieldState state, string title, string sub)
        {
            shield.SetState(state);
            heroTitle.Text = title;
            heroSub.Text = sub;
            switch (state)
            {
                case ShieldState.Ok: heroTitle.ForeColor = statusBanner.AccentColor = Theme.Good; break;
                case ShieldState.Danger: heroTitle.ForeColor = statusBanner.AccentColor = Theme.Danger; break;
                case ShieldState.Busy: heroTitle.ForeColor = Theme.Text; statusBanner.AccentColor = Theme.Accent; break;
                default: heroTitle.ForeColor = statusBanner.AccentColor = Theme.Warn; break;
            }
            statusBanner.Invalidate();
        }

        // ---------- Interface language ----------

        void SetLanguage(Lang.Language lang)
        {
            if (Lang.Current == lang) return;
            Lang.Current = lang;
            ApplyLanguage();
            SaveSettings();
        }

        void UpdateLangButtons()
        {
            bool en = Lang.Current == Lang.Language.English;
            btnLangEn.Back = en ? Theme.Accent : Theme.Btn;
            btnLangEn.Hover = en ? Theme.AccentHot : Theme.BtnHot;
            btnLangEn.TextColor = en ? Theme.Text : Theme.BtnText;
            btnLangEn.Invalidate();
            btnLangUk.Back = !en ? Theme.Accent : Theme.Btn;
            btnLangUk.Hover = !en ? Theme.AccentHot : Theme.BtnHot;
            btnLangUk.TextColor = !en ? Theme.Text : Theme.BtnText;
            btnLangUk.Invalidate();
        }

        // ---------- Scan performance selector ----------

        void SetPerfMode(int mode)
        {
            if (perfMode == mode) return;
            perfMode = mode;
            UpdatePerfButtons();
            SaveSettings();
        }

        void UpdatePerfButtons()
        {
            var btns = new ModernButton[] { btnPerfLow, btnPerfNormal, btnPerfHigh };
            string[] keys = { "perf.low", "perf.normal", "perf.high" };
            for (int i = 0; i < btns.Length; i++)
            {
                bool on = perfMode == i;
                // radio-style ●/○ marker makes the active mode obvious at a glance
                btns[i].Text = (on ? "● " : "○ ") + Lang.T(keys[i]);
                btns[i].Back = on ? Theme.Accent : Theme.Btn;
                btns[i].Hover = on ? Theme.AccentHot : Theme.BtnHot;
                btns[i].TextColor = on ? Theme.Text : Theme.BtnText;
                btns[i].Invalidate();
            }
        }

        // ---------- Scheduled quick scan selector ----------

        void SetSchedMode(int mode)
        {
            if (schedMode == mode) return;
            schedMode = mode;
            UpdateSchedButtons();
            SaveSettings();
            statusLabel.Text = Lang.T(mode == 0 ? "status.schedOff"
                : mode == 1 ? "status.schedDaily" : "status.schedWeekly");
        }

        void UpdateSchedButtons()
        {
            var btns = new ModernButton[] { btnSchedOff, btnSchedDaily, btnSchedWeekly };
            string[] keys = { "sched.off", "sched.daily", "sched.weekly" };
            for (int i = 0; i < btns.Length; i++)
            {
                bool on = schedMode == i;
                btns[i].Text = (on ? "● " : "○ ") + Lang.T(keys[i]);
                btns[i].Back = on ? Theme.Accent : Theme.Btn;
                btns[i].Hover = on ? Theme.AccentHot : Theme.BtnHot;
                btns[i].TextColor = on ? Theme.Text : Theme.BtnText;
                btns[i].Invalidate();
            }
        }

        // Refreshes the STATUS block on the settings page (engine / db / monitor / quarantine / scheduler)
        void RefreshSettingsStatus()
        {
            if (setStatusVals == null) return;
            setStatusCaps[0].Text = Lang.T("sstat.engine");
            setStatusCaps[1].Text = Lang.T("sstat.database");
            setStatusCaps[2].Text = Lang.T("sstat.monitoring");
            setStatusCaps[3].Text = Lang.T("sstat.quarantine");
            setStatusCaps[4].Text = Lang.T("sstat.schedule");

            bool engine = clamDir != null;
            setStatusVals[0].Text = engine
                ? (clamVersion != "—" ? "ClamAV " + clamVersion : Lang.T("sval.ready"))
                : Lang.T("sval.notFound");
            setStatusVals[0].ForeColor = engine ? Theme.Good : Theme.Danger;

            bool db = DbExists();
            setStatusVals[1].Text = db ? DbDateString() : "—";
            setStatusVals[1].ForeColor = db && !DbIsStale(DbNewestTime(), DateTime.Now) ? Theme.Good : Theme.Warn;

            bool mon = chkMonitor.Checked;
            setStatusVals[2].Text = mon
                ? Lang.T("sval.enabled") + " (" + watchDirs.Count + ")"
                : Lang.T("sval.disabled");
            setStatusVals[2].ForeColor = mon ? Theme.Good : Theme.Muted;

            int q = QuarantineCount();
            setStatusVals[3].Text = string.Format(Lang.T("sval.filesN"), q);
            setStatusVals[3].ForeColor = q > 0 ? Theme.Warn : Theme.Text;

            setStatusVals[4].Text = Lang.T(schedMode == 0 ? "sval.disabled"
                : schedMode == 1 ? "sched.daily" : "sched.weekly");
            setStatusVals[4].ForeColor = schedMode != 0 ? Theme.Good : Theme.Muted;
        }

        // Re-applies text to every persistent control after a language switch.
        // Dialogs and message boxes need no such handling: they're built fresh
        // each time they're opened and simply pick up the current language.
        void ApplyLanguage()
        {
            navs[0].Text = Lang.T("nav.dashboard");
            navs[1].Text = Lang.T("nav.logs");
            navs[2].Text = Lang.T("nav.quarantine");
            navs[3].Text = Lang.T("nav.settings");

            if (cardQuar != null) { cardQuar.HeaderText = Lang.T("card.quarantine"); cardQuar.Invalidate(); }
            if (cardScan != null) { cardScan.HeaderText = Lang.T("card.scanning"); cardScan.Invalidate(); }
            cardSettingsPanel.HeaderText = Lang.T("card.settings"); cardSettingsPanel.Invalidate();

            dashQuick.Text = Lang.T("btn.quickScan");
            dashScanFile.Text = Lang.T("btn.scanFileDash");
            dashScanFile.SubText = Lang.T("btn.scanFileSub");
            dashScanFolder.Text = Lang.T("btn.scanFolderDash");
            dashScanFolder.SubText = Lang.T("btn.scanFolderSub");
            dashScanAll.Text = Lang.T("btn.scanAll");
            dashScanAll.SubText = Lang.T("btn.scanAllSub");
            dashScanRam.Text = Lang.T("btn.scanRam");
            dashScanRam.SubText = Lang.T("btn.scanRamSub");
            btnUpdate.Text = Lang.T("btn.updateDb");
            btnScanLog.Text = Lang.T("btn.openLog");
            if (btnQuarExclusions != null) btnQuarExclusions.Text = Lang.T("btn.exclusions");
            if (btnQuarDelete != null) btnQuarDelete.Text = Lang.T("btn.deleteForever");
            if (btnQuarRestore != null) btnQuarRestore.Text = Lang.T("btn.restore");
            if (btnQuarToExcl != null) btnQuarToExcl.Text = Lang.T("btn.restoreExclude");
            if (btnQuarOpenFolder != null) btnQuarOpenFolder.Text = Lang.T("btn.openFolder");
            if (quarList != null)
            {
                UpdateQuarHeaders();
                quarMenuRestore.Text = Lang.T("btn.restore");
                // "&&": a menu item treats a single "&" as a mnemonic marker
                quarMenuRestoreExcl.Text = Lang.T("btn.restoreExclude").Replace("&", "&&");
                quarMenuDelete.Text = Lang.T("menu.deleteForever");
                quarMenuOpen.Text = Lang.T("menu.openOrigin");
                quarMenuProps.Text = Lang.T("menu.properties");
                quarEmpty.Title = Lang.T("quarantine.emptyTitle");
                quarEmpty.Sub = Lang.T("quarantine.emptySub");
                quarEmpty.Invalidate();
                if (quarSearch.IsHandleCreated) SetQuarSearchCue();
                if (pages != null && pages[2] != null && pages[2].Visible) ReloadQuarantineList();
            }
            btnStop.Text = Lang.T("btn.stop");
            dashStop.Text = Lang.T("btn.stop");
            btnClearLog.Text = Lang.T("btn.clearLog");
            chkLogDetails.Text = Lang.T("log.showDetails");
            btnWatchDirs.Text = Lang.T("btn.folders");

            chkRiskyOnly.Text = Lang.T("settings.riskyOnly");
            chkQuarantine.Text = Lang.T("settings.autoQuarantine");
            chkAutoUpdate.Text = Lang.T("settings.autoUpdate");
            chkFullRisky.Text = Lang.T("settings.fullRisky");
            chkAutostart.Text = Lang.T("settings.autostart");
            chkUsbPrompt.Text = Lang.T("settings.usbPrompt");
            chkNotify.Text = Lang.T("settings.notifications");
            chkSkipBig.Text = Lang.T("settings.skipBig");
            UpdateMonitorLabel();
            langLabel.Text = Lang.T("settings.language");
            UpdateLangButtons();
            perfLabel.Text = Lang.T("settings.performance");
            perfHint.Text = Lang.T("settings.perfHint");
            UpdatePerfButtons(); // re-applies the localized ●/○ labels
            schedLabel.Text = Lang.T("settings.schedule");
            UpdateSchedButtons();
            setStatusHeader.Text = Lang.T("settings.status").ToUpperInvariant();
            RefreshSettingsStatus();
            btnInstall.Text = Lang.T("btn.installPF");
            installedBadge.Text = "✓ " + Lang.T("badge.installedPF");
            btnFixWinTemp.Text = Lang.T("btn.fixWinTemp");
            btnAbout.Text = Lang.T("btn.about");
            btnEngines.Text = Lang.T("btn.engines");
            btnGetYara.Text = Lang.T("btn.getYara");
            btnEnterVtKey.Text = Lang.T("btn.enterVtKey");

            trayOpenItem.Text = Lang.T("tray.open");
            trayExitItem.Text = Lang.T("tray.exit");

            RefreshDbStatus();
            UpdateStatsUi();
            RefreshHistory();
        }

        // A second instance of the app sent a broadcast — bring this window forward
        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WmShow && WmShow != 0) RestoreFromTray();
            if (m.Msg == WM_DEVICECHANGE) HandleDeviceChange(ref m); // USB drive plugged in
            base.WndProc(ref m);
        }

        // Informational tray balloon, gated by the notifications toggle. Threat
        // alerts don't go through here — they call tray.ShowBalloonTip directly
        // and are always shown.
        void Notify(int ms, string text, ToolTipIcon icon)
        {
            if (chkNotify != null && !chkNotify.Checked) return;
            tray.ShowBalloonTip(ms, AppName, text, icon);
        }

        void RestoreFromTray()
        {
            ShowInTaskbar = true;
            WindowState = FormWindowState.Normal;
            Activate();
        }

        void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            if (!reallyClose && e.CloseReason == CloseReason.UserClosing)
            {
                // The close button minimizes to tray; actual exit is via the tray menu
                e.Cancel = true;
                WindowState = FormWindowState.Minimized;
                ShowInTaskbar = false;
                return;
            }
            StopWatchers();
            StopCurrent();
            KillClamdNow(); // synchronous: the async StopClamd worker wouldn't survive process exit
            CleanupMemDumps(); // remove any RAM dumps from an in-flight scan
            tray.Visible = false;
        }

    }
}
