// Temporarily pausing protection (the classic AV "disable for N hours"):
// the tray menu offers 1 / 2 / 5 hours or until the app restarts. A pause
// stops the background protection layers — new-file monitoring, the scheduled
// quick scan, and USB-arrival prompts — while manual scans and database
// updates keep working. The state is deliberately NOT persisted: any app
// restart (including a PC reboot) restores full protection, which is also
// what makes the "until restart" option work.
using System;
using System.Windows.Forms;

namespace AVUI
{
    public partial class MainForm : Form
    {
        // MinValue = protection active; MaxValue = paused until the app restarts;
        // anything else = paused until that moment (auto-resumed by pauseTimer)
        DateTime protectionPauseUntil = DateTime.MinValue;
        Timer pauseTimer; // fires once at the pause deadline to auto-resume
        ToolStripMenuItem trayPauseItem, trayPause1h, trayPause2h, trayPause5h, trayPauseRestart, trayResumeItem;

        // Pure rule (unit-tested): is a pause with this deadline active at `now`?
        internal static bool ProtectionPauseActive(DateTime until, DateTime now)
        {
            if (until == DateTime.MinValue) return false;
            if (until == DateTime.MaxValue) return true; // until restart
            return now < until;
        }

        bool ProtectionPaused
        {
            get { return ProtectionPauseActive(protectionPauseUntil, DateTime.Now); }
        }

        // "until 18:45" / "until restart" — shared by the log, status bar and hero
        string PauseDescription()
        {
            return protectionPauseUntil == DateTime.MaxValue
                ? Lang.T("pause.untilRestartText")
                : string.Format(Lang.T("pause.untilTime"), protectionPauseUntil.ToString("HH:mm"));
        }

        // The tray items live between OPEN and EXIT; texts come via ApplyLanguage
        void BuildPauseMenu(ContextMenuStrip menu)
        {
            trayPause1h = new ToolStripMenuItem();
            trayPause1h.Click += delegate { PauseProtection(1); };
            trayPause2h = new ToolStripMenuItem();
            trayPause2h.Click += delegate { PauseProtection(2); };
            trayPause5h = new ToolStripMenuItem();
            trayPause5h.Click += delegate { PauseProtection(5); };
            trayPauseRestart = new ToolStripMenuItem();
            trayPauseRestart.Click += delegate { PauseProtection(0); };
            trayPauseItem = new ToolStripMenuItem();
            trayPauseItem.DropDownItems.AddRange(new ToolStripItem[]
                { trayPause1h, trayPause2h, trayPause5h, trayPauseRestart });
            // a submenu is its own drop-down — it does not inherit the parent
            // menu's dark renderer, so it gets the same one explicitly
            trayPauseItem.DropDown.Renderer = new ToolStripProfessionalRenderer(new DarkMenuColors());
            trayPauseItem.DropDown.ForeColor = Theme.Text;
            trayResumeItem = new ToolStripMenuItem();
            trayResumeItem.Visible = false; // shown only while a pause is active
            trayResumeItem.Click += delegate { ResumeProtection(false); };
            menu.Items.Add(trayPauseItem);
            menu.Items.Add(trayResumeItem);
        }

        void ApplyPauseLanguage()
        {
            trayPauseItem.Text = Lang.T("tray.pauseMenu");
            trayPause1h.Text = Lang.T("pause.for1h");
            trayPause2h.Text = Lang.T("pause.for2h");
            trayPause5h.Text = Lang.T("pause.for5h");
            trayPauseRestart.Text = Lang.T("pause.untilRestart");
            trayResumeItem.Text = Lang.T("tray.resumeProtection");
        }

        // hours <= 0 = until the app restarts. Re-pausing while already paused
        // simply replaces the deadline.
        void PauseProtection(int hours)
        {
            protectionPauseUntil = hours <= 0 ? DateTime.MaxValue : DateTime.Now.AddHours(hours);
            StopWatchers(); // also clears the pending-files queue and stops the debounce
            if (pauseTimer == null)
            {
                pauseTimer = new Timer();
                pauseTimer.Tick += delegate { OnPauseTimerTick(); };
            }
            pauseTimer.Stop();
            if (protectionPauseUntil != DateTime.MaxValue)
            {
                RearmPauseTimer();
                pauseTimer.Start();
            }
            trayResumeItem.Visible = true;
            string desc = PauseDescription();
            AppendLog(string.Format(Lang.T("log.protectionPaused"), desc), Theme.Warn, "WARN", false);
            statusLabel.Text = string.Format(Lang.T("msg.protectionPaused"), desc);
            Notify(4000, string.Format(Lang.T("msg.protectionPaused"), desc), ToolTipIcon.Warning);
            // a running scan owns the hero — the paused state shows once it ends
            if (!scan.Running && !updateRunning) RefreshDbStatus();
            RefreshSettingsStatus();
        }

        // auto = the deadline passed on its own (vs the user clicking RESUME)
        void ResumeProtection(bool auto)
        {
            if (pauseTimer != null) pauseTimer.Stop();
            if (protectionPauseUntil == DateTime.MinValue) return; // not paused
            protectionPauseUntil = DateTime.MinValue;
            if (chkMonitor.Checked) StartWatchers();
            trayResumeItem.Visible = false;
            AppendLog(Lang.T("log.protectionResumed"), Theme.Good);
            statusLabel.Text = Lang.T("msg.protectionResumed");
            if (auto) Notify(4000, Lang.T("msg.protectionResumed"), ToolTipIcon.Info);
            if (!scan.Running && !updateRunning) RefreshDbStatus(); // hero returns to the real state
            RefreshSettingsStatus();
        }

        // WinForms timers don't run during sleep and fire late after waking, so
        // the tick re-checks the deadline instead of trusting the interval.
        void OnPauseTimerTick()
        {
            if (ProtectionPaused) { RearmPauseTimer(); return; } // woke early — wait out the remainder
            pauseTimer.Stop();
            ResumeProtection(true);
        }

        void RearmPauseTimer()
        {
            double ms = (protectionPauseUntil - DateTime.Now).TotalMilliseconds + 500;
            if (ms < 1000) ms = 1000;
            if (ms > int.MaxValue) ms = int.MaxValue;
            pauseTimer.Interval = (int)ms; // setting Interval restarts the countdown
        }
    }
}
