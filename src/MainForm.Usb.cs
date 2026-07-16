// USB drive detection: WM_DEVICECHANGE volume arrival → offer to scan the new drive.
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
        // Volume arrival broadcasts (drive letter mounts) are delivered to every
        // top-level window automatically — no RegisterDeviceNotification needed.
        internal const int WM_DEVICECHANGE = 0x0219;
        const int DBT_DEVICEARRIVAL = 0x8000;
        const int DBT_DEVTYP_VOLUME = 0x0002;

        // Called from WndProc. Reads the DEV_BROADCAST_VOLUME payload: devicetype at
        // offset 4 of the header, then the drive-letter bitmask at offset 12.
        void HandleDeviceChange(ref Message m)
        {
            if (m.WParam.ToInt64() != DBT_DEVICEARRIVAL || m.LParam == IntPtr.Zero) return;
            int unitmask;
            try
            {
                if (Marshal.ReadInt32(m.LParam, 4) != DBT_DEVTYP_VOLUME) return;
                unitmask = Marshal.ReadInt32(m.LParam, 12);
            }
            catch { return; }
            foreach (string root in DriveRootsFromMask(unitmask))
            {
                // BeginInvoke: the prompt is modal — never block WndProc with it
                try { BeginInvoke((Action<string>)OfferUsbScan, root); } catch { }
            }
        }

        // Bit 0 = A:, bit 1 = B:, … — one bit per mounted drive letter
        internal static List<string> DriveRootsFromMask(int unitmask)
        {
            var roots = new List<string>();
            for (int i = 0; i < 26; i++)
                if ((unitmask & (1 << i)) != 0) roots.Add((char)('A' + i) + ":\\");
            return roots;
        }

        void OfferUsbScan(string root)
        {
            if (chkUsbPrompt == null || !chkUsbPrompt.Checked) return;
            if (ProtectionPaused) return; // the user asked for quiet — no prompts either
            if (clamDir == null || !DbExists()) return; // nothing to scan with yet
            try
            {
                var d = new DriveInfo(root);
                // only removable media (flash drives, card readers) — mounting a
                // fixed/network volume shouldn't nag the user
                if (d.DriveType != DriveType.Removable || !d.IsReady) return;
            }
            catch { return; }
            if (scan.Running || updateRunning)
            {
                Notify(6000, string.Format(Lang.T("tray.usbBusy"), root), ToolTipIcon.Info);
                return;
            }
            // Invisible topmost owner: the prompt must surface above other windows
            // even while the app sits minimized in the tray.
            bool yes;
            using (var top = new Form())
            {
                top.TopMost = true;
                top.ShowInTaskbar = false;
                top.FormBorderStyle = FormBorderStyle.None;
                top.StartPosition = FormStartPosition.CenterScreen;
                top.Size = new Size(1, 1);
                top.Opacity = 0;
                top.Show();
                yes = MessageBox.Show(top, string.Format(Lang.T("usb.scanPrompt"), root),
                    Lang.T("usb.title"), MessageBoxButtons.YesNo, MessageBoxIcon.Question)
                    == DialogResult.Yes;
            }
            if (!yes) return;
            RestoreFromTray(); // show the dashboard so the scan progress is visible
            RunClamscan(root);
        }
    }
}
