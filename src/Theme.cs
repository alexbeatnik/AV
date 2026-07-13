// Dark theme palette, rounded-corner helpers, Win32 interop for the dark title bar.
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
    static class NativeMethods
    {
        public const int HWND_BROADCAST = 0xffff;
        [DllImport("user32.dll")]
        public static extern int RegisterWindowMessage(string message);
        [DllImport("user32.dll")]
        public static extern bool PostMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
        // EM_SETCUEBANNER: gray placeholder text inside an empty TextBox
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);
        public const int EM_SETCUEBANNER = 0x1501;
        // A modal dialog owned by the window disables it at the Win32 level —
        // the reliable "is some dialog open?" probe (Form.Modal etc. don't see
        // MessageBox), used to postpone timer-triggered work like scheduled scans
        [DllImport("user32.dll")]
        public static extern bool IsWindowEnabled(IntPtr hWnd);
    }

    // Dark theme palette — deep navy-tinted surfaces + vivid accents, the look
    // commercial AV dashboards (Bitdefender/Norton-class) use on dark themes
    static class Theme
    {
        public static readonly Color Bg        = Color.FromArgb(16, 18, 24);    // window background
        public static readonly Color Card      = Color.FromArgb(30, 33, 42);    // cards
        public static readonly Color CardLine  = Color.FromArgb(48, 52, 64);    // thin card border
        public static readonly Color LogBg     = Color.FromArgb(12, 13, 18);    // log/list background
        public static readonly Color Text      = Color.FromArgb(232, 234, 240);
        public static readonly Color Muted     = Color.FromArgb(148, 155, 170);
        public static readonly Color Accent    = Color.FromArgb(66, 133, 255);  // blue
        public static readonly Color AccentHot = Color.FromArgb(108, 160, 255);
        public static readonly Color Good      = Color.FromArgb(48, 199, 110);  // green shield
        public static readonly Color Warn      = Color.FromArgb(232, 197, 71);  // yellow (values)
        public static readonly Color Danger    = Color.FromArgb(239, 68, 68);
        public static readonly Color DangerHot = Color.FromArgb(248, 113, 113);
        public static readonly Color Disabled  = Color.FromArgb(92, 97, 108); // clearly gray, not just faded
        public static readonly Color Btn       = Color.FromArgb(216, 219, 226); // light buttons
        public static readonly Color BtnHot    = Color.FromArgb(233, 235, 240);
        public static readonly Color BtnText   = Color.FromArgb(51, 54, 62);
        public const int Radius = 12; // card corner radius

        public static GraphicsPath Round(RectangleF r, float rad)
        {
            var p = new GraphicsPath();
            float d = rad * 2;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        // Elevated card surface: soft drop shadow under the panel, fill, hairline
        // border, and a 1px top highlight — reads as depth on a dark background.
        // Draws within the control's own bounds (w × h), leaving room for the shadow.
        public static void PaintCard(Graphics g, int w, int h)
        {
            var r = new RectangleF(1.5f, 0.5f, w - 4, h - 6);
            for (int i = 1; i <= 4; i++)
                using (var path = Round(new RectangleF(r.X, r.Y + i, r.Width, r.Height), Radius))
                using (var b = new SolidBrush(Color.FromArgb(13, 0, 0, 0)))
                    g.FillPath(b, path);
            using (var path = Round(r, Radius))
            {
                using (var b = new SolidBrush(Card)) g.FillPath(b, path);
                using (var pen = new Pen(CardLine)) g.DrawPath(pen, path);
            }
            using (var hl = new Pen(Color.FromArgb(16, 255, 255, 255)))
                g.DrawLine(hl, r.X + Radius, r.Y + 1, r.Right - Radius, r.Y + 1);
        }

        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        // Dark window title bar (Win10 1903+); without it the frame stays white
        public static void DarkTitleBar(Form f)
        {
            EventHandler apply = delegate
            {
                try
                {
                    int on = 1;
                    if (DwmSetWindowAttribute(f.Handle, 20, ref on, 4) != 0)
                        DwmSetWindowAttribute(f.Handle, 19, ref on, 4); // older Win10 builds
                }
                catch { }
            };
            if (f.IsHandleCreated) apply(null, EventArgs.Empty);
            else f.HandleCreated += apply;
        }
    }
}
