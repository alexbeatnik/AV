// Custom-drawn controls: buttons, toggle, shield, nav tabs, cards, progress bar.
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
    class ModernButton : Control, IButtonControl
    {
        public Color Back, Hover, TextColor;
        public IconDraw Icon;   // optional glyph; null = text-only button
        public bool CardStyle;  // icon centered above the text, for the big dashboard actions
        public string SubText;  // muted one-line caption under the label (card-style tiles only)
        bool over, down;
        DialogResult dialogResult = DialogResult.None;

        public ModernButton(string text, Color back, Color hover, Color fore)
        {
            Text = text;
            Back = back; Hover = hover; TextColor = fore;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Height = 36;
            Width = 150;
            Font = new Font("Segoe UI Semibold", 9f);
            Cursor = Cursors.Hand;
            Margin = new Padding(0, 4, 8, 4);
            MouseEnter += delegate { over = true; Invalidate(); };
            MouseLeave += delegate { over = false; down = false; Invalidate(); };
            MouseDown += delegate { down = true; Invalidate(); };
            MouseUp += delegate { down = false; Invalidate(); };
        }

        public DialogResult DialogResult
        {
            get { return dialogResult; }
            set { dialogResult = value; }
        }
        public void NotifyDefault(bool value) { }
        public void PerformClick() { if (Enabled) OnClick(EventArgs.Empty); }

        protected override void OnClick(EventArgs e)
        {
            var f = FindForm();
            if (dialogResult != DialogResult.None && f != null && f.Modal) f.DialogResult = dialogResult;
            base.OnClick(e);
        }

        protected override void OnEnabledChanged(EventArgs e) { base.OnEnabledChanged(e); Invalidate(); }
        protected override void OnTextChanged(EventArgs e) { base.OnTextChanged(e); Invalidate(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(BackColor); // background behind the rounded corners (card color when on a card)
            // disabled = dark surface with muted text (not a bright gray slab)
            Color c = !Enabled ? Color.FromArgb(36, 39, 48) : (down ? Back : (over ? Hover : Back));
            using (var path = Theme.Round(new RectangleF(0.5f, 0.5f, Width - 1, Height - 1), CardStyle ? 14 : 9))
            using (var b = new SolidBrush(c))
            {
                g.FillPath(b, path);
                // hairline border gives card-style tiles (and disabled buttons) definition
                if (CardStyle || !Enabled)
                    using (var pen = new Pen(over && Enabled ? Theme.Accent : Theme.CardLine))
                        g.DrawPath(pen, path);
            }

            Color fg = Enabled ? TextColor : Theme.Muted;
            // NoPrefix: button labels may contain a literal "&" ("Restore & exclude")
            const TextFormatFlags NoPre = TextFormatFlags.NoPrefix;
            if (Icon == null)
            {
                TextRenderer.DrawText(g, Text, Font, ClientRectangle, fg,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | NoPre);
                return;
            }
            if (CardStyle)
            {
                // icon scales with the tile so big dashboard tiles get big glyphs
                float iconSize = Math.Min(Width * 0.30f, Height * 0.36f);
                var iconRect = new RectangleF((Width - iconSize) / 2f, Height * 0.16f, iconSize, iconSize);
                Icon(g, iconRect, fg);
                int textTop = (int)(iconRect.Bottom + 10);
                if (string.IsNullOrEmpty(SubText))
                {
                    var textRect = new Rectangle(4, textTop, Width - 8, Height - textTop - 6);
                    TextRenderer.DrawText(g, Text, Font, textRect, fg,
                        TextFormatFlags.HorizontalCenter | TextFormatFlags.Top | TextFormatFlags.WordBreak | NoPre);
                }
                else
                {
                    // label on one line + a muted caption below (dashboard action tiles)
                    TextRenderer.DrawText(g, Text, Font, new Rectangle(4, textTop - 2, Width - 8, 17), fg,
                        TextFormatFlags.HorizontalCenter | TextFormatFlags.Top | TextFormatFlags.EndEllipsis | NoPre);
                    using (var sf = new Font("Segoe UI", 7.75f))
                        TextRenderer.DrawText(g, SubText, sf, new Rectangle(4, textTop + 16, Width - 8, 15),
                            Enabled ? Theme.Muted : Color.FromArgb(100, 106, 120),
                            TextFormatFlags.HorizontalCenter | TextFormatFlags.Top | TextFormatFlags.EndEllipsis | NoPre);
                }
            }
            else
            {
                const int iconBox = 16, gap = 7;
                Size textSize = TextRenderer.MeasureText(Text, Font);
                int totalW = iconBox + gap + textSize.Width;
                int startX = Math.Max(6, (Width - totalW) / 2);
                var iconRect = new RectangleF(startX, (Height - iconBox) / 2f, iconBox, iconBox);
                Icon(g, iconRect, fg);
                var textRect = new Rectangle(startX + iconBox + gap, 0, Width - (startX + iconBox + gap) - 4, Height);
                TextRenderer.DrawText(g, Text, Font, textRect, fg,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | NoPre);
            }
        }
    }

    // Animated toggle switch, used instead of the system CheckBox
    class Toggle : Control
    {
        public event EventHandler CheckedChanged;
        bool isOn;
        float knob; // 0..1 — animated knob position
        readonly Timer anim = new Timer();

        public Toggle(string text)
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Height = 26;
            Cursor = Cursors.Hand;
            Text = text;
            anim.Interval = 15;
            anim.Tick += delegate
            {
                float target = isOn ? 1f : 0f;
                knob += (target - knob) * 0.35f;
                if (Math.Abs(target - knob) < 0.03f) { knob = target; anim.Stop(); }
                Invalidate();
            };
            Click += delegate { Checked = !Checked; };
        }

        public bool Checked
        {
            get { return isOn; }
            set
            {
                if (isOn == value) return;
                isOn = value;
                if (IsHandleCreated && Visible) anim.Start();
                else { knob = isOn ? 1f : 0f; Invalidate(); }
                if (CheckedChanged != null) CheckedChanged(this, EventArgs.Empty);
            }
        }

        void FitWidth()
        {
            Width = 64 + TextRenderer.MeasureText(Text, Font).Width;
            Invalidate();
        }

        protected override void OnTextChanged(EventArgs e) { base.OnTextChanged(e); FitWidth(); }
        // the form's font arrives after the constructor runs — re-measure width then
        protected override void OnFontChanged(EventArgs e) { base.OnFontChanged(e); FitWidth(); }
        protected override void OnParentChanged(EventArgs e) { base.OnParentChanged(e); FitWidth(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(BackColor);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            const int tw = 40, th = 20; // track
            int ty = (Height - th) / 2;
            Color track = isOn ? Theme.Accent : Color.FromArgb(75, 80, 92);
            using (var path = Theme.Round(new RectangleF(0, ty, tw, th), th / 2f))
            using (var b = new SolidBrush(track))
                g.FillPath(b, path);
            float kx = 3 + knob * (tw - th); // ranges 3..23
            using (var b = new SolidBrush(Color.White))
                g.FillEllipse(b, kx, ty + 3, th - 6, th - 6);
            TextRenderer.DrawText(g, Text, Font, new Rectangle(tw + 10, 0, Width - tw - 10, Height),
                Theme.Text, TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
        }
    }

    // Dark colors for the tray context menu (the system default is stark white)
    class DarkMenuColors : ProfessionalColorTable
    {
        public override Color ToolStripDropDownBackground { get { return Theme.LogBg; } }
        public override Color ImageMarginGradientBegin { get { return Theme.LogBg; } }
        public override Color ImageMarginGradientMiddle { get { return Theme.LogBg; } }
        public override Color ImageMarginGradientEnd { get { return Theme.LogBg; } }
        public override Color MenuItemSelected { get { return Theme.Card; } }
        public override Color MenuItemBorder { get { return Theme.Card; } }
        public override Color MenuBorder { get { return Theme.CardLine; } }
    }

    enum ShieldState { Ok, Warning, Danger, Busy }

    // Large filled shield icon, drawn with anti-aliasing
    class ShieldIndicator : Control
    {
        public ShieldState State = ShieldState.Warning;
        float progress = -1f; // 0..1 while a scan runs; -1 = unknown (three dots)

        public ShieldIndicator()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                | ControlStyles.OptimizedDoubleBuffer, true);
            Size = new Size(96, 96);
        }

        public void SetState(ShieldState s) { State = s; progress = -1f; Invalidate(); }

        // The busy shield doubles as a progress readout: once the scan knows its
        // total, the percent replaces the three dots (see UpdateScanProgress)
        public void SetProgress(double f)
        {
            float v = (float)Math.Max(0, Math.Min(1, f));
            if (Math.Abs(v - progress) < 0.005f) return; // skip sub-half-percent repaints
            progress = v;
            Invalidate();
        }

        static GraphicsPath ShieldPath(float w, float h)
        {
            var p = new GraphicsPath();
            p.AddBezier(w * .50f, h * .04f, w * .68f, h * .10f, w * .80f, h * .12f, w * .88f, h * .12f);
            p.AddLine(w * .88f, h * .12f, w * .88f, h * .48f);
            p.AddBezier(w * .88f, h * .48f, w * .88f, h * .72f, w * .68f, h * .88f, w * .50f, h * .96f);
            p.AddBezier(w * .50f, h * .96f, w * .32f, h * .88f, w * .12f, h * .72f, w * .12f, h * .48f);
            p.AddLine(w * .12f, h * .48f, w * .12f, h * .12f);
            p.AddBezier(w * .12f, h * .12f, w * .20f, h * .12f, w * .32f, h * .10f, w * .50f, h * .04f);
            p.CloseFigure();
            return p;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            Color c;
            switch (State)
            {
                case ShieldState.Ok: c = Theme.Good; break;
                case ShieldState.Danger: c = Theme.Danger; break;
                case ShieldState.Busy: c = Theme.Accent; break;
                default: c = Theme.Warn; break;
            }

            float w = Width, h = Height;

            // Soft radial glow in the state color behind the shield — the "status
            // lighting" look commercial AV dashboards use around their hero icon
            using (var gp = new GraphicsPath())
            {
                gp.AddEllipse(0, 0, w, h);
                using (var pgb = new PathGradientBrush(gp))
                {
                    pgb.CenterColor = Color.FromArgb(55, c);
                    pgb.SurroundColors = new Color[] { Color.FromArgb(0, c) };
                    g.FillPath(pgb, gp);
                }
            }
            // inset the shield so the glow has room around it; the transform keeps
            // all the glyph coordinates below in the original 0..w/0..h space
            const float inset = 0.10f;
            g.TranslateTransform(w * inset, h * inset);
            g.ScaleTransform(1 - inset * 2, 1 - inset * 2);

            using (var path = ShieldPath(w, h))
            {
                using (var b = new SolidBrush(c)) g.FillPath(b, path);
                using (var pen = new Pen(Color.FromArgb(70, Color.Black), 2f)) g.DrawPath(pen, path);
            }

            using (var pen = new Pen(Color.White, w * 0.08f))
            {
                pen.StartCap = LineCap.Round;
                pen.EndCap = LineCap.Round;
                if (State == ShieldState.Ok)
                {
                    g.DrawLine(pen, w * .32f, h * .50f, w * .45f, h * .63f);
                    g.DrawLine(pen, w * .45f, h * .63f, w * .68f, h * .36f);
                }
                else if (State == ShieldState.Busy)
                {
                    if (progress >= 0f)
                    {
                        // scan progress percent; "100%" gets a slightly smaller face to fit
                        string txt = ((int)Math.Round(progress * 100)) + "%";
                        using (var f = new Font("Segoe UI Semibold", h * (txt.Length > 3 ? 0.155f : 0.19f), GraphicsUnit.Pixel))
                        using (var sf = new StringFormat())
                        using (var b = new SolidBrush(Color.White))
                        {
                            sf.Alignment = StringAlignment.Center;
                            sf.LineAlignment = StringAlignment.Center;
                            g.DrawString(txt, f, b, new RectangleF(0, h * 0.28f, w, h * 0.40f), sf);
                        }
                    }
                    else using (var b = new SolidBrush(Color.White))
                    {
                        float r = w * 0.045f;
                        g.FillEllipse(b, w * .32f - r, h * .48f - r, r * 2, r * 2);
                        g.FillEllipse(b, w * .50f - r, h * .48f - r, r * 2, r * 2);
                        g.FillEllipse(b, w * .68f - r, h * .48f - r, r * 2, r * 2);
                    }
                }
                else
                {
                    g.DrawLine(pen, w * .50f, h * .28f, w * .50f, h * .55f);
                    using (var b = new SolidBrush(Color.White))
                    {
                        float r = w * 0.05f;
                        g.FillEllipse(b, w * .50f - r, h * .66f - r, r * 2, r * 2);
                    }
                }
            }
        }
    }

    // Horizontal top-bar nav tab: icon + label, active state = filled accent pill.
    // Deliberately not a left icon rail (that shape reads as a clone of the reference
    // Synology-style AV UIs this project used to imitate) — top tabs with text instead.
    class NavTab : Control
    {
        public IconDraw Icon;
        public bool Active;
        bool hover;

        public NavTab(string text, IconDraw icon)
        {
            Text = text;
            Icon = icon;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            Font = new Font("Segoe UI Semibold", 9.5f);
            Height = 44;
            Cursor = Cursors.Hand;
            Margin = new Padding(2, 0, 2, 0);
            MouseEnter += delegate { hover = true; Invalidate(); };
            MouseLeave += delegate { hover = false; Invalidate(); };
        }

        public void SetActive(bool a) { Active = a; Invalidate(); }

        void FitWidth() { Width = 46 + TextRenderer.MeasureText(Text, Font).Width; }
        protected override void OnTextChanged(EventArgs e) { base.OnTextChanged(e); FitWidth(); }
        protected override void OnFontChanged(EventArgs e) { base.OnFontChanged(e); FitWidth(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Theme.Bg);
            // active tab = filled accent pill (the current commercial-dashboard idiom);
            // hover on inactive tabs = soft white pill
            var pill = new RectangleF(1, 6, Width - 2, Height - 14);
            if (Active)
                using (var path = Theme.Round(pill, pill.Height / 2f))
                using (var b = new SolidBrush(Color.FromArgb(34, Theme.Accent)))
                    g.FillPath(b, path);
            else if (hover)
                using (var path = Theme.Round(pill, pill.Height / 2f))
                using (var b = new SolidBrush(Color.FromArgb(13, 255, 255, 255)))
                    g.FillPath(b, path);
            Color c = Active ? Theme.AccentHot : (hover ? Theme.Text : Theme.Muted);
            var iconRect = new RectangleF(15, (Height - 8 - 18) / 2f, 18, 18);
            if (Icon != null) Icon(g, iconRect, c);
            var textRect = new Rectangle((int)iconRect.Right + 8, 0, Width - (int)iconRect.Right - 16, Height - 8);
            TextRenderer.DrawText(g, Text, Font, textRect, c, TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
        }
    }

    // Wide, short status banner (protection state) — deliberately NOT another square
    // card in a 3-across grid, which is the part of the old layout that read as a
    // direct copy of the reference AV UIs. A colored left bar reflects the state.
    class StatusBanner : Panel
    {
        public Color AccentColor = Theme.Good;

        public StatusBanner()
        {
            BackColor = Theme.Bg;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Theme.PaintCard(g, Width, Height);
            // slim status accent — a wider bar reads as a stuck progress bar
            using (var b = new SolidBrush(AccentColor))
            using (var path = Theme.Round(new RectangleF(1, Height * 0.22f, 3, Height * 0.56f), 1.5f))
                g.FillPath(b, path);
        }
    }

    // Compact one-row statistics strip: small muted captions with the value below
    // each, laid out left to right — replaces the old tall SYSTEM card that ate
    // half the dashboard for a handful of numbers.
    class StatStrip : Panel
    {
        public string[] Captions = new string[0];
        public string[] Values = new string[0];
        public Color[] ValueColors; // optional per-value override (Color.Empty = default text)

        public StatStrip()
        {
            BackColor = Theme.Bg;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Theme.PaintCard(g, Width, Height);
            using (var capF = new Font("Segoe UI Semibold", 8f))
            using (var valF = new Font("Segoe UI Semibold", 13.5f)) // values carry the row — keep them prominent
            {
                float x = 20;
                for (int i = 0; i < Captions.Length; i++)
                {
                    string cap = Captions[i].ToUpperInvariant();
                    string val = i < Values.Length ? Values[i] : "";
                    int cell = Math.Max(TextRenderer.MeasureText(g, cap, capF).Width,
                                        TextRenderer.MeasureText(g, val, valF).Width);
                    TextRenderer.DrawText(g, cap, capF, new Rectangle((int)x, 11, cell + 4, 15),
                        Theme.Muted, TextFormatFlags.Left | TextFormatFlags.NoPadding);
                    Color vc = ValueColors != null && i < ValueColors.Length && !ValueColors[i].IsEmpty
                        ? ValueColors[i] : Theme.Text;
                    TextRenderer.DrawText(g, val, valF, new Rectangle((int)x, 28, cell + 4, 28),
                        vc, TextFormatFlags.Left | TextFormatFlags.NoPadding);
                    x += cell + 28;
                }
            }
        }
    }

    // Friendly placeholder shown instead of an empty list (shield glyph + two lines)
    class EmptyState : Control
    {
        public string Title = "", Sub = "";

        public EmptyState()
        {
            BackColor = Theme.LogBg;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(BackColor);
            float cx = Width / 2f, cy = Height / 2f;
            Ico.ShieldIcon(g, new RectangleF(cx - 26, cy - 78, 52, 52), Color.FromArgb(70, 76, 92));
            using (var tf = new Font("Segoe UI Semibold", 12f))
                TextRenderer.DrawText(g, Title, tf, new Rectangle(0, (int)cy - 12, Width, 30),
                    Theme.Text, TextFormatFlags.HorizontalCenter | TextFormatFlags.Top);
            TextRenderer.DrawText(g, Sub, Font, new Rectangle(0, (int)cy + 20, Width, 24),
                Theme.Muted, TextFormatFlags.HorizontalCenter | TextFormatFlags.Top);
        }
    }

    // Card with rounded corners, a thin border, and an UPPERCASE header
    class CardPanel : Panel
    {
        public string HeaderText = "";

        public CardPanel(string header)
        {
            HeaderText = header;
            BackColor = Theme.Bg; // corners show the page background through them
            Padding = new Padding(16, 44, 16, 14);
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Theme.PaintCard(g, Width, Height);
            using (var f = new Font("Segoe UI Semibold", 9.5f))
            using (var b = new SolidBrush(Theme.Muted))
                g.DrawString(HeaderText.ToUpperInvariant(), f, b, 16, 15);
        }
    }

    // Thin progress bar: marquee (while the total is unknown) or a real percentage
    class SlimMarquee : Control
    {
        readonly Timer timer = new Timer();
        float pos;
        double fraction = -1; // -1 = indeterminate mode (marquee)

        public SlimMarquee()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                | ControlStyles.OptimizedDoubleBuffer, true);
            Height = 3;
            timer.Interval = 16;
            timer.Tick += delegate { pos = (pos + 0.012f) % 1.3f; Invalidate(); };
            Visible = false;
        }

        public void Start() { fraction = -1; Visible = true; timer.Start(); }
        public void Stop() { timer.Stop(); Visible = false; fraction = -1; }

        public void SetFraction(double f)
        {
            fraction = Math.Max(0, Math.Min(1, f));
            timer.Stop();
            if (!Visible) Visible = true;
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.Clear(Theme.Bg);
            using (var b = new SolidBrush(Theme.Accent))
            {
                if (fraction >= 0)
                {
                    e.Graphics.FillRectangle(b, 0, 0, (int)(Width * fraction), Height);
                }
                else
                {
                    int w = (int)(Width * 0.3f);
                    int x = (int)(Width * pos) - w;
                    e.Graphics.FillRectangle(b, x, 0, w, Height);
                }
            }
        }
    }
}
