// Vector glyphs drawn with GDI+ strokes — buttons carry icons without image assets.
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
    // Rounded button with hover/pressed states instead of the system Button.
    // Implements IButtonControl so it can act as AcceptButton/CancelButton.
    delegate void IconDraw(Graphics g, RectangleF r, Color c);

    // Small vector glyphs drawn with GDI+ strokes (same technique as ShieldIndicator/
    // NavIcon) so buttons can carry an icon without shipping any image assets.
    static class Ico
    {
        static Pen P(Color c, RectangleF r, float thicknessFactor)
        {
            var pen = new Pen(c, Math.Max(1.3f, Math.Min(r.Width, r.Height) * thicknessFactor));
            pen.StartCap = pen.EndCap = LineCap.Round;
            pen.LineJoin = LineJoin.Round;
            return pen;
        }

        // Concentric sweep — quick/full scan
        public static void Radar(Graphics g, RectangleF r, Color c)
        {
            float cx = r.X + r.Width / 2f, cy = r.Y + r.Height / 2f, rad = Math.Min(r.Width, r.Height) / 2f;
            using (var pen = P(c, r, 0.11f))
            {
                g.DrawEllipse(pen, cx - rad, cy - rad, rad * 2, rad * 2);
                g.DrawEllipse(pen, cx - rad * 0.58f, cy - rad * 0.58f, rad * 1.16f, rad * 1.16f);
                g.DrawLine(pen, cx, cy, cx + rad * 0.82f, cy - rad * 0.48f);
            }
            using (var b = new SolidBrush(c))
                g.FillEllipse(b, cx - rad * 0.13f, cy - rad * 0.13f, rad * 0.26f, rad * 0.26f);
        }

        // Document/page — scan a single file
        public static void FileIcon(Graphics g, RectangleF r, Color c)
        {
            float w = r.Width, h = r.Height, fold = w * 0.3f;
            using (var p = new GraphicsPath())
            {
                p.AddLine(r.X + w * 0.2f, r.Y, r.X + w - fold, r.Y);
                p.AddLine(r.X + w - fold, r.Y, r.X + w * 0.82f, r.Y + fold * 0.75f);
                p.AddLine(r.X + w * 0.82f, r.Y + fold * 0.75f, r.X + w * 0.82f, r.Y + h);
                p.AddLine(r.X + w * 0.82f, r.Y + h, r.X + w * 0.2f, r.Y + h);
                p.CloseFigure();
                using (var pen = P(c, r, 0.1f)) g.DrawPath(pen, p);
            }
        }

        // Folder — scan a folder / pick a directory
        public static void FolderIcon(Graphics g, RectangleF r, Color c)
        {
            float w = r.Width, h = r.Height;
            using (var p = new GraphicsPath())
            {
                p.AddLine(r.X, r.Y + h * 0.16f, r.X + w * 0.4f, r.Y + h * 0.16f);
                p.AddLine(r.X + w * 0.4f, r.Y + h * 0.16f, r.X + w * 0.5f, r.Y + h * 0.32f);
                p.AddLine(r.X + w * 0.5f, r.Y + h * 0.32f, r.X + w, r.Y + h * 0.32f);
                p.AddLine(r.X + w, r.Y + h * 0.32f, r.X + w, r.Y + h * 0.92f);
                p.AddLine(r.X + w, r.Y + h * 0.92f, r.X, r.Y + h * 0.92f);
                p.CloseFigure();
                using (var pen = P(c, r, 0.11f)) g.DrawPath(pen, p);
            }
        }

        // Stacked drives — full-PC / system scan
        public static void Stack(Graphics g, RectangleF r, Color c)
        {
            float w = r.Width, h = r.Height, bh = h * 0.24f, gap = h * 0.12f;
            using (var pen = P(c, r, 0.09f))
            {
                for (int i = 0; i < 3; i++)
                {
                    float y = r.Y + i * (bh + gap);
                    using (var path = Theme.Round(new RectangleF(r.X, y, w, bh), bh * 0.28f))
                        g.DrawPath(pen, path);
                }
            }
            using (var b = new SolidBrush(c))
                for (int i = 0; i < 3; i++)
                {
                    float y = r.Y + i * (bh + gap);
                    g.FillEllipse(b, r.X + w * 0.1f, y + bh / 2f - w * 0.045f, w * 0.09f, w * 0.09f);
                }
        }

        // Memory chip with pins — RAM / process-memory scan
        public static void Memory(Graphics g, RectangleF r, Color c)
        {
            float w = r.Width, h = r.Height, inset = Math.Min(w, h) * 0.22f;
            var body = new RectangleF(r.X + inset, r.Y + inset, w - inset * 2, h - inset * 2);
            using (var pen = P(c, r, 0.09f))
            {
                using (var path = Theme.Round(body, body.Width * 0.14f)) g.DrawPath(pen, path);
                var die = new RectangleF(body.X + body.Width * 0.28f, body.Y + body.Height * 0.28f,
                    body.Width * 0.44f, body.Height * 0.44f);
                using (var path = Theme.Round(die, die.Width * 0.18f)) g.DrawPath(pen, path);
                for (int i = 0; i < 3; i++) // three pins per side
                {
                    float t = 0.32f + i * 0.18f, px = r.X + w * t, py = r.Y + h * t;
                    g.DrawLine(pen, px, r.Y, px, body.Y);            // top
                    g.DrawLine(pen, px, body.Bottom, px, r.Y + h);   // bottom
                    g.DrawLine(pen, r.X, py, body.X, py);            // left
                    g.DrawLine(pen, body.Right, py, r.X + w, py);    // right
                }
            }
        }

        // Circular refresh arrow — update database
        public static void Refresh(Graphics g, RectangleF r, Color c)
        {
            float cx = r.X + r.Width / 2f, cy = r.Y + r.Height / 2f, rad = Math.Min(r.Width, r.Height) / 2f * 0.82f;
            using (var pen = P(c, r, 0.12f))
                g.DrawArc(pen, cx - rad, cy - rad, rad * 2, rad * 2, -30, 300);
            using (var b = new SolidBrush(c))
            {
                float ax = cx + rad * (float)Math.Cos(-30 * Math.PI / 180), ay = cy + rad * (float)Math.Sin(-30 * Math.PI / 180);
                var tri = new PointF[] {
                    new PointF(ax, ay - rad * 0.42f), new PointF(ax + rad * 0.48f, ay), new PointF(ax - rad * 0.05f, ay + rad * 0.3f)
                };
                g.FillPolygon(b, tri);
            }
        }

        // Outline shield — quarantine
        public static void ShieldIcon(Graphics g, RectangleF r, Color c)
        {
            float w = r.Width, h = r.Height;
            using (var p = new GraphicsPath())
            {
                p.AddBezier(r.X + w * .50f, r.Y, r.X + w * .70f, r.Y + h * .08f, r.X + w * .85f, r.Y + h * .10f, r.X + w * .95f, r.Y + h * .10f);
                p.AddLine(r.X + w * .95f, r.Y + h * .10f, r.X + w * .95f, r.Y + h * .48f);
                p.AddBezier(r.X + w * .95f, r.Y + h * .48f, r.X + w * .95f, r.Y + h * .74f, r.X + w * .70f, r.Y + h * .90f, r.X + w * .50f, r.Y + h);
                p.AddBezier(r.X + w * .50f, r.Y + h, r.X + w * .30f, r.Y + h * .90f, r.X + w * .05f, r.Y + h * .74f, r.X + w * .05f, r.Y + h * .48f);
                p.AddLine(r.X + w * .05f, r.Y + h * .48f, r.X + w * .05f, r.Y + h * .10f);
                p.AddBezier(r.X + w * .05f, r.Y + h * .10f, r.X + w * .15f, r.Y + h * .10f, r.X + w * .30f, r.Y + h * .08f, r.X + w * .50f, r.Y);
                p.CloseFigure();
                using (var pen = P(c, r, 0.09f)) g.DrawPath(pen, p);
            }
        }

        // Radiation symbol — quarantine tab
        public static void Radiation(Graphics g, RectangleF r, Color c)
        {
            float cx = r.X + r.Width / 2f, cy = r.Y + r.Height / 2f;
            float rOuter = Math.Min(r.Width, r.Height) / 2f * 0.9f;
            float rInner = rOuter * 0.28f;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var b = new SolidBrush(c))
            {
                for (int i = 0; i < 3; i++)
                {
                    float startAngle = -30f + i * 120f;
                    using (var gp = new GraphicsPath())
                    {
                        gp.AddArc(cx - rOuter, cy - rOuter, rOuter * 2, rOuter * 2, startAngle, 60);
                        gp.AddLine(cx + rOuter * (float)Math.Cos((startAngle + 60) * Math.PI / 180),
                                   cy + rOuter * (float)Math.Sin((startAngle + 60) * Math.PI / 180),
                                   cx + rInner * (float)Math.Cos((startAngle + 60) * Math.PI / 180),
                                   cy + rInner * (float)Math.Sin((startAngle + 60) * Math.PI / 180));
                        gp.AddArc(cx - rInner, cy - rInner, rInner * 2, rInner * 2, startAngle + 60, -60);
                        gp.CloseFigure();
                        g.FillPath(b, gp);
                    }
                }
                g.FillEllipse(b, cx - rInner * 0.7f, cy - rInner * 0.7f, rInner * 1.4f, rInner * 1.4f);
            }
        }

        // No-entry circle — exclusions
        public static void Ban(Graphics g, RectangleF r, Color c)
        {
            float cx = r.X + r.Width / 2f, cy = r.Y + r.Height / 2f, rad = Math.Min(r.Width, r.Height) / 2f * 0.86f;
            using (var pen = P(c, r, 0.1f))
            {
                g.DrawEllipse(pen, cx - rad, cy - rad, rad * 2, rad * 2);
                float d = rad * 0.68f;
                g.DrawLine(pen, cx - d, cy - d, cx + d, cy + d);
            }
        }

        // Lines on a page — log file
        public static void LogIcon(Graphics g, RectangleF r, Color c)
        {
            using (var pen = P(c, r, 0.09f))
            using (var path = Theme.Round(new RectangleF(r.X, r.Y, r.Width, r.Height), r.Width * 0.14f))
                g.DrawPath(pen, path);
            using (var pen = P(c, r, 0.08f))
                for (int i = 0; i < 3; i++)
                {
                    float y = r.Y + r.Height * (0.3f + i * 0.22f);
                    g.DrawLine(pen, r.X + r.Width * 0.2f, y, r.X + r.Width * 0.8f, y);
                }
        }

        // Filled square — stop a running scan
        public static void StopIcon(Graphics g, RectangleF r, Color c)
        {
            float m = Math.Min(r.Width, r.Height) * 0.2f;
            using (var b = new SolidBrush(c))
            using (var path = Theme.Round(new RectangleF(r.X + m, r.Y + m, r.Width - m * 2, r.Height - m * 2), 2))
                g.FillPath(b, path);
        }

        // Trash can — permanent delete
        public static void Trash(Graphics g, RectangleF r, Color c)
        {
            float w = r.Width, h = r.Height;
            using (var pen = P(c, r, 0.1f))
            {
                g.DrawLine(pen, r.X + w * 0.18f, r.Y + h * 0.28f, r.X + w * 0.82f, r.Y + h * 0.28f);
                g.DrawLine(pen, r.X + w * 0.36f, r.Y + h * 0.28f, r.X + w * 0.4f, r.Y + h * 0.12f);
                g.DrawLine(pen, r.X + w * 0.4f, r.Y + h * 0.12f, r.X + w * 0.6f, r.Y + h * 0.12f);
                g.DrawLine(pen, r.X + w * 0.6f, r.Y + h * 0.12f, r.X + w * 0.64f, r.Y + h * 0.28f);
                using (var path = Theme.Round(new RectangleF(r.X + w * 0.24f, r.Y + h * 0.28f, w * 0.52f, h * 0.62f), w * 0.06f))
                    g.DrawPath(pen, path);
            }
        }

        // Curved undo arrow — restore from quarantine
        public static void Restore(Graphics g, RectangleF r, Color c)
        {
            float cx = r.X + r.Width / 2f, cy = r.Y + r.Height / 2f, rad = Math.Min(r.Width, r.Height) / 2f * 0.82f;
            using (var pen = P(c, r, 0.11f))
            {
                g.DrawArc(pen, cx - rad, cy - rad, rad * 2, rad * 2, 130, 260);
                double ang = 130 * Math.PI / 180;
                float ax = cx + rad * (float)Math.Cos(ang), ay = cy + rad * (float)Math.Sin(ang);
                g.DrawLine(pen, ax, ay, ax + rad * 0.5f, ay - rad * 0.1f);
                g.DrawLine(pen, ax, ay, ax + rad * 0.15f, ay + rad * 0.45f);
            }
        }

        // Downward arrow into a tray — install
        public static void Download(Graphics g, RectangleF r, Color c)
        {
            float w = r.Width, h = r.Height, cx = r.X + w / 2f;
            using (var pen = P(c, r, 0.1f))
            {
                g.DrawLine(pen, cx, r.Y, cx, r.Y + h * 0.62f);
                g.DrawLine(pen, cx, r.Y + h * 0.62f, cx - w * 0.22f, r.Y + h * 0.4f);
                g.DrawLine(pen, cx, r.Y + h * 0.62f, cx + w * 0.22f, r.Y + h * 0.4f);
                g.DrawLine(pen, r.X, r.Y + h * 0.86f, r.X + w, r.Y + h * 0.86f);
            }
        }

        // X mark — close/cancel
        public static void Close(Graphics g, RectangleF r, Color c)
        {
            using (var pen = P(c, r, 0.12f))
            {
                float m = Math.Min(r.Width, r.Height) * 0.2f;
                g.DrawLine(pen, r.X + m, r.Y + m, r.X + r.Width - m, r.Y + r.Height - m);
                g.DrawLine(pen, r.X + r.Width - m, r.Y + m, r.X + m, r.Y + r.Height - m);
            }
        }

        // Checkmark — confirm/OK
        public static void Check(Graphics g, RectangleF r, Color c)
        {
            using (var pen = P(c, r, 0.13f))
            {
                g.DrawLine(pen, r.X + r.Width * 0.16f, r.Y + r.Height * 0.52f, r.X + r.Width * 0.42f, r.Y + r.Height * 0.78f);
                g.DrawLine(pen, r.X + r.Width * 0.42f, r.Y + r.Height * 0.78f, r.X + r.Width * 0.86f, r.Y + r.Height * 0.24f);
            }
        }

        // Small "+" badge over the bottom-right corner of a base glyph
        static void PlusBadge(Graphics g, RectangleF r, Color c)
        {
            float s = Math.Min(r.Width, r.Height) * 0.4f;
            var br = new RectangleF(r.Right - s, r.Bottom - s, s, s);
            using (var pen = P(c, br, 0.16f))
            {
                float cx = br.X + br.Width / 2f, cy = br.Y + br.Height / 2f, h = br.Width * 0.32f;
                g.DrawLine(pen, cx - h, cy, cx + h, cy);
                g.DrawLine(pen, cx, cy - h, cx, cy + h);
            }
        }

        public static void FilePlus(Graphics g, RectangleF r, Color c) { FileIcon(g, r, c); PlusBadge(g, r, c); }
        public static void FolderPlus(Graphics g, RectangleF r, Color c) { FolderIcon(g, r, c); PlusBadge(g, r, c); }

        // Magnifying glass — scanner nav tab
        public static void Search(Graphics g, RectangleF r, Color c)
        {
            float rad = Math.Min(r.Width, r.Height) * 0.32f;
            float cx = r.X + r.Width * 0.42f, cy = r.Y + r.Height * 0.42f;
            using (var pen = P(c, r, 0.13f))
            {
                g.DrawEllipse(pen, cx - rad, cy - rad, rad * 2, rad * 2);
                float hx = cx + rad * 0.72f, hy = cy + rad * 0.72f;
                g.DrawLine(pen, hx, hy, r.X + r.Width * 0.92f, r.Y + r.Height * 0.92f);
            }
        }

        // Gear — settings nav tab
        public static void Gear(Graphics g, RectangleF r, Color c)
        {
            float cx = r.X + r.Width / 2f, cy = r.Y + r.Height / 2f;
            float rOuter = Math.Min(r.Width, r.Height) * 0.46f, rInner = rOuter * 0.55f;
            using (var pen = P(c, r, 0.11f))
            {
                g.DrawEllipse(pen, cx - rOuter * 0.62f, cy - rOuter * 0.62f, rOuter * 1.24f, rOuter * 1.24f);
                g.DrawEllipse(pen, cx - rInner * 0.5f, cy - rInner * 0.5f, rInner, rInner);
                for (int i = 0; i < 8; i++)
                {
                    double a = Math.PI / 4 * i + Math.PI / 8;
                    float x1 = cx + (float)Math.Cos(a) * rOuter * 0.62f, y1 = cy + (float)Math.Sin(a) * rOuter * 0.62f;
                    float x2 = cx + (float)Math.Cos(a) * rOuter, y2 = cy + (float)Math.Sin(a) * rOuter;
                    g.DrawLine(pen, x1, y1, x2, y2);
                }
            }
        }

        // Circled "i" — the About dialog
        public static void Info(Graphics g, RectangleF r, Color c)
        {
            float cx = r.X + r.Width / 2f, cy = r.Y + r.Height / 2f, rad = Math.Min(r.Width, r.Height) / 2f * 0.9f;
            using (var pen = P(c, r, 0.1f))
                g.DrawEllipse(pen, cx - rad, cy - rad, rad * 2, rad * 2);
            using (var b = new SolidBrush(c))
            {
                float dr = rad * 0.14f;
                g.FillEllipse(b, cx - dr, cy - rad * 0.52f - dr, dr * 2, dr * 2);
            }
            using (var pen = P(c, r, 0.12f))
                g.DrawLine(pen, cx, cy - rad * 0.1f, cx, cy + rad * 0.5f);
        }

        // Open padlock — restoring a folder permission
        public static void Unlock(Graphics g, RectangleF r, Color c)
        {
            float w = r.Width, h = r.Height;
            var body = new RectangleF(r.X + w * 0.12f, r.Y + h * 0.46f, w * 0.76f, h * 0.46f);
            using (var pen = P(c, r, 0.12f))
            {
                var shackle = new RectangleF(r.X + w * 0.16f, r.Y, w * 0.5f, h * 0.5f);
                g.DrawArc(pen, shackle, 180, 195);
                g.DrawLine(pen, shackle.X, shackle.Y + shackle.Height / 2f, shackle.X, body.Y + body.Height * 0.2f);
            }
            using (var b = new SolidBrush(c))
            using (var path = Theme.Round(body, w * 0.1f))
                g.FillPath(b, path);
        }
    }
}
