// Tests for the risky-extension filter, the file-lock probe, theme geometry,
// the scheduled-scan due rule, the temp-download filter, and the watchability probe.
using System;
using System.Drawing;
using System.IO;
using AVUI;

namespace AVUI.Tests
{
    static class RiskyExtensionsTests
    {
        public static void TestExecutablesAreRisky()
        {
            Assert.True(MainForm.RiskyExtensions.Contains(".exe"), ".exe");
            Assert.True(MainForm.RiskyExtensions.Contains(".dll"), ".dll");
            Assert.True(MainForm.RiskyExtensions.Contains(".msi"), ".msi");
        }

        public static void TestScriptsAndDocsAreRisky()
        {
            Assert.True(MainForm.RiskyExtensions.Contains(".js"), ".js");
            Assert.True(MainForm.RiskyExtensions.Contains(".ps1"), ".ps1");
            Assert.True(MainForm.RiskyExtensions.Contains(".docm"), ".docm");
            Assert.True(MainForm.RiskyExtensions.Contains(".pdf"), ".pdf");
            Assert.True(MainForm.RiskyExtensions.Contains(".zip"), ".zip");
        }

        public static void TestLookupIsCaseInsensitive()
        {
            Assert.True(MainForm.RiskyExtensions.Contains(".EXE"), "upper-case .EXE");
            Assert.True(MainForm.RiskyExtensions.Contains(".Zip"), "mixed-case .Zip");
        }

        public static void TestHarmlessTypesAreNotRisky()
        {
            Assert.False(MainForm.RiskyExtensions.Contains(".txt"), ".txt");
            Assert.False(MainForm.RiskyExtensions.Contains(".jpg"), ".jpg");
            Assert.False(MainForm.RiskyExtensions.Contains(".mp4"), ".mp4");
            Assert.False(MainForm.RiskyExtensions.Contains(""), "empty extension");
        }
    }

    // settings.ini timestamps: a value that parses as long but lies outside
    // DateTime's tick range must be rejected, not crash startup
    static class TicksParseTests
    {
        public static void TestValidTicksParse()
        {
            DateTime dt;
            long ticks = new DateTime(2026, 7, 15).Ticks;
            Assert.True(MainForm.TryParseTicks(ticks.ToString(), out dt), "valid ticks accepted");
            Assert.Equal(new DateTime(2026, 7, 15), dt, "round-trips the value");
        }

        public static void TestMaxValueTicksParse()
        {
            DateTime dt;
            Assert.True(MainForm.TryParseTicks(DateTime.MaxValue.Ticks.ToString(), out dt),
                "DateTime.MaxValue.Ticks is the last valid value");
        }

        public static void TestTicksBeyondMaxRejected()
        {
            DateTime dt;
            Assert.False(MainForm.TryParseTicks("3155378976000000000", out dt),
                "ticks past DateTime.MaxValue must not throw or parse");
        }

        public static void TestGarbageRejected()
        {
            DateTime dt;
            Assert.False(MainForm.TryParseTicks("", out dt), "empty");
            Assert.False(MainForm.TryParseTicks("abc", out dt), "non-numeric");
            Assert.False(MainForm.TryParseTicks("0", out dt), "zero");
            Assert.False(MainForm.TryParseTicks("-5", out dt), "negative");
        }
    }

    static class FileLockTests
    {
        public static void TestClosedFileIsNotLocked()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllText(tmp.File("free.txt"), "x");
                Assert.False(MainForm.IsFileLocked(tmp.File("free.txt")), "closed file");
            }
        }

        public static void TestExclusivelyOpenedFileIsLocked()
        {
            using (var tmp = new TempDir())
            {
                string p = tmp.File("busy.txt");
                File.WriteAllText(p, "x");
                using (new FileStream(p, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                    Assert.True(MainForm.IsFileLocked(p), "file opened with FileShare.None");
                Assert.False(MainForm.IsFileLocked(p), "unlocked again after the handle closes");
            }
        }
    }

    static class TempDownloadExtensionTests
    {
        public static void TestBrowserTempExtensionsAreSkipped()
        {
            Assert.True(MainForm.HasTempDownloadExtension(@"C:\d\setup.exe.crdownload"), ".crdownload (Chrome)");
            Assert.True(MainForm.HasTempDownloadExtension(@"C:\d\movie.mkv.part"), ".part (Firefox)");
            Assert.True(MainForm.HasTempDownloadExtension(@"C:\d\x.tmp"), ".tmp");
            Assert.True(MainForm.HasTempDownloadExtension(@"C:\d\y.opdownload"), ".opdownload (Opera)");
        }

        public static void TestLookupIsCaseInsensitive()
        {
            Assert.True(MainForm.HasTempDownloadExtension(@"C:\d\SETUP.EXE.CRDOWNLOAD"), "upper-case extension");
        }

        public static void TestFinalNamesAreNotSkipped()
        {
            Assert.False(MainForm.HasTempDownloadExtension(@"C:\d\setup.exe"), ".exe");
            Assert.False(MainForm.HasTempDownloadExtension(@"C:\d\archive.zip"), ".zip");
            Assert.False(MainForm.HasTempDownloadExtension(@"C:\d\noext"), "no extension at all");
        }

        public static void TestOnlyTheFinalExtensionCounts()
        {
            // after the rename .part → .exe the file must become scannable
            Assert.False(MainForm.HasTempDownloadExtension(@"C:\d\setup.part.exe"), "temp marker not at the end");
        }
    }

    static class CanWatchDirectoryTests
    {
        public static void TestExistingReadableDirIsWatchable()
        {
            using (var tmp = new TempDir())
                Assert.True(MainForm.CanWatchDirectory(tmp.Path), "fresh temp dir");
        }

        public static void TestMissingDirIsNotWatchable()
        {
            Assert.False(MainForm.CanWatchDirectory(
                @"C:\no\such\dir\" + Guid.NewGuid().ToString("N")), "nonexistent dir");
        }
    }

    static class ScheduledScanTests
    {
        static readonly DateTime Now = new DateTime(2026, 7, 11, 12, 0, 0);

        public static void TestOffNeverDue()
        {
            Assert.False(MainForm.ScheduledScanDue(0, DateTime.MinValue, Now), "off + never ran");
            Assert.False(MainForm.ScheduledScanDue(0, Now.AddYears(-1), Now), "off + long overdue");
        }

        public static void TestDailyDueAfter24Hours()
        {
            Assert.False(MainForm.ScheduledScanDue(1, Now.AddHours(-23), Now), "23h ago — not due yet");
            Assert.True(MainForm.ScheduledScanDue(1, Now.AddHours(-24), Now), "exactly 24h ago");
            Assert.True(MainForm.ScheduledScanDue(1, Now.AddDays(-9), Now), "long overdue (PC was off)");
        }

        public static void TestWeeklyDueAfterSevenDays()
        {
            Assert.False(MainForm.ScheduledScanDue(2, Now.AddDays(-6), Now), "6 days ago — not due yet");
            Assert.True(MainForm.ScheduledScanDue(2, Now.AddDays(-7), Now), "exactly 7 days ago");
        }

        public static void TestNeverAnchoredCountsAsOverdue()
        {
            Assert.True(MainForm.ScheduledScanDue(1, DateTime.MinValue, Now), "daily, never anchored");
        }

        public static void TestFutureLastRunIsNotDue()
        {
            // clock set back: must not fire until real time catches up again
            Assert.False(MainForm.ScheduledScanDue(1, Now.AddHours(5), Now), "last run in the future");
        }
    }

    static class ThemeTests
    {
        public static void TestRoundProducesClosedPath()
        {
            using (var path = Theme.Round(new RectangleF(0, 0, 100, 40), 10))
                Assert.True(path.PointCount > 0, "rounded-rect path has geometry");
        }

        public static void TestPaintCardDrawsWithoutErrors()
        {
            // smoke test: the card painter must work on a plain in-memory bitmap
            using (var bmp = new Bitmap(200, 100))
            using (var g = Graphics.FromImage(bmp))
                Theme.PaintCard(g, bmp.Width, bmp.Height); // throws on any GDI+ error
        }
    }
}
