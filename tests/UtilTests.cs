// Tests for the command-line and path helpers in MainForm (src\MainForm.Scan.cs).
using System;
using AVUI;

namespace AVUI.Tests
{
    static class QuoteTests
    {
        public static void TestWrapsInQuotes()
        {
            Assert.Equal("\"C:\\dir\\file.txt\"", MainForm.Quote("C:\\dir\\file.txt"), "plain path");
        }

        public static void TestDoublesTrailingBackslash()
        {
            // a single trailing \ before the closing quote would escape it on the
            // command line, so Quote must double it
            Assert.Equal("\"C:\\dir\\\\\"", MainForm.Quote("C:\\dir\\"), "trailing backslash");
        }

        public static void TestPathWithSpaces()
        {
            Assert.Equal("\"C:\\Program Files\\AV\"", MainForm.Quote("C:\\Program Files\\AV"), "spaces");
        }
    }

    static class IsUnderTests
    {
        public static void TestPathEqualsRoot()
        {
            Assert.True(MainForm.IsUnder("C:\\quarantine", "C:\\quarantine"), "root itself is under root");
        }

        public static void TestPathInsideRoot()
        {
            Assert.True(MainForm.IsUnder("C:\\quarantine\\evil.exe", "C:\\quarantine"), "file inside root");
            Assert.True(MainForm.IsUnder("C:\\quarantine\\a\\b\\c.txt", "C:\\quarantine"), "nested file");
        }

        public static void TestSiblingWithSamePrefixIsNotUnder()
        {
            // the reason IsUnder exists at all: plain StartsWith would match these
            Assert.False(MainForm.IsUnder("C:\\quarantine2\\x.exe", "C:\\quarantine"), "quarantine2 is a sibling");
            Assert.False(MainForm.IsUnder("C:\\Program Files (x86)\\a.dll", "C:\\Program Files"), "Program Files (x86)");
        }

        public static void TestCaseInsensitive()
        {
            Assert.True(MainForm.IsUnder("c:\\QUARANTINE\\evil.exe", "C:\\quarantine"), "case-insensitive match");
        }

        public static void TestRootTrailingBackslashIgnored()
        {
            Assert.True(MainForm.IsUnder("C:\\quarantine\\evil.exe", "C:\\quarantine\\"), "root with trailing backslash");
        }

        public static void TestEmptyRootNeverMatches()
        {
            Assert.False(MainForm.IsUnder("C:\\anything", ""), "empty root");
            Assert.False(MainForm.IsUnder("C:\\anything", "\\"), "backslash-only root");
        }

        public static void TestUnrelatedPath()
        {
            Assert.False(MainForm.IsUnder("D:\\other\\file.txt", "C:\\quarantine"), "different drive");
        }
    }

    static class FormatSpanTests
    {
        // FormatSpan renders through Lang.T — pin the language so the expected
        // strings are stable regardless of the machine the tests run on
        static IDisposable English()
        {
            return new LangScope(Lang.Language.English);
        }

        public static void TestSecondsOnly()
        {
            using (English())
                Assert.Equal("45s", MainForm.FormatSpan(TimeSpan.FromSeconds(45)), "45 seconds");
        }

        public static void TestMinutesAndSeconds()
        {
            using (English())
                Assert.Equal("1m 30s", MainForm.FormatSpan(TimeSpan.FromSeconds(90)), "90 seconds");
        }

        public static void TestHoursAndMinutes()
        {
            using (English())
                Assert.Equal("2h 5m", MainForm.FormatSpan(new TimeSpan(2, 5, 40)), "2h 5m 40s truncates seconds");
        }

        public static void TestExactHourBoundary()
        {
            using (English())
                Assert.Equal("1h 0m", MainForm.FormatSpan(TimeSpan.FromHours(1)), "exactly one hour");
        }

        public static void TestZero()
        {
            using (English())
                Assert.Equal("0s", MainForm.FormatSpan(TimeSpan.Zero), "zero span");
        }
    }

    static class ScanLimitsTests
    {
        public static void TestContainsAllLimits()
        {
            string args = MainForm.ScanLimitsArg(true);
            Assert.True(args.Contains("--max-filesize="), "max-filesize present");
            Assert.True(args.Contains("--max-scansize="), "max-scansize present");
            Assert.True(args.Contains("--max-recursion="), "max-recursion present");
            Assert.True(args.Contains("--max-files="), "max-files present");
            Assert.True(args.Contains("--max-scantime="), "max-scantime present");
            Assert.True(args.StartsWith(" "), "starts with a separator space (concatenated after other args)");
        }

        public static void TestSkipBigCapsFileSize()
        {
            string on = MainForm.ScanLimitsArg(true);
            Assert.True(on.Contains("--max-filesize=200M"), "skip-big caps files at 200 MB");
            Assert.True(on.Contains("--max-scansize=200M"), "skip-big caps scan size at 200 MB");
        }

        public static void TestNoSkipBigMeansUnlimited()
        {
            string off = MainForm.ScanLimitsArg(false);
            Assert.True(off.Contains("--max-filesize=0"), "off = unlimited file size (0)");
            Assert.True(off.Contains("--max-scansize=0"), "off = unlimited scan size (0)");
        }
    }

    // Swaps Lang.Current and restores it on dispose, so tests don't leak language state
    sealed class LangScope : IDisposable
    {
        readonly Lang.Language previous;
        public LangScope(Lang.Language lang) { previous = Lang.Current; Lang.Current = lang; }
        public void Dispose() { Lang.Current = previous; }
    }
}
