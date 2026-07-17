// Tests for the dashboard's display copy of the last scans.log line
// (src\MainForm.Ui.cs, FormatHistoryLine): the file keeps ISO timestamps,
// the dashboard shows dd.MM.yyyy like every other date on it.
using System;
using AVUI;

namespace AVUI.Tests
{
    static class HistoryLineTests
    {
        public static void TestIsoStampIsReformattedForDisplay()
        {
            Assert.Equal("16.07.2026 09:23  quick scan  scanned: 8123",
                MainForm.FormatHistoryLine("2026-07-16 09:23  quick scan  scanned: 8123"),
                "ISO stamp becomes dd.MM.yyyy, the rest of the line is untouched");
        }

        public static void TestStampOnlyLine()
        {
            Assert.Equal("01.02.2025 23:59", MainForm.FormatHistoryLine("2025-02-01 23:59"),
                "a line that is exactly one stamp still reformats");
        }

        public static void TestLineWithoutStampPassesThrough()
        {
            Assert.Equal("some free-form note", MainForm.FormatHistoryLine("some free-form note"),
                "no leading stamp — line unchanged");
            Assert.Equal("2026-13-40 99:99  broken", MainForm.FormatHistoryLine("2026-13-40 99:99  broken"),
                "an invalid date is not a stamp — line unchanged");
        }

        public static void TestShortAndNullLines()
        {
            Assert.Equal("short", MainForm.FormatHistoryLine("short"), "too short to hold a stamp");
            Assert.Equal(null, MainForm.FormatHistoryLine(null), "null passes through");
        }

        // ---- HistoryLinesThatFit: how many lines the activity card lists ----
        // (the label's Consolas 9pt font is ~15px tall with 8px vertical padding)

        public static void TestTypicalCardHeightFitsSeveralLines()
        {
            // 100 - 8 = 92 available, 17px per line → 5 full lines
            Assert.Equal(5, MainForm.HistoryLinesThatFit(100, 8, 15),
                "a mid-height card lists as many full lines as fit");
        }

        public static void TestCollapsedHeightStillShowsOneLine()
        {
            // a minimized window collapses the docked layout to ~0 height —
            // the count must bottom out at one line, never zero or negative
            Assert.Equal(1, MainForm.HistoryLinesThatFit(0, 8, 15),
                "collapsed layout keeps one line");
            Assert.Equal(1, MainForm.HistoryLinesThatFit(10, 8, 15),
                "less than one line of room still shows one line");
        }

        public static void TestTallCardIsCappedAtEight()
        {
            Assert.Equal(8, MainForm.HistoryLinesThatFit(1000, 8, 15),
                "the card never lists more than 8 entries");
        }

        public static void TestExactlyOneLineOfRoom()
        {
            // avail == lineH is not "> lineH" — the guard path returns 1 either way
            Assert.Equal(1, MainForm.HistoryLinesThatFit(25, 8, 15),
                "exactly one line of room shows one line");
        }
    }
}
