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
    }
}
