// Tests for the stale-database rule (src\MainForm.Settings.cs) that turns the
// hero yellow and shows the update button when the signatures have aged.
using System;
using AVUI;

namespace AVUI.Tests
{
    static class DbStaleTests
    {
        static readonly DateTime Now = new DateTime(2026, 7, 14, 12, 0, 0);

        public static void TestFreshDbIsNotStale()
        {
            Assert.False(MainForm.DbIsStale(Now.AddDays(-1), Now), "yesterday's database is fresh");
        }

        public static void TestOldDbIsStale()
        {
            Assert.True(MainForm.DbIsStale(Now.AddDays(-8), Now), "8-day-old database is stale");
        }

        public static void TestThresholdBoundaryIsStale()
        {
            Assert.True(MainForm.DbIsStale(Now.AddDays(-MainForm.DbStaleDays), Now),
                "exactly DbStaleDays counts as stale");
        }

        public static void TestJustUnderThresholdIsNotStale()
        {
            Assert.False(MainForm.DbIsStale(Now.AddDays(-MainForm.DbStaleDays).AddHours(1), Now),
                "an hour under the threshold is still fresh");
        }

        public static void TestMissingDbIsNotStale()
        {
            // no database at all is a different hero state — the stale warning must not fire
            Assert.False(MainForm.DbIsStale(DateTime.MinValue, Now), "MinValue means no database");
        }

        public static void TestFutureTimestampIsNotStale()
        {
            Assert.False(MainForm.DbIsStale(Now.AddDays(1), Now), "clock set back must not flag stale");
        }
    }
}
