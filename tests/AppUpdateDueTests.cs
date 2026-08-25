// Tests for the app self-update due-time rule: an unconditional check on every
// launch, then once per 24 hours while the app keeps running.
using System;
using AVUI;

namespace AVUI.Tests
{
    public static class AppUpdateDueTests
    {
        static readonly DateTime Now = new DateTime(2026, 7, 14, 12, 0, 0);

        public static void TestStartupAlwaysChecks()
        {
            // even a check from minutes ago doesn't suppress the launch check
            Assert.True(MainForm.AppUpdateDue(false, Now.AddMinutes(-5), Now, 24), "fresh launch");
            Assert.True(MainForm.AppUpdateDue(false, DateTime.MinValue, Now, 24), "never checked");
        }

        public static void TestPeriodAppliesAfterStartupCheck()
        {
            Assert.False(MainForm.AppUpdateDue(true, Now.AddHours(-23), Now, 24), "23h — not yet");
            Assert.True(MainForm.AppUpdateDue(true, Now.AddHours(-24), Now, 24), "24h — due");
            Assert.True(MainForm.AppUpdateDue(true, Now.AddDays(-3), Now, 24), "long overdue");
        }

        public static void TestFutureLastCheckIsNotDue()
        {
            // clock set back: self-heals once real time catches up (same rule as
            // the scheduled scan)
            Assert.False(MainForm.AppUpdateDue(true, Now.AddHours(5), Now, 24), "future timestamp");
        }

        public static void TestNewerReleaseWins()
        {
            Assert.True(MainForm.IsNewerRelease("0.2.1", "0.2.0"), "patch bump");
            Assert.True(MainForm.IsNewerRelease("0.3.0", "0.2.9"), "minor bump");
            Assert.True(MainForm.IsNewerRelease("1.0", "0.9.9"), "two-component tag");
        }

        public static void TestSameOrOlderReleaseIsNotNewer()
        {
            Assert.False(MainForm.IsNewerRelease("0.2.0", "0.2.0"), "identical");
            Assert.False(MainForm.IsNewerRelease("0.1.9", "0.2.0"), "older release");
            // "0.2.0" and "0.2.0.0" are the same build — a re-tag must not re-download
            Assert.False(MainForm.IsNewerRelease("0.2.0.0", "0.2.0"), "padded to four components");
        }

        public static void TestMalformedTagIsNotNewer()
        {
            // the tag regex accepts "[\d.]+", which Version's constructor rejects —
            // that used to throw out of the middle of the update worker
            Assert.False(MainForm.IsNewerRelease("1", "0.2.0"), "single component");
            Assert.False(MainForm.IsNewerRelease("1.2.3.", "0.2.0"), "trailing dot");
            Assert.False(MainForm.IsNewerRelease("1.2.3.4.5", "0.2.0"), "too many components");
            Assert.False(MainForm.IsNewerRelease("99999999999.0", "0.2.0"), "component overflows int");
            Assert.False(MainForm.IsNewerRelease("", "0.2.0"), "empty tag");
            Assert.False(MainForm.IsNewerRelease(null, "0.2.0"), "null tag");
            Assert.False(MainForm.IsNewerRelease("9.9.9", "nonsense"), "unreadable local version");
        }
    }
}
