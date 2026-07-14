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
    }
}
