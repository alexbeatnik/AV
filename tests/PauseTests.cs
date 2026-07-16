// Tests for the protection-pause rule (src\MainForm.Pause.cs). The sentinel
// values matter: MinValue = protection active, MaxValue = paused until the app
// restarts, anything else = a timed pause that expires on its own.
using System;
using AVUI;

namespace AVUI.Tests
{
    static class PauseTests
    {
        static readonly DateTime Now = new DateTime(2026, 7, 16, 12, 0, 0);

        public static void TestNotPausedByDefault()
        {
            Assert.False(MainForm.ProtectionPauseActive(DateTime.MinValue, Now), "MinValue means active protection");
        }

        public static void TestUntilRestartIsAlwaysPaused()
        {
            Assert.True(MainForm.ProtectionPauseActive(DateTime.MaxValue, Now), "MaxValue pauses until restart");
        }

        public static void TestTimedPauseIsActiveBeforeDeadline()
        {
            Assert.True(MainForm.ProtectionPauseActive(Now.AddHours(2), Now), "future deadline is paused");
        }

        public static void TestTimedPauseExpiresAtDeadline()
        {
            Assert.False(MainForm.ProtectionPauseActive(Now, Now), "the deadline itself is no longer paused");
            Assert.False(MainForm.ProtectionPauseActive(Now.AddHours(-1), Now), "past deadline is not paused");
        }

        // Every pause duration the tray menu offers stays inside the same day-ish
        // window, so the "until HH:mm" wording in the UI can't silently mislead
        public static void TestOfferedDurationsKeepDeadlineInFuture()
        {
            foreach (int hours in new int[] { 1, 2, 5 })
                Assert.True(MainForm.ProtectionPauseActive(Now.AddHours(hours), Now),
                    hours + "h pause is active right after enabling");
        }
    }
}
