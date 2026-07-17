// Tests for the 429-cooldown clearing rule (src\MainForm.Updates.cs,
// ShouldClearDbCooldown): a database download that succeeds while the CDN
// cooldown is still pending ("try anyway") proves the block is over, so the
// stale deadline must not keep blocking the daily auto-check.
using System;
using AVUI;

namespace AVUI.Tests
{
    static class DbCooldownTests
    {
        static readonly DateTime Now = new DateTime(2026, 7, 17, 12, 0, 0);

        public static void TestSuccessDuringCooldownClearsIt()
        {
            Assert.True(MainForm.ShouldClearDbCooldown(true, Now.AddHours(3), Now),
                "a successful download mid-cooldown clears the stale deadline");
        }

        public static void TestSuccessWithNoCooldownIsANoOp()
        {
            // MinValue = never rate-limited — nothing to clear, no settings write
            Assert.False(MainForm.ShouldClearDbCooldown(true, DateTime.MinValue, Now),
                "no pending cooldown — nothing to clear");
        }

        public static void TestSuccessAfterCooldownExpiredIsANoOp()
        {
            Assert.False(MainForm.ShouldClearDbCooldown(true, Now.AddHours(-1), Now),
                "an already-expired cooldown needs no clearing");
        }

        public static void TestFailureNeverClears()
        {
            Assert.False(MainForm.ShouldClearDbCooldown(false, Now.AddHours(3), Now),
                "a failed download proves nothing — the cooldown stays");
        }
    }
}
