// Tests for the hero-ownership ladder (src\MainForm.Settings.cs,
// HeroOwnerNow): background repaint paths — the daily db-check callback, a
// language switch — may only paint the idle protection state when nothing is
// in flight, otherwise a running scan's busy hero gets overwritten with a
// green "Protected" while files are still being checked.
using System;
using AVUI;

namespace AVUI.Tests
{
    static class HeroOwnerTests
    {
        public static void TestIdleWhenNothingRuns()
        {
            Assert.Equal(HeroOwner.Idle, MainForm.HeroOwnerNow(false, false, false),
                "nothing in flight — the protection state may be painted");
        }

        public static void TestScanOwnsTheHero()
        {
            Assert.Equal(HeroOwner.Scan, MainForm.HeroOwnerNow(false, true, false),
                "a running scan owns the hero");
        }

        public static void TestUpdateOwnsTheHero()
        {
            Assert.Equal(HeroOwner.Update, MainForm.HeroOwnerNow(false, false, true),
                "a running update owns the hero");
        }

        public static void TestVtPhaseOwnsTheHero()
        {
            Assert.Equal(HeroOwner.VtPhase, MainForm.HeroOwnerNow(true, false, false),
                "a held-open VirusTotal phase owns the hero");
        }

        public static void TestVtPhaseOutranksEverything()
        {
            // FinishScan hands the visuals to the verdicts — the VT phase wins
            // even if the flags overlap for a moment
            Assert.Equal(HeroOwner.VtPhase, MainForm.HeroOwnerNow(true, true, true),
                "the VirusTotal phase outranks scan and update");
        }

        public static void TestScanOutranksUpdate()
        {
            Assert.Equal(HeroOwner.Scan, MainForm.HeroOwnerNow(false, true, true),
                "the scan's busy hero wins over the update's");
        }
    }
}
