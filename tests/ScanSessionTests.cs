// Tests for the per-scan state object (src\ScanSession.cs). ResetScanState
// replaces the session wholesale instead of resetting fields one by one, so a
// fresh instance being completely clean IS the "no state leaks between scans"
// guarantee — these tests pin that contract down.
using System;
using AVUI;

namespace AVUI.Tests
{
    static class ScanSessionTests
    {
        public static void TestFreshSessionIsIdle()
        {
            var s = new ScanSession();
            Assert.False(s.Running, "not running");
            Assert.False(s.Monitor, "not a monitor scan");
            Assert.False(s.Cancel, "no stale cancel flag");
            Assert.Equal("", s.Desc, "empty description");
        }

        public static void TestFreshSessionCountersAreZero()
        {
            var s = new ScanSession();
            Assert.Equal(0, s.Scanned, "scanned");
            Assert.Equal(0, s.Found, "found");
            Assert.Equal(0, s.Moved, "moved");
            Assert.Equal(0, s.TotalToScan, "total to scan");
            Assert.Equal(0, s.InitialTotal, "initial total");
            Assert.Equal(0, s.FoundFiles.Count, "found-files list is empty");
        }

        public static void TestFreshSessionEtaWindowIsUnstarted()
        {
            var s = new ScanSession();
            Assert.Equal(DateTime.MinValue, s.RateWinTime, "ETA window not started");
            Assert.Equal(0, s.RateWinCount, "ETA window count");
            Assert.Equal("", s.LastEta, "no stale ETA text");
            Assert.False(s.LoggedTotal, "total not logged yet");
            Assert.False(s.Listing, "not listing");
            Assert.Equal(0, s.Listed, "nothing listed");
        }

        public static void TestFreshSessionYaraPhaseIsClean()
        {
            var s = new ScanSession();
            Assert.True(s.YaraListPath == null, "no list path");
            Assert.False(s.YaraPhasePending, "no pending phase");
            Assert.False(s.YaraPhaseExpected, "no expected phase");
            Assert.False(s.YaraRunning, "yara not running");
            Assert.Equal(DateTime.MinValue, s.YaraPhaseStart, "phase didn't run");
            Assert.Equal(0, s.YaraMatches.Count, "no stale matches");
            Assert.Equal(0L, s.YaraTotalBytes, "no stale workload total");
            Assert.Equal(0.0, s.YaraLastFraction, "no stale progress fraction");
            Assert.Equal(0, s.YaraErrLines, "no stale error count");
        }

        // Each scan gets its own list/map instances — a captured reference to a
        // superseded session must never alias the new session's collections
        public static void TestSessionsDoNotShareCollections()
        {
            var a = new ScanSession();
            var b = new ScanSession();
            a.FoundFiles.Add(new string[] { "x", "y" });
            a.YaraMatches["p"] = "rule";
            Assert.Equal(0, b.FoundFiles.Count, "FoundFiles are per-session");
            Assert.Equal(0, b.YaraMatches.Count, "YaraMatches are per-session");
        }
    }
}
