// Tests for the install-time data carry-over rule: a file travels to the
// install dir only when the destination doesn't have it yet — a freshly
// downloaded exe's default settings.ini must never wipe the installed one
// (that's how the VirusTotal key used to disappear on every manual update).
using System;
using System.IO;
using AVUI;

namespace AVUI.Tests
{
    public static class CarryOverTests
    {
        public static void TestCopiesWhenDestinationMissing()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllText(tmp.File("src.ini"), "vtcheck=1");
                MainForm.CarryOverFile(tmp.File("src.ini"), tmp.File("dst.ini"));
                Assert.True(File.Exists(tmp.File("dst.ini")), "copied");
                Assert.Equal("vtcheck=1", File.ReadAllText(tmp.File("dst.ini")), "content");
            }
        }

        public static void TestNeverOverwritesExistingDestination()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllText(tmp.File("src.ini"), "fresh defaults");
                File.WriteAllText(tmp.File("dst.ini"), "the user's real settings");
                MainForm.CarryOverFile(tmp.File("src.ini"), tmp.File("dst.ini"));
                Assert.Equal("the user's real settings", File.ReadAllText(tmp.File("dst.ini")), "destination kept");
            }
        }

        public static void TestMissingSourceIsANoOp()
        {
            using (var tmp = new TempDir())
            {
                MainForm.CarryOverFile(tmp.File("nope.ini"), tmp.File("dst.ini"));
                Assert.False(File.Exists(tmp.File("dst.ini")), "nothing created");
            }
        }
    }
}
