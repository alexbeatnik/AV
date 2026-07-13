// Tests for the loss-safe database file swap (src\MainForm.Updates.cs).
using System;
using System.IO;
using AVUI;

namespace AVUI.Tests
{
    // PromoteDownloadedFile must never leave a moment where neither the old
    // nor the new database exists at the destination path.
    static class PromoteDownloadedFileTests
    {
        public static void TestMovesWhenDestinationMissing()
        {
            using (var tmp = new TempDir())
            {
                string part = tmp.File("daily.cvd.part");
                string dest = tmp.File("daily.cvd");
                File.WriteAllText(part, "new database");
                MainForm.PromoteDownloadedFile(part, dest);
                Assert.Equal("new database", File.ReadAllText(dest), "downloaded content lands at dest");
                Assert.False(File.Exists(part), "the .part file is consumed");
            }
        }

        public static void TestReplacesExistingDestination()
        {
            using (var tmp = new TempDir())
            {
                string part = tmp.File("daily.cvd.part");
                string dest = tmp.File("daily.cvd");
                File.WriteAllText(dest, "old database");
                File.WriteAllText(part, "new database");
                MainForm.PromoteDownloadedFile(part, dest);
                Assert.Equal("new database", File.ReadAllText(dest), "existing dest is replaced with the new content");
                Assert.False(File.Exists(part), "the .part file is consumed");
            }
        }

        public static void TestFailedPromoteKeepsTheExistingDatabase()
        {
            using (var tmp = new TempDir())
            {
                string part = tmp.File("daily.cvd.part"); // never created
                string dest = tmp.File("daily.cvd");
                File.WriteAllText(dest, "old database");
                Assert.Throws<FileNotFoundException>(
                    delegate { MainForm.PromoteDownloadedFile(part, dest); },
                    "promoting a missing .part fails");
                Assert.Equal("old database", File.ReadAllText(dest), "the working database survives a failed swap");
            }
        }
    }

    // PromoteExtractedFolder must never leave a moment where the old clamav
    // folder is gone and the new one is not yet in place.
    static class PromoteExtractedFolderTests
    {
        static string MakeInstall(TempDir tmp, string name, string marker)
        {
            string dir = tmp.File(name);
            Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, "clamscan.exe"), marker);
            return dir;
        }

        public static void TestMovesWhenDestinationMissing()
        {
            using (var tmp = new TempDir())
            {
                string src = MakeInstall(tmp, "extracted", "new scanner");
                string dst = tmp.File("clamav");
                MainForm.PromoteExtractedFolder(src, dst);
                Assert.Equal("new scanner", File.ReadAllText(Path.Combine(dst, "clamscan.exe")), "extracted folder lands at dest");
                Assert.False(Directory.Exists(src), "the source folder is consumed");
            }
        }

        public static void TestReplacesExistingInstall()
        {
            using (var tmp = new TempDir())
            {
                string src = MakeInstall(tmp, "extracted", "new scanner");
                string dst = MakeInstall(tmp, "clamav", "old scanner");
                MainForm.PromoteExtractedFolder(src, dst);
                Assert.Equal("new scanner", File.ReadAllText(Path.Combine(dst, "clamscan.exe")), "existing install is replaced");
                Assert.False(Directory.Exists(dst + "-old"), "the old install copy is cleaned up");
            }
        }

        public static void TestFailedPromoteKeepsTheExistingInstall()
        {
            using (var tmp = new TempDir())
            {
                string src = tmp.File("extracted"); // never created
                string dst = MakeInstall(tmp, "clamav", "old scanner");
                Assert.Throws<DirectoryNotFoundException>(
                    delegate { MainForm.PromoteExtractedFolder(src, dst); },
                    "promoting a missing folder fails");
                Assert.Equal("old scanner", File.ReadAllText(Path.Combine(dst, "clamscan.exe")), "the working install survives a failed swap");
                Assert.False(Directory.Exists(dst + "-old"), "the rolled-back install does not linger under the -old name");
            }
        }

        // A previous update died between the two moves: dst is gone and the only
        // working install sits under the -old name. It must never be deleted
        // before the new one is in place.
        public static void TestOrphanedOldInstallSurvivesAFailedRetry()
        {
            using (var tmp = new TempDir())
            {
                MakeInstall(tmp, "clamav-old", "last working scanner");
                string src = tmp.File("extracted"); // never created
                string dst = tmp.File("clamav");    // missing: crash happened after dst -> -old
                Assert.Throws<DirectoryNotFoundException>(
                    delegate { MainForm.PromoteExtractedFolder(src, dst); },
                    "promoting a missing folder fails");
                Assert.Equal("last working scanner", File.ReadAllText(Path.Combine(dst, "clamscan.exe")),
                    "the orphaned -old install is restored to the live path, not deleted");
            }
        }

        public static void TestOrphanedOldInstallIsReplacedOnASuccessfulRetry()
        {
            using (var tmp = new TempDir())
            {
                MakeInstall(tmp, "clamav-old", "last working scanner");
                string src = MakeInstall(tmp, "extracted", "new scanner");
                string dst = tmp.File("clamav"); // missing: crash happened after dst -> -old
                MainForm.PromoteExtractedFolder(src, dst);
                Assert.Equal("new scanner", File.ReadAllText(Path.Combine(dst, "clamscan.exe")), "retry installs the new scanner");
                Assert.False(Directory.Exists(dst + "-old"), "the orphaned -old copy is cleaned up after success");
            }
        }

        public static void TestStaleOldFolderFromInterruptedInstallIsReplaced()
        {
            using (var tmp = new TempDir())
            {
                MakeInstall(tmp, "clamav-old", "stale leftover");
                string src = MakeInstall(tmp, "extracted", "new scanner");
                string dst = MakeInstall(tmp, "clamav", "old scanner");
                MainForm.PromoteExtractedFolder(src, dst);
                Assert.Equal("new scanner", File.ReadAllText(Path.Combine(dst, "clamscan.exe")), "swap works despite a stale -old folder");
                Assert.False(Directory.Exists(dst + "-old"), "the stale -old folder is gone");
            }
        }
    }

    // Watch/exclusion lists live on a case-insensitive filesystem: adding
    // "c:\temp" when "C:\Temp" is already stored must not create a duplicate
    // (duplicate watchers, repeated monitor scans).
    static class AddPathOnceTests
    {
        public static void TestAddsNewPaths()
        {
            var list = new System.Collections.Generic.List<string>();
            MainForm.AddPathOnce(list, @"C:\Temp");
            MainForm.AddPathOnce(list, @"C:\Users\a\Downloads");
            Assert.Equal(2, list.Count, "distinct paths are both stored");
        }

        public static void TestExactDuplicateIsIgnored()
        {
            var list = new System.Collections.Generic.List<string>();
            MainForm.AddPathOnce(list, @"C:\Temp");
            MainForm.AddPathOnce(list, @"C:\Temp");
            Assert.Equal(1, list.Count, "exact duplicate is not stored twice");
        }

        public static void TestCaseVariantIsIgnored()
        {
            var list = new System.Collections.Generic.List<string>();
            MainForm.AddPathOnce(list, @"C:\Temp");
            MainForm.AddPathOnce(list, @"c:\temp");
            MainForm.AddPathOnce(list, @"C:\TEMP");
            Assert.Equal(1, list.Count, "case variants of the same path collapse to one entry");
            Assert.Equal(@"C:\Temp", list[0], "the first-seen spelling is kept");
        }
    }
}
