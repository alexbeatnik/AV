// Tests for EnsureParentDir (src\MainForm.Quarantine.cs) — quarantine restores
// into folders the user has deleted since the file was quarantined.
using System;
using System.IO;
using AVUI;

namespace AVUI.Tests
{
    static class EnsureParentDirTests
    {
        public static void TestCreatesMissingNestedParents()
        {
            using (var tmp = new TempDir())
            {
                string origin = Path.Combine(tmp.Path, @"deleted\sub\folder\evil.exe");
                MainForm.EnsureParentDir(origin);
                Assert.True(Directory.Exists(Path.GetDirectoryName(origin)), "nested parent chain is recreated");
            }
        }

        public static void TestNoOpWhenParentAlreadyExists()
        {
            using (var tmp = new TempDir())
            {
                string origin = tmp.File("file.txt");
                MainForm.EnsureParentDir(origin); // must not throw
                Assert.True(Directory.Exists(tmp.Path), "existing parent is left alone");
            }
        }

        public static void TestRestoreIntoDeletedFolderRoundTrips()
        {
            // the full restore scenario: quarantine a file, delete its folder,
            // then EnsureParentDir + XorCopy must bring the original bytes back
            using (var tmp = new TempDir())
            {
                string originDir = Path.Combine(tmp.Path, "downloads");
                Directory.CreateDirectory(originDir);
                string origin = Path.Combine(originDir, "sample.bin");
                File.WriteAllBytes(origin, new byte[] { 1, 2, 3, 250 });

                string quar = tmp.File("sample.bin" + MainForm.QuarExt);
                MainForm.XorCopy(origin, quar);
                File.Delete(origin);
                Directory.Delete(originDir); // the user removed the folder meanwhile

                MainForm.EnsureParentDir(origin);
                MainForm.XorCopy(quar, origin);
                Assert.True(File.Exists(origin), "file is restored into the recreated folder");
                Assert.Equal("01-02-03-FA", BitConverter.ToString(File.ReadAllBytes(origin)),
                    "restored bytes match the original");
            }
        }
    }
}
