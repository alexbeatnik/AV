// Tests for the startup sweep of stale scan temp files (src\MainForm.Monitor.cs).
// A hard crash leaves --file-list files and av-mem-* RAM-dump folders (up to
// 128 MB) in %TEMP%; the sweep must remove exactly those and nothing else.
using System;
using System.IO;
using AVUI;

namespace AVUI.Tests
{
    static class SweepTempTests
    {
        public static void TestSweepDeletesOwnLeftovers()
        {
            using (var dir = new TempDir())
            {
                File.WriteAllText(dir.File("av-list-abc123.txt"), "x");
                File.WriteAllText(dir.File("av-list-2-abc123.txt"), "x"); // chunked list
                File.WriteAllText(dir.File("av-batch-abc123.txt"), "x");
                File.WriteAllText(dir.File("av-yara-abc123.txt"), "x");
                string memDir = dir.File("av-mem-abc123");
                Directory.CreateDirectory(memDir);
                File.WriteAllText(Path.Combine(memDir, "proc_pid1_0x1000.bin"), "x");

                MainForm.SweepStaleTempFiles(dir.Path);

                Assert.False(File.Exists(dir.File("av-list-abc123.txt")), "list file swept");
                Assert.False(File.Exists(dir.File("av-list-2-abc123.txt")), "chunk list swept");
                Assert.False(File.Exists(dir.File("av-batch-abc123.txt")), "batch list swept");
                Assert.False(File.Exists(dir.File("av-yara-abc123.txt")), "yara list swept");
                Assert.False(Directory.Exists(memDir), "mem-dump folder swept with its contents");
            }
        }

        public static void TestSweepKeepsForeignFiles()
        {
            using (var dir = new TempDir())
            {
                File.WriteAllText(dir.File("report.txt"), "x");        // unrelated file
                File.WriteAllText(dir.File("av-listing.txt"), "x");    // similar name, no GUID dash
                File.WriteAllText(dir.File("av-memo.txt"), "x");       // not a dump folder
                Directory.CreateDirectory(dir.File("av-memories"));    // dir not matching av-mem-*

                MainForm.SweepStaleTempFiles(dir.Path);

                Assert.True(File.Exists(dir.File("report.txt")), "unrelated file kept");
                Assert.True(File.Exists(dir.File("av-listing.txt")), "near-miss file kept");
                Assert.True(File.Exists(dir.File("av-memo.txt")), "near-miss file kept (2)");
                Assert.True(Directory.Exists(dir.File("av-memories")), "near-miss folder kept");
            }
        }

        public static void TestSweepOnMissingDirIsANoOp()
        {
            MainForm.SweepStaleTempFiles(Path.Combine(Path.GetTempPath(),
                "av-tests-no-such-dir-" + Guid.NewGuid().ToString("N"))); // must not throw
        }
    }
}
