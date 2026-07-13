// Tests for the process-memory-scan region predicate and dump-name sanitizer.
using System;
using System.Collections.Generic;
using System.IO;
using AVUI;

namespace AVUI.Tests
{
    static class MemScanTests
    {
        // Windows memory constants mirrored from MainForm.MemScan.
        const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000;
        const uint MEM_PRIVATE = 0x20000, MEM_MAPPED = 0x40000, MEM_IMAGE = 0x1000000;
        const uint PAGE_NOACCESS = 0x01, PAGE_READONLY = 0x02, PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_GUARD = 0x100;
        const long Cap = 100L * 1024 * 1024;

        public static void TestPrivateExecutableRegionIsDumped()
        {
            Assert.True(MainForm.ShouldDumpRegion(MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEM_PRIVATE, 4096, Cap),
                "committed private RWX code (classic injected shellcode) must be scanned");
            Assert.True(MainForm.ShouldDumpRegion(MEM_COMMIT, PAGE_EXECUTE_READ, MEM_MAPPED, 4096, Cap),
                "mapped executable (non-image) code must be scanned");
        }

        public static void TestImageRegionIsSkipped()
        {
            Assert.False(MainForm.ShouldDumpRegion(MEM_COMMIT, PAGE_EXECUTE_READ, MEM_IMAGE, 4096, Cap),
                "disk-backed image code is scanned as a file, not dumped from RAM");
        }

        public static void TestNonExecutableRegionIsSkipped()
        {
            Assert.False(MainForm.ShouldDumpRegion(MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE, 4096, Cap),
                "plain data pages are not code");
            Assert.False(MainForm.ShouldDumpRegion(MEM_COMMIT, PAGE_READONLY, MEM_PRIVATE, 4096, Cap),
                "read-only data pages are not code");
        }

        public static void TestUncommittedRegionIsSkipped()
        {
            Assert.False(MainForm.ShouldDumpRegion(MEM_RESERVE, PAGE_EXECUTE_READWRITE, MEM_PRIVATE, 4096, Cap),
                "reserved-but-not-committed memory has nothing to read");
        }

        public static void TestGuardAndNoAccessSkipped()
        {
            Assert.False(MainForm.ShouldDumpRegion(MEM_COMMIT, PAGE_EXECUTE_READ | PAGE_GUARD, MEM_PRIVATE, 4096, Cap),
                "guard pages fault on read");
            Assert.False(MainForm.ShouldDumpRegion(MEM_COMMIT, PAGE_NOACCESS, MEM_PRIVATE, 4096, Cap),
                "no-access pages are unreadable");
        }

        public static void TestOversizedRegionSkipped()
        {
            Assert.False(MainForm.ShouldDumpRegion(MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEM_PRIVATE, Cap + 1, Cap),
                "a region larger than the cap is skipped so one process can't dump gigabytes");
            Assert.True(MainForm.ShouldDumpRegion(MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEM_PRIVATE, Cap, Cap),
                "exactly at the cap is still dumped");
            Assert.False(MainForm.ShouldDumpRegion(MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEM_PRIVATE, 0, Cap),
                "an empty region is skipped");
        }

        public static void TestStripeSpreadsFilesEvenly()
        {
            var files = new List<string>();
            for (int i = 0; i < 10; i++) files.Add("f" + i);
            var slices = MainForm.StripeFiles(files, 4);
            Assert.Equal(4, slices.Count, "one bucket per process");
            // 10 files over 4 buckets → sizes 3,3,2,2 (max-min <= 1, i.e. balanced)
            Assert.Equal(3, slices[0].Count, "bucket 0 gets files 0,4,8");
            Assert.Equal(3, slices[1].Count, "bucket 1 gets files 1,5,9");
            Assert.Equal(2, slices[2].Count, "bucket 2 gets files 2,6");
            Assert.Equal(2, slices[3].Count, "bucket 3 gets files 3,7");
            Assert.Equal("f0", slices[0][0], "round-robin: bucket 0 first item is file 0");
            Assert.Equal("f4", slices[0][1], "round-robin: bucket 0 second item is file 4");
        }

        public static void TestStripeKeepsEveryFileExactlyOnce()
        {
            var files = new List<string>();
            for (int i = 0; i < 37; i++) files.Add("x" + i);
            var slices = MainForm.StripeFiles(files, 4);
            int total = 0;
            var seen = new System.Collections.Generic.HashSet<string>();
            foreach (var s in slices) foreach (var f in s) { total++; seen.Add(f); }
            Assert.Equal(37, total, "no file dropped or duplicated");
            Assert.Equal(37, seen.Count, "every file present exactly once");
        }

        public static void TestStripeTailIsDistributed()
        {
            // Mimics memory dumps appended at the tail: they must NOT all land in one bucket.
            var files = new List<string>();
            for (int i = 0; i < 100; i++) files.Add("disk" + i);
            for (int i = 0; i < 8; i++) files.Add("mem" + i); // the appended dumps
            var slices = MainForm.StripeFiles(files, 4);
            foreach (var s in slices)
            {
                int mem = 0;
                foreach (var f in s) if (f.StartsWith("mem")) mem++;
                Assert.True(mem > 0, "each bucket gets at least one tail (memory-dump) file");
            }
        }

        public static void TestSortPathsBySizeSmallestFirst()
        {
            var sizes = new Dictionary<string, long>
            {
                { "big", 200L * 1024 * 1024 },
                { "tiny", 1024 },
                { "mid", 5L * 1024 * 1024 },
            };
            var files = new List<string> { "big", "tiny", "mid" };
            MainForm.SortPathsBySize(files, delegate(string p) { return sizes[p]; });
            Assert.Equal("tiny", files[0], "smallest file scanned first");
            Assert.Equal("mid", files[1], "medium file second");
            Assert.Equal("big", files[2], "heaviest file falls to the tail");
        }

        public static void TestSortPathsBySizeMissingSizeIsZero()
        {
            // A file whose size can't be read (returns 0) sorts to the front, not crashes.
            var files = new List<string> { "a", "b" };
            MainForm.SortPathsBySize(files, delegate(string p) { return p == "a" ? 100L : 0L; });
            Assert.Equal("b", files[0], "unreadable/zero-size sorts first");
            Assert.Equal("a", files[1], "sized file after");
        }

        public static void TestSanitizeNameStripsInvalidChars()
        {
            string clean = MainForm.SanitizeName("chrome");
            Assert.Equal("chrome", clean, "a plain name is unchanged");
            string bad = MainForm.SanitizeName("weird:na/me");
            foreach (char c in Path.GetInvalidFileNameChars())
                Assert.True(bad.IndexOf(c) < 0, "sanitized name keeps no invalid char");
            Assert.Equal("proc", MainForm.SanitizeName(""), "an empty process name falls back to a placeholder");
            Assert.Equal("proc", MainForm.SanitizeName(null), "a null process name falls back to a placeholder");
        }
    }
}
