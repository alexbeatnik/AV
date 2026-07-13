// Tests for the quarantine machinery (src\MainForm.Quarantine.cs): the XOR
// neutralization transform, unique .quar naming, and the index.txt format.
using System;
using System.IO;
using System.Text;
using AVUI;

namespace AVUI.Tests
{
    static class XorCopyTests
    {
        public static void TestRoundTripRestoresOriginalBytes()
        {
            using (var tmp = new TempDir())
            {
                var original = new byte[1024];
                new Random(42).NextBytes(original);
                File.WriteAllBytes(tmp.File("a.bin"), original);

                MainForm.XorCopy(tmp.File("a.bin"), tmp.File("b.quar"));
                MainForm.XorCopy(tmp.File("b.quar"), tmp.File("c.bin"));

                var restored = File.ReadAllBytes(tmp.File("c.bin"));
                Assert.Equal(original.Length, restored.Length, "length preserved");
                for (int i = 0; i < original.Length; i++)
                    if (original[i] != restored[i])
                        throw new Exception("byte " + i + " differs after round trip");
            }
        }

        public static void TestOutputDiffersFromInput()
        {
            using (var tmp = new TempDir())
            {
                byte[] payload = Encoding.ASCII.GetBytes("MZ fake malware body");
                File.WriteAllBytes(tmp.File("mal.exe"), payload);
                MainForm.XorCopy(tmp.File("mal.exe"), tmp.File("mal.exe.quar"));
                byte[] stored = File.ReadAllBytes(tmp.File("mal.exe.quar"));
                Assert.Equal(payload.Length, stored.Length, "same length");
                bool anySame = false;
                for (int i = 0; i < payload.Length; i++)
                    if (payload[i] == stored[i]) anySame = true;
                // XOR 0xFF flips every bit — no byte can survive unchanged
                Assert.False(anySame, "no byte of the neutralized file matches the original");
            }
        }

        public static void TestAllByteValuesRoundTrip()
        {
            using (var tmp = new TempDir())
            {
                var all = new byte[256];
                for (int i = 0; i < 256; i++) all[i] = (byte)i;
                File.WriteAllBytes(tmp.File("all.bin"), all);
                MainForm.XorCopy(tmp.File("all.bin"), tmp.File("all.quar"));
                MainForm.XorCopy(tmp.File("all.quar"), tmp.File("all2.bin"));
                var back = File.ReadAllBytes(tmp.File("all2.bin"));
                for (int i = 0; i < 256; i++)
                    Assert.Equal(all[i], back[i], "byte value " + i);
            }
        }

        public static void TestEmptyFile()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllBytes(tmp.File("empty"), new byte[0]);
                MainForm.XorCopy(tmp.File("empty"), tmp.File("empty.quar"));
                Assert.Equal(0L, new FileInfo(tmp.File("empty.quar")).Length, "empty stays empty");
            }
        }

        public static void TestRefusesToOverwriteExistingDestination()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllText(tmp.File("src.txt"), "data");
                File.WriteAllText(tmp.File("dst.quar"), "already here");
                // FileMode.CreateNew must throw rather than clobber another quarantined file
                Assert.Throws<IOException>(
                    delegate { MainForm.XorCopy(tmp.File("src.txt"), tmp.File("dst.quar")); },
                    "existing destination");
            }
        }
    }

    static class UniqueQuarPathTests
    {
        public static void TestAppendsQuarExtension()
        {
            using (var tmp = new TempDir())
                Assert.Equal(tmp.File("evil.exe" + MainForm.QuarExt),
                    MainForm.UniqueQuarPath(tmp.Path, "evil.exe"), "first slot");
        }

        public static void TestNumbersCollisions()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllText(tmp.File("evil.exe" + MainForm.QuarExt), "");
                Assert.Equal(tmp.File("evil.exe(1)" + MainForm.QuarExt),
                    MainForm.UniqueQuarPath(tmp.Path, "evil.exe"), "second slot");

                File.WriteAllText(tmp.File("evil.exe(1)" + MainForm.QuarExt), "");
                Assert.Equal(tmp.File("evil.exe(2)" + MainForm.QuarExt),
                    MainForm.UniqueQuarPath(tmp.Path, "evil.exe"), "third slot");
            }
        }
    }

    static class QuarPropertiesTests
    {
        public static void TestFormatSize()
        {
            Assert.Equal("512 B", MainForm.FormatSize(512), "bytes");
            Assert.Equal("1.0 KB", MainForm.FormatSize(1024), "one kilobyte");
            Assert.Equal("2.3 MB", MainForm.FormatSize(2411725), "megabytes with one decimal");
            Assert.Equal("145 KB", MainForm.FormatSize(148480), "three-digit values drop the decimal");
            Assert.Equal("1.5 GB", MainForm.FormatSize(1610612736L), "gigabytes");
        }

        public static void TestSha256OfQuarFileMatchesOriginalContent()
        {
            using (var tmp = new TempDir())
            {
                // SHA256("abc") is a well-known constant
                File.WriteAllText(tmp.File("abc.txt"), "abc");
                MainForm.XorCopy(tmp.File("abc.txt"), tmp.File("abc.txt" + MainForm.QuarExt));
                Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    MainForm.Sha256OfQuarFile(tmp.File("abc.txt" + MainForm.QuarExt)),
                    "hash of the neutralized file equals the hash of the original bytes");
                Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    MainForm.Sha256OfQuarFile(tmp.File("abc.txt")),
                    "raw legacy files are hashed as-is");
            }
        }
    }

    static class QuarIndexTests
    {
        public static void TestReadParsesEntries()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllLines(tmp.File("index.txt"), new string[]
                {
                    "evil.exe.quar|C:\\Users\\x\\Downloads\\evil.exe|2026-07-08 12:00",
                    "bad.dll.quar|C:\\Temp\\bad.dll|2026-07-07 09:30"
                });
                var map = MainForm.ReadQuarIndex(tmp.File("index.txt"));
                Assert.Equal(2, map.Count, "two entries");
                Assert.Equal("C:\\Users\\x\\Downloads\\evil.exe", map["evil.exe.quar"][1], "origin path");
                Assert.Equal("2026-07-07 09:30", map["bad.dll.quar"][2], "date field");
            }
        }

        public static void TestReadSkipsMalformedLines()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllLines(tmp.File("index.txt"), new string[]
                {
                    "no separators at all",
                    "onlyone|field",
                    "",
                    "good.quar|C:\\x\\good.exe|2026-01-01 00:00"
                });
                var map = MainForm.ReadQuarIndex(tmp.File("index.txt"));
                Assert.Equal(1, map.Count, "only the well-formed line survives");
                Assert.True(map.ContainsKey("good.quar"), "good entry present");
            }
        }

        public static void TestOldEntriesArePaddedToFiveFields()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllLines(tmp.File("index.txt"), new string[]
                {
                    "old.quar|C:\\x\\old.exe|2026-01-01 00:00",
                    "new.quar|C:\\x\\new.exe|2026-01-02 00:00|Win.Trojan.Agent|Quick scan"
                });
                var map = MainForm.ReadQuarIndex(tmp.File("index.txt"));
                Assert.Equal(5, map["old.quar"].Length, "old entry padded to 5 fields");
                Assert.Equal("", map["old.quar"][3], "old entry has empty threat");
                Assert.Equal("Win.Trojan.Agent", map["new.quar"][3], "new entry threat kept");
                Assert.Equal("Quick scan", map["new.quar"][4], "new entry source kept");
            }
        }

        public static void TestReadMissingFileReturnsEmptyMap()
        {
            using (var tmp = new TempDir())
                Assert.Equal(0, MainForm.ReadQuarIndex(tmp.File("nope.txt")).Count, "missing index");
        }

        public static void TestReadIsCaseInsensitiveOnLookup()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllLines(tmp.File("index.txt"),
                    new string[] { "Evil.EXE.quar|C:\\x\\Evil.EXE|2026-01-01 00:00" });
                var map = MainForm.ReadQuarIndex(tmp.File("index.txt"));
                Assert.True(map.ContainsKey("evil.exe.quar"), "lookup ignores case");
            }
        }

        public static void TestRemoveDeletesOnlyMatchingEntry()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllLines(tmp.File("index.txt"), new string[]
                {
                    "a.exe.quar|C:\\x\\a.exe|2026-01-01 00:00",
                    "b.exe.quar|C:\\x\\b.exe|2026-01-02 00:00"
                });
                MainForm.RemoveQuarIndexEntry(tmp.File("index.txt"), "a.exe.quar");
                var map = MainForm.ReadQuarIndex(tmp.File("index.txt"));
                Assert.Equal(1, map.Count, "one entry left");
                Assert.True(map.ContainsKey("b.exe.quar"), "the other entry kept");
            }
        }

        public static void TestRemoveDoesNotTouchLongerNamesWithSamePrefix()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllLines(tmp.File("index.txt"), new string[]
                {
                    "a.exe|C:\\x\\a.exe|2026-01-01 00:00",
                    "a.exe.quar|C:\\x\\a.exe|2026-01-02 00:00"
                });
                // removing "a.exe" must not also remove "a.exe.quar"
                MainForm.RemoveQuarIndexEntry(tmp.File("index.txt"), "a.exe");
                var map = MainForm.ReadQuarIndex(tmp.File("index.txt"));
                Assert.True(map.ContainsKey("a.exe.quar"), "longer name kept");
                Assert.False(map.ContainsKey("a.exe"), "exact match removed");
            }
        }

        public static void TestRemoveOnMissingFileIsANoOp()
        {
            using (var tmp = new TempDir())
                MainForm.RemoveQuarIndexEntry(tmp.File("nope.txt"), "x.quar"); // must not throw
        }
    }
}
