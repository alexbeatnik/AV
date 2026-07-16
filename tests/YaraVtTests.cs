// Tests for the YARA output parser, the ANSI scan-list filter, the
// YARA-phase progress estimate, and the VirusTotal response parser.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using AVUI;

namespace AVUI.Tests
{
    // The YARA phase has no per-file output — progress is bytes read vs the
    // list's total size (YaraWorkloadBytes / YaraProgressFraction).
    public static class YaraProgressTests
    {
        public static void TestWorkloadSumsFileSizes()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllBytes(tmp.File("a.bin"), new byte[100]);
                File.WriteAllBytes(tmp.File("b.bin"), new byte[250]);
                long sum = MainForm.YaraWorkloadBytes(
                    new string[] { tmp.File("a.bin"), tmp.File("b.bin") }, false);
                Assert.Equal(350L, sum, "sum of both files");
            }
        }

        public static void TestWorkloadSkipsMissingFiles()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllBytes(tmp.File("a.bin"), new byte[100]);
                long sum = MainForm.YaraWorkloadBytes(
                    new string[] { tmp.File("a.bin"), tmp.File("gone.bin") }, false);
                Assert.Equal(100L, sum, "missing file counts as 0");
            }
        }

        public static void TestWorkloadRespectsSkipBigCap()
        {
            // SetLength makes the boundary files instantly, without writing data
            using (var tmp = new TempDir())
            {
                string atCap = tmp.File("at-cap.bin");
                string over = tmp.File("over.bin");
                using (var fs = new FileStream(atCap, FileMode.Create)) fs.SetLength(209715200);
                using (var fs = new FileStream(over, FileMode.Create)) fs.SetLength(209715201);
                Assert.Equal(209715200L, MainForm.YaraWorkloadBytes(new string[] { atCap, over }, true),
                    "file at the cap is counted, one byte over is skipped");
                Assert.Equal(419430401L, MainForm.YaraWorkloadBytes(new string[] { atCap, over }, false),
                    "skipBig off counts everything");
            }
        }

        public static void TestFractionBasics()
        {
            Assert.Equal(0.5, MainForm.YaraProgressFraction(50, 100), "half read");
            Assert.Equal(0.0, MainForm.YaraProgressFraction(0, 100), "nothing read yet");
            Assert.Equal(0.0, MainForm.YaraProgressFraction(50, 0), "total unknown");
            Assert.Equal(0.0, MainForm.YaraProgressFraction(-1, 100), "negative read");
        }

        public static void TestFractionIsCappedBelowFull()
        {
            // rule compilation reads extra bytes — only process exit may show 100%
            Assert.Equal(0.99, MainForm.YaraProgressFraction(100, 100), "full read caps at 99%");
            Assert.Equal(0.99, MainForm.YaraProgressFraction(500, 100), "overshoot caps at 99%");
        }
    }

    // The weekly rules refresh also updates yara64.exe itself when a newer
    // release is out; the decision must be strictly conservative — re-download
    // only when both versions are readable and the remote one is newer.
    public static class YaraEngineVersionTests
    {
        public static void TestNewerRemoteWins()
        {
            Assert.True(MainForm.YaraVersionIsNewer("v4.5.3", "4.5.2"), "patch bump");
            Assert.True(MainForm.YaraVersionIsNewer("v4.6.0", "4.5.9"), "minor bump");
            Assert.True(MainForm.YaraVersionIsNewer("v5.0", "4.5.2"), "major bump, two-part tag");
        }

        public static void TestSameOrOlderRemoteDoesNotUpdate()
        {
            Assert.True(!MainForm.YaraVersionIsNewer("v4.5.2", "4.5.2"), "same version");
            Assert.True(!MainForm.YaraVersionIsNewer("v4.5.1", "4.5.2"), "remote older");
        }

        public static void TestUnreadableSidesNeverUpdate()
        {
            Assert.True(!MainForm.YaraVersionIsNewer(null, "4.5.2"), "no tag (offline)");
            Assert.True(!MainForm.YaraVersionIsNewer("v4.5.3", null), "no local output");
            Assert.True(!MainForm.YaraVersionIsNewer("garbage", "4.5.2"), "unparsable tag");
            Assert.True(!MainForm.YaraVersionIsNewer("v4.5.3", "error: foo"), "unparsable local");
        }

        public static void TestVersionParsingTolerance()
        {
            Assert.Equal(new Version(4, 5, 2), MainForm.ParseYaraVersion("v4.5.2"), "leading v");
            Assert.Equal(new Version(4, 5, 2), MainForm.ParseYaraVersion("yara 4.5.2 (build 7)"), "surrounding chatter");
            Assert.Equal(new Version(4, 5, 0), MainForm.ParseYaraVersion("4.5"), "two-part version pads to .0");
            Assert.True(MainForm.ParseYaraVersion("no digits here") == null, "no version-like token");
            Assert.True(MainForm.ParseYaraVersion(null) == null, "null input");
        }
    }

    public static class YaraParseTests
    {
        public static void TestMatchLineIsParsed()
        {
            string rule, path;
            Assert.True(MainForm.ParseYaraMatch(@"MAL_Ransom_Generic C:\Users\x\evil.exe", out rule, out path), "parsed");
            Assert.Equal("MAL_Ransom_Generic", rule, "rule");
            Assert.Equal(@"C:\Users\x\evil.exe", path, "path");
        }

        public static void TestPathWithSpacesIsKeptWhole()
        {
            string rule, path;
            Assert.True(MainForm.ParseYaraMatch(@"SUSP_Rule C:\Program Files\bad app\a b.dll", out rule, out path), "parsed");
            Assert.Equal(@"C:\Program Files\bad app\a b.dll", path, "path with spaces");
        }

        public static void TestErrorLineIsRejected()
        {
            string rule, path;
            Assert.False(MainForm.ParseYaraMatch(@"error scanning C:\x\y.exe: could not open file", out rule, out path), "error chatter");
        }

        public static void TestCompileWarningIsRejected()
        {
            string rule, path;
            Assert.False(MainForm.ParseYaraMatch(@"warning: rule ""x"" in C:\rules.yar(10): too slow", out rule, out path), "compile warning");
            Assert.False(MainForm.ParseYaraMatch(@"C:\rules.yar(10): error: syntax error", out rule, out path), "path-first error");
        }

        public static void TestEmptyAndGarbageRejected()
        {
            string rule, path;
            Assert.False(MainForm.ParseYaraMatch("", out rule, out path), "empty");
            Assert.False(MainForm.ParseYaraMatch(null, out rule, out path), "null");
            Assert.False(MainForm.ParseYaraMatch("justoneword", out rule, out path), "no space");
            Assert.False(MainForm.ParseYaraMatch("Rule relative\\path.exe", out rule, out path), "relative path");
        }
    }

    public static class VtParseTests
    {
        const string Sample = "{\"data\":{\"attributes\":{\"last_analysis_stats\":{"
            + "\"harmless\":2,\"type-unsupported\":10,\"suspicious\":1,\"confirmed-timeout\":0,"
            + "\"timeout\":0,\"failure\":1,\"malicious\":45,\"undetected\":22}}}}";

        public static void TestParsesMaliciousAndSuspicious()
        {
            int mal, susp, total;
            Assert.True(MainForm.VtParseStats(Sample, out mal, out susp, out total), "parsed");
            Assert.Equal(45, mal, "malicious");
            Assert.Equal(1, susp, "suspicious");
        }

        public static void TestTotalCountsOnlyVerdicts()
        {
            int mal, susp, total;
            MainForm.VtParseStats(Sample, out mal, out susp, out total);
            // harmless + undetected + malicious + suspicious; timeouts/failures excluded
            Assert.Equal(2 + 22 + 45 + 1, total, "total verdicts");
        }

        public static void TestCleanFile()
        {
            string json = "{\"last_analysis_stats\":{\"harmless\":0,\"malicious\":0,\"suspicious\":0,\"undetected\":70}}";
            int mal, susp, total;
            Assert.True(MainForm.VtParseStats(json, out mal, out susp, out total), "parsed");
            Assert.Equal(0, mal, "malicious");
            Assert.Equal(70, total, "total");
        }

        public static void TestMissingStatsReturnsFalse()
        {
            int mal, susp, total;
            Assert.False(MainForm.VtParseStats("{\"error\":{\"code\":\"NotFoundError\"}}", out mal, out susp, out total), "no stats");
            Assert.False(MainForm.VtParseStats(null, out mal, out susp, out total), "null");
            Assert.False(MainForm.VtParseStats("", out mal, out susp, out total), "empty");
        }

        public static void TestTruncatedJsonReturnsFalse()
        {
            int mal, susp, total;
            Assert.False(MainForm.VtParseStats("{\"last_analysis_stats\":{\"malicious\":4", out mal, out susp, out total), "no closing brace");
        }
    }

    // yara64 opens paths through the ANSI code page, so the scan list is
    // re-encoded and paths the code page cannot represent are dropped.
    public static class AnsiSafePathsTests
    {
        static readonly Encoding Cp1251 = Encoding.GetEncoding(1251); // Cyrillic ANSI

        public static void TestAsciiPathsSurvive()
        {
            int skipped;
            var res = MainForm.AnsiSafePaths(
                new List<string> { @"C:\Users\x\file.exe", @"D:\a b\c.dll" }, Cp1251, out skipped);
            Assert.Equal(2, res.Count, "kept");
            Assert.Equal(0, skipped, "none skipped");
        }

        public static void TestCyrillicSurvivesItsOwnCodePage()
        {
            int skipped;
            var res = MainForm.AnsiSafePaths(
                new List<string> { @"C:\Users\Олексій\Завантаження\файл.exe" }, Cp1251, out skipped);
            Assert.Equal(1, res.Count, "kept");
            Assert.Equal(@"C:\Users\Олексій\Завантаження\файл.exe", res[0], "unchanged");
        }

        public static void TestUnrepresentablePathIsSkippedAndCounted()
        {
            int skipped;
            var res = MainForm.AnsiSafePaths(
                new List<string> { @"C:\ok.exe", "C:\\snow☃man.exe", "C:\\emoji\U0001F600.dll" },
                Cp1251, out skipped);
            Assert.Equal(1, res.Count, "only the ASCII path kept");
            Assert.Equal(2, skipped, "two skipped");
        }

        public static void TestEmptyListIsFine()
        {
            int skipped;
            var res = MainForm.AnsiSafePaths(new List<string>(), Cp1251, out skipped);
            Assert.Equal(0, res.Count, "empty");
            Assert.Equal(0, skipped, "none skipped");
        }
    }

    // Verdict tiers for files flagged only by a YARA rule (held back until the
    // VirusTotal answer decides quarantine / release / user decision).
    public static class VtClassifyTests
    {
        public static void TestThresholdConfirms()
        {
            Assert.Equal(VtVerdict.Confirmed, MainForm.VtClassify(200, 3, 0, 70), "3 engines");
            Assert.Equal(VtVerdict.Confirmed, MainForm.VtClassify(200, 45, 1, 70), "many engines");
        }

        public static void TestCleanWithEnoughVerdictsIsLikelyClean()
        {
            Assert.Equal(VtVerdict.LikelyClean, MainForm.VtClassify(200, 0, 0, 72), "0/72");
            Assert.Equal(VtVerdict.LikelyClean, MainForm.VtClassify(200, 0, 0, 20), "exactly at the minimum");
        }

        public static void TestCleanWithTooFewVerdictsIsInconclusive()
        {
            // a 200 whose stats failed to parse (all zeros) must NOT clear the file
            Assert.Equal(VtVerdict.Inconclusive, MainForm.VtClassify(200, 0, 0, 0), "unparsed stats");
            Assert.Equal(VtVerdict.Inconclusive, MainForm.VtClassify(200, 0, 0, 19), "below the minimum");
        }

        public static void TestFewFlagsAreInconclusive()
        {
            Assert.Equal(VtVerdict.Inconclusive, MainForm.VtClassify(200, 1, 0, 70), "1 engine");
            Assert.Equal(VtVerdict.Inconclusive, MainForm.VtClassify(200, 2, 5, 70), "2 engines + suspicious");
            Assert.Equal(VtVerdict.Inconclusive, MainForm.VtClassify(200, 0, 4, 70), "suspicious only");
        }

        public static void TestNotFoundIsUnknown()
        {
            Assert.Equal(VtVerdict.Unknown, MainForm.VtClassify(404, 0, 0, 0), "404");
        }

        public static void TestErrorsAreUnavailable()
        {
            Assert.Equal(VtVerdict.Unavailable, MainForm.VtClassify(0, 0, 0, 0), "network error");
            Assert.Equal(VtVerdict.Unavailable, MainForm.VtClassify(401, 0, 0, 0), "bad key");
            Assert.Equal(VtVerdict.Unavailable, MainForm.VtClassify(500, 0, 0, 0), "server error");
        }
    }
}
