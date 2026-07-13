// Tests for the YARA output parser and the VirusTotal response parser.
using System;
using AVUI;

namespace AVUI.Tests
{
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
}
