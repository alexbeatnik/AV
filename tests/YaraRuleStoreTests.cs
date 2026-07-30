// Tests for the neutralized YARA rule storage (src\MainForm.Yara.cs).
//
// A .yar file is tens of thousands of literal malware strings, so a resident
// AV reads the rule set as malware and deletes it — Defender detects the plain
// YARA Forge core rules as Trojan:HTML/Sonbokli.A!cl. The rules are therefore
// stored XOR-neutralized (the same transform the quarantine uses) and only
// unpacked into a per-scan working folder for as long as yara64 needs to read
// them. What matters here: the stored form never contains the plain rule text,
// and the unpacked copy never outlives the scan.
using System;
using System.Collections.Generic;
using System.IO;
using AVUI;

namespace AVUI.Tests
{
    static class YaraRuleStoreTests
    {
        // A rule body with the kind of literal strings that make an AV bite
        const string RuleText =
            "rule Trojan_Sample { strings: $a = \"malicious_payload_marker\" condition: $a }";

        static string PackRules(string path, string text)
        {
            string plain = path + ".src";
            File.WriteAllText(plain, text);
            MainForm.XorCopy(plain, path);
            File.Delete(plain);
            return path;
        }

        public static void TestStoredRulesDoNotContainThePlainText()
        {
            using (var dir = new TempDir())
            {
                string packed = PackRules(dir.File("forge-core.yarx"), RuleText);
                string onDisk = File.ReadAllText(packed);
                Assert.False(onDisk.Contains("malicious_payload_marker"),
                    "the stored rules must not carry the plain malware string");
                Assert.False(onDisk.Contains("rule Trojan_Sample"),
                    "the stored rules must not carry the plain rule header");
            }
        }

        public static void TestMaterializeUnpacksRulesIntoAWorkFolder()
        {
            using (var dir = new TempDir())
            {
                string packed = PackRules(dir.File("forge-core.yarx"), RuleText);
                string runRoot = dir.File("rules-run");
                string workDir;

                List<string> files = MainForm.MaterializeYaraRules(packed, null, runRoot, out workDir);

                Assert.Equal(1, files.Count, "the Forge set is the only rule file");
                Assert.True(workDir != null, "a work folder was created");
                Assert.True(MainForm.IsUnder(workDir, runRoot), "the work folder lives under the run root");
                Assert.Equal(RuleText, File.ReadAllText(files[0]), "the unpacked rules are the original text");
            }
        }

        public static void TestMaterializeKeepsConcurrentScansApart()
        {
            using (var dir = new TempDir())
            {
                string packed = PackRules(dir.File("forge-core.yarx"), RuleText);
                string runRoot = dir.File("rules-run");
                string firstDir, secondDir;

                List<string> first = MainForm.MaterializeYaraRules(packed, null, runRoot, out firstDir);
                List<string> second = MainForm.MaterializeYaraRules(packed, null, runRoot, out secondDir);

                Assert.False(firstDir == secondDir, "each scan gets its own work folder");
                Assert.False(first[0] == second[0], "neither scan unpacks over the other's file");
                Assert.True(File.Exists(first[0]) && File.Exists(second[0]), "both copies are readable");
            }
        }

        public static void TestMaterializePassesCustomRulesThroughUntouched()
        {
            using (var dir = new TempDir())
            {
                string packed = PackRules(dir.File("forge-core.yarx"), RuleText);
                string custom = dir.File("my.yar");
                File.WriteAllText(custom, "rule Mine { condition: true }");
                string runRoot = dir.File("rules-run");
                string workDir;

                var customList = new List<string>();
                customList.Add(custom);
                List<string> files = MainForm.MaterializeYaraRules(packed, customList, runRoot, out workDir);

                Assert.Equal(2, files.Count, "Forge set plus the custom file");
                Assert.Equal(custom, files[1], "the user's own file is used where it lies");
            }
        }

        // The rules having been eaten between the readiness check and the scan
        // is the whole failure mode this storage scheme exists for: it must
        // report "nothing to compile", not throw.
        public static void TestMaterializeWithoutStoredRulesYieldsNoWorkFolder()
        {
            using (var dir = new TempDir())
            {
                string runRoot = dir.File("rules-run");
                string workDir;

                List<string> files = MainForm.MaterializeYaraRules(
                    dir.File("gone.yarx"), null, runRoot, out workDir);

                Assert.Equal(0, files.Count, "no rules to compile");
                Assert.True(workDir == null, "nothing was unpacked, so there is nothing to clean");
            }
        }

        public static void TestCleanRemovesTheUnpackedRules()
        {
            using (var dir = new TempDir())
            {
                string packed = PackRules(dir.File("forge-core.yarx"), RuleText);
                string runRoot = dir.File("rules-run");
                string workDir;
                List<string> files = MainForm.MaterializeYaraRules(packed, null, runRoot, out workDir);

                MainForm.CleanYaraRunDir(workDir);

                Assert.False(Directory.Exists(workDir), "the work folder is gone");
                Assert.False(File.Exists(files[0]), "the plain rules do not outlive the scan");
                Assert.True(File.Exists(packed), "the stored rules survive");
            }
        }

        public static void TestCleanOnNullIsANoOp()
        {
            MainForm.CleanYaraRunDir(null); // the no-work-folder path must not throw
        }

        public static void TestSweepRemovesWorkFoldersLeftByACrash()
        {
            using (var dir = new TempDir())
            {
                string runRoot = dir.File("rules-run");
                string stale = Path.Combine(runRoot, "abc123");
                Directory.CreateDirectory(stale);
                File.WriteAllText(Path.Combine(stale, "forge-core.yar"), RuleText);

                MainForm.SweepYaraRunDir(runRoot);

                Assert.False(Directory.Exists(stale), "the leftover work folder is swept");
            }
        }

        public static void TestSweepOnMissingRootIsANoOp()
        {
            MainForm.SweepYaraRunDir(Path.Combine(Path.GetTempPath(),
                "av-tests-no-such-dir-" + Guid.NewGuid().ToString("N"))); // must not throw
        }

        public static void TestMigrateNeutralizesALegacyPlainRuleFile()
        {
            using (var dir = new TempDir())
            {
                string legacy = dir.File("forge-core.yar");
                string packed = dir.File("forge-core.yarx");
                File.WriteAllText(legacy, RuleText);

                MainForm.MigrateLegacyForgeRules(legacy, packed);

                Assert.False(File.Exists(legacy), "the plain file no longer sits on disk");
                Assert.True(File.Exists(packed), "the rules were carried over");
                Assert.False(File.ReadAllText(packed).Contains("malicious_payload_marker"),
                    "the carried-over rules are neutralized");

                string workDir;
                List<string> files = MainForm.MaterializeYaraRules(packed, null, dir.File("rules-run"), out workDir);
                Assert.Equal(RuleText, File.ReadAllText(files[0]), "and still unpack to the original rules");
            }
        }

        public static void TestMigrateDropsTheLegacyFileWhenAlreadyMigrated()
        {
            using (var dir = new TempDir())
            {
                string legacy = dir.File("forge-core.yar");
                string packed = PackRules(dir.File("forge-core.yarx"), RuleText);
                File.WriteAllText(legacy, "stale plain leftover");

                MainForm.MigrateLegacyForgeRules(legacy, packed);

                Assert.False(File.Exists(legacy), "the stale plain file is removed");
                string workDir;
                List<string> files = MainForm.MaterializeYaraRules(packed, null, dir.File("rules-run"), out workDir);
                Assert.Equal(RuleText, File.ReadAllText(files[0]), "the existing store was not overwritten");
            }
        }

        public static void TestMigrateWithoutALegacyFileIsANoOp()
        {
            using (var dir = new TempDir())
            {
                string packed = PackRules(dir.File("forge-core.yarx"), RuleText);
                MainForm.MigrateLegacyForgeRules(dir.File("forge-core.yar"), packed);
                Assert.True(File.Exists(packed), "an already-migrated install is untouched");
            }
        }
    }
}
