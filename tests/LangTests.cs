// Tests for the two-language string table (src\Lang.cs).
using System;
using System.Text;
using System.Text.RegularExpressions;
using AVUI;

namespace AVUI.Tests
{
    static class LangTests
    {
        // ---- Table-wide property tests: every entry, not hand-picked lists ----
        // The per-feature tests below stay: they additionally assert that the
        // Ukrainian text is a real translation (differs from English), which
        // can't be required table-wide — brand keys are identical on purpose.

        public static void TestEveryKeyExistsInBothLanguages()
        {
            int keys = 0;
            foreach (string key in Lang.AllKeys())
            {
                keys++;
                Assert.True(Lang.Raw(Lang.Language.Ukrainian, key) != null,
                    key + " is missing from the Ukrainian table");
            }
            Assert.True(keys > 300, "the table enumerates (got " + keys + " keys)");
            // same count + every English key present above = the key sets are equal
            Assert.Equal(keys, Lang.CountFor(Lang.Language.Ukrainian), "no Ukrainian-only keys");
        }

        public static void TestEveryEntryKeepsItsPlaceholders()
        {
            // a {N} present in one language but not the other makes string.Format
            // throw or silently drop data at the call site — for every entry the
            // placeholder sets must match exactly
            foreach (string key in Lang.AllKeys())
                Assert.Equal(
                    Placeholders(Lang.Raw(Lang.Language.English, key)),
                    Placeholders(Lang.Raw(Lang.Language.Ukrainian, key)),
                    key + ": {N} placeholders differ between English and Ukrainian");
        }

        // Sorted, de-duplicated list of {N} indices ("0,1,") — format specs like
        // {0:HH:mm} count as their index; alignment/format details may differ
        static string Placeholders(string s)
        {
            var seen = new System.Collections.Generic.SortedDictionary<int, bool>();
            foreach (Match m in Regex.Matches(s, "\\{(\\d+)"))
                seen[int.Parse(m.Groups[1].Value)] = true;
            var sb = new StringBuilder();
            foreach (var kv in seen) sb.Append(kv.Key).Append(',');
            return sb.ToString();
        }

        public static void TestEnglishLookup()
        {
            using (new LangScope(Lang.Language.English))
                Assert.Equal("Ready.", Lang.T("status.ready"), "English string");
        }

        public static void TestUkrainianLookup()
        {
            using (new LangScope(Lang.Language.Ukrainian))
                Assert.Equal("Готово.", Lang.T("status.ready"), "Ukrainian string");
        }

        public static void TestUnknownKeyReturnsTheKeyItself()
        {
            using (new LangScope(Lang.Language.English))
                Assert.Equal("no.such.key", Lang.T("no.such.key"), "unknown key falls through to itself");
            using (new LangScope(Lang.Language.Ukrainian))
                Assert.Equal("no.such.key", Lang.T("no.such.key"), "same in Ukrainian");
        }

        public static void TestNewKeysExistInBothLanguages()
        {
            // scheduler + license strings added in 0.0.7 — a key that falls back to
            // itself (or to English in the Ukrainian table) means a missing A() entry
            string[] keys =
            {
                "settings.schedule", "sched.off", "sched.daily", "sched.weekly",
                "sstat.schedule", "status.schedOff", "status.schedDaily", "status.schedWeekly",
                "log.scheduledScanStart", "tray.scheduledScan", "about.license"
            };
            foreach (string key in keys)
            {
                string en, uk;
                using (new LangScope(Lang.Language.English)) en = Lang.T(key);
                using (new LangScope(Lang.Language.Ukrainian)) uk = Lang.T(key);
                Assert.True(en != key, key + " exists in English");
                Assert.True(uk != key && uk != en, key + " has its own Ukrainian translation");
            }
        }

        public static void TestV008KeysExistInBothLanguages()
        {
            // notifications toggle + DB version-check error added in 0.0.8
            string[] keys = { "settings.notifications", "err.versionCheckFailed" };
            foreach (string key in keys)
            {
                string en, uk;
                using (new LangScope(Lang.Language.English)) en = Lang.T(key);
                using (new LangScope(Lang.Language.Ukrainian)) uk = Lang.T(key);
                Assert.True(en != key, key + " exists in English");
                Assert.True(uk != key && uk != en, key + " has its own Ukrainian translation");
            }
        }

        public static void TestSaveErrorKeysExistInBothLanguages()
        {
            // save-failure diagnostics moved from hardcoded English into the table
            string[] keys = { "log.settingsSaveFailed", "log.vtKeySaveFailed" };
            foreach (string key in keys)
            {
                string en, uk;
                using (new LangScope(Lang.Language.English)) en = Lang.T(key);
                using (new LangScope(Lang.Language.Ukrainian)) uk = Lang.T(key);
                Assert.True(en != key, key + " exists in English");
                Assert.True(uk != key && uk != en, key + " has its own Ukrainian translation");
                Assert.True(en.Contains("{0}") && uk.Contains("{0}"), key + " keeps {0} in both languages");
            }
        }

        public static void TestStaleDbKeysExistInBothLanguages()
        {
            // the stale-database hero state (offline UX polish)
            string[] keys = { "hero.dbStale", "hero.dbStaleSub" };
            foreach (string key in keys)
            {
                string en, uk;
                using (new LangScope(Lang.Language.English)) en = Lang.T(key);
                using (new LangScope(Lang.Language.Ukrainian)) uk = Lang.T(key);
                Assert.True(en != key, key + " exists in English");
                Assert.True(uk != key && uk != en, key + " has its own Ukrainian translation");
            }
            using (new LangScope(Lang.Language.English))
                Assert.True(Lang.T("hero.dbStaleSub").Contains("{0}"), "hero.dbStaleSub keeps its {0} placeholder (English)");
            using (new LangScope(Lang.Language.Ukrainian))
                Assert.True(Lang.T("hero.dbStaleSub").Contains("{0}"), "hero.dbStaleSub keeps its {0} placeholder (Ukrainian)");
        }

        public static void TestFirstRunChoiceKeepsBothPlaceholders()
        {
            // {0} = the portable folder, {1} = the per-user install dir (added in
            // 0.0.8) — the call site formats with both arguments in this order
            foreach (Lang.Language lang in new Lang.Language[] { Lang.Language.English, Lang.Language.Ukrainian })
                using (new LangScope(lang))
                {
                    string s = Lang.T("msg.firstRunModeChoice");
                    Assert.True(s.Contains("{0}"), "firstRunModeChoice (" + lang + ") keeps {0}");
                    Assert.True(s.Contains("{1}"), "firstRunModeChoice (" + lang + ") keeps {1}");
                    Assert.True(Lang.T("msg.installConfirm").Contains("{0}"),
                        "installConfirm (" + lang + ") keeps {0}");
                }
        }

        public static void TestFormatPlaceholdersSurviveTranslation()
        {
            // keys used with string.Format must keep their placeholders in both languages
            string[] formatKeys = { "settings.monitorLabel", "status.progress", "hero.dbFrom", "msg.deleteConfirm", "about.version" };
            foreach (string key in formatKeys)
            {
                string en, uk;
                using (new LangScope(Lang.Language.English)) en = Lang.T(key);
                using (new LangScope(Lang.Language.Ukrainian)) uk = Lang.T(key);
                Assert.True(en.Contains("{0}"), key + " (en) keeps {0}");
                Assert.True(uk.Contains("{0}"), key + " (uk) keeps {0}");
            }
        }

        public static void TestPhaseAndVtSummaryKeysExistInBothLanguages()
        {
            // v0.0.5: scan phase labels, YARA phase progress, VT verdict summary
            string[] keys =
            {
                "phase.label", "status.vtPending", "status.yaraProgress", "log.hbYaraPct",
                "log.vtPendingAllClean", "tray.vtPendingAllClean",
                "log.vtPendingDone", "tray.vtPendingDone"
            };
            foreach (string key in keys)
            {
                string en, uk;
                using (new LangScope(Lang.Language.English)) en = Lang.T(key);
                using (new LangScope(Lang.Language.Ukrainian)) uk = Lang.T(key);
                Assert.True(en != key, key + " exists in English");
                Assert.True(uk != key && uk != en, key + " has its own Ukrainian translation");
            }
        }

        public static void TestPhaseAndVtSummaryKeysAreFormattable()
        {
            // each key must keep the placeholders its call site formats with
            foreach (Lang.Language lang in new Lang.Language[] { Lang.Language.English, Lang.Language.Ukrainian })
                using (new LangScope(lang))
                {
                    string s = string.Format(Lang.T("phase.label"), 2, 3);
                    Assert.True(s.Contains("2") && s.Contains("3"), "phase.label (" + lang + ") keeps {0} and {1}");
                    s = string.Format(Lang.T("status.vtPending"), 4, 7);
                    Assert.True(s.Contains("4") && s.Contains("7"), "status.vtPending (" + lang + ") keeps {0} and {1}");
                    s = string.Format(Lang.T("status.yaraProgress"), 42.0, ", ~1m");
                    Assert.True(s.Contains("42") && s.Contains("~1m"), "status.yaraProgress (" + lang + ") keeps {0} and {1}");
                    s = string.Format(Lang.T("log.hbYaraPct"), DateTime.Now, "5s", 42.0);
                    Assert.True(s.Contains("42") && s.Contains("5s"), "log.hbYaraPct (" + lang + ") keeps {1} and {2}");
                    s = string.Format(Lang.T("tray.vtPendingAllClean"), 6);
                    Assert.True(s.Contains("6"), "tray.vtPendingAllClean (" + lang + ") keeps {0}");
                    s = string.Format(Lang.T("log.vtPendingAllClean"), 6);
                    Assert.True(s.Contains("6"), "log.vtPendingAllClean (" + lang + ") keeps {0}");
                    s = string.Format(Lang.T("tray.vtPendingDone"), 4, 7);
                    Assert.True(s.Contains("4") && s.Contains("7"), "tray.vtPendingDone (" + lang + ") keeps {0} and {1}");
                    s = string.Format(Lang.T("log.vtPendingDone"), 4, 7);
                    Assert.True(s.Contains("4") && s.Contains("7"), "log.vtPendingDone (" + lang + ") keeps {0} and {1}");
                }
        }

        public static void TestVtWaitHeroKeysExistInBothLanguages()
        {
            // the busy hero shown while a finished scan waits for its held-back
            // VirusTotal verdicts (the scan now ends with the last verdict)
            string[] keys = { "hero.vtWaitTitle", "hero.vtWaitSub" };
            foreach (string key in keys)
            {
                string en, uk;
                using (new LangScope(Lang.Language.English)) en = Lang.T(key);
                using (new LangScope(Lang.Language.Ukrainian)) uk = Lang.T(key);
                Assert.True(en != key, key + " exists in English");
                Assert.True(uk != key && uk != en, key + " has its own Ukrainian translation");
            }
        }

        public static void TestVtOfflineKeysExistInBothLanguages()
        {
            // the "no internet" state of the VirusTotal cell (engines strip) and
            // its longer wording in the Engines dialog
            string[] keys = { "sval.vtOffline", "engines.vtStatusOffline" };
            foreach (string key in keys)
            {
                string en, uk;
                using (new LangScope(Lang.Language.English)) en = Lang.T(key);
                using (new LangScope(Lang.Language.Ukrainian)) uk = Lang.T(key);
                Assert.True(en != key, key + " exists in English");
                Assert.True(uk != key && uk != en, key + " has its own Ukrainian translation");
            }
        }

        public static void TestBrandButtonKeysExist()
        {
            // btn.ok / btn.virustotal are deliberately identical in both languages
            // (OK and the VirusTotal brand name) — they only must exist in the table
            foreach (Lang.Language lang in new Lang.Language[] { Lang.Language.English, Lang.Language.Ukrainian })
                using (new LangScope(lang))
                {
                    Assert.Equal("OK", Lang.T("btn.ok"), "btn.ok (" + lang + ")");
                    Assert.Equal("VIRUSTOTAL", Lang.T("btn.virustotal"), "btn.virustotal (" + lang + ")");
                }
        }

        public static void TestTimeFormatsAreFormattable()
        {
            // the FormatSpan patterns must be valid string.Format inputs in both languages
            foreach (Lang.Language lang in new Lang.Language[] { Lang.Language.English, Lang.Language.Ukrainian })
                using (new LangScope(lang))
                {
                    string.Format(Lang.T("time.hm"), 1.0, 2.0);
                    string.Format(Lang.T("time.ms"), 1.0, 2.0);
                    string.Format(Lang.T("time.s"), 1.0); // throws FormatException if broken
                }
        }
    }
}
