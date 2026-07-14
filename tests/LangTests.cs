// Tests for the two-language string table (src\Lang.cs).
using System;
using AVUI;

namespace AVUI.Tests
{
    static class LangTests
    {
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
