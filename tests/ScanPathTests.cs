// Tests for quick-scan root merging and the clamscan exclusion regex.
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using AVUI;

namespace AVUI.Tests
{
    static class ScanRootMergeTests
    {
        public static void TestNestedRootIsAbsorbed()
        {
            var list = new List<string>();
            MainForm.MergeScanRoot(list, @"C:\Users\bob\AppData\Local");
            MainForm.MergeScanRoot(list, @"C:\Users\bob\AppData\Local\Temp");
            Assert.Equal(1, list.Count, "child of an existing root is not added");
            Assert.Equal(@"C:\Users\bob\AppData\Local", list[0], "the broad root is kept");
        }

        public static void TestBroaderRootReplacesNarrower()
        {
            var list = new List<string>();
            MainForm.MergeScanRoot(list, @"C:\Users\bob\AppData\Local\Temp");
            MainForm.MergeScanRoot(list, @"C:\Users\bob\AppData\Roaming");
            MainForm.MergeScanRoot(list, @"C:\Users\bob\AppData");
            Assert.Equal(1, list.Count, "both narrower roots absorbed by the broader one");
            Assert.Equal(@"C:\Users\bob\AppData", list[0], "the broader root wins");
        }

        public static void TestUnrelatedRootsAccumulate()
        {
            var list = new List<string>();
            MainForm.MergeScanRoot(list, @"C:\Users\bob\Downloads");
            MainForm.MergeScanRoot(list, @"D:\Data");
            Assert.Equal(2, list.Count, "unrelated roots are both kept");
        }

        public static void TestSamePrefixSiblingIsNotMerged()
        {
            var list = new List<string>();
            MainForm.MergeScanRoot(list, @"C:\Program Files");
            MainForm.MergeScanRoot(list, @"C:\Program Files (x86)");
            Assert.Equal(2, list.Count, "a sibling sharing a name prefix stays separate");
        }

        public static void TestDuplicateRootIsIgnored()
        {
            var list = new List<string>();
            MainForm.MergeScanRoot(list, @"C:\Users\bob\Downloads");
            MainForm.MergeScanRoot(list, @"C:\Users\bob\Downloads");
            Assert.Equal(1, list.Count, "an exact duplicate is not added twice");
        }
    }

    static class ExcludeRegexTests
    {
        public static void TestMatchesTheFolderItselfAndItsContents()
        {
            string rx = MainForm.ExcludePathRegex(@"C:\Users\bob\quarantine");
            Assert.True(Regex.IsMatch(@"C:\Users\bob\quarantine", rx), "the folder itself");
            Assert.True(Regex.IsMatch(@"C:\Users\bob\quarantine\evil.exe", rx), "a file inside");
            Assert.True(Regex.IsMatch(@"C:\Users\bob\quarantine\a\b\c.dll", rx), "nested content");
        }

        public static void TestDoesNotMatchSiblingWithSamePrefix()
        {
            string rx = MainForm.ExcludePathRegex(@"C:\Users\bob\quarantine");
            Assert.False(Regex.IsMatch(@"C:\Users\bob\quarantine2\evil.exe", rx), "quarantine2 must not be excluded");
            Assert.False(Regex.IsMatch(@"C:\Users\bob\quarantine2", rx), "the sibling folder itself either");
        }

        public static void TestIsCaseInsensitive()
        {
            string rx = MainForm.ExcludePathRegex(@"C:\Users\bob\quarantine");
            Assert.True(Regex.IsMatch(@"c:\users\BOB\QUARANTINE\x.exe", rx), "path casing is ignored");
        }

        public static void TestSpecialRegexCharactersAreEscaped()
        {
            string rx = MainForm.ExcludePathRegex(@"C:\Program Files (x86)\App");
            Assert.True(Regex.IsMatch(@"C:\Program Files (x86)\App\a.exe", rx), "parentheses escaped, still matches");
            Assert.False(Regex.IsMatch(@"C:\Program Files x86\App\a.exe", rx), "no unescaped-group false positive");
        }

        public static void TestTrailingBackslashIsNormalized()
        {
            string rx = MainForm.ExcludePathRegex(@"C:\Users\bob\quarantine\");
            Assert.True(Regex.IsMatch(@"C:\Users\bob\quarantine\evil.exe", rx), "trailing backslash on input ignored");
            Assert.False(Regex.IsMatch(@"C:\Users\bob\quarantine2", rx), "sibling still not matched");
        }

        public static void TestOnlyMatchesFromTheStartOfThePath()
        {
            string rx = MainForm.ExcludePathRegex(@"C:\Temp");
            Assert.False(Regex.IsMatch(@"D:\backup\C:\Temp", rx), "anchored at the start");
            Assert.False(Regex.IsMatch(@"C:\Users\bob\Temp\x.exe", rx), "same-named folder elsewhere not matched");
        }
    }
}
