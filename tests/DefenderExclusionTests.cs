// Tests for the scope of the Windows Defender exclusion (src\MainForm.Install.cs).
//
// The exclusion exists because two of this app's own files read as malware to
// Defender: the YARA rule set (literal malware strings by construction) and the
// unsigned released exe (a cloud reputation verdict, not a signature). One
// exclusion on the install folder covers both — but only when there IS an
// install folder. A portable run's "own folder" is whatever the user dropped
// the exe into, and excluding Downloads or a USB stick from Defender would be a
// real hole in its coverage rather than a fix for ours. That distinction is the
// load-bearing part, so it is pinned here.
using System;
using AVUI;

namespace AVUI.Tests
{
    static class DefenderExclusionTests
    {
        const string Installed = @"C:\Users\u\AppData\Local\Programs\AV";
        const string Portable = @"C:\Users\u\Downloads";

        public static void TestInstalledExcludesTheWholeInstallFolder()
        {
            Assert.Equal(Installed,
                MainForm.DefenderExclusionDirFor(true, Installed, Installed + @"\yara"),
                "an install must exclude its own folder, so AV.exe is covered as well as the rules");
        }

        public static void TestPortableExcludesOnlyTheYaraFolder()
        {
            string dir = MainForm.DefenderExclusionDirFor(false, Installed, Portable + @"\yara");
            Assert.Equal(Portable + @"\yara", dir,
                "a portable run must exclude only its yara folder");
            Assert.False(dir == Portable,
                "a portable run must never exclude the folder the exe was dropped into");
        }

        // The exclusion is handed to Defender as a path string; a trailing
        // separator on it is not worth risking against an API we can't query back
        // (reading exclusions needs admin), so both scopes are normalized.
        public static void TestTrailingSeparatorIsStripped()
        {
            Assert.Equal(Installed,
                MainForm.DefenderExclusionDirFor(true, Installed + @"\", Installed + @"\yara"),
                "the install path must be normalized before it is excluded");
            Assert.Equal(Portable + @"\yara",
                MainForm.DefenderExclusionDirFor(false, Installed, Portable + @"\yara\"),
                "the yara path must be normalized before it is excluded");
        }
    }
}
