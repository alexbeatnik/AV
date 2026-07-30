// AV — a multi-engine antivirus UI for Windows: ClamAV + YARA rules +
// VirusTotal hash lookups. Dark theme, card-based dashboard.
// The metadata below is not decoration: a Win32 version resource with empty
// company/description/copyright fields is one of the features Defender's
// cloud ML model weighs when it scores an unsigned executable, and a sparse
// one contributed to the Trojan:Win32/Bearfoos.B!ml false positive on the
// released build. Keep these fields populated (see README, "Windows Defender
// flags the download").
using System.Reflection;

[assembly: AssemblyTitle("AV")]
[assembly: AssemblyProduct("AV")]
[assembly: AssemblyDescription("Multi-engine antivirus UI for Windows: ClamAV signatures, YARA rules and VirusTotal hash lookups.")]
[assembly: AssemblyCompany("Oleksii Poliakov")]
[assembly: AssemblyCopyright("Copyright 2026 Oleksii Poliakov — Apache License 2.0")]
[assembly: AssemblyVersion("0.1.8.0")]
[assembly: AssemblyFileVersion("0.1.8.0")]
