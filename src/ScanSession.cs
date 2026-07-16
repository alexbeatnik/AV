// Per-scan state. One instance is created by ResetScanState when a scan starts
// and the MainForm.scan field keeps referencing it until the next scan replaces
// it, so late readers (the threat dialog, the scans.log writer, VirusTotal
// verdicts for the just-finished scan) still see the finished scan's numbers.
//
// Background workers (the file-listing thread, the clamd starter, the YARA
// workload sizer) capture the instance they were started for — a superseded
// scan's late writes land in its own dead object instead of corrupting the
// next scan's state. Everything in here dies with the scan; state that must
// outlive it stays on MainForm: vtPendingYara (verdicts arrive minutes later),
// the cumulative statistics, the clamd daemon, and the memory-dump paths
// (cleaned after the modal threat dialog).
//
// All non-volatile members are owned by the UI thread. The volatile ones are
// the only cross-thread traffic: Cancel/Listing/Listed are shared with the
// listing thread, YaraTotalBytes goes through Interlocked.
using System;
using System.Collections.Generic;

namespace AVUI
{
    sealed class ScanSession
    {
        public bool Running;             // scan in progress (any phase, incl. listing)
        public bool Monitor;             // triggered by the folder monitor, not the user
        public volatile bool Cancel;     // Stop pressed — every phase exit and background walker checks it
        public string Desc = "";         // human description for scans.log / the quarantine index

        // ClamAV phase: counters driven by clamscan/clamdscan output lines
        public int Scanned, Found, Moved;
        public readonly List<string[]> FoundFiles = new List<string[]>(); // {path, threat name}
        public int TotalToScan;          // exact workload, known once the file list is built
        public int InitialTotal;         // TotalToScan snapshot for the "skipped files" summary line
        public DateTime Started;
        public DateTime LastOutput;      // last scanner output (detects "stuck on a big file")
        public bool LoggedTotal;         // "Files to check: N" already logged

        // ETA: moving-window rate estimate (see UpdateScanProgress)
        public DateTime RateWinTime;     // MinValue = window not started
        public int RateWinCount;
        public string LastEta = "";      // last estimate ("~5m"), reused by the heartbeat

        // File-listing stage (shared with the background listing thread)
        public volatile bool Listing;    // list is being built, the scanner hasn't started yet
        public volatile int Listed;      // files listed so far (heartbeat/status readout)

        // Parallel clamdscan bookkeeping
        public int ProcsLeft;            // running clamdscan children; 0 → the ClamAV phase is over
        public int AggExit;              // aggregated exit code across the chunks

        // YARA phase (see MainForm.Yara.cs)
        public string YaraListPath;      // this scan's file list, reused by the YARA pass
        public bool YaraPhasePending;    // YARA should follow the ClamAV part
        public bool YaraPhaseExpected;   // YaraReady() snapshot at scan start — drives only the phase label
        public int YaraClamCode;         // ClamAV exit code, held while the YARA phase runs
        public DateTime YaraPhaseStart;  // MinValue = the phase didn't run
        public volatile bool YaraRunning;
        public readonly Dictionary<string, string> YaraMatches
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); // path → rule
        public long YaraTotalBytes;      // progress denominator; Interlocked (sized on a worker thread)
        public double YaraLastFraction;  // last progress estimate, reused by the heartbeat
        public int YaraErrLines;         // non-match yara output lines (warnings, unreadable files)
    }
}
