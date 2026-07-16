// Process-memory scanning for Quick Scan: reads the executable, non-image
// regions (injected shellcode, unpacked/reflectively-loaded code) out of every
// running process' RAM and dumps them to temp files so clamd can scan them.
// This catches payloads that are masked or absent on disk but live in memory.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace AVUI
{
    public partial class MainForm : Form
    {
        readonly List<string> memDumpPaths = new List<string>(); // dumped RAM regions to scan then delete
        string memDumpDir; // temp folder holding this scan's dumps

        // Should this committed region be dumped and scanned? Only executable code
        // pages that are NOT backed by an on-disk image (MEM_IMAGE) — those are the
        // masked/injected ones; image code is already covered by the file scan. Guard
        // and no-access pages are skipped (unreadable), and absurdly large regions are
        // capped so a single process can't make the scan dump gigabytes.
        internal static bool ShouldDumpRegion(uint state, uint protect, uint type, long regionSize, long maxRegionBytes)
        {
            const uint MEM_COMMIT = 0x1000;
            const uint MEM_IMAGE = 0x1000000;
            const uint PAGE_NOACCESS = 0x01;
            const uint PAGE_GUARD = 0x100;
            const uint EXEC_MASK = 0x10 | 0x20 | 0x40 | 0x80; // EXECUTE, _READ, _READWRITE, _WRITECOPY
            if (state != MEM_COMMIT) return false;
            if ((protect & PAGE_GUARD) != 0) return false;
            if ((protect & PAGE_NOACCESS) != 0) return false;
            if ((protect & EXEC_MASK) == 0) return false; // only executable code
            if (type == MEM_IMAGE) return false;          // clean disk-backed image — scanned as a file
            if (regionSize <= 0) return false;
            if (maxRegionBytes > 0 && regionSize > maxRegionBytes) return false;
            return true;
        }

        // Strips characters that can't appear in a file name so the dump can encode
        // the source process name (which shows up on any FOUND line in the log).
        internal static string SanitizeName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "proc";
            var sb = new StringBuilder(name.Length);
            foreach (char c in name)
                sb.Append(Array.IndexOf(Path.GetInvalidFileNameChars(), c) >= 0 ? '_' : c);
            string s = sb.ToString();
            return s.Length == 0 ? "proc" : s;
        }

        // Skip any single region larger than this. Kept small on purpose: real
        // injected/masked code (shellcode, beacons, reflectively-loaded DLLs) is
        // almost always a few MB at most, while the big executable regions are benign
        // JIT/browser code — and scanning a raw code blob is expensive per byte, so a
        // few large ones dominate the whole quick scan. 16 MB covers the payloads that
        // matter without making clamd chew tens of MB of harmless JIT.
        const long MemMaxRegionBytes = 16L * 1024 * 1024;
        const long MemMaxTotalBytes = 128L * 1024 * 1024;   // overall cap so a scan never fills the disk or dominates its time

        // Walks every accessible process' address space and dumps the qualifying
        // regions to memDumpDir. Runs on the background listing thread; stops on
        // its session's cancel flag OR when a newer scan superseded this one
        // (gen != countGen) — the gen guard protects the shared
        // memDumpDir/memDumpPaths from a stale dump thread racing the new scan.
        // Returns the dump file paths.
        List<string> DumpRunningProcessMemory(ScanSession ses, int gen, out int procCount, out int regionCount, out long totalBytes)
        {
            procCount = 0; regionCount = 0; totalBytes = 0;
            var files = new List<string>();
            try
            {
                memDumpDir = Path.Combine(Path.GetTempPath(), "av-mem-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(memDumpDir);
            }
            catch { memDumpDir = null; return files; }

            int selfPid = 0;
            try { selfPid = Process.GetCurrentProcess().Id; } catch { }

            foreach (Process p in Process.GetProcesses())
            {
                // when stopping, keep iterating (skipping the work) so every Process
                // in the snapshot still gets disposed instead of leaking handles
                bool stop = ses.Cancel || gen != countGen || totalBytes >= MemMaxTotalBytes;
                int pid = 0; string pname = "proc";
                if (!stop) { try { pid = p.Id; pname = p.ProcessName; } catch { } }
                try { p.Dispose(); } catch { }
                if (stop || pid == 0 || pid == selfPid) continue; // never scan our own RAM

                IntPtr h = MemNative.OpenProcess(
                    MemNative.PROCESS_QUERY_INFORMATION | MemNative.PROCESS_VM_READ, false, pid);
                if (h == IntPtr.Zero) continue; // protected / higher-integrity process — no access
                procCount++;
                try
                {
                    IntPtr addr = IntPtr.Zero;
                    MemNative.MEMORY_BASIC_INFORMATION mbi;
                    uint mbiSize = (uint)Marshal.SizeOf(typeof(MemNative.MEMORY_BASIC_INFORMATION));
                    while (MemNative.VirtualQueryEx(h, addr, out mbi, mbiSize) != IntPtr.Zero)
                    {
                        long regionSize = mbi.RegionSize.ToInt64();
                        if (regionSize <= 0) break;
                        if (!ses.Cancel && gen == countGen && totalBytes < MemMaxTotalBytes
                            && ShouldDumpRegion(mbi.State, mbi.Protect, mbi.Type, regionSize, MemMaxRegionBytes))
                        {
                            long wrote;
                            string f = DumpRegion(h, mbi.BaseAddress, regionSize, pname, pid, out wrote);
                            if (f != null)
                            {
                                totalBytes += wrote;
                                files.Add(f);
                                regionCount++;
                            }
                        }
                        long next = mbi.BaseAddress.ToInt64() + regionSize;
                        if (next <= addr.ToInt64()) break; // no forward progress — avoid an infinite loop
                        addr = new IntPtr(next);
                        if (ses.Cancel || gen != countGen || totalBytes >= MemMaxTotalBytes) break;
                    }
                }
                catch { }
                finally { MemNative.CloseHandle(h); }
            }
            lock (memDumpPaths) memDumpPaths.AddRange(files);
            return files;
        }

        // Reads one region out of the target process and writes it to a temp .bin,
        // named so the log's FOUND line points at the source process.
        string DumpRegion(IntPtr h, IntPtr baseAddr, long size, string pname, int pid, out long bytesWritten)
        {
            bytesWritten = 0;
            try
            {
                var buf = new byte[size];
                IntPtr read;
                if (!MemNative.ReadProcessMemory(h, baseAddr, buf, new IntPtr(size), out read)) return null;
                int n = (int)read.ToInt64();
                if (n <= 0) return null;
                string name = SanitizeName(pname) + "_pid" + pid
                    + "_0x" + baseAddr.ToInt64().ToString("x") + ".bin";
                string path = Path.Combine(memDumpDir, name);
                using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write))
                    fs.Write(buf, 0, n);
                bytesWritten = n;
                return path;
            }
            catch { return null; } // region freed / unreadable / disk error — skip
        }

        // Deletes this scan's RAM dumps and their folder. Called at the very end of a
        // scan (after the threat dialog, so found dumps stay listable) and on exit.
        void CleanupMemDumps()
        {
            lock (memDumpPaths)
            {
                foreach (string p in memDumpPaths) TryDelete(p);
                memDumpPaths.Clear();
            }
            if (memDumpDir != null)
            {
                try { if (Directory.Exists(memDumpDir)) Directory.Delete(memDumpDir, true); } catch { }
                memDumpDir = null;
            }
        }

        static class MemNative
        {
            public const uint PROCESS_QUERY_INFORMATION = 0x0400;
            public const uint PROCESS_VM_READ = 0x0010;

            [StructLayout(LayoutKind.Sequential)]
            public struct MEMORY_BASIC_INFORMATION
            {
                public IntPtr BaseAddress;
                public IntPtr AllocationBase;
                public uint AllocationProtect;
                public IntPtr RegionSize;
                public uint State;
                public uint Protect;
                public uint Type;
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

            [DllImport("kernel32.dll")]
            public static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr,
                out MEMORY_BASIC_INFORMATION mbi, uint length);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr,
                byte[] buffer, IntPtr size, out IntPtr bytesRead);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool CloseHandle(IntPtr h);
        }
    }
}
