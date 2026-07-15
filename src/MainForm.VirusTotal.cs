// VirusTotal integration: SHA256 hash lookups for suspicious files (YARA-only
// detections, new files caught by the monitor) against the VirusTotal database
// of 70+ engines, plus an OPT-IN upload of files VT has never seen. By default
// only the hash ever leaves the machine; uploading makes the file available to
// all VT researchers, so it's off until the user explicitly enables it.
// The free API tier allows 4 requests/minute — a queue with a 16s interval
// keeps us inside that, and 429 responses trigger a longer pause.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace AVUI
{
    // What a VirusTotal answer means for a file that only a YARA rule flagged.
    internal enum VtVerdict
    {
        Confirmed,    // enough engines agree — a real threat
        LikelyClean,  // VT knows the file and no engine flags it — likely a YARA false positive
        Inconclusive, // a few engines flag it, or too few verdicts to trust a "clean"
        Unknown,      // VT has never seen the file — stays suspicious
        Unavailable   // no usable answer (bad key, network error)
    }

    public partial class MainForm : Form
    {
        string vtApiKey = "";        // lives in vt.key, its own file (empty = feature dormant); see SaveVtKey
        string vtKeyPath;            // <exe dir>\vt.key — set in LoadSettings
        bool vtCheckEnabled = true;  // settings: vtcheck=0 turns hash lookups off
        bool vtUploadEnabled;        // settings: vtupload=1 — OPT-IN, off by default
        readonly List<string[]> vtQueue = new List<string[]>(); // {path, hash-or-null}
        // Files flagged only by a YARA rule, held back (not quarantined, no threat
        // dialog) until the VirusTotal verdict arrives. The rate limit means the
        // verdict may land after another scan has started and reset the shared
        // scan state, so each entry carries its own scan's context:
        // path → {"YARA:<rule>", scan description}
        readonly Dictionary<string, string[]> vtPendingYara
            = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        // Threat verdicts that arrived while an unrelated scan was running:
        // parked here instead of that scan's foundFiles, surfaced by
        // FlushVtLateThreats once the scan is done. {path, threat, scan desc}
        readonly List<string[]> vtLateThreats = new List<string[]>();
        Timer vtTimer;
        volatile bool vtBusy;        // a lookup/upload is in flight
        DateTime vtPauseUntil;       // backoff after 429 / rejected key
        const int VtIntervalMs = 16000;           // free tier: 4 requests/minute
        const long VtUploadMaxBytes = 32 * 1048576; // the simple upload endpoint caps at 32 MB
        const int VtMaliciousThreshold = 3;       // engines flagging a file before we treat it as a threat

        bool VtActive { get { return vtCheckEnabled && vtApiKey.Length > 0; } }

        // Queues a file for a hash lookup. hash may be null — the worker computes
        // it then (kept off the UI thread). Runs on the UI thread only. Returns
        // false when the item was dropped (feature off / queue full) — a caller
        // deferring an action until the verdict must not wait in that case.
        bool VtQueueFile(string path, string hash)
        {
            if (!VtActive) return false;
            foreach (string[] q in vtQueue)
                if (string.Equals(q[0], path, StringComparison.OrdinalIgnoreCase)) return true; // already queued
            if (vtQueue.Count >= 100) return false;
            vtQueue.Add(new string[] { path, hash });
            if (vtTimer == null)
            {
                vtTimer = new Timer();
                vtTimer.Tick += delegate { OnVtTick(); };
            }
            if (!vtTimer.Enabled)
            {
                vtTimer.Interval = 1000; // first item goes out right away
                vtTimer.Start();
            }
            return true;
        }

        void OnVtTick()
        {
            vtTimer.Interval = VtIntervalMs; // steady rate after the first pop
            if (vtBusy || DateTime.Now < vtPauseUntil) return;
            if (vtQueue.Count == 0) { vtTimer.Stop(); return; }
            string[] item = vtQueue[0];
            vtQueue.RemoveAt(0);
            vtBusy = true;
            string path = item[0], hash = item[1], key = vtApiKey;
            System.Threading.ThreadPool.QueueUserWorkItem(delegate { VtLookupWorker(path, hash, key); });
        }

        void VtLookupWorker(string path, string hash, string key)
        {
            const System.Net.SecurityProtocolType Tls13 = (System.Net.SecurityProtocolType)12288;
            System.Net.ServicePointManager.SecurityProtocol |= System.Net.SecurityProtocolType.Tls12 | Tls13;
            int status = 0, mal = 0, susp = 0, total = 0;
            string err = null;
            try
            {
                if (hash == null) hash = Sha256OfQuarFile(path); // plain SHA256 for non-.quar files
                var req = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(
                    "https://www.virustotal.com/api/v3/files/" + hash);
                req.Headers["x-apikey"] = key;
                req.UserAgent = "AV";
                req.Timeout = 30000;
                try
                {
                    using (var resp = (System.Net.HttpWebResponse)req.GetResponse())
                    using (var sr = new StreamReader(resp.GetResponseStream()))
                    {
                        status = (int)resp.StatusCode;
                        string json = sr.ReadToEnd();
                        VtParseStats(json, out mal, out susp, out total);
                    }
                }
                catch (System.Net.WebException we)
                {
                    var resp = we.Response as System.Net.HttpWebResponse;
                    if (resp != null) status = (int)resp.StatusCode;
                    else err = we.Message;
                }
            }
            catch (Exception ex) { err = ex.Message; }
            string fPath = path, fHash = hash, fErr = err;
            int fStatus = status, fMal = mal, fSusp = susp, fTotal = total;
            try
            {
                BeginInvoke((Action)delegate
                {
                    vtBusy = false;
                    VtOnResult(fPath, fHash, fStatus, fMal, fSusp, fTotal, fErr);
                });
            }
            catch { vtBusy = false; } // the form is already closed
        }

        // Extracts malicious/suspicious counts and the verdict total from the
        // "last_analysis_stats" object of a VT API v3 /files response.
        internal static bool VtParseStats(string json, out int malicious, out int suspicious, out int total)
        {
            malicious = suspicious = total = 0;
            if (json == null) return false;
            int i = json.IndexOf("\"last_analysis_stats\"", StringComparison.Ordinal);
            if (i < 0) return false;
            int open = json.IndexOf('{', i);
            if (open < 0) return false;
            int close = json.IndexOf('}', open);
            if (close < 0) return false;
            string body = json.Substring(open + 1, close - open - 1);
            foreach (Match m in Regex.Matches(body, "\"([a-z\\-_]+)\"\\s*:\\s*(\\d+)"))
            {
                string name = m.Groups[1].Value;
                int v;
                if (!int.TryParse(m.Groups[2].Value, out v)) continue;
                if (name == "malicious") malicious = v;
                else if (name == "suspicious") suspicious = v;
                if (name == "malicious" || name == "suspicious"
                    || name == "harmless" || name == "undetected") total += v;
            }
            return total > 0;
        }

        // Maps a VT lookup outcome to a verdict tier for a YARA-flagged file. A
        // "clean" answer is only trusted when enough engines actually voted —
        // a 200 whose stats failed to parse (total 0) must not clear a file.
        internal static VtVerdict VtClassify(int status, int mal, int susp, int total)
        {
            if (status == 200)
            {
                if (mal >= VtMaliciousThreshold) return VtVerdict.Confirmed;
                if (mal == 0 && susp == 0 && total >= 20) return VtVerdict.LikelyClean;
                return VtVerdict.Inconclusive;
            }
            if (status == 404) return VtVerdict.Unknown;
            return VtVerdict.Unavailable;
        }

        void VtOnResult(string path, string hash, int status, int mal, int susp, int total, string err)
        {
            string name = null;
            try { name = Path.GetFileName(path); } catch { name = path; }
            if (status == 429)
            {
                vtPauseUntil = DateTime.Now.AddMinutes(10);
                vtQueue.Insert(0, new string[] { path, hash }); // retry after the pause; a pending YARA file stays pending
                AppendLog(Lang.T("log.vtRateLimited"), Theme.Warn, "WARN", true);
                return;
            }
            if (status == 401 || status == 403)
            {
                vtPauseUntil = DateTime.Now.AddHours(1);
                AppendLog(Lang.T("log.vtBadKey"), Theme.Warn, "WARN", false);
            }
            // A file held back on YARA suspicion gets its own resolution path —
            // this is where "quarantine or not" is actually decided.
            string[] pendingYara;
            if (vtPendingYara.TryGetValue(path, out pendingYara))
            {
                vtPendingYara.Remove(path);
                ResolvePendingYara(path, name, pendingYara[0], pendingYara[1],
                    VtClassify(status, mal, susp, total),
                    mal, susp, total, err != null ? err : "HTTP " + status);
                return;
            }
            if (status == 200)
            {
                if (mal >= VtMaliciousThreshold)
                {
                    AppendLog(string.Format(Lang.T("log.vtMalicious"), mal, total, path), Theme.Danger, "INFECTED", false);
                    tray.ShowBalloonTip(8000, AppName,
                        string.Format(Lang.T("tray.vtMalicious"), mal, name), ToolTipIcon.Warning); // threat alerts always show
                    if (File.Exists(path))
                    {
                        string threat = "VirusTotal " + mal + "/" + total;
                        if (chkQuarantine.Checked)
                        {
                            QuarantineFile(path, threat, Lang.T("desc.vtCheck")); // bumps totalMoved itself
                            SaveSettings();
                            UpdateStatsUi();
                        }
                        else
                            VtReportThreat(path, threat, Lang.T("desc.vtCheck"));
                    }
                }
                else if (mal > 0 || susp > 0)
                    AppendLog(string.Format(Lang.T("log.vtSuspicious"), mal + susp, total, path), Theme.Warn, "WARN", false);
                else
                    AppendLog(string.Format(Lang.T("log.vtClean"), name, total), Theme.Muted, "OK", true);
            }
            else if (status == 404)
            {
                AppendLog(string.Format(Lang.T("log.vtUnknown"), name), Theme.Muted, null, false);
                if (vtUploadEnabled && File.Exists(path))
                    VtBeginUpload(path);
            }
            else if (status != 401 && status != 403)
                AppendLog(string.Format(Lang.T("log.vtError"), err != null ? err : "HTTP " + status), Theme.Warn, "WARN", true);
        }

        // Decides the fate of a file that was held back on a YARA-only match.
        // Confirmed → the normal threat flow with a combined threat name;
        // LikelyClean → released, nothing touched; everything else stays a
        // suspicion: silent quarantine when auto-quarantine is on (the user asked
        // for hands-off handling), the threat dialog otherwise.
        void ResolvePendingYara(string path, string name, string yaraThreat, string scanDesc,
            VtVerdict verdict, int mal, int susp, int total, string err)
        {
            if (!File.Exists(path))
            {
                AppendLog(string.Format(Lang.T("log.vtPendingGone"), name), Theme.Muted, null, true);
                return;
            }
            if (verdict == VtVerdict.LikelyClean)
            {
                AppendLog(string.Format(Lang.T("log.vtYaraLikelyFp"), path, total, yaraThreat), Theme.Good, "OK", false);
                return;
            }
            string threat = yaraThreat;
            if (verdict == VtVerdict.Confirmed)
            {
                threat = yaraThreat + " + VirusTotal " + mal + "/" + total;
                AppendLog(string.Format(Lang.T("log.vtYaraConfirmed"), mal, total, path), Theme.Danger, "INFECTED", false);
                tray.ShowBalloonTip(8000, AppName,
                    string.Format(Lang.T("tray.vtMalicious"), mal, name), ToolTipIcon.Warning); // threat alerts always show
            }
            else if (verdict == VtVerdict.Unknown)
            {
                AppendLog(string.Format(Lang.T("log.vtYaraUnknown"), name, yaraThreat), Theme.Warn, "WARN", false);
                // uploading needs the file in place — skip when quarantine is about to move it
                if (vtUploadEnabled && !chkQuarantine.Checked) VtBeginUpload(path);
            }
            else if (verdict == VtVerdict.Inconclusive)
                AppendLog(string.Format(Lang.T("log.vtYaraInconclusive"), mal + susp, total, path), Theme.Warn, "WARN", false);
            else // Unavailable
                AppendLog(string.Format(Lang.T("log.vtYaraUnavailable"), name, err), Theme.Warn, "WARN", false);

            if (chkQuarantine.Checked && QuarantineFile(path, threat, scanDesc))
            {
                AppendLog(string.Format(Lang.T("log.vtYaraQuarantined"), name), Theme.Warn, "WARN", false);
                SaveSettings();
                UpdateStatsUi();
                return;
            }
            // no auto-quarantine — or it failed (locked file): either way the user
            // must still get the threat dialog to decide what happens to the file
            VtReportThreat(path, threat, scanDesc);
        }

        // Puts a VT-confirmed threat in front of the user without touching a
        // running scan's foundFiles/currentScanDesc — the verdict may belong to
        // an earlier scan whose state was already reset.
        void VtReportThreat(string path, string threat, string scanDesc)
        {
            vtLateThreats.Add(new string[] { path, threat, scanDesc });
            if (!scanRunning) FlushVtLateThreats();
        }

        // Shows the parked verdicts in their own threat dialog. Called right away
        // when nothing is running, otherwise from FinishScan.
        void FlushVtLateThreats()
        {
            if (vtLateThreats.Count == 0) return;
            var late = new List<string[]>(vtLateThreats);
            vtLateThreats.Clear();
            RestoreFromTray();
            ShowThreatDialog(late);
        }

        // ---------- Opt-in upload of files unknown to VirusTotal ----------

        void VtBeginUpload(string path)
        {
            long size = 0;
            try { size = new FileInfo(path).Length; } catch { return; }
            if (size <= 0 || size > VtUploadMaxBytes)
            {
                AppendLog(string.Format(Lang.T("log.vtTooBigToUpload"), Path.GetFileName(path)), Theme.Muted, null, true);
                return;
            }
            AppendLog(string.Format(Lang.T("log.vtUploading"), Path.GetFileName(path)), Theme.Muted);
            vtBusy = true; // uploads share the same rate budget
            string key = vtApiKey;
            System.Threading.ThreadPool.QueueUserWorkItem(delegate { VtUploadWorker(path, key); });
        }

        void VtUploadWorker(string path, string key)
        {
            string err = null;
            try
            {
                const System.Net.SecurityProtocolType Tls13 = (System.Net.SecurityProtocolType)12288;
                System.Net.ServicePointManager.SecurityProtocol |= System.Net.SecurityProtocolType.Tls12 | Tls13;
                byte[] fileBytes = File.ReadAllBytes(path);
                string boundary = "----AVBoundary" + Guid.NewGuid().ToString("N");
                var req = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(
                    "https://www.virustotal.com/api/v3/files");
                req.Method = "POST";
                req.Headers["x-apikey"] = key;
                req.UserAgent = "AV";
                req.Timeout = 300000; // up to 32 MB on a slow uplink
                req.ContentType = "multipart/form-data; boundary=" + boundary;
                byte[] head = Encoding.UTF8.GetBytes(
                    "--" + boundary + "\r\n"
                    + "Content-Disposition: form-data; name=\"file\"; filename=\""
                    + Path.GetFileName(path).Replace("\"", "_") + "\"\r\n"
                    + "Content-Type: application/octet-stream\r\n\r\n");
                byte[] tail = Encoding.UTF8.GetBytes("\r\n--" + boundary + "--\r\n");
                req.ContentLength = head.Length + fileBytes.Length + tail.Length;
                using (var rs = req.GetRequestStream())
                {
                    rs.Write(head, 0, head.Length);
                    rs.Write(fileBytes, 0, fileBytes.Length);
                    rs.Write(tail, 0, tail.Length);
                }
                using (var resp = (System.Net.HttpWebResponse)req.GetResponse())
                using (var sr = new StreamReader(resp.GetResponseStream()))
                    sr.ReadToEnd(); // 200 with an analysis id — nothing to keep
            }
            catch (Exception ex) { err = ex.Message; }
            string fPath = path, fErr = err;
            try
            {
                BeginInvoke((Action)delegate
                {
                    vtBusy = false;
                    if (fErr == null)
                        AppendLog(string.Format(Lang.T("log.vtUploaded"), Path.GetFileName(fPath)), Theme.Good);
                    else
                        AppendLog(string.Format(Lang.T("log.vtUploadFailed"), fErr), Theme.Warn, "WARN", false);
                });
            }
            catch { vtBusy = false; }
        }

        // Opens the public VirusTotal page for a hash — needs no API key, used by
        // the quarantine properties and threat dialogs.
        static void VtOpenInBrowser(string sha256)
        {
            try { Process.Start("https://www.virustotal.com/gui/file/" + sha256); }
            catch { }
        }

        // ---------- API-key validation (Settings → Engines → TEST KEY) ----------

        // The EICAR test file — a hash VirusTotal certainly knows, so a lookup of
        // it is a cheap probe of whether an API key is accepted.
        const string VtEicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

        // Tries one lookup with the given key and reports the outcome; done runs
        // on the UI thread with (keyWorks, message, color).
        void VtTestKey(string key, Action<bool, string, Color> done)
        {
            System.Threading.ThreadPool.QueueUserWorkItem(delegate
            {
                int status = 0;
                string err = null;
                try
                {
                    const System.Net.SecurityProtocolType Tls13 = (System.Net.SecurityProtocolType)12288;
                    System.Net.ServicePointManager.SecurityProtocol |= System.Net.SecurityProtocolType.Tls12 | Tls13;
                    var req = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(
                        "https://www.virustotal.com/api/v3/files/" + VtEicarSha256);
                    req.Headers["x-apikey"] = key;
                    req.UserAgent = "AV";
                    req.Timeout = 15000;
                    try
                    {
                        using (var resp = (System.Net.HttpWebResponse)req.GetResponse())
                            status = (int)resp.StatusCode;
                    }
                    catch (System.Net.WebException we)
                    {
                        var resp = we.Response as System.Net.HttpWebResponse;
                        if (resp != null) status = (int)resp.StatusCode;
                        else err = we.Message;
                    }
                }
                catch (Exception ex) { err = ex.Message; }
                bool ok; string msg; Color color;
                if (status == 200) { ok = true; msg = Lang.T("engines.vtKeyOk"); color = Theme.Good; }
                else if (status == 401 || status == 403) { ok = false; msg = Lang.T("engines.vtKeyBad"); color = Theme.Danger; }
                else if (status == 429) { ok = true; msg = Lang.T("engines.vtKeyRate"); color = Theme.Warn; } // quota spent — but the key itself works
                else { ok = false; msg = string.Format(Lang.T("engines.vtKeyNet"), err != null ? err : "HTTP " + status); color = Theme.Warn; }
                bool fOk = ok; string fMsg = msg; Color fColor = color;
                try { BeginInvoke((Action)delegate { done(fOk, fMsg, fColor); }); }
                catch { } // the form is already closed
            });
        }
    }
}
