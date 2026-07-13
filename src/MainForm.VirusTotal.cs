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
    public partial class MainForm : Form
    {
        string vtApiKey = "";        // settings: vtkey= (empty = feature dormant)
        bool vtCheckEnabled = true;  // settings: vtcheck=0 turns hash lookups off
        bool vtUploadEnabled;        // settings: vtupload=1 — OPT-IN, off by default
        readonly List<string[]> vtQueue = new List<string[]>(); // {path, hash-or-null}
        Timer vtTimer;
        volatile bool vtBusy;        // a lookup/upload is in flight
        DateTime vtPauseUntil;       // backoff after 429 / rejected key
        const int VtIntervalMs = 16000;           // free tier: 4 requests/minute
        const long VtUploadMaxBytes = 32 * 1048576; // the simple upload endpoint caps at 32 MB
        const int VtMaliciousThreshold = 3;       // engines flagging a file before we treat it as a threat

        bool VtActive { get { return vtCheckEnabled && vtApiKey.Length > 0; } }

        // Queues a file for a hash lookup. hash may be null — the worker computes
        // it then (kept off the UI thread). Runs on the UI thread only.
        void VtQueueFile(string path, string hash)
        {
            if (!VtActive || vtQueue.Count >= 100) return;
            foreach (string[] q in vtQueue)
                if (string.Equals(q[0], path, StringComparison.OrdinalIgnoreCase)) return;
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

        void VtOnResult(string path, string hash, int status, int mal, int susp, int total, string err)
        {
            string name = null;
            try { name = Path.GetFileName(path); } catch { name = path; }
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
                        {
                            foundFiles.Add(new string[] { path, threat });
                            if (!scanRunning) { RestoreFromTray(); ShowThreatDialog(); }
                        }
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
            else if (status == 429)
            {
                vtPauseUntil = DateTime.Now.AddMinutes(10);
                vtQueue.Insert(0, new string[] { path, hash }); // retry after the pause
                AppendLog(Lang.T("log.vtRateLimited"), Theme.Warn, "WARN", true);
            }
            else if (status == 401 || status == 403)
            {
                vtPauseUntil = DateTime.Now.AddHours(1);
                AppendLog(Lang.T("log.vtBadKey"), Theme.Warn, "WARN", false);
            }
            else
                AppendLog(string.Format(Lang.T("log.vtError"), err != null ? err : "HTTP " + status), Theme.Warn, "WARN", true);
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
    }
}
