// Two-language string table (English default, Ukrainian alternative).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Microsoft.Win32;

namespace AVUI
{
    // Two-language string table (English default, Ukrainian alternative).
    // Lang.Current selects the active language; Lang.T(key) resolves a string,
    // falling back to English and then to the key itself if nothing matches.
    static class Lang
    {
        public enum Language { English, Ukrainian }
        public static Language Current = Language.English;

        static readonly Dictionary<string, string> En = new Dictionary<string, string>();
        static readonly Dictionary<string, string> Uk = new Dictionary<string, string>();

        public static string T(string key)
        {
            var dict = Current == Language.Ukrainian ? Uk : En;
            string v;
            if (dict.TryGetValue(key, out v)) return v;
            if (En.TryGetValue(key, out v)) return v;
            return key;
        }

        static void A(string key, string en, string uk) { En[key] = en; Uk[key] = uk; }

        static Lang()
        {
            // Install / uninstall
            A("install.title", "AV — Setup", "AV — встановлення");
            A("install.installing", "Installing AV…", "Встановлюю AV…");
            A("install.failed", "Installation failed:\r\n", "Не вдалося встановити:\r\n");
            A("uninstall.confirm", "Remove AV along with ClamAV, the signature database and quarantine?", "Видалити AV разом із ClamAV, базами сигнатур і карантином?");
            A("uninstall.done", "AV has been removed.", "AV видалено.");
            A("uninstall.error", "Removal error: ", "Помилка видалення: ");

            // Main window chrome
            A("status.ready", "Ready.", "Готово.");
            A("tray.open", "Open", "Відкрити");
            A("tray.exit", "Exit", "Вихід");

            // Top nav tabs
            A("nav.dashboard", "Dashboard", "Огляд");
            A("nav.logs", "Logs", "Логи");
            A("nav.quarantine", "Quarantine", "Карантин");
            A("nav.settings", "Settings", "Налаштування");

            // Cards
            A("card.system", "System", "Система");
            A("card.quarantine", "Quarantine", "Карантин");
            A("card.scanning", "Scanning", "Сканування");
            A("card.settings", "Settings", "Налаштування");

            // Buttons
            A("btn.quickScan", "QUICK SCAN", "ШВИДКИЙ СКАН");
            A("btn.scanFileDash", "SCAN FILE", "СКАНУВАТИ ФАЙЛ");
            A("btn.scanFileSub", "Choose a single file", "Перевірити один файл");
            A("btn.scanFolderDash", "SCAN FOLDER", "СКАНУВАТИ ПАПКУ");
            A("btn.scanFolderSub", "Scan any directory", "Перевірити будь-яку папку");
            A("btn.scanAll", "FULL PC", "ВЕСЬ ПК");
            A("btn.scanAllSub", "All local drives", "Усі локальні диски");
            A("btn.scanRam", "SCAN RAM", "СКАН RAM");
            A("btn.scanRamSub", "Running processes' memory", "Пам'ять запущених процесів");
            A("btn.updateDb", "UPDATE DATABASE", "ОНОВИТИ БАЗИ");
            A("btn.openLog", "OPEN LOG FILE", "ВІДКРИТИ ФАЙЛ ЖУРНАЛУ");
            A("btn.exclusions", "MANAGE EXCLUSIONS…", "КЕРУВАТИ ВИКЛЮЧЕННЯМИ…");
            A("btn.quick", "QUICK", "ШВИДКИЙ");
            A("btn.file", "FILE", "ФАЙЛ");
            A("btn.folder", "FOLDER", "ПАПКА");
            A("btn.stop", "STOP", "ЗУПИНИТИ");
            A("btn.clearLog", "CLEAR", "ОЧИСТИТИ");
            A("btn.folders", "MANAGE…", "КЕРУВАТИ…");

            // Logs page
            A("log.showDetails", "Details", "Деталі");
            A("section.scan", "Scan", "Сканування");
            A("section.summary", "Summary", "Підсумок");

            // Quarantine page
            A("col.size", "Size", "Розмір");
            A("col.source", "Source", "Джерело");
            A("btn.restoreExclude", "Restore & exclude", "Відновити й виключити");
            A("quarantine.searchCue", "Search quarantine…", "Пошук у карантині…");
            A("quarantine.emptyTitle", "No files in quarantine", "У карантині порожньо");
            A("quarantine.emptySub", "Detected threats will appear here.", "Виявлені загрози з'являтимуться тут.");
            A("quarantine.reasonManual", "Manual", "Вручну");
            A("stat.quarFiles", "Files", "Файлів");
            A("stat.totalSize", "Total size", "Загальний розмір");
            A("stat.lastDetection", "Last detection", "Останнє виявлення");
            A("status.selected", "Selected: {0}", "Вибрано: {0}");
            A("menu.openOrigin", "Open original folder", "Відкрити початкову папку");
            A("menu.properties", "Properties", "Властивості");
            A("prop.title", "File properties", "Властивості файлу");
            A("prop.file", "File", "Файл");
            A("prop.threat", "Threat", "Загроза");
            A("prop.origin", "Original path", "Початковий шлях");
            A("prop.source", "Source", "Джерело");
            A("prop.when", "Quarantined", "У карантині з");
            A("prop.size", "Size", "Розмір");
            A("btn.copyHash", "COPY HASH", "КОПІЮВАТИ ХЕШ");
            A("status.hashCopied", "SHA256 copied to clipboard.", "SHA256 скопійовано в буфер обміну.");
            A("btn.installedPF", "INSTALLED", "ВСТАНОВЛЕНО");
            A("btn.installPF", "INSTALL FOR THIS USER", "ВСТАНОВИТИ ДЛЯ КОРИСТУВАЧА");
            A("btn.fixWinTemp", "FIX C:\\WINDOWS\\TEMP ACCESS", "ВІДНОВИТИ ДОСТУП ДО C:\\WINDOWS\\TEMP");
            A("btn.close", "Close", "Закрити");
            A("btn.toExclusions", "To exclusions", "У виключення");
            A("btn.delete", "Delete", "Видалити");
            A("btn.toQuarantine", "To quarantine", "В карантин");
            A("btn.deleteForever", "Delete", "Видалити");
            A("menu.deleteForever", "Delete permanently", "Видалити назавжди");
            A("btn.restore", "Restore", "Відновити");
            A("btn.openFolder", "Open folder", "Відкрити папку");
            A("btn.deleteFile", "Delete file", "Видалити файл");
            A("btn.removeFromList", "Remove from list", "Прибрати зі списку");
            A("btn.addFile", "Add file…", "Додати файл…");
            A("btn.addFolder", "Add folder…", "Додати папку…");
            A("btn.cancel", "Cancel", "Скасувати");

            // Settings page
            A("settings.monitorLabel", "Auto-check new files in folders ({0})", "Автоперевірка нових файлів у папках ({0})");
            A("settings.riskyOnly", "Check risky file types only (exe, scripts, archives, documents)", "Перевіряти лише небезпечні типи (exe, скрипти, архіви, документи)");
            A("settings.autoQuarantine", "Auto-quarantine (don't ask what to do with detections)", "Автоматично в карантин (не питати, що робити зі знайденим)");
            A("settings.autoUpdate", "Update database automatically (once a day)", "Оновлювати бази автоматично (раз на добу)");
            A("settings.fullRisky", "Full scan: risky file types only (much faster)", "У повному скані перевіряти лише небезпечні типи (набагато швидше)");
            A("settings.autostart", "Start with Windows (in tray)", "Запускати разом з Windows (у треї)");
            A("settings.language", "Interface language:", "Мова інтерфейсу:");
            A("settings.usbPrompt", "Offer to scan USB drives when connected", "Пропонувати перевірку USB-накопичувачів при підключенні");
            A("settings.notifications", "Tray notifications (threat alerts are always shown)", "Сповіщення в треї (про знайдені загрози — завжди)");
            A("settings.skipBig", "Skip files larger than 200 MB (faster scans)", "Пропускати файли, більші за 200 МБ (швидше сканування)");
            A("settings.status", "Status", "Стан");
            A("sstat.engine", "Engine", "Рушій");
            A("sstat.database", "Database", "Бази");
            A("sstat.monitoring", "Monitoring", "Моніторинг");
            A("sstat.quarantine", "Quarantine", "Карантин");
            A("sval.ready", "Ready", "Готовий");
            A("sval.notFound", "Not found", "Не знайдено");
            A("sval.enabled", "Enabled", "Увімкнено");
            A("sval.disabled", "Disabled", "Вимкнено");
            A("sval.filesN", "{0} files", "Файлів: {0}");
            A("badge.installedPF", "Installed", "Встановлено");
            A("settings.performance", "Scan performance:", "Продуктивність сканування:");
            A("settings.perfHint", "Low — quieter PC, slower scans. High — fastest, loads the CPU.",
                "Низька — тихіше для ПК, повільніше. Висока — найшвидше, навантажує процесор.");
            A("perf.low", "Low", "Низька");
            A("perf.normal", "Normal", "Звичайна");
            A("perf.high", "High", "Висока");

            // Scheduled quick scan
            A("settings.schedule", "Scheduled quick scan:", "Плановий швидкий скан:");
            A("sched.off", "Off", "Вимк.");
            A("sched.daily", "Daily", "Щодня");
            A("sched.weekly", "Weekly", "Щотижня");
            A("sstat.schedule", "Scheduled scan", "Плановий скан");
            A("status.schedOff", "Scheduled scan disabled.", "Планове сканування вимкнено.");
            A("status.schedDaily", "Quick scan will run automatically every day.", "Швидкий скан виконуватиметься автоматично щодня.");
            A("status.schedWeekly", "Quick scan will run automatically every week.", "Швидкий скан виконуватиметься автоматично щотижня.");
            A("log.scheduledScanStart", "Scheduled scan: the quick scan is due — started automatically.\r\n", "Планове сканування: настав час швидкого скану — запущено автоматично.\r\n");
            A("tray.scheduledScan", "Scheduled quick scan started.", "Розпочато плановий швидкий скан.");

            // USB drive detection
            A("usb.title", "New drive detected", "Виявлено новий накопичувач");
            A("usb.scanPrompt", "New drive detected: {0}\r\n\r\nScan it for threats now?",
                "Підключено новий накопичувач: {0}\r\n\r\nПеревірити його на загрози зараз?");
            A("tray.usbBusy", "Drive {0} connected. A scan is already running — you can check it later from the dashboard.",
                "Підключено диск {0}. Сканування вже триває — перевірити його можна пізніше з панелі.");
            A("msg.installConfirm", "The app will be copied to\r\n{0}\r\ntogether with ClamAV and the database, Start Menu/Desktop shortcuts will be created,\r\nand it will be registered in \"Apps\". No administrator rights are needed. Continue?",
                "Програма скопіюється в\r\n{0}\r\nразом із ClamAV і базами, з'являться ярлики в Пуску, на робочому столі\r\nта запис у «Програмах». Права адміністратора не потрібні. Продовжити?");
            A("msg.fixWinTempConfirm", "On this PC, C:\\Windows\\Temp is locked down so even reading its contents is denied "
                + "to regular apps — a common malware drop point can't be monitored as a result.\r\n\r\n"
                + "This will restore the default Windows read permission on that one folder only "
                + "(via a one-time administrator prompt). The app itself keeps running without admin rights "
                + "afterwards. Continue?",
                "На цьому ПК доступ до C:\\Windows\\Temp обмежено настільки, що звичайні програми не можуть "
                + "навіть прочитати її вміст — тож типове місце для дропу малваре лишається поза наглядом.\r\n\r\n"
                + "Зараз буде відновлено стандартний Windows-дозвіл на читання лише для цієї папки "
                + "(через одноразовий запит адміністратора). Сама програма й надалі працюватиме без прав адміністратора. Продовжити?");
            A("status.fixWinTempCancelled", "C:\\Windows\\Temp access fix cancelled.", "Відновлення доступу до C:\\Windows\\Temp скасовано.");
            A("status.fixWinTempFailed", "Could not restore access to C:\\Windows\\Temp (blocked by policy?).", "Не вдалося відновити доступ до C:\\Windows\\Temp (можливо, заблоковано політикою).");
            A("status.fixWinTempDone", "Access restored — C:\\Windows\\Temp is now monitored.", "Доступ відновлено — C:\\Windows\\Temp тепер під наглядом.");

            // Threat dialog
            A("threat.title", "Threats found — what to do?", "Знайдено загрози — що робити?");
            A("col.file", "File", "Файл");
            A("col.threat", "Threat", "Загроза");
            A("threat.hint", "The action applies to the selected files (none selected = all).", "Дія застосовується до виділених файлів (нічого не виділено = до всіх).");
            A("msg.deleteConfirm", "Permanently delete {0} file(s)?", "Видалити назавжди {0} файл(ів)?");
            A("title.deletion", "Deletion", "Видалення");
            A("title.error", "Error", "Помилка");
            A("status.exclusionsCount", "Exclusions: {0}.", "Виключень: {0}.");

            // Quarantine dialog
            A("quarantine.title", "Quarantine", "Карантин");
            A("col.origin", "Origin", "Звідки");
            A("col.when", "When", "Коли");
            A("quarantine.unknownOrigin", "(unknown)", "(невідомо)");
            A("msg.restoreConfirm", "WARNING: this file was flagged as infected. Really restore it?", "УВАГА: файл було позначено як заражений. Точно відновити?");
            A("msg.unknownOriginPath", "Unknown original path for {0}.\r\nOpen the quarantine folder and retrieve the file manually.", "Невідомий вихідний шлях для {0}.\r\nВідкрий папку карантину і забери файл вручну.");
            A("msg.fileExists", "File already exists: {0}", "Файл уже існує: {0}");
            A("msg.quarantineMoveFailed", "Failed to move to quarantine:\r\n{0}", "Не вдалося перемістити в карантин:\r\n{0}");

            // Exclusions dialog
            A("excl.title", "Scan exclusions", "Виключення зі сканування");
            A("col.path", "Path", "Шлях");
            A("col.type", "Type", "Тип");
            A("type.file", "file", "файл");
            A("type.folder", "folder", "папка");
            A("type.missing", "missing", "відсутній");
            A("msg.onlyExistingToQuarantine", "Only an existing file can be quarantined: {0}", "В карантин можна перемістити лише наявний файл: {0}");
            A("msg.deleteFromDiskConfirm", "Permanently delete {0} file(s) from disk and remove from the list?", "Видалити з диска {0} файл(ів) і прибрати зі списку?");

            // Watch dirs / path list editor
            A("watch.editTitle", "Folders to monitor (one per line)", "Папки для моніторингу (одна на рядок)");
            A("log.folderNotFound", "Folder not found, skipping: {0}\r\n", "Папку не знайдено, пропускаю: {0}\r\n");
            A("log.pathNotFound", "Path not found, skipping: {0}\r\n", "Шлях не знайдено, пропускаю: {0}\r\n");

            // Monitoring
            A("status.monitorOn", "Monitoring enabled: new files will be checked automatically.", "Моніторинг увімкнено: нові файли перевірятимуться автоматично.");
            A("status.monitorOff", "Monitoring disabled.", "Моніторинг вимкнено.");
            A("log.watchFailed", "Failed to watch {0}: {1}\r\n", "Не вдалося стежити за {0}: {1}\r\n");
            // count comes after the colon so Ukrainian needs no plural declension
            A("log.watchingFolders", "Monitoring: {0} folder(s).\r\n", "Папок у моніторингу: {0}.\r\n");

            // Scanning: pickers and generic
            A("dlg.pickFolder", "Choose a folder to scan", "Вибери папку для сканування");
            A("dlg.pickFile", "Choose a file to scan", "Вибери файл для сканування");
            A("log.scanning", "Scanning: {0}\r\n", "Сканую: {0}\r\n");
            A("log.buildingList", "Building file list…\r\n", "Складаю список файлів…\r\n");
            A("status.scanning", "Scanning…", "Сканування…");
            A("log.listCreateFailedInline", "Could not create the file list ({0}), passing files on the command line.\r\n", "Не вдалося створити список файлів ({0}), передаю в рядку.\r\n");
            A("log.newFilesHeader", "New files ({1}) — auto-check:\r\n", "Нові файли ({1}) — автоперевірка:\r\n");
            A("status.autoCheck", "Auto-checking new files: {0}…", "Автоперевірка нових файлів: {0}…");
            A("log.filesToCheck", "Files to check: {0}", "Файлів для перевірки: {0}");
            A("desc.autoCheck", "auto-check of new files", "автоперевірка нових файлів");

            // Progress / ETA
            A("status.progress", "Scanned {0} of {1} ({2:0}%){3}, threats: {4}", "Скановано {0} із {1} ({2:0}%){3}, загроз: {4}");
            A("eta.remainingPrefix", ", remaining ", ", залишилось ");
            A("eta.estimating", ", estimating time…", ", оцінюю час…");
            A("time.hm", "{0:0}h {1:0}m", "{0:0} год {1:0} хв");
            A("time.ms", "{0:0}m {1:0}s", "{0:0} хв {1:0} с");
            A("time.s", "{0:0}s", "{0:0} с");

            // Heartbeat
            A("log.hbListing", "Building file list… found {1}, elapsed {2}\r\n", "Складаю список файлів… знайдено {1}, минуло {2}\r\n");
            A("log.hbEngineLoading", "Engine is loading the database into memory… elapsed {1}\r\n", "Рушій вантажить бази в пам'ять… минуло {1}\r\n");
            A("log.hbRunning", "Running… scanned {1}, elapsed {2}\r\n", "Триває… проскановано {1}, минуло {2}\r\n");
            A("log.hbBigFile", "Scanning a large file… scanned {1} of {2} ({3:0}%), elapsed {4}\r\n", "Сканую великий файл… проскановано {1} із {2} ({3:0}%), минуло {4}\r\n");
            A("log.hbProgress", "Scanned {1} of {2} ({3:0}%), {4} files remaining{5}{6}\r\n", "Проскановано {1} із {2} ({3:0}%), залишилось {4} файлів{5}{6}\r\n");
            A("log.threatsSuffix", ", threats: {0}", ", загроз: {0}");

            // Log file / history
            A("history.empty", "No scans yet.", "Ще не було жодного сканування.");
            A("log.emptyLogFile", "The log is empty — no scans yet.", "Журнал поки порожній — ще не було жодного сканування.");

            // Auto-update
            A("status.dbUpToDate", "Signature database is up to date.", "Бази сигнатур актуальні.");
            A("tray.dbUpdateDownloading", "A database update is available — downloading…", "Вийшло оновлення баз сигнатур — завантажую…");
            A("log.dbNewerAutoDownload", "\r\nA newer database is available — downloading automatically…\r\n", "\r\nДоступні новіші бази — завантажую автоматично…\r\n");
            A("hero.dbUpdateAvailable", "A signature database update is available", "Доступне оновлення баз сигнатур");
            A("status.dbUpdateAvailablePress", "A database update is available — press \"Update Database\".", "Доступне оновлення баз — натисни «Оновити бази».");
            A("tray.dbUpdateAvailablePress", "A signature database update is available — press \"Update Database\".", "Доступне оновлення баз сигнатур — натисни «Оновити бази».");

            // Full scan
            A("msg.fullScanRiskyWarn", "Full scan ({0}): risky file types only — exe, scripts,\r\narchives, documents. This is much faster than checking everything\r\n(all files can be enabled in Settings). Continue?",
                "Повне сканування ({0}): небезпечні типи файлів — exe, скрипти,\r\nархіви, документи. Це набагато швидше, ніж перевіряти все підряд\r\n(усі файли можна ввімкнути в налаштуваннях). Продовжити?");
            A("msg.fullScanAllWarn", "Full scan ({0}) of ALL files can take many hours.\r\nContinue?", "Повне сканування ({0}) УСІХ файлів може тривати багато годин.\r\nПродовжити?");
            A("title.fullScan", "Full PC Scan", "Сканування всього ПК");
            A("desc.fullScan", "full scan ({0})", "повне сканування ({0})");
            A("log.fullScanRisky", "Full scan (risky types): {0}\r\n", "Повне сканування (небезпечні типи): {0}\r\n");
            A("log.fullScanAll", "Full scan (all files): {0}\r\n", "Повне сканування (усі файли): {0}\r\n");
            A("status.fullScanRunning", "Full PC scan…", "Повне сканування ПК…");

            // Quick scan
            A("desc.quickScan", "quick scan", "швидке сканування");
            A("log.quickScanHeader", "Quick scan: risky file types in common infection points.\r\n", "Швидке сканування: небезпечні типи файлів у типових місцях зараження.\r\n");
            A("log.quickScanProcesses", "  + executables of running processes\r\n", "  + виконувані файли запущених процесів\r\n");
            A("log.quickScanMemory", "  + memory (RAM) of running processes — catches code masked on disk\r\n\r\n", "  + пам'ять (RAM) запущених процесів — ловить код, замаскований на диску\r\n\r\n");
            A("status.quickScanRunning", "Quick scan…", "Швидке сканування…");
            A("desc.memScan", "RAM scan", "скан пам'яті");
            A("log.memScanHeader", "RAM scan: executable memory of every running process.\r\n", "Скан RAM: виконувана пам'ять кожного запущеного процесу.\r\n");
            A("status.memScanRunning", "Scanning RAM…", "Сканую RAM…");
            A("status.memScanning", "Scanning process memory (RAM)…", "Сканую пам'ять процесів (RAM)…");
            A("log.memScanDone", "Dumped {0} executable memory region(s) from {1} process(es) ({2}) for scanning.\r\n", "Знято {0} виконуваних ділянок пам'яті з {1} процесів ({2}) для перевірки.\r\n");

            // File listing
            A("status.buildingListFound", "Building file list… found {0}", "Складаю список файлів… знайдено {0}");
            A("status.scanCancelled", "Scan cancelled.", "Сканування скасовано.");
            A("log.cancelled", "Cancelled.\r\n", "Скасовано.\r\n");
            A("status.noFiles", "No files to check.", "Немає файлів для перевірки.");
            A("log.noFiles", "No files to check.\r\n", "Немає файлів для перевірки.\r\n");
            A("status.listCreateFailed", "Could not create the file list.", "Не вдалося створити список файлів.");
            A("log.listCreateFailed", "Could not create the file list: {0}\r\n", "Не вдалося створити список файлів: {0}\r\n");

            // clamd engine
            A("status.engineStarting", "Starting scan engine (loading database into memory)…", "Запускаю рушій сканування (бази вантажаться в пам'ять)…");
            A("log.engineStarting", "Starting the clamd engine (loading database into memory, ~30 seconds)…\r\n", "Запускаю рушій clamd (бази вантажаться в пам'ять, ~пів хвилини)…\r\n");
            A("log.daemonFallback", "clamd failed to start ({0}) — falling back to clamscan.\r\n", "clamd не запустився ({0}) — сканую через clamscan.\r\n");
            A("log.scanningThreads", "Scanning using {0} parallel process(es).\r\n", "Сканую у {0} потоки.\r\n");
            A("log.clamdscanStartFailed", "Failed to start clamdscan: {0}\r\n", "Не вдалося запустити clamdscan: {0}\r\n");
            A("err.daemonExited", "clamd exited unexpectedly", "clamd несподівано завершився");
            A("err.daemonTimeout", "clamd did not respond within 3 minutes", "clamd не відповів за 3 хвилини");

            // Scan output / results
            A("status.scannedFound", "Scanned: {0}, threats found: {1}", "Скановано: {0}, знайдено загроз: {1}");
            A("log.summary", "\r\nSummary: scanned {0} files in {1}, threats found: {2}\r\n", "\r\nПідсумок: проскановано {0} файлів за {1}, знайдено загроз: {2}\r\n");
            A("log.skippedExplanation", "Some calculated files ({0}) were skipped (e.g. system files, excluded folders, or locked in exclusive use by other programs).\r\n", "Частину обрахованих файлів ({0}) було пропущено (наприклад, системні файли, виключені папки або файли, що заблоковані іншими програмами).\r\n");
            A("status.doneClean", "Done. Scanned: {0}. No threats found.", "Готово. Скановано: {0}. Загроз не знайдено.");
            A("log.newFilesClean", "New files are clean ✔\r\n", "Нові файли чисті ✔\r\n");
            A("tray.newFilesClean", "Checked new files: {0} — clean.", "Перевірено нових файлів: {0} — чисто.");
            A("log.noThreatsFound", "\r\nNo threats found ✔\r\n", "\r\nЗагроз не знайдено ✔\r\n");
            A("tray.scanDoneClean", "Scan complete: no threats found.", "Сканування завершено: загроз не знайдено.");
            A("status.threatsFound", "Scanned: {0}. THREATS FOUND: {1}{2}", "Скановано: {0}. ЗНАЙДЕНО ЗАГРОЗ: {1}{2}");
            A("status.quarantinedSuffix", ", quarantined: {0}", ", у карантині: {0}");
            A("hero.threatsFoundTitle", "Threats found!", "Знайдено загрози!");
            A("hero.threatsFoundSub", "Infected files: {0}{1} — check the log", "Заражених файлів: {0}{1} — перевір лог");
            A("log.threatsFound", "\r\nTHREATS FOUND: {0}{1}\r\n", "\r\nЗНАЙДЕНО ЗАГРОЗ: {0}{1}\r\n");
            A("tray.threatsFoundWarn", "WARNING: threats found: {0}{1}", "УВАГА: знайдено загроз: {0}{1}");
            A("status.scanInterrupted", "Scan interrupted or an error occurred (code {0}).", "Сканування перервано або сталася помилка (код {0}).");

            // Install / download ClamAV
            A("msg.firstRunModeChoice", "Welcome! How do you want to use AV?\r\n\r\n"
                + "YES — install for this user (recommended): the app copies itself to\r\n{1}\r\n"
                + "together with everything it downloads, adds Start Menu/Desktop shortcuts and an\r\n"
                + "\"Apps\" entry. No administrator rights are needed.\r\n\r\n"
                + "NO — portable mode: everything (ClamAV, signature database, quarantine, settings)\r\n"
                + "stays in the current folder:\r\n{0}",
                "Вітаю! Як використовувати AV?\r\n\r\n"
                + "ТАК — встановити для цього користувача (рекомендовано): програма скопіюється в\r\n{1}\r\n"
                + "разом з усім, що завантажить, додасть ярлики в Пуск, на робочий стіл і запис у\r\n"
                + "«Програмах». Права адміністратора не потрібні.\r\n\r\n"
                + "НІ — портативний режим: усе (ClamAV, бази сигнатур, карантин, налаштування)\r\n"
                + "лишиться в поточній папці:\r\n{0}");
            A("status.installCancelled", "Installation cancelled.", "Встановлення скасовано.");
            A("msg.offerInstallChoice", "ClamAV was not found next to the program. How do you want to set it up?\r\n\r\n"
                + "YES — install for this user: the app copies itself to its own folder, downloads ClamAV\r\n"
                + "(~220 MB) and the database, and adds Start Menu/Desktop shortcuts and an \"Apps\" entry.\r\n"
                + "No administrator rights are needed.\r\n\r\n"
                + "NO — portable mode: download ClamAV into the current folder.",
                "ClamAV не знайдено поруч з програмою. Як налаштувати?\r\n\r\n"
                + "ТАК — встановити для цього користувача: програма скопіюється у власну папку, скачає\r\n"
                + "ClamAV (~220 МБ) і бази, додасть ярлики в Пуск, на робочий стіл та в «Програми».\r\n"
                + "Права адміністратора не потрібні.\r\n\r\n"
                + "НІ — портативний режим: скачати ClamAV у поточну папку.");
            A("msg.offerPortableDownload", "ClamAV was not found next to the program.\r\n\r\n"
                + "Download it automatically from GitHub (~220 MB) and install it into the \"clamav\" folder?\r\n"
                + "The signature database will be downloaded automatically afterwards.",
                "ClamAV не знайдено поруч з програмою.\r\n\r\n"
                + "Завантажити його автоматично з GitHub (~220 МБ) і встановити в папку \"clamav\"?\r\n"
                + "Після цього автоматично завантажаться бази сигнатур.");
            A("status.foundArchiveExtracting", "Found a downloaded archive — extracting…", "Знайдено завантажений архів — розпаковую…");
            A("hero.installingClamAV", "Installing ClamAV", "Установлення ClamAV");
            A("hero.extractingArchive", "Extracting archive…", "Розпаковую архів…");
            A("status.findingLatestClamAV", "Looking up the latest ClamAV release on GitHub…", "Шукаю останню версію ClamAV на GitHub…");
            A("hero.findingLatestRelease", "Looking up the latest release…", "Шукаю останній реліз…");
            A("log.downloading", "Downloading {0}\r\n", "Завантажую {0}\r\n");
            A("status.downloadingClamAV", "Downloading ClamAV: {0} of {1} MB", "Завантаження ClamAV: {0} з {1} МБ");
            A("status.clamAVDownloadCancelled", "ClamAV download cancelled.", "Завантаження ClamAV скасовано.");
            A("hero.installCancelled", "Installation cancelled", "Установлення скасовано");
            A("hero.pressUpdateRetry", "Press \"Update Database\" to try again", "Натисни «Оновити бази», щоб спробувати ще раз");
            A("status.clamAVDownloadFailed", "Failed to download ClamAV: {0}", "Не вдалося завантажити ClamAV: {0}");
            A("hero.downloadError", "Download error", "Помилка завантаження");
            A("hero.checkConnectionRetry", "Check your internet connection and press \"Update Database\" again", "Перевір інтернет-з'єднання і натисни «Оновити бази» ще раз");
            A("status.extractingClamAV", "Extracting ClamAV…", "Розпаковую ClamAV…");
            A("err.noClamscanInArchive", "clamscan.exe not found in the archive", "В архіві немає clamscan.exe");
            A("status.clamAVInstallError", "ClamAV installation error: {0}", "Помилка встановлення ClamAV: {0}");
            A("hero.installError", "Installation error", "Помилка встановлення");
            A("status.clamAVInstalled", "ClamAV installed.", "ClamAV встановлено.");
            A("log.clamAVInstalled", "ClamAV installed ✔\r\n", "ClamAV встановлено ✔\r\n");

            // DB update
            A("msg.cooldownWarn", "The update server has temporarily rate-limited downloads from this address (HTTP 429 —\r\n"
                + "too many requests). This will resolve on its own, expected around {0}.\r\n"
                + "Retrying may extend the block. Try anyway?",
                "Сервер оновлень тимчасово обмежив завантаження з цієї адреси (HTTP 429 —\r\n"
                + "забагато запитів). Це мине саме собою, орієнтовно після {0}.\r\n"
                + "Повторні спроби можуть подовжити блокування. Спробувати все одно?");
            A("log.updatingDbFirstTime", "Updating the signature database (first time is ~200 MB, please wait)…\r\n\r\n", "Оновлюю бази сигнатур (перший раз це ~200 МБ, зачекай)…\r\n\r\n");
            A("log.autoUpdating", "Auto-updating database…\r\n", "Автооновлення баз…\r\n");
            A("status.autoUpdatingDb", "Auto-updating database…", "Автооновлення баз…");
            A("status.updatingDb", "Updating database…", "Оновлення баз…");
            A("hero.updatingDb", "Updating database", "Оновлення баз");
            A("hero.downloadingSignatures", "Downloading signatures from database.clamav.net…", "Завантажую сигнатури з database.clamav.net…");
            A("log.dbAlreadyCurrent", "{0}: already up to date (version {1})\r\n", "{0}: вже актуальна (версія {1})\r\n");
            A("status.dbUpdated", "Database updated.", "Бази оновлено.");
            A("status.dbAlreadyCurrent2", "Database already up to date.", "Бази вже актуальні.");
            A("log.dbUpdated", "\r\nDatabase updated ✔\r\n", "\r\nБази оновлено ✔\r\n");
            A("log.dbAlreadyCurrentLog", "\r\nDatabase already up to date ✔\r\n", "\r\nБази вже актуальні ✔\r\n");
            A("status.updateCancelled", "Update cancelled.", "Оновлення скасовано.");
            A("log.updateCancelled", "\r\nUpdate cancelled.\r\n", "\r\nОновлення скасовано.\r\n");
            A("status.serverRateLimited", "Update server temporarily rate-limited us — will retry later.", "Сервер оновлень тимчасово обмежив завантаження — спробую пізніше.");
            A("log.rateLimitedExplain", "\r\nUpdate server responded 429: too many downloads from this address.\r\n"
                + "This is a temporary server-side limit — your internet connection is fine. The current database still works.\r\n",
                "\r\nСервер оновлень відповів 429: забагато завантажень з цієї адреси.\r\n"
                + "Це тимчасове обмеження сервера, з інтернетом усе гаразд. Наявні бази працюють.\r\n");
            A("log.nextAttempt", "Next automatic attempt: after {0:HH:mm}.\r\n", "Наступна автоматична спроба — після {0:HH:mm}.\r\n");
            A("status.updateError", "Database update error.", "Помилка оновлення баз.");
            A("log.updateErrorDetail", "\r\nUpdate error: {0}\r\nCheck your internet connection.\r\n", "\r\nПомилка оновлення: {0}\r\nПеревір інтернет-з'єднання.\r\n");
            A("err.notADatabaseFile", "{0}: the downloaded file doesn't look like a ClamAV database", "{0}: завантажений файл не схожий на базу ClamAV");
            A("err.versionCheckFailed", "{0}: could not read the database version from the server", "{0}: не вдалося прочитати версію бази з сервера");
            A("status.downloadingDb", "Downloading {0}: {1:0} / {2:0} MB ({3:0}%)", "Завантаження {0}: {1:0} / {2:0} МБ ({3:0}%)");
            A("log.dbFileDownloaded", "{0} downloaded ✔\r\n", "{0} завантажено ✔\r\n");

            // Misc / process / autostart
            A("log.processStartFailed", "Failed to start {0}: {1}\r\n", "Не вдалося запустити {0}: {1}\r\n");
            A("status.startError", "Startup error.", "Помилка запуску.");
            A("hero.scanningTitle", "Scanning…", "Сканування…");
            A("hero.scanningSub", "This may take a while", "Це може зайняти якийсь час");
            A("status.autostartOn", "Autostart enabled.", "Автозапуск увімкнено.");
            A("status.autostartOff", "Autostart disabled.", "Автозапуск вимкнено.");
            A("log.clamscanNotFound", "clamscan.exe not found. Press \"Update Database\" to download ClamAV automatically.\r\n", "clamscan.exe не знайдено. Натисни «Оновити бази», щоб завантажити ClamAV автоматично.\r\n");
            A("log.clamDirNotWritable", "The ClamAV folder is not writable ({0}) — the signature database can't be stored there. Scanning works if a database already exists; otherwise use the portable setup or run the fix from Settings.\r\n",
                "Папка ClamAV недоступна для запису ({0}) — бази сигнатур не вдасться зберегти в ній. Сканування працюватиме, якщо бази вже є; інакше скористайся портативним варіантом або виправ доступ у налаштуваннях.\r\n");
            A("log.clamAVPath", "ClamAV: {0}\r\n", "ClamAV: {0}\r\n");
            A("hero.clamAVNotFound", "ClamAV not found", "ClamAV не знайдено");
            A("hero.putPortableClamAV", "Place a portable ClamAV build in the \"clamav\" folder next to the program", "Поклади portable ClamAV у папку \"clamav\" поруч з програмою");
            A("hero.protected", "Protected", "Захищено");
            A("hero.dbFrom", "Signature database from {0}", "Бази сигнатур від {0}");
            A("hero.dbNeeded", "Signature database needed", "Потрібні бази сигнатур");
            A("hero.pressUpdateFirstTime", "Press \"Update Database\" — first download is ~250 MB", "Натисни «Оновити бази» — перший раз завантажиться ~250 МБ");
            A("tray.appUpdateInstalling", "Updating AV to {0} — the app will restart in a few seconds…", "Оновлюю AV до {0} — програма перезапуститься за кілька секунд…");
            A("stats.neverScanned", "never", "ще не було");
            // About dialog
            A("btn.about", "ABOUT", "ПРО ПРОГРАМУ");
            A("about.title", "About AV", "Про AV");
            // no "&" here: a Label eats it as a mnemonic marker
            A("about.version", "Version {0} — free, open source, Apache 2.0 license", "Версія {0} — безкоштовна, відкритий код, ліцензія Apache 2.0");
            A("about.desc", "A lightweight, portable multi-engine antivirus for Windows: the ClamAV signature "
                + "engine, community YARA rules, and VirusTotal hash checks for unknown files — plus new-file "
                + "monitoring, USB checks and a neutralized quarantine. No background services, no ads.",
                "Легкий портативний багаторушійний антивірус для Windows: сигнатурний рушій ClamAV, "
                + "YARA-правила спільноти та перевірка невідомих файлів на VirusTotal — плюс моніторинг нових "
                + "файлів, перевірка USB та знешкоджений карантин. Без фонових служб і реклами.");
            A("about.quickStart", "Quick start", "Швидкий старт");
            A("about.howTo",
                "1. Press UPDATE DATABASE on the dashboard — the first download is ~250 MB.\r\n"
                + "2. QUICK SCAN checks common infection points in minutes.\r\n"
                + "3. Monitoring checks new files in Downloads, Desktop and other folders automatically.\r\n"
                + "4. Detections land in Quarantine — restore or delete them there.\r\n"
                + "5. Closing the window minimizes to tray; protection keeps running.\r\n"
                + "6. Runs portable (everything stays in its own folder) or installed per-user (no admin rights) — the first start asks once; installing later is one button in Settings.",
                "1. Натисни «ОНОВИТИ БАЗИ» на панелі — перше завантаження ~250 МБ.\r\n"
                + "2. «ШВИДКИЙ СКАН» за лічені хвилини перевіряє типові місця зараження.\r\n"
                + "3. Моніторинг автоматично перевіряє нові файли в Downloads, на робочому столі та інших папках.\r\n"
                + "4. Знахідки потрапляють у Карантин — там їх можна відновити або видалити.\r\n"
                + "5. Закриття вікна згортає програму в трей; захист продовжує працювати.\r\n"
                + "6. Працює портативно (усе лежить у власній папці) або встановленою для користувача (без прав адміністратора) — вибір один раз при першому запуску, встановити можна й пізніше з налаштувань.");
            A("about.star", "★  Star this project on GitHub", "★  Постав зірку проєкту на GitHub");
            A("about.releases", "↓  All releases — download the latest version", "↓  Усі релізи — завантажити найновішу версію");
            A("about.follow", "+  Follow the author on GitHub", "+  Підписатися на автора на GitHub");
            A("about.license", "§  Apache 2.0 license — free to use, modify and share", "§  Ліцензія Apache 2.0 — вільно використовуй, змінюй і поширюй");
            A("about.powered", "Powered by the ClamAV® engine (© Cisco Systems, Inc), YARA (© VirusTotal), rules by "
                + "YARA Forge, and the VirusTotal API. This project is an independent open-source UI and is not "
                + "affiliated with any of them.",
                "Працює на рушії ClamAV® (© Cisco Systems, Inc), YARA (© VirusTotal), правилах YARA Forge та "
                + "API VirusTotal. Цей проєкт — незалежний open-source інтерфейс, не афілійований з жодним із них.");

            // Dashboard stat strip captions
            A("stat.clamav", "ClamAV", "ClamAV");
            A("stat.lastScan", "Last scan", "Останній скан");
            A("stat.scans", "Scans", "Перевірок");
            A("stat.files", "Files scanned", "Файлів перевірено");
            A("stat.threats", "Threats", "Загроз");
            A("stat.quarantined", "Quarantined", "У карантині");
            A("stat.database", "Database", "База");
            A("stat.signatures", "Signatures", "Сигнатур");
            A("stat.yara", "YARA rules", "YARA-правила");
            A("stat.virustotal", "VirusTotal", "VirusTotal");
            A("sval.downloading", "Downloading…", "Завантажується…");
            A("sval.vtNoKey", "No API key", "Немає ключа");

            // YARA engine
            A("btn.engines", "DETECTION ENGINES…", "РУШІЇ ВИЯВЛЕННЯ…");
            A("engines.title", "Detection engines — ClamAV, YARA & VirusTotal", "Рушії виявлення — ClamAV, YARA і VirusTotal");
            A("engines.clamavReady", "Ready: ClamAV {0}, database from {1}", "Готово: ClamAV {0}, база від {1}");
            A("engines.clamavNoDb", "Database not downloaded yet — press UPDATE DATABASE on the dashboard",
                "Базу ще не завантажено — натисни ОНОВИТИ БАЗУ на головній сторінці");
            A("engines.clamavMissing", "ClamAV not found — it is downloaded during the first database update",
                "ClamAV не знайдено — він завантажиться під час першого оновлення бази");
            A("engines.clamavCore", "The core signature engine — always on; updates run from the dashboard.",
                "Основний сигнатурний рушій — завжди увімкнений; оновлення — з головної сторінки.");
            A("settings.yaraEnabled", "Use YARA rules — a second detection engine", "Використовувати YARA-правила — другий рушій виявлення");
            A("engines.yaraStatusReady", "Ready: {0} rule file(s), rules from {1}", "Готово: файлів правил: {0}, правила від {1}");
            A("engines.yaraStatusDownloading", "Downloading the engine and rules…", "Завантажую рушій і правила…");
            A("engines.yaraStatusMissing", "Not installed yet — downloads automatically when enabled", "Ще не встановлено — завантажиться автоматично після ввімкнення");
            A("btn.updateYaraRules", "UPDATE RULES NOW", "ОНОВИТИ ПРАВИЛА ЗАРАЗ");
            A("btn.customRules", "CUSTOM RULES FOLDER…", "ПАПКА ВЛАСНИХ ПРАВИЛ…");
            A("engines.yaraHint", "After every ClamAV scan the same files are checked against community YARA rules "
                + "(YARA Forge core set, refreshed weekly). Drop your own .yar files into the custom rules folder.",
                "Після кожного сканування ClamAV ті самі файли перевіряються YARA-правилами спільноти "
                + "(набір YARA Forge core, оновлюється щотижня). Власні .yar-файли можна класти в папку власних правил.");
            A("section.yara", "YARA scan", "YARA-сканування");
            A("log.yaraScanning", "Checking the same files against YARA rules…\r\n", "Перевіряю ті самі файли YARA-правилами…\r\n");
            A("status.yaraScanning", "YARA scan…", "YARA-сканування…");
            A("log.hbYara", "YARA rules are checking the files… elapsed {1}\r\n", "YARA-правила перевіряють файли… минуло {1}\r\n");
            A("log.yaraClean", "YARA: no additional detections ✔\r\n", "YARA: додаткових загроз не виявлено ✔\r\n");
            A("log.yaraFound", "YARA: suspicious files found: {0}\r\n", "YARA: знайдено підозрілих файлів: {0}\r\n");
            A("log.yaraExitCode", "yara64 finished with code {0} (some files may have been skipped).\r\n", "yara64 завершився з кодом {0} (частину файлів могло бути пропущено).\r\n");
            A("log.yaraDownloadingEngine", "Downloading the YARA engine (yara64.exe, ~2 MB)…\r\n", "Завантажую рушій YARA (yara64.exe, ~2 МБ)…\r\n");
            A("log.yaraDownloadingRules", "Downloading YARA rules (YARA Forge core, ~10 MB)…\r\n", "Завантажую YARA-правила (YARA Forge core, ~10 МБ)…\r\n");
            A("log.yaraReady", "YARA engine ready: {0} rule file(s) ✔\r\n", "Рушій YARA готовий: файлів правил: {0} ✔\r\n");
            A("log.yaraSetupFailed", "YARA setup failed: {0} — will retry later.\r\n", "Не вдалося налаштувати YARA: {0} — спробую пізніше.\r\n");
            A("err.noYaraInArchive", "yara64.exe not found in the archive", "В архіві немає yara64.exe");
            A("err.noRulesInArchive", "no .yar rules found in the archive", "В архіві немає .yar-правил");
            A("status.yaraUpdating", "Updating YARA rules in the background…", "Оновлюю YARA-правила у фоні…");
            A("status.enginesSaved", "Engine settings saved.", "Налаштування рушіїв збережено.");

            // VirusTotal
            A("engines.vtKeyLabel", "API key (free account at virustotal.com):", "API-ключ (безкоштовний акаунт на virustotal.com):");
            A("engines.vtGetKey", "Get a key", "Отримати ключ");
            A("engines.vtStatusOn", "Ready: hash checks enabled", "Готово: перевірка за хешем увімкнена");
            A("engines.vtStatusNoKey", "No API key — VirusTotal checks are off", "Немає API-ключа — перевірки VirusTotal не працюють");
            A("btn.testKey", "TEST KEY", "ПЕРЕВІРИТИ КЛЮЧ");
            A("engines.vtKeyEmpty", "Enter a key first.", "Спершу введи ключ.");
            A("engines.vtTesting", "Checking the key…", "Перевіряю ключ…");
            A("engines.vtKeyOk", "✓ The key works", "✓ Ключ працює");
            A("engines.vtKeyBad", "Key rejected — copy it again from virustotal.com", "Ключ відхилено — скопіюй його ще раз із virustotal.com");
            A("engines.vtKeyRate", "The key works, but the minute quota is used up — try again shortly",
                "Ключ працює, але хвилинну квоту вичерпано — спробуй трохи пізніше");
            A("engines.vtKeyNet", "No answer from VirusTotal: {0}", "Немає відповіді від VirusTotal: {0}");
            A("btn.getYara", "DOWNLOAD YARA RULES", "ЗАВАНТАЖИТИ YARA-ПРАВИЛА");
            A("btn.enterVtKey", "ENTER VIRUSTOTAL KEY…", "ВВЕСТИ КЛЮЧ VIRUSTOTAL…");
            A("vtkey.title", "VirusTotal API key", "API-ключ VirusTotal");
            A("vtkey.intro", "VirusTotal checks suspicious files by SHA256 hash against 70+ antivirus engines. "
                + "It needs a free API key — one minute to get, no payment details.",
                "VirusTotal перевіряє підозрілі файли за SHA256-хешем у 70+ антивірусних рушіях. "
                + "Потрібен безкоштовний API-ключ — забирає хвилину, без платіжних даних.");
            A("vtkey.getFree", "Get a free key at virustotal.com →", "Отримати безкоштовний ключ на virustotal.com →");
            A("settings.vtCheck", "Check suspicious files by SHA256 hash on VirusTotal", "Перевіряти підозрілі файли за SHA256-хешем на VirusTotal");
            A("settings.vtUpload", "Upload files unknown to VirusTotal for analysis", "Завантажувати невідомі VirusTotal файли на аналіз");
            A("engines.vtHint", "Hash checks send only the SHA256 of suspicious files (YARA detections, new files "
                + "from the monitor) — the file itself never leaves this PC. The upload option sends the actual file "
                + "to VirusTotal, where it becomes available to security researchers worldwide — leave it off for "
                + "files that may contain private data.",
                "Перевірка за хешем надсилає лише SHA256 підозрілих файлів (знахідки YARA, нові файли з "
                + "моніторингу) — сам файл не покидає цей ПК. Опція завантаження надсилає сам файл на VirusTotal, "
                + "де він стає доступним дослідникам безпеки з усього світу — не вмикайте її для файлів із "
                + "приватними даними.");
            A("desc.vtCheck", "VirusTotal check", "перевірка VirusTotal");
            A("log.vtMalicious", "VirusTotal: {0} of {1} engines flag {2}\r\n", "VirusTotal: {0} із {1} рушіїв вважають загрозою {2}\r\n");
            A("tray.vtMalicious", "VirusTotal: {0} engines flag file {1}", "VirusTotal: {0} рушіїв вважають загрозою файл {1}");
            A("log.vtSuspicious", "VirusTotal: {0} of {1} engines are suspicious of {2}\r\n", "VirusTotal: {0} із {1} рушіїв мають підозру щодо {2}\r\n");
            A("log.vtClean", "VirusTotal: {0} is clean (0/{1})\r\n", "VirusTotal: {0} чистий (0/{1})\r\n");
            A("log.vtUnknown", "VirusTotal: {0} is not in the database yet.\r\n", "VirusTotal: файлу {0} ще немає в базі.\r\n");
            A("log.vtUploading", "VirusTotal: uploading {0} for analysis…\r\n", "VirusTotal: завантажую {0} на аналіз…\r\n");
            A("log.vtUploaded", "VirusTotal: {0} submitted — results will appear on virustotal.com ✔\r\n", "VirusTotal: {0} надіслано — результати з'являться на virustotal.com ✔\r\n");
            A("log.vtUploadFailed", "VirusTotal upload failed: {0}\r\n", "Не вдалося завантажити на VirusTotal: {0}\r\n");
            A("log.vtTooBigToUpload", "VirusTotal: {0} is larger than 32 MB — not uploaded.\r\n", "VirusTotal: {0} більший за 32 МБ — не завантажую.\r\n");
            A("log.vtRateLimited", "VirusTotal rate limit reached — pausing checks for a while.\r\n", "Досягнуто ліміт запитів VirusTotal — перевірки призупинено на деякий час.\r\n");
            A("log.vtBadKey", "VirusTotal rejected the API key — check it in Settings → Engines.\r\n", "VirusTotal відхилив API-ключ — перевір його в Налаштування → Рушії.\r\n");
            A("log.vtError", "VirusTotal error: {0}\r\n", "Помилка VirusTotal: {0}\r\n");

            // YARA suspicion held for the VirusTotal verdict (trust tiers)
            A("log.yaraSuspiciousPending", "{0}: {1} — suspicious, awaiting the VirusTotal verdict before acting…\r\n",
                "{0}: {1} — підозріло, чекаю на вердикт VirusTotal перед діями…\r\n");
            A("log.yaraPendingCount", "YARA: {0} suspicious file(s) sent for a VirusTotal check — nothing is touched until the verdict arrives.\r\n",
                "YARA: підозрілих файлів надіслано на перевірку VirusTotal: {0} — до вердикту нічого не чіпаю.\r\n");
            A("log.donePendingVt", "Scan finished; {0} suspicious file(s) are awaiting the VirusTotal verdict — results will appear here.\r\n",
                "Сканування завершено; файлів в очікуванні вердикту VirusTotal: {0} — результати з'являться тут.\r\n");
            A("tray.donePendingVt", "Scan finished — {0} suspicious file(s) awaiting the VirusTotal verdict",
                "Сканування завершено — файлів чекають на вердикт VirusTotal: {0}");
            A("log.vtYaraLikelyFp", "{0}: clean on VirusTotal (0/{1}) — the {2} match looks like a false positive; the file was left in place.\r\n",
                "{0}: чистий на VirusTotal (0/{1}) — збіг {2} схожий на хибне спрацювання; файл залишено на місці.\r\n");
            A("log.vtYaraConfirmed", "VirusTotal confirms the YARA suspicion: {0} of {1} engines flag {2}\r\n",
                "VirusTotal підтверджує підозру YARA: {0} із {1} рушіїв вважають загрозою {2}\r\n");
            A("log.vtYaraUnknown", "VirusTotal has never seen {0} ({1}) — still suspicious.\r\n",
                "VirusTotal ще не бачив {0} ({1}) — файл лишається підозрілим.\r\n");
            A("log.vtYaraInconclusive", "VirusTotal: only {0} of {1} engines flag {2} — inconclusive.\r\n",
                "VirusTotal: лише {0} із {1} рушіїв мають підозру щодо {2} — вердикт неоднозначний.\r\n");
            A("log.vtYaraUnavailable", "No VirusTotal verdict for {0} ({1}) — handling it as a regular detection.\r\n",
                "Немає вердикту VirusTotal для {0} ({1}) — обробляю як звичайну знахідку.\r\n");
            A("log.vtYaraQuarantined", "{0} moved to quarantine (it can be restored from the Quarantine page).\r\n",
                "{0} переміщено в карантин (можна відновити на сторінці «Карантин»).\r\n");
            A("log.vtPendingGone", "{0} disappeared before the VirusTotal verdict arrived — nothing to do.\r\n",
                "{0} зник до отримання вердикту VirusTotal — дій не потрібно.\r\n");
            A("log.phaseTiming", "Engine timing — ClamAV: {0}, YARA: {1}\r\n",
                "Тривалість фаз — ClamAV: {0}, YARA: {1}\r\n");
            A("log.yaraPathsSkipped", "YARA: {0} file(s) skipped — their paths contain characters the YARA engine cannot open.\r\n",
                "YARA: пропущено файлів: {0} — у їхніх шляхах є символи, які рушій YARA не може відкрити.\r\n");
            A("log.yaraMoreErrors", "YARA: …and {0} more warning/error line(s) hidden.\r\n",
                "YARA: …і ще рядків попереджень/помилок: {0} (приховано).\r\n");
        }
    }
}
