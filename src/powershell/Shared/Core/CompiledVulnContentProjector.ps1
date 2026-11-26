$Script:CompiledVulnContentProjectorSource = @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;

namespace DefenderReporting.Store
{
    public sealed class CompiledMemoryTelemetry
    {
        public long PeakWorkingSetBytes { get; set; }
        public string PeakWorkingSetStage { get; set; }
        public long PeakPrivateMemoryBytes { get; set; }
        public string PeakPrivateMemoryStage { get; set; }
        public long PeakGcHeapBytes { get; set; }
        public string PeakGcHeapStage { get; set; }
        public long PreTrimWorkingSetBytes { get; set; }
        public long PreTrimPrivateMemoryBytes { get; set; }
        public long PreTrimGcHeapBytes { get; set; }
        public long PostTrimWorkingSetBytes { get; set; }
        public long PostTrimPrivateMemoryBytes { get; set; }
        public long PostTrimGcHeapBytes { get; set; }
        public long ElapsedMilliseconds { get; set; }
    }

    public sealed class MemoryTelemetrySession : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessMemoryCounters
        {
            public uint Size, PageFaultCount;
            public UIntPtr PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage, PrivateUsage;
        }
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool GetProcessMemoryInfo(IntPtr process, out ProcessMemoryCounters counters, uint size);
        private readonly System.Diagnostics.Process process = System.Diagnostics.Process.GetCurrentProcess();
        private readonly System.Diagnostics.Stopwatch stopwatch = System.Diagnostics.Stopwatch.StartNew();
        private readonly Timer timer;
        private long peakWorkingSet, peakPrivateMemory, peakGcHeap;
        private string stage = "initialization", peakWorkingSetStage = "initialization", peakPrivateMemoryStage = "initialization", peakGcHeapStage = "initialization";
        private int completed;

        public MemoryTelemetrySession(int intervalMilliseconds)
        {
            if (intervalMilliseconds > 0) timer = new Timer(_ => Sample(), null, 0, Math.Max(25, intervalMilliseconds));
        }

        public void SetStage(string value) { Volatile.Write(ref stage, String.IsNullOrWhiteSpace(value) ? "unknown" : value); Sample(); }
        public void Sample()
        {
            try
            {
                long workingSet, privateMemory; ReadMemory(out workingSet, out privateMemory); var currentStage = Volatile.Read(ref stage);
                UpdatePeak(ref peakWorkingSet, workingSet, ref peakWorkingSetStage, currentStage);
                UpdatePeak(ref peakPrivateMemory, privateMemory, ref peakPrivateMemoryStage, currentStage);
                UpdatePeak(ref peakGcHeap, GC.GetTotalMemory(false), ref peakGcHeapStage, currentStage);
            }
            catch { }
        }

        public CompiledMemoryTelemetry Complete(Action trimWorkingSet)
        {
            if (Interlocked.Exchange(ref completed, 1) != 0) throw new InvalidOperationException("Memory telemetry session is already complete.");
            if (timer != null) timer.Change(Timeout.Infinite, Timeout.Infinite); Sample();
            long preTrimWorkingSet, preTrimPrivateMemory; ReadMemory(out preTrimWorkingSet, out preTrimPrivateMemory);
            var result = new CompiledMemoryTelemetry {
                PeakWorkingSetBytes = peakWorkingSet, PeakWorkingSetStage = peakWorkingSetStage,
                PeakPrivateMemoryBytes = peakPrivateMemory, PeakPrivateMemoryStage = peakPrivateMemoryStage,
                PeakGcHeapBytes = peakGcHeap, PeakGcHeapStage = peakGcHeapStage,
                PreTrimWorkingSetBytes = preTrimWorkingSet, PreTrimPrivateMemoryBytes = preTrimPrivateMemory, PreTrimGcHeapBytes = GC.GetTotalMemory(false)
            };
            trimWorkingSet();
            long postTrimWorkingSet, postTrimPrivateMemory; ReadMemory(out postTrimWorkingSet, out postTrimPrivateMemory);
            result.PostTrimWorkingSetBytes = postTrimWorkingSet; result.PostTrimPrivateMemoryBytes = postTrimPrivateMemory; result.PostTrimGcHeapBytes = GC.GetTotalMemory(false); result.ElapsedMilliseconds = stopwatch.ElapsedMilliseconds;
            if (timer != null) timer.Dispose(); lock (process) process.Dispose(); return result;
        }

        public void Dispose() { if (Interlocked.Exchange(ref completed, 1) == 0) { if (timer != null) timer.Dispose(); lock (process) process.Dispose(); } }
        private static void UpdatePeak(ref long peak, long value, ref string peakStage, string currentStage)
        {
            long observed;
            while (value > (observed = Volatile.Read(ref peak))) if (Interlocked.CompareExchange(ref peak, value, observed) == observed) { Volatile.Write(ref peakStage, currentStage); break; }
        }
        private void ReadMemory(out long workingSet, out long privateMemory)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                var counters = new ProcessMemoryCounters(); counters.Size = (uint)Marshal.SizeOf(typeof(ProcessMemoryCounters));
                if (GetProcessMemoryInfo(process.Handle, out counters, counters.Size)) { workingSet = checked((long)counters.WorkingSetSize.ToUInt64()); privateMemory = checked((long)counters.PrivateUsage.ToUInt64()); return; }
            }
            // psapi.dll is Windows-only. Process exposes the corresponding procfs-backed
            // counters on Unix, so keep private-memory telemetry useful in Linux CI and
            // Azure-hosted PowerShell as well.
            try {
                ReadPortableMemory(out workingSet, out privateMemory);
            }
            catch {
                workingSet = 0; privateMemory = 0;
            }
            if (workingSet <= 0) workingSet = Environment.WorkingSet;
            if (privateMemory <= 0) privateMemory = workingSet;
        }
        private void ReadPortableMemory(out long workingSet, out long privateMemory)
        {
            lock (process) {
                process.Refresh();
                workingSet = process.WorkingSet64;
                privateMemory = process.PrivateMemorySize64;
            }
        }
    }

    public sealed class CompiledNormalizationResult
    {
        public long ProcessedCount { get; set; }
        public int DeviceCount { get; set; }
        public int CveCount { get; set; }
        public int SoftwareCount { get; set; }
        public int VendorCount { get; set; }
        public long FirstLastSwappedCount { get; set; }
        public CompiledMemoryTelemetry MemoryTelemetry { get; set; }
    }

    // Reproduces Newtonsoft.Json default string escaping (as used by the in-process payload writer): only control characters,
// quote, backslash, U+0085, U+2028 and U+2029 are escaped, with short forms and lowercase hex; everything else is emitted raw.
public sealed class NewtonsoftDefaultEscapingEncoder : JavaScriptEncoder
{
    public static readonly NewtonsoftDefaultEscapingEncoder Instance = new NewtonsoftDefaultEscapingEncoder();
    private NewtonsoftDefaultEscapingEncoder() { }
    public override int MaxOutputCharactersPerInputCharacter { get { return 6; } }
    public override bool WillEncode(int unicodeScalar) { return unicodeScalar < 0x20 || unicodeScalar == 0x22 || unicodeScalar == 0x5C || unicodeScalar == 0x85 || unicodeScalar == 0x2028 || unicodeScalar == 0x2029; }
    public override unsafe int FindFirstCharacterToEncode(char* text, int textLength) { for (var index = 0; index < textLength; index++) if (WillEncode(text[index])) return index; return -1; }
    public override unsafe bool TryEncodeUnicodeScalar(int unicodeScalar, char* buffer, int bufferLength, out int numberOfCharactersWritten)
    {
        if (!WillEncode(unicodeScalar)) { return TryWriteScalarAsChar(unicodeScalar, buffer, bufferLength, out numberOfCharactersWritten); }
        char shortForm = (char)0;
        switch (unicodeScalar) { case 0x08: shortForm = (char)98; break; case 0x09: shortForm = (char)116; break; case 0x0A: shortForm = (char)110; break; case 0x0C: shortForm = (char)102; break; case 0x0D: shortForm = (char)114; break; case 0x22: shortForm = (char)34; break; case 0x5C: shortForm = (char)92; break; }
        if (shortForm != (char)0) { if (bufferLength < 2) { numberOfCharactersWritten = 0; return false; } buffer[0] = (char)92; buffer[1] = shortForm; numberOfCharactersWritten = 2; return true; }
        if (bufferLength < 6) { numberOfCharactersWritten = 0; return false; }
        const string hex = "0123456789abcdef";
        buffer[0] = (char)92; buffer[1] = (char)117; buffer[2] = hex[(unicodeScalar >> 12) & 0xF]; buffer[3] = hex[(unicodeScalar >> 8) & 0xF]; buffer[4] = hex[(unicodeScalar >> 4) & 0xF]; buffer[5] = hex[unicodeScalar & 0xF];
        numberOfCharactersWritten = 6; return true;
    }
    private static unsafe bool TryWriteScalarAsChar(int unicodeScalar, char* buffer, int bufferLength, out int numberOfCharactersWritten)
    {
        var text = Char.ConvertFromUtf32(unicodeScalar);
        if (bufferLength < text.Length) { numberOfCharactersWritten = 0; return false; }
        for (var index = 0; index < text.Length; index++) buffer[index] = text[index];
        numberOfCharactersWritten = text.Length; return true;
    }
}

public static class BoundedContentNormalizer
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessWorkingSetSize(IntPtr process, IntPtr minimumWorkingSetSize, IntPtr maximumWorkingSetSize);
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);
        private static readonly JsonWriterOptions CompactWriterOptions = new JsonWriterOptions { SkipValidation = true };
        private static readonly JsonWriterOptions InProcessCompatibleWriterOptions = new JsonWriterOptions { SkipValidation = true, Encoder = NewtonsoftDefaultEscapingEncoder.Instance };
        // Projection is single-threaded; the active payload contract selects the string escaping used for every fragment and the final payload.
        [ThreadStatic] private static bool inProcessCompatibleEscaping;
        private static JsonWriterOptions WriterOptions { get { return inProcessCompatibleEscaping ? InProcessCompatibleWriterOptions : CompactWriterOptions; } }
        private sealed class Device { public string Id, Name, OsVersion, MachineInfoJson; public int Group, Platform; public int[] Tags; public bool Onboarded; }
        private sealed class MachineOverlay { public string Name, Group, Platform, OsVersion, MachineInfoJson; public string[] Tags; }
        private sealed class Software { public int Vendor; public string Name, Reference, InventoryIdentity; }
        private sealed class Update { public string Name, Id, Url; }
        private sealed class CveEnrichment { /* String-like enrichment fields hold staged raw JSON so supplied empty or whitespace values are preserved. */ public string PublishedDate, Description, EpssJson, ExploitAvailableJson, NvdLastModified, NvdBaseScoreJson, NvdBaseSeverity, NvdVector, NvdKevDate, NvdActionDue, NvdRequiredAction, WeaknessesJson; public string[] AffectedSoftware, Weaknesses; }
        private sealed class Cve { public string Id, Url, ScoreJson; public double? Score; public int Severity, Exploit, BatchTitle; public CveEnrichment Enrichment; public int[] AffectedSoftware; }
        private sealed class InventoryRecord { public string Cpe, EndOfSupportStatus, EndOfSupportDate; }
        private sealed class NormalizationOptions { public StringComparer InventoryKeyComparer, SeverityKeyComparer; public Dictionary<string, int> SeverityIndexes; public bool InProcessCompatible; }
        private struct Template { public int Software, Cve, Version, Update, UpdateAvailable, DiskStart, DiskCount, RegistryStart, RegistryCount; }
        private struct HashKey { public ulong First, Second; public HashKey(ulong first, ulong second) { First = first; Second = second; } }
        private sealed class UlongIndexMap
        {
            private ulong[] firstKeys, secondKeys; private int[] values; private int count;
            public UlongIndexMap(int expectedCount) { var capacity = 1024; var required = Math.Max(1, expectedCount) * 10 / 7 + 1; while (capacity < required) capacity *= 2; firstKeys = new ulong[capacity]; secondKeys = new ulong[capacity]; values = new int[capacity]; }
            public bool TryGetValue(HashKey key, out int value) { var slot = Slot(key, values.Length); while (values[slot] != 0) { if (firstKeys[slot] == key.First && secondKeys[slot] == key.Second) { value = values[slot] - 1; return true; } slot = (slot + 1) & (values.Length - 1); } value = 0; return false; }
            public void Add(HashKey key, int value) { if ((count + 1) * 10 >= values.Length * 7) Resize(); var slot = Slot(key, values.Length); while (values[slot] != 0) { if (firstKeys[slot] == key.First && secondKeys[slot] == key.Second) throw new ArgumentException("Duplicate hash key."); slot = (slot + 1) & (values.Length - 1); } firstKeys[slot] = key.First; secondKeys[slot] = key.Second; values[slot] = value + 1; count++; }
            public void Clear() { firstKeys = Array.Empty<ulong>(); secondKeys = Array.Empty<ulong>(); values = Array.Empty<int>(); count = 0; }
            private void Resize() { var oldFirst = firstKeys; var oldSecond = secondKeys; var oldValues = values; firstKeys = new ulong[oldFirst.Length * 2]; secondKeys = new ulong[firstKeys.Length]; values = new int[firstKeys.Length]; for (var index = 0; index < oldValues.Length; index++) if (oldValues[index] != 0) { var key = new HashKey(oldFirst[index], oldSecond[index]); var slot = Slot(key, values.Length); while (values[slot] != 0) slot = (slot + 1) & (values.Length - 1); firstKeys[slot] = key.First; secondKeys[slot] = key.Second; values[slot] = oldValues[index]; } }
            private static int Slot(HashKey key, int length) { var hash = key.First ^ key.Second; hash ^= hash >> 33; hash *= 0xff51afd7ed558ccdUL; hash ^= hash >> 33; return (int)(hash & (ulong)(length - 1)); }
        }

        public static CompiledNormalizationResult Project(string dictionaryPath, string[] refPaths, string outputPath)
        {
            using (var telemetry = new MemoryTelemetrySession(0)) return Project(dictionaryPath, refPaths, outputPath, telemetry);
        }

        public static CompiledNormalizationResult Project(string dictionaryPath, string[] refPaths, string outputPath, MemoryTelemetrySession telemetry)
        {
            return Project(dictionaryPath, refPaths, outputPath, telemetry, Path.GetTempPath());
        }

        public static CompiledNormalizationResult Project(string dictionaryPath, string[] refPaths, string outputPath, MemoryTelemetrySession telemetry, string stagingParent)
        {
            if (refPaths == null) throw new ArgumentNullException("refPaths");
            if (telemetry == null) throw new ArgumentNullException("telemetry");
            if (String.IsNullOrWhiteSpace(stagingParent)) throw new ArgumentNullException("stagingParent");
            var stageRoot = Path.Combine(stagingParent, "bounded-normalizer-" + Guid.NewGuid().ToString("N"));
            return (CompiledNormalizationResult)RunWithStagingCleanup(stageRoot, () => { var previousEscaping = inProcessCompatibleEscaping; try { return ProjectStaged(dictionaryPath, refPaths, outputPath, telemetry, stageRoot); } finally { inProcessCompatibleEscaping = previousEscaping; } });
        }

        // Staged fragments contain plaintext tenant data, so the staging directory is removed on success and failure;
        // cleanup failures are surfaced, and a failed projection keeps its original exception as the first inner exception.
        public static object RunWithStagingCleanup(string stageRoot, Func<object> body)
        {
            if (String.IsNullOrWhiteSpace(stageRoot)) throw new ArgumentNullException("stageRoot");
            if (body == null) throw new ArgumentNullException("body");
            object result;
            try { result = body(); }
            catch (Exception original)
            {
                var failedCleanupError = TryDeleteStagingDirectory(stageRoot);
                if (failedCleanupError != null) throw new AggregateException("Bounded normalization failed (" + original.Message + ") and its plaintext staging directory '" + stageRoot + "' could not be removed (" + failedCleanupError.Message + ").", original, failedCleanupError);
                throw;
            }
            var cleanupError = TryDeleteStagingDirectory(stageRoot);
            if (cleanupError != null) throw new IOException("Bounded normalization completed but its plaintext staging directory '" + stageRoot + "' could not be removed: " + cleanupError.Message, cleanupError);
            return result;
        }

        // Deletes directly instead of probing with Directory.Exists, which reports false on access errors and invalid paths.
        // Only a confirmed-absent directory counts as success; every other failure is returned for the caller to surface.
        public static Exception TryDeleteStagingDirectory(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) return new ArgumentNullException("path");
            Exception lastError = null;
            for (var attempt = 0; attempt < 3; attempt++)
            {
                if (attempt > 0) Thread.Sleep(100 * attempt);
                try { Directory.Delete(path, true); return null; }
                catch (DirectoryNotFoundException notFound)
                {
                    if (IsConfirmedAbsent(path)) return null;
                    lastError = notFound;
                }
                catch (Exception error) { lastError = error; }
            }
            return lastError;
        }

        private static bool IsConfirmedAbsent(string path)
        {
            try { File.GetAttributes(path); return false; }
            catch (FileNotFoundException) { return true; }
            catch (DirectoryNotFoundException) { return true; }
            catch (Exception) { return false; }
        }

        private static CompiledNormalizationResult ProjectStaged(string dictionaryPath, string[] refPaths, string outputPath, MemoryTelemetrySession telemetry, string stageRoot)
        {
            telemetry.SetStage("template-interning");
            var expectedTemplates = Directory.Exists(dictionaryPath) ? File.ReadLines(Path.Combine(dictionaryPath, "contentTemplates.ndjson"), Utf8).Count() : 1024;
            var normalizationOptions = ReadNormalizationOptions(Path.Combine(dictionaryPath, "normalizationOptions.json"));
            var inProcessCompatible = normalizationOptions.InProcessCompatible; inProcessCompatibleEscaping = inProcessCompatible;
            var machineOverlays = ReadMachineOverlays(Path.Combine(dictionaryPath, "machines.ndjson"), inProcessCompatible);
            var cveEnrichment = ReadCveEnrichment(Path.Combine(dictionaryPath, "cveEnrichment.ndjson"), inProcessCompatible);
            var inventorySource = ReadInventory(Path.Combine(dictionaryPath, "inventory.ndjson"), normalizationOptions.InventoryKeyComparer);
            var vendors = new List<string>(); var vendorMap = Map();
            var exploits = new List<string>(); var exploitMap = Map();
            var groups = new List<string>(); var groupMap = Map();
            var platforms = new List<string>(); var platformMap = Map();
            var tags = new List<string>(); var tagMap = Map();
            var versions = new List<string>(); var versionMap = Map();
            var dates = new List<string>(); var dateMap = Map();
            var diskPaths = new List<string>(); var diskMap = Map();
            var registryPaths = new List<string>(); var registryMap = Map(); var templatePathMap = Map();
            var batchTitles = new List<string>(); var batchMap = Map();
            var affectedSoftware = new List<string>(); var affectedSoftwareMap = Map();
            var softwareMap = HashMap(expectedTemplates); var softwareCount = 0;
            var updateMap = HashMap(inProcessCompatible ? 0 : expectedTemplates); var updateCount = 0;
            var cveMap = HashMap(expectedTemplates); var cveCount = 0;
            var deviceOnboarded = new List<bool>();
            var deviceIds = new List<string>();
            var profileDeviceIndexes = new List<int>();
            var deviceKeyMap = new Dictionary<string, int>(StringComparer.Ordinal);
            var softwareIdentities = new List<string>();
            var softwareVendorIndexes = inProcessCompatible ? new List<int>() : null;
            var usedVendorIndexes = inProcessCompatible ? new HashSet<int>() : null;
            var inventoryValues = new List<InventoryRecord>(); var inventoryValueMap = Map();
            var templateList = new List<Template>();
            var templateDiskIndexes = new List<int>(); var templateRegistryIndexes = new List<int>();
            Directory.CreateDirectory(stageRoot);
            var deviceFragment = Path.Combine(stageRoot, "devices.ndjson"); var softwareFragment = Path.Combine(stageRoot, "software.ndjson"); var updateFragment = Path.Combine(stageRoot, "updates.ndjson"); var cveFragment = Path.Combine(stageRoot, "cves.ndjson"); var vulnFragment = Path.Combine(stageRoot, "vulns.ndjson");
            using (var deviceOutput = new StreamWriter(deviceFragment, false, Utf8, 65536))
            using (var softwareOutput = new StreamWriter(softwareFragment, false, Utf8, 65536))
            using (var updateOutput = new StreamWriter(updateFragment, false, Utf8, 65536))
            using (var cveOutput = new StreamWriter(cveFragment, false, Utf8, 65536))
            {

            ReadDictionaryArray(dictionaryPath, "deviceProfiles", item =>
                {
                    var deviceId = Value(item, "id");
                    var deviceKey = String.IsNullOrWhiteSpace(deviceId) ? String.Join("|", Value(item, "n"), Value(item, "g"), Value(item, "o"), Value(item, "ov")) : deviceId;
                    int existingDeviceIndex;
                    if (deviceKeyMap.TryGetValue(deviceKey, out existingDeviceIndex)) { deviceIds.Add(deviceId); deviceOnboarded.Add(Boolean(item, "ob")); profileDeviceIndexes.Add(existingDeviceIndex); return; }
                    var tagIndexes = new List<int>();
                    MachineOverlay overlay = null;
                    var hasOverlay = !String.IsNullOrWhiteSpace(deviceId) && machineOverlays.TryGetValue(deviceId, out overlay);
                    JsonElement tagValues;
                    if (hasOverlay && overlay.Tags != null && overlay.Tags.Length > 0)
                        foreach (var value in overlay.Tags) { var index = Intern(value, tags, tagMap); if (index >= 0) tagIndexes.Add(index); }
                    else if (item.TryGetProperty("t", out tagValues) && tagValues.ValueKind == JsonValueKind.Array)
                        foreach (var tag in tagValues.EnumerateArray()) { var value = ScalarString(tag); if (inProcessCompatible && String.IsNullOrWhiteSpace(value)) continue; var index = Intern(value, tags, tagMap); if (index >= 0) tagIndexes.Add(index); }
                    var group = hasOverlay && !String.IsNullOrWhiteSpace(overlay.Group) ? overlay.Group : Value(item, "g"); if (String.IsNullOrWhiteSpace(group)) group = "(none)";
                    var platform = hasOverlay && !String.IsNullOrWhiteSpace(overlay.Platform) ? overlay.Platform : Value(item, "o");
                    var name = hasOverlay && !String.IsNullOrWhiteSpace(overlay.Name) ? overlay.Name : Value(item, "n");
                    var osVersion = hasOverlay && !String.IsNullOrWhiteSpace(overlay.OsVersion) ? overlay.OsVersion : Value(item, "ov");
                    var device = new Device {
                        Id = deviceId, Name = EmptyFallback(name, "(no machine data)"), OsVersion = NullIfEmpty(osVersion), MachineInfoJson = hasOverlay ? overlay.MachineInfoJson : null,
                        Group = Intern(group, groups, groupMap), Platform = Intern(platform, platforms, platformMap), Tags = tagIndexes.ToArray(), Onboarded = Boolean(item, "ob")
                    };
                    var lookupIndex = deviceKeyMap.Count; deviceKeyMap.Add(deviceKey, lookupIndex);
                    deviceIds.Add(device.Id); deviceOnboarded.Add(device.Onboarded); profileDeviceIndexes.Add(lookupIndex); WriteDeviceFragment(deviceOutput, device);
                });

            ReadDictionaryArray(dictionaryPath, "contentTemplates", item =>
                {
                    var vendor = Value(item, "sv"); var name = Value(item, "sn"); var reference = Value(item, "rr");
                    var vendorIndex = Intern(vendor, vendors, vendorMap);
                    var softwareKey = GetHashKey(vendor, name, reference);
                    int softwareIndex;
                    if (!softwareMap.TryGetValue(softwareKey, out softwareIndex)) {
                        softwareIndex = softwareCount++; softwareMap.Add(softwareKey, softwareIndex);
                        var software = new Software { Vendor = vendorIndex, Name = name, Reference = reference, InventoryIdentity = vendor + "|" + name };
                        softwareIdentities.Add(software.InventoryIdentity); if (inProcessCompatible) softwareVendorIndexes.Add(vendorIndex); WriteSoftwareFragment(softwareOutput, software);
                    }

                    var cveId = Value(item, "c"); var scoreText = inProcessCompatible ? CompatibleScoreKey(item) : Value(item, "sc"); var severity = Value(item, "sev"); var exploit = Value(item, "ex"); var url = ConvertCveUrl(Value(item, "bu")); var batch = Value(item, "bt");
                    var cveKey = GetHashKey(cveId, scoreText, severity, exploit, url, batch);
                    int cveIndex;
                    if (!cveMap.TryGetValue(cveKey, out cveIndex)) {
                        cveIndex = cveCount++; cveMap.Add(cveKey, cveIndex);
                        double parsedScore; double? score = Double.TryParse(scoreText, NumberStyles.Float, CultureInfo.InvariantCulture, out parsedScore) ? parsedScore : (double?)null;
                        CveEnrichment enrichment; cveEnrichment.TryGetValue(cveId, out enrichment);
                        var affectedIndexes = new List<int>();
                        if (enrichment != null && enrichment.AffectedSoftware != null) foreach (var affected in enrichment.AffectedSoftware) { var affectedIndex = Intern(affected, affectedSoftware, affectedSoftwareMap); if (affectedIndex >= 0) affectedIndexes.Add(affectedIndex); }
                        WriteCveFragment(cveOutput, new Cve { Id = cveId, Score = score, ScoreJson = inProcessCompatible ? CompatibleScoreJson(item) : null, Severity = SeverityIndex(severity, normalizationOptions.SeverityIndexes), Exploit = Intern(exploit, exploits, exploitMap), Url = url, BatchTitle = Intern(batch, batchTitles, batchMap), Enrichment = enrichment, AffectedSoftware = affectedIndexes.Count > 0 ? affectedIndexes.ToArray() : null });
                    }

                    var updateName = Value(item, "ru"); var updateIndex = -1;
                    if (inProcessCompatible) {
                        // Mirrors Resolve-UpdateLookupIndex: its [hashtable] parameter receives a fresh copy of the index map per call, so every
                        // eligible template appends its own update entry and whitespace-only names are retained.
                        if (!String.IsNullOrEmpty(updateName) && updateName != "--") { updateIndex = updateCount++; WriteUpdateFragment(updateOutput, new Update { Name = updateName, Id = Value(item, "rid"), Url = Value(item, "url") }); }
                    } else if (!String.IsNullOrWhiteSpace(updateName) && updateName != "--") {
                        // High-cardinality compact contract: updates are interned globally by exact per-field values.
                        var updateId = Value(item, "rid"); var updateUrl = Value(item, "url"); var updateKey = GetFieldHashKey(updateName, updateId, updateUrl);
                        if (!updateMap.TryGetValue(updateKey, out updateIndex)) { updateIndex = updateCount++; updateMap.Add(updateKey, updateIndex); WriteUpdateFragment(updateOutput, new Update { Name = updateName, Id = updateId, Url = updateUrl }); }
                    }
                    int diskStart, diskCount, registryStart, registryCount;
                    if (inProcessCompatible) {
                        AppendTemplatePathArray(item, "dp", diskPaths, templatePathMap, templateDiskIndexes, out diskStart, out diskCount);
                        AppendTemplatePathArray(item, "rp", registryPaths, templatePathMap, templateRegistryIndexes, out registryStart, out registryCount);
                    } else {
                        InternFlatArray(item, "dp", diskPaths, diskMap, templateDiskIndexes, out diskStart, out diskCount);
                        InternFlatArray(item, "rp", registryPaths, registryMap, templateRegistryIndexes, out registryStart, out registryCount);
                    }
                    templateList.Add(new Template {
                        Software = softwareIndex, Cve = cveIndex, Version = Intern(Value(item, "ver"), versions, versionMap), Update = updateIndex,
                        UpdateAvailable = Boolean(item, "ua") ? 1 : 0, DiskStart = diskStart, DiskCount = diskCount, RegistryStart = registryStart, RegistryCount = registryCount
                    });
                });
            }
            foreach (var map in new[] { vendorMap, exploitMap, groupMap, platformMap, tagMap, versionMap, diskMap, registryMap, templatePathMap, batchMap, affectedSoftwareMap }) map.Clear();
            softwareMap.Clear(); updateMap.Clear(); cveMap.Clear();
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true); GC.WaitForPendingFinalizers();

            telemetry.SetStage("ref-projection");
            long processed = 0; long swappedCount = 0;
            using (var vulnOutput = new StreamWriter(vulnFragment, false, Utf8, 65536))
            {
                foreach (var refPath in refPaths)
                {
                    using (var input = OpenInput(refPath)) using (var reader = new StreamReader(input, Utf8, true, 65536))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            if (String.IsNullOrWhiteSpace(line)) continue;
                            using (var refDocument = JsonDocument.Parse(line))
                            {
                                try {
                                var values = refDocument.RootElement; if (values.ValueKind != JsonValueKind.Array || values.GetArrayLength() < 5) continue;
                                var deviceIndex = values[1].GetInt32(); var templateIndex = values[2].GetInt32();
                                if (deviceIndex < 0 || deviceIndex >= deviceOnboarded.Count || templateIndex < 0 || templateIndex >= templateList.Count || !deviceOnboarded[deviceIndex]) continue;
                                var first = NormalizeDate(ScalarString(values[3])); var last = NormalizeDate(ScalarString(values[4]));
                                if (!String.IsNullOrEmpty(first) && !String.IsNullOrEmpty(last) && CompareSeenDates(first, last) > 0) { var swap = first; first = last; last = swap; swappedCount++; }
                                var template = templateList[templateIndex];
                                if (inProcessCompatible && template.Software >= 0 && template.Software < softwareVendorIndexes.Count) { var usedVendorIndex = softwareVendorIndexes[template.Software]; if (usedVendorIndex >= 0) usedVendorIndexes.Add(usedVendorIndex); }
                                var firstIndex = Intern(first, dates, dateMap); var lastIndex = Intern(last, dates, dateMap);
                                var inventoryIndex = -1;
                                if (inventorySource != null && inventorySource.Count > 0 && deviceIds != null && softwareIdentities != null && deviceIndex < deviceIds.Count && template.Software >= 0 && template.Software < softwareIdentities.Count) {
                                    var version = template.Version >= 0 && template.Version < versions.Count ? versions[template.Version] : String.Empty;
                                    InventoryRecord inventoryRecord;
                                    if (inventorySource.TryGetValue(deviceIds[deviceIndex] + "|" + softwareIdentities[template.Software] + "|" + version, out inventoryRecord)) {
                                        var inventoryValueKey = (inventoryRecord.Cpe ?? String.Empty) + "|" + (inventoryRecord.EndOfSupportStatus ?? String.Empty) + "|" + (inventoryRecord.EndOfSupportDate ?? String.Empty);
                                        if (!inventoryValueMap.TryGetValue(inventoryValueKey, out inventoryIndex)) { inventoryIndex = inventoryValues.Count; inventoryValueMap.Add(inventoryValueKey, inventoryIndex); inventoryValues.Add(inventoryRecord); }
                                    }
                                }
                                try { WriteVulnFragment(vulnOutput, profileDeviceIndexes[deviceIndex], template, firstIndex, lastIndex, inventoryIndex, templateDiskIndexes, templateRegistryIndexes); }
                                catch (Exception error) { throw new InvalidDataException("Bounded vulnerability projection failed at ref " + processed.ToString(CultureInfo.InvariantCulture) + ", device " + deviceIndex.ToString(CultureInfo.InvariantCulture) + ", template " + templateIndex.ToString(CultureInfo.InvariantCulture) + ".", error); }
                                processed++;
                                if (processed % 250000 == 0) telemetry.Sample();
                                }
                                catch (Exception error) { throw new InvalidDataException("Bounded ref processing failed after " + processed.ToString(CultureInfo.InvariantCulture) + " projected rows.", error); }
                            }
                        }
                    }
                }
            }
            telemetry.SetStage("pre-assembly-cleanup");
            var resultDeviceCount = deviceKeyMap.Count;
            var resultVendorCount = vendors.Count;
            var allowedAffectedSoftware = inProcessCompatible ? BuildAllowedAffectedSoftware(vendors, usedVendorIndexes, affectedSoftware) : null;
            usedVendorIndexes = null; softwareVendorIndexes = null;
            templateList = null; deviceOnboarded = null; deviceIds = null; profileDeviceIndexes = null; deviceKeyMap = null; softwareIdentities = null; inventorySource.Clear(); inventoryValueMap.Clear(); templateDiskIndexes = null; templateRegistryIndexes = null; dateMap.Clear();
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true); GC.WaitForPendingFinalizers(); TrimCurrentProcessWorkingSet();
            telemetry.SetStage("lookup-and-payload-assembly");
            using (var file = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 65536, FileOptions.SequentialScan))
            using (var gzip = new GZipStream(file, CompressionLevel.Fastest, false))
            using (var writer = new Utf8JsonWriter(gzip, WriterOptions))
            {
                writer.WriteStartObject(); writer.WriteString("vulnsFormat", "rows-v1");
                if (inProcessCompatible) {
                    // The in-process payload writer (Open-CombinedPayloadWriter) streams vulns before lookups.
                    telemetry.SetStage("vulnerability-assembly");
                    writer.WritePropertyName("vulns"); CopyJsonLines(writer, vulnFragment);
                }
                writer.WritePropertyName("lookups"); writer.WriteStartObject();
                WriteStrings(writer, "vendors", vendors); vendors = null; WriteFixedStrings(writer, "severities", new[] { "Critical", "High", "Medium", "Low", "None" }); WriteStrings(writer, "exploitLevels", exploits); exploits = null;
                WriteStrings(writer, "groups", groups); groups = null; WriteStrings(writer, "platforms", platforms); platforms = null; WriteStrings(writer, "tags", tags); tags = null;
                writer.WritePropertyName("updates"); CopyJsonLines(writer, updateFragment);
                WriteStrings(writer, "versions", versions); versions = null; WriteStrings(writer, "dates", dates); dates = null; WriteStrings(writer, "diskPaths", diskPaths); diskPaths = null; WriteStrings(writer, "regPaths", registryPaths); registryPaths = null;
                WriteStrings(writer, "affSoftware", affectedSoftware); affectedSoftware = null; WriteStrings(writer, "batchTitles", batchTitles); batchTitles = null;
                writer.WritePropertyName("devices"); CopyJsonLines(writer, deviceFragment);
                writer.WritePropertyName("inventory"); writer.WriteStartArray(); foreach (var inventory in inventoryValues) { writer.WriteStartObject(); WriteNullableString(writer, "cpe", inventory.Cpe); WriteNullableString(writer, "eos", inventory.EndOfSupportStatus); WriteNullableString(writer, "eod", inventory.EndOfSupportDate); writer.WriteEndObject(); } writer.WriteEndArray(); inventoryValues = null;
                writer.WritePropertyName("software"); CopyJsonLines(writer, softwareFragment);
                writer.WritePropertyName("cves");
                if (inProcessCompatible) CopyCveLinesWithAffectedSoftwareFilter(writer, cveFragment, allowedAffectedSoftware);
                else CopyJsonLines(writer, cveFragment);
                allowedAffectedSoftware = null;
                writer.WriteNull("noTagsIdx"); writer.WriteEndObject();
                if (!inProcessCompatible) {
                    telemetry.SetStage("pre-vulnerability-assembly-cleanup");
                    GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
                    GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true); GC.WaitForPendingFinalizers(); TrimCurrentProcessWorkingSet();
                    telemetry.SetStage("vulnerability-assembly");
                    writer.WritePropertyName("vulns"); CopyJsonLines(writer, vulnFragment);
                }
                writer.WriteEndObject();
            }
            var result = new CompiledNormalizationResult { ProcessedCount = processed, DeviceCount = resultDeviceCount, CveCount = cveCount, SoftwareCount = softwareCount, VendorCount = resultVendorCount, FirstLastSwappedCount = swappedCount };
            telemetry.SetStage("cleanup"); telemetry.Sample();
            vendors = null; exploits = null; groups = null; platforms = null; tags = null; versions = null; dates = null; diskPaths = null; registryPaths = null; batchTitles = null; affectedSoftware = null; inventoryValues = null;
            deviceOnboarded = null; deviceIds = null; softwareIdentities = null; templateList = null; templateDiskIndexes = null; templateRegistryIndexes = null;
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true); GC.WaitForPendingFinalizers();
            result.MemoryTelemetry = telemetry.Complete(TrimCurrentProcessWorkingSet);
            return result;
        }

        public static void TrimCurrentProcessWorkingSet()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
            try { SetProcessWorkingSetSize(System.Diagnostics.Process.GetCurrentProcess().Handle, new IntPtr(-1), new IntPtr(-1)); } catch { }
        }

        private static Dictionary<string, int> Map() { return new Dictionary<string, int>(StringComparer.Ordinal); }
        private static UlongIndexMap HashMap(int expectedCount) { return new UlongIndexMap(expectedCount); }
        private static HashKey GetHashKey(params string[] values)
        {
            const ulong offset1 = 14695981039346656037UL, offset2 = 7809847782465536322UL, prime1 = 1099511628211UL, prime2 = 14029467366897019727UL; var first = offset1; var second = offset2;
            // Hashes the same character sequence as the in-process "a|b|c" lookup key so pipe-containing fields deduplicate identically.
            for (var valueIndex = 0; valueIndex < values.Length; valueIndex++) {
                if (valueIndex > 0) { first ^= '|'; first *= prime1; second ^= (ulong)'|' + 0x9e37UL; second *= prime2; }
                var value = values[valueIndex]; if (value != null) foreach (var character in value) { first ^= character; first *= prime1; second ^= (ulong)character + 0x9e37UL; second *= prime2; }
            }
            return new HashKey(first, second);
        }
        // High-cardinality compact contract: update lookups are interned globally by exact per-field values.
        private static HashKey GetFieldHashKey(params string[] values)
        {
            const ulong offset1 = 14695981039346656037UL, offset2 = 7809847782465536322UL, prime1 = 1099511628211UL, prime2 = 14029467366897019727UL; var first = offset1; var second = offset2;
            foreach (var value in values) { if (value != null) foreach (var character in value) { first ^= character; first *= prime1; second ^= (ulong)character + 0x9e37UL; second *= prime2; } first ^= 0xFF; first *= prime1; second ^= 0xA5; second *= prime2; }
            return new HashKey(first, second);
        }
        private static void ReadDictionaryArray(string path, string propertyName, Action<JsonElement> action)
        {
            if (!Directory.Exists(path)) throw new InvalidDataException("Bounded normalization requires a staged dictionary fragment directory.");
            var fragmentPath = Path.Combine(path, propertyName + ".ndjson");
            using (var reader = new StreamReader(fragmentPath, Utf8, true, 65536))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (String.IsNullOrWhiteSpace(line)) continue;
                    using (var document = JsonDocument.Parse(line)) action(document.RootElement);
                }
            }
        }
        // The wrapper always stages every fragment (empty is valid); a missing file is a contract violation, and access errors propagate unchanged.
        private static IEnumerable<string> ReadRequiredFragmentLines(string path)
        {
            try { return File.ReadLines(path, Utf8); }
            catch (Exception exception) when (exception is FileNotFoundException || exception is DirectoryNotFoundException) { throw new InvalidDataException("Bounded normalization requires the staged fragment '" + Path.GetFileName(path) + "'.", exception); }
        }
        private static string ReadRequiredFragmentText(string path)
        {
            try { return File.ReadAllText(path, Utf8); }
            catch (Exception exception) when (exception is FileNotFoundException || exception is DirectoryNotFoundException) { throw new InvalidDataException("Bounded normalization requires the staged fragment '" + Path.GetFileName(path) + "'.", exception); }
        }
        private static Dictionary<string, MachineOverlay> ReadMachineOverlays(string path, bool inProcessCompatible)
        {
            var result = new Dictionary<string, MachineOverlay>(StringComparer.Ordinal);
            foreach (var line in ReadRequiredFragmentLines(path)) { if (String.IsNullOrWhiteSpace(line)) continue; using (var document = JsonDocument.Parse(line)) { var item = document.RootElement; var id = Value(item, "id"); if (String.IsNullOrWhiteSpace(id)) continue; result[id] = new MachineOverlay { Name = Value(item, "n"), Group = Value(item, "g"), Platform = Value(item, "o"), OsVersion = Value(item, "ov"), Tags = inProcessCompatible ? ScalarStringArray(item, "t") : StringArray(item, "t"), MachineInfoJson = RawValue(item, "m") }; } }
            return result;
        }
        private static Dictionary<string, CveEnrichment> ReadCveEnrichment(string path, bool inProcessCompatible)
        {
            var result = new Dictionary<string, CveEnrichment>(StringComparer.Ordinal);
            foreach (var line in ReadRequiredFragmentLines(path)) { if (String.IsNullOrWhiteSpace(line)) continue; using (var document = JsonDocument.Parse(line)) { var item = document.RootElement; var id = Value(item, "id"); if (String.IsNullOrWhiteSpace(id)) continue; result[id] = new CveEnrichment { PublishedDate = RawValue(item, "pd"), Description = RawValue(item, "desc"), EpssJson = RawValue(item, "ep"), AffectedSoftware = inProcessCompatible ? ScalarStringArray(item, "as") : StringArray(item, "as"), ExploitAvailableJson = RawValue(item, "ea"), NvdLastModified = RawValue(item, "nlm"), NvdBaseScoreJson = RawValue(item, "nbs"), NvdBaseSeverity = RawValue(item, "nsv"), NvdVector = RawValue(item, "nvec"), NvdKevDate = RawValue(item, "nkev"), NvdActionDue = RawValue(item, "ndu"), NvdRequiredAction = RawValue(item, "nact"), WeaknessesJson = inProcessCompatible ? RawValue(item, "nw") : null, Weaknesses = inProcessCompatible ? null : StringArray(item, "nw") }; } }
            return result;
        }
        private static Dictionary<string, InventoryRecord> ReadInventory(string path, StringComparer comparer)
        {
            var result = new Dictionary<string, InventoryRecord>(comparer);
            foreach (var line in ReadRequiredFragmentLines(path)) { if (String.IsNullOrWhiteSpace(line)) continue; using (var document = JsonDocument.Parse(line)) { var item = document.RootElement; var key = Value(item, "k"); if (String.IsNullOrWhiteSpace(key)) continue; result[key] = new InventoryRecord { Cpe = NullIfEmpty(Value(item, "cpe")), EndOfSupportStatus = NullIfEmpty(Value(item, "eos")), EndOfSupportDate = NullIfEmpty(Value(item, "eod")) }; } }
            return result;
        }
        // Keeps empty and whitespace entries; callers apply the in-process Get-OrCreateIndex rule that skips only empty values.
        private static string[] ScalarStringArray(JsonElement item, string name) { JsonElement value; if (!item.TryGetProperty(name, out value) || value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Undefined) return null; var values = new List<string>(); if (value.ValueKind == JsonValueKind.Array) { foreach (var element in value.EnumerateArray()) values.Add(ScalarString(element)); } else values.Add(ScalarString(value)); return values.ToArray(); }
        private static string[] StringArray(JsonElement item, string name) { JsonElement value; if (!item.TryGetProperty(name, out value) || value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Undefined) return null; var values = new List<string>(); if (value.ValueKind == JsonValueKind.Array) { foreach (var element in value.EnumerateArray()) { var text = ScalarString(element); if (!String.IsNullOrWhiteSpace(text)) values.Add(text); } } else { var text = ScalarString(value); if (!String.IsNullOrWhiteSpace(text)) values.Add(text); } return values.Count == 0 ? null : values.ToArray(); }
        private static string RawValue(JsonElement item, string name) { JsonElement value; if (!item.TryGetProperty(name, out value) || value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Undefined) return null; return value.GetRawText(); }
        private static Stream OpenInput(string path) { var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan); return path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? (Stream)new GZipStream(file, CompressionMode.Decompress, false) : file; }
        private static string Value(JsonElement item, string name) { JsonElement value; return item.TryGetProperty(name, out value) ? ScalarString(value) : String.Empty; }
        private static string ScalarString(JsonElement value) { if (value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Undefined) return String.Empty; return value.ValueKind == JsonValueKind.String ? value.GetString() ?? String.Empty : value.GetRawText().Trim('"'); }
        private static bool IsFloatingPointJsonNumber(string value) { return value.IndexOf('.') >= 0 || value.IndexOf('e') >= 0 || value.IndexOf('E') >= 0; }
        private static string CompatibleScoreKey(JsonElement item)
        {
            JsonElement value;
            if (!item.TryGetProperty("sc", out value) || value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Undefined) return String.Empty;
            if (value.ValueKind == JsonValueKind.Number && IsFloatingPointJsonNumber(value.GetRawText())) return System.Management.Automation.LanguagePrimitives.ConvertTo<string>(value.GetDouble());
            if (value.ValueKind == JsonValueKind.True) return "True";
            if (value.ValueKind == JsonValueKind.False) return "False";
            return ScalarString(value);
        }
        private static string CompatibleScoreJson(JsonElement item)
        {
            JsonElement value;
            if (!item.TryGetProperty("sc", out value) || value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Undefined) return null;
            var raw = value.GetRawText();
            long integer;
            if (value.ValueKind == JsonValueKind.Number && !IsFloatingPointJsonNumber(raw) && !Int64.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out integer)) return "\"" + raw + "\"";
            return raw;
        }
        private static bool Boolean(JsonElement item, string name) { JsonElement value; if (!item.TryGetProperty(name, out value)) return false; return value.ValueKind == JsonValueKind.True || (value.ValueKind == JsonValueKind.String && String.Equals(value.GetString(), "true", StringComparison.OrdinalIgnoreCase)); }
        private static int Intern(string value, List<string> values, Dictionary<string, int> map) { if (String.IsNullOrEmpty(value)) return -1; int index; if (!map.TryGetValue(value, out index)) { index = values.Count; map.Add(value, index); values.Add(value); } return index; }
        private static void InternFlatArray(JsonElement item, string name, List<string> values, Dictionary<string, int> map, List<int> flattened, out int start, out int count) { start = flattened.Count; JsonElement array; if (item.TryGetProperty(name, out array)) { if (array.ValueKind == JsonValueKind.Array) foreach (var element in array.EnumerateArray()) { var index = Intern(ScalarString(element), values, map); if (index >= 0) flattened.Add(index); } else { var index = Intern(ScalarString(array), values, map); if (index >= 0) flattened.Add(index); } } count = flattened.Count - start; }
        // Mirrors Get-StringArray (drops null/whitespace entries) followed by Resolve-NormalizedLookupIndexList, whose [hashtable]
        // parameter is a fresh case-sensitive copy per call: values deduplicate only within one template, so each template appends its own entries.
        private static void AppendTemplatePathArray(JsonElement item, string name, List<string> values, Dictionary<string, int> map, List<int> flattened, out int start, out int count) { start = flattened.Count; map.Clear(); JsonElement array; if (item.TryGetProperty(name, out array) && array.ValueKind != JsonValueKind.Null && array.ValueKind != JsonValueKind.Undefined) { if (array.ValueKind == JsonValueKind.Array) { foreach (var element in array.EnumerateArray()) { if (element.ValueKind == JsonValueKind.Null || element.ValueKind == JsonValueKind.Undefined) continue; AppendTemplatePath(ScalarString(element), values, map, flattened); } } else AppendTemplatePath(ScalarString(array), values, map, flattened); } map.Clear(); count = flattened.Count - start; }
        private static void AppendTemplatePath(string value, List<string> values, Dictionary<string, int> map, List<int> flattened) { if (String.IsNullOrWhiteSpace(value)) return; flattened.Add(Intern(value, values, map)); }
        // Mirrors the in-process `[datetime]$firstSeen -gt [datetime]$lastSeen` swap check, including its failure (first value
        // converted first) when a permissively normalized M/D/YYYY value such as 2026-02-30 is not a calendar date.
        private static int CompareSeenDates(string first, string last) { var firstDate = ConvertSeenDate(first); return firstDate.CompareTo(ConvertSeenDate(last)); }
        private static DateTime ConvertSeenDate(string value)
        {
            DateTime parsed;
            if (DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed)) return parsed;
            throw new InvalidCastException("Cannot convert value \"" + value + "\" to type \"System.DateTime\". Error: \"String '" + value + "' was not recognized as a valid DateTime.\"");
        }
        private static readonly Regex MonthDayYearPrefix = new Regex(@"^(\d{1,2})/(\d{1,2})/(\d{4})", RegexOptions.CultureInvariant);
        // Mirrors Convert-FastToYmdDate/Convert-ToYmdDate: blank or unparseable values normalize to no date (never the raw text).
        private static string NormalizeDate(string value)
        {
            if (value == null) return String.Empty;
            if (value.Length >= 10 && value[4] == '-' && value[7] == '-') return value.Substring(0, 10);
            var raw = value.Trim();
            if (raw.Length == 0) return String.Empty;
            if (raw.Length >= 10 && raw[4] == '-' && raw[7] == '-') return raw.Substring(0, 10);
            var match = MonthDayYearPrefix.Match(raw);
            int month, day, year;
            if (match.Success && Int32.TryParse(match.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out month) && Int32.TryParse(match.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out day) && Int32.TryParse(match.Groups[3].Value, NumberStyles.None, CultureInfo.InvariantCulture, out year) && month >= 1 && month <= 12 && day >= 1 && day <= 31)
                return year.ToString("D4", CultureInfo.InvariantCulture) + "-" + month.ToString("D2", CultureInfo.InvariantCulture) + "-" + day.ToString("D2", CultureInfo.InvariantCulture);
            // PowerShell's [datetime] cast parses with the invariant culture and default styles, then formats with the current culture.
            DateTime parsed; return DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed) ? parsed.ToString("yyyy-MM-dd", CultureInfo.CurrentCulture) : String.Empty;
        }
        private static int SeverityIndex(string value, Dictionary<string, int> severityIndexes) { int index; return value != null && severityIndexes.TryGetValue(value, out index) ? index : -1; }
        private static StringComparer ResolveKeyComparer(string descriptor, string optionName)
        {
            // Absent descriptors use the default PowerShell hashtable comparer (OrdinalIgnoreCase) that the in-process normalizer sees.
            if (String.IsNullOrEmpty(descriptor) || descriptor == "OrdinalIgnoreCase") return StringComparer.OrdinalIgnoreCase;
            if (descriptor == "Ordinal") return StringComparer.Ordinal;
            if (descriptor == "InvariantCulture") return StringComparer.InvariantCulture;
            if (descriptor == "InvariantCultureIgnoreCase") return StringComparer.InvariantCultureIgnoreCase;
            if (descriptor.StartsWith("Culture:", StringComparison.Ordinal)) return StringComparer.Create(CultureInfo.GetCultureInfo(descriptor.Substring(8)), false);
            if (descriptor.StartsWith("CultureIgnoreCase:", StringComparison.Ordinal)) return StringComparer.Create(CultureInfo.GetCultureInfo(descriptor.Substring(18)), true);
            throw new InvalidDataException("Unsupported bounded normalization key comparer '" + descriptor + "' for " + optionName + ".");
        }
        // in-process-compatible mirrors the PowerShell in-process payload shape for stores at or below the in-process template limit;
        // high-cardinality-compact keeps the previously accepted compiled payload shape (global update/path interning).
        private static bool ResolvePayloadContract(string contract)
        {
            if (String.Equals(contract, "in-process-compatible", StringComparison.Ordinal)) return true;
            if (String.Equals(contract, "high-cardinality-compact", StringComparison.Ordinal)) return false;
            throw new InvalidDataException("Unsupported or missing bounded normalization payloadContract '" + contract + "'.");
        }
        private static NormalizationOptions ReadNormalizationOptions(string path)
        {
            var options = new NormalizationOptions { InventoryKeyComparer = ResolveKeyComparer(null, "inventoryKeyComparer"), SeverityKeyComparer = ResolveKeyComparer(null, "severityKeyComparer") };
            var severityEntries = new List<KeyValuePair<string, int>> { new KeyValuePair<string, int>("Critical", 0), new KeyValuePair<string, int>("High", 1), new KeyValuePair<string, int>("Medium", 2), new KeyValuePair<string, int>("Low", 3), new KeyValuePair<string, int>("None", 4) };
            {
                using (var document = JsonDocument.Parse(ReadRequiredFragmentText(path)))
                {
                    var root = document.RootElement;
                    options.InventoryKeyComparer = ResolveKeyComparer(Value(root, "inventoryKeyComparer"), "inventoryKeyComparer");
                    options.SeverityKeyComparer = ResolveKeyComparer(Value(root, "severityKeyComparer"), "severityKeyComparer");
                    options.InProcessCompatible = ResolvePayloadContract(Value(root, "payloadContract"));
                    JsonElement severities;
                    if (root.TryGetProperty("severityIndexes", out severities) && severities.ValueKind == JsonValueKind.Object)
                    {
                        severityEntries.Clear();
                        foreach (var property in severities.EnumerateObject()) severityEntries.Add(new KeyValuePair<string, int>(property.Name, property.Value.GetInt32()));
                    }
                }
            }
            options.SeverityIndexes = new Dictionary<string, int>(options.SeverityKeyComparer);
            foreach (var entry in severityEntries) options.SeverityIndexes[entry.Key] = entry.Value;
            return options;
        }
        private static string ConvertCveUrl(string value) { const string marker = "/security-guidance/advisory/"; var index = value.IndexOf(marker, StringComparison.OrdinalIgnoreCase); if (index >= 0) { var id = value.Substring(index + marker.Length); if (id.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) return "https://msrc.microsoft.com/update-guide/vulnerability/" + id; } return value; }
        private static string EmptyFallback(string value, string fallback) { return String.IsNullOrWhiteSpace(value) ? fallback : value; }
        private static string NullIfEmpty(string value) { return String.IsNullOrWhiteSpace(value) ? null : value; }
        private static void WriteFragment(StreamWriter output, Action<Utf8JsonWriter> action)
        {
            using (var buffer = new MemoryStream()) { using (var json = new Utf8JsonWriter(buffer, WriterOptions)) action(json); output.WriteLine(Utf8.GetString(buffer.GetBuffer(), 0, checked((int)buffer.Length))); }
        }
        private static void WriteDeviceFragment(StreamWriter output, Device value) { WriteFragment(output, writer => { writer.WriteStartObject(); writer.WriteString("id", value.Id); writer.WriteString("n", value.Name); writer.WriteNumber("g", value.Group); writer.WriteNumber("o", value.Platform); if (value.OsVersion == null) writer.WriteNull("ov"); else writer.WriteString("ov", value.OsVersion); writer.WritePropertyName("t"); WriteIntArray(writer, value.Tags); writer.WritePropertyName("m"); WriteRawNullable(writer, value.MachineInfoJson); writer.WriteEndObject(); }); }
        private static void WriteSoftwareFragment(StreamWriter output, Software value) { WriteFragment(output, writer => { writer.WriteStartObject(); writer.WriteNumber("v", value.Vendor); writer.WriteString("n", value.Name); writer.WriteString("r", value.Reference); writer.WriteEndObject(); }); }
        private static void WriteUpdateFragment(StreamWriter output, Update value) { WriteFragment(output, writer => { writer.WriteStartObject(); writer.WriteString("n", value.Name); writer.WriteString("id", value.Id); writer.WriteString("url", value.Url); writer.WriteEndObject(); }); }
        private static void WriteCveFragment(StreamWriter output, Cve value) { WriteFragment(output, writer => { writer.WriteStartObject(); writer.WriteString("id", value.Id); writer.WritePropertyName("sc"); if (inProcessCompatibleEscaping) WriteRawNullable(writer, value.ScoreJson); else if (value.Score.HasValue) writer.WriteNumberValue(value.Score.Value); else writer.WriteNullValue(); writer.WriteNumber("sv", value.Severity); writer.WriteNumber("ex", value.Exploit); writer.WriteString("u", value.Url); writer.WriteNumber("bt", value.BatchTitle); var e = value.Enrichment; writer.WritePropertyName("pd"); WriteRawNullable(writer, e == null ? null : e.PublishedDate); writer.WritePropertyName("desc"); WriteRawNullable(writer, e == null ? null : e.Description); writer.WritePropertyName("ep"); WriteRawNullable(writer, e == null ? null : e.EpssJson); writer.WritePropertyName("as"); WriteNullableIntArray(writer, value.AffectedSoftware); writer.WritePropertyName("ea"); WriteRawNullable(writer, e == null ? null : e.ExploitAvailableJson); writer.WritePropertyName("nlm"); WriteRawNullable(writer, e == null ? null : e.NvdLastModified); writer.WritePropertyName("nbs"); WriteRawNullable(writer, e == null ? null : e.NvdBaseScoreJson); writer.WritePropertyName("nsv"); WriteRawNullable(writer, e == null ? null : e.NvdBaseSeverity); writer.WritePropertyName("nvec"); WriteRawNullable(writer, e == null ? null : e.NvdVector); writer.WritePropertyName("nkev"); WriteRawNullable(writer, e == null ? null : e.NvdKevDate); writer.WritePropertyName("ndu"); WriteRawNullable(writer, e == null ? null : e.NvdActionDue); writer.WritePropertyName("nact"); WriteRawNullable(writer, e == null ? null : e.NvdRequiredAction); writer.WritePropertyName("nw"); if (e != null && e.WeaknessesJson != null) WriteRawNullable(writer, e.WeaknessesJson); else WriteNullableStringArray(writer, e == null ? null : e.Weaknesses); writer.WriteEndObject(); }); }
        private static void WriteVulnFragment(StreamWriter output, int deviceIndex, Template template, int firstIndex, int lastIndex, int inventoryIndex, List<int> diskIndexes, List<int> registryIndexes)
        {
            output.Write('['); WriteInteger(output, deviceIndex); output.Write(','); WriteInteger(output, template.Cve); output.Write(','); WriteInteger(output, template.Software); output.Write(','); WriteInteger(output, template.Version);
            output.Write(','); WriteInteger(output, firstIndex); output.Write(','); WriteInteger(output, lastIndex); output.Write(','); WriteInteger(output, template.UpdateAvailable); output.Write(','); WriteInteger(output, template.Update); output.Write(',');
            WriteNullableIntegerRange(output, diskIndexes, template.DiskStart, template.DiskCount); output.Write(','); WriteNullableIntegerRange(output, registryIndexes, template.RegistryStart, template.RegistryCount); output.Write(','); WriteInteger(output, inventoryIndex); output.Write(']'); output.WriteLine();
        }
        private static void WriteInteger(StreamWriter output, int value) { output.Write(value.ToString(CultureInfo.InvariantCulture)); }
        private static void WriteNullableIntegerRange(StreamWriter output, List<int> values, int start, int count) { if (count <= 0) { output.Write("null"); return; } output.Write('['); for (var index = 0; index < count; index++) { if (index > 0) output.Write(','); WriteInteger(output, values[start + index]); } output.Write(']'); }
        // Mirrors Get-VendorMatchKey so affected-software filtering matches the in-process normalizer.
        public static string GetVendorMatchKey(string vendor)
        {
            if (String.IsNullOrWhiteSpace(vendor)) return String.Empty;
            var trimmed = vendor.Trim();
            if (Environment.GetEnvironmentVariable("DEFENDER_REPORTING_NORMALIZE_VENDOR_MATCH") != "1") return trimmed;
            var normalized = trimmed.ToLowerInvariant();
            normalized = System.Text.RegularExpressions.Regex.Replace(normalized, "[^a-z0-9]+", " ");
            normalized = System.Text.RegularExpressions.Regex.Replace(normalized, "\\b(corporation|corp|incorporated|inc|llc|ltd|limited|company|co|gmbh|ag|plc|pte)\\b", " ");
            return System.Text.RegularExpressions.Regex.Replace(normalized, "\\s+", " ").Trim();
        }

        // Mirrors Update-NormalizedAffectedSoftwareLookup: keep affected-software entries whose vendor was observed in projected rows,
        // falling back to every vendor in the lookup when no row was projected.
        public static bool[] BuildAllowedAffectedSoftware(IList<string> vendors, ICollection<int> usedVendorIndexes, IList<string> affectedSoftware)
        {
            var datasetVendors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (usedVendorIndexes != null) foreach (var vendorIndex in usedVendorIndexes) { if (vendorIndex < 0 || vendorIndex >= vendors.Count) continue; var key = GetVendorMatchKey(vendors[vendorIndex]); if (!String.IsNullOrWhiteSpace(key)) datasetVendors.Add(key); }
            if (datasetVendors.Count == 0) foreach (var vendor in vendors) { if (!String.IsNullOrWhiteSpace(vendor)) datasetVendors.Add(GetVendorMatchKey(vendor)); }
            var allowed = new bool[affectedSoftware.Count];
            for (var index = 0; index < affectedSoftware.Count; index++)
            {
                var value = affectedSoftware[index];
                if (String.IsNullOrWhiteSpace(value)) continue;
                var separatorIndex = value.IndexOf(':');
                var vendor = separatorIndex >= 0 ? value.Substring(0, separatorIndex) : value;
                allowed[index] = datasetVendors.Contains(GetVendorMatchKey(vendor));
            }
            return allowed;
        }

        private static void CopyCveLinesWithAffectedSoftwareFilter(Utf8JsonWriter writer, string path, bool[] allowedAffectedSoftware)
        {
            writer.WriteStartArray();
            var filtered = new List<int>();
            foreach (var line in File.ReadLines(path, Utf8))
            {
                if (String.IsNullOrWhiteSpace(line)) continue;
                using (var document = JsonDocument.Parse(line))
                {
                    var root = document.RootElement;
                    JsonElement affected;
                    if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("as", out affected) || affected.ValueKind != JsonValueKind.Array) { writer.WriteRawValue(line, true); continue; }
                    filtered.Clear();
                    foreach (var item in affected.EnumerateArray()) { int index; if (item.ValueKind == JsonValueKind.Number && item.TryGetInt32(out index) && index >= 0 && index < allowedAffectedSoftware.Length && allowedAffectedSoftware[index]) filtered.Add(index); }
                    writer.WriteStartObject();
                    foreach (var property in root.EnumerateObject())
                    {
                        if (property.NameEquals("as")) { writer.WritePropertyName("as"); if (filtered.Count == 0) writer.WriteNullValue(); else { writer.WriteStartArray(); foreach (var index in filtered) writer.WriteNumberValue(index); writer.WriteEndArray(); } }
                        else property.WriteTo(writer);
                    }
                    writer.WriteEndObject();
                }
            }
            writer.WriteEndArray();
        }

        private static void CopyJsonLines(Utf8JsonWriter writer, string path) { writer.WriteStartArray(); foreach (var line in File.ReadLines(path, Utf8)) { if (String.IsNullOrWhiteSpace(line)) continue; writer.WriteRawValue(line, true); } writer.WriteEndArray(); }
        private static void WriteIntArray(Utf8JsonWriter writer, int[] values) { writer.WriteStartArray(); if (values != null) foreach (var value in values) writer.WriteNumberValue(value); writer.WriteEndArray(); }
        private static void WriteNullableIntArray(Utf8JsonWriter writer, int[] values) { if (values == null || values.Length == 0) { writer.WriteNullValue(); return; } WriteIntArray(writer, values); }
        private static void WriteNullableStringArray(Utf8JsonWriter writer, string[] values) { if (values == null || values.Length == 0) { writer.WriteNullValue(); return; } writer.WriteStartArray(); foreach (var value in values) writer.WriteStringValue(value); writer.WriteEndArray(); }
        private static void WriteNullableString(Utf8JsonWriter writer, string name, string value) { if (String.IsNullOrWhiteSpace(value)) writer.WriteNull(name); else writer.WriteString(name, value); }
        private static void WriteRawNullable(Utf8JsonWriter writer, string json) { if (String.IsNullOrWhiteSpace(json)) writer.WriteNullValue(); else writer.WriteRawValue(json, true); }
        private static void WriteNullableIntRange(Utf8JsonWriter writer, List<int> values, int start, int count) { if (count <= 0) { writer.WriteNullValue(); return; } writer.WriteStartArray(); for (var index = 0; index < count; index++) writer.WriteNumberValue(values[start + index]); writer.WriteEndArray(); }
        private static void WriteStrings(Utf8JsonWriter writer, string name, List<string> values) { writer.WritePropertyName(name); writer.WriteStartArray(); foreach (var value in values) writer.WriteStringValue(value); writer.WriteEndArray(); }
        private static void WriteFixedStrings(Utf8JsonWriter writer, string name, string[] values) { writer.WritePropertyName(name); writer.WriteStartArray(); foreach (var value in values) writer.WriteStringValue(value); writer.WriteEndArray(); }
    }

    public static class VulnContentProjector
    {
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);
        private static readonly JsonWriterOptions WriterOptions = new JsonWriterOptions { SkipValidation = true };

        public static long Project(string[] inputPaths, string[] refPaths, string dictionaryPath)
        {
            if (inputPaths.Length != refPaths.Length) throw new ArgumentException("Input/ref path counts differ.");
            var devices = new Dictionary<string, int>(StringComparer.Ordinal);
            var contents = new Dictionary<string, int>(StringComparer.Ordinal);
            var root = Path.GetDirectoryName(dictionaryPath) ?? Path.GetTempPath();
            var deviceFragment = Path.Combine(root, "compiled-device-profiles.ndjson");
            var contentFragment = Path.Combine(root, "compiled-content-templates.ndjson");
            long rows = 0;
            using (var deviceWriter = new StreamWriter(deviceFragment, false, Utf8))
            using (var contentWriter = new StreamWriter(contentFragment, false, Utf8))
            {
                for (var fileIndex = 0; fileIndex < inputPaths.Length; fileIndex++)
                {
                    using (var input = OpenInput(inputPaths[fileIndex]))
                    using (var reader = new StreamReader(input, Utf8, true, 65536))
                    using (var output = CreateGzip(refPaths[fileIndex]))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            if (string.IsNullOrWhiteSpace(line)) continue;
                            using (var document = JsonDocument.Parse(line))
                            {
                                var row = document.RootElement;
                                if (row.ValueKind != JsonValueKind.Object) continue;
                                var deviceJson = DeviceJson(row);
                                // The complete projected JSON is an unambiguous ordinal key.
                                // DeviceId alone cannot represent different per-observation profiles.
                                var deviceKey = deviceJson;
                                if (!devices.TryGetValue(deviceKey, out var deviceIndex))
                                {
                                    deviceIndex = devices.Count;
                                    devices.Add(deviceKey, deviceIndex);
                                    deviceWriter.WriteLine(deviceJson);
                                }
                                var contentJson = ContentJson(row);
                                var contentKey = Hash(contentJson);
                                if (!contents.TryGetValue(contentKey, out var contentIndex))
                                {
                                    contentIndex = contents.Count;
                                    contents.Add(contentKey, contentIndex);
                                    contentWriter.WriteLine(contentJson);
                                }
                                WriteRef(output, String(row, "Id"), deviceIndex, contentIndex, String(row, "FirstSeenTimestamp"), String(row, "LastSeenTimestamp"));
                                rows++;
                            }
                        }
                    }
                }
            }
            WriteDictionary(dictionaryPath, deviceFragment, contentFragment);
            File.Delete(deviceFragment);
            File.Delete(contentFragment);
            return rows;
        }

        public static long CreateProceduralCurrent(string[] inputPaths, string outputPath, string snapshotDate)
        {
            long rows = 0;
            using (var output = CreateGzip(outputPath))
            {
                foreach (var path in inputPaths)
                {
                    using (var input = OpenInput(path))
                    using (var reader = new StreamReader(input, Utf8, true, 65536))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            if (string.IsNullOrWhiteSpace(line)) continue;
                            using (var document = JsonDocument.Parse(line))
                            {
                                var row = document.RootElement;
                                if (row.ValueKind != JsonValueKind.Object || !Boolean(row, "IsOnboarded")) continue;
                                using (var writer = new Utf8JsonWriter(output, WriterOptions))
                                {
                                    writer.WriteStartObject();
                                    foreach (var property in row.EnumerateObject())
                                    {
                                        if (property.NameEquals("FirstSeenTimestamp") || property.NameEquals("LastSeenTimestamp")) continue;
                                        property.WriteTo(writer);
                                    }
                                    var first = String(row, "FirstSeenTimestamp");
                                    var last = String(row, "LastSeenTimestamp");
                                    if (string.IsNullOrWhiteSpace(first) || string.CompareOrdinal(first, snapshotDate) < 0) first = snapshotDate;
                                    if (string.IsNullOrWhiteSpace(last) || string.CompareOrdinal(last, first) < 0) last = first;
                                    writer.WriteString("FirstSeenTimestamp", first); writer.WriteString("LastSeenTimestamp", last);
                                    writer.WriteEndObject(); writer.Flush();
                                }
                                output.WriteByte(10); rows++;
                            }
                        }
                    }
                }
            }
            return rows;
        }

        private static Stream OpenInput(string path)
        {
            var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan);
            return path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? new GZipStream(file, CompressionMode.Decompress, false) : file;
        }
        private static GZipStream CreateGzip(string path) => new GZipStream(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 65536, FileOptions.SequentialScan), CompressionLevel.Optimal, false);
        private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Utf8.GetBytes(value)));
        private static bool Try(JsonElement row, string name, out JsonElement value) => row.TryGetProperty(name, out value);
        private static string String(JsonElement row, string name)
        {
            if (!Try(row, name, out var value) || value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Undefined) return string.Empty;
            return value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : value.GetRawText().Trim('"');
        }
        private static bool Boolean(JsonElement row, string name)
        {
            if (!Try(row, name, out var value)) return false;
            if (value.ValueKind == JsonValueKind.True) return true;
            if (value.ValueKind == JsonValueKind.String && bool.TryParse(value.GetString(), out var parsed)) return parsed;
            return false;
        }

        private static string DeviceJson(JsonElement row)
        {
            using (var memory = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(memory, WriterOptions))
                {
                    writer.WriteStartObject();
                    writer.WriteString("id", String(row, "DeviceId")); writer.WriteString("n", String(row, "DeviceName")); writer.WriteString("g", String(row, "RbacGroupName"));
                    writer.WriteString("o", String(row, "OSPlatform")); writer.WriteString("ov", String(row, "OSVersion")); writer.WritePropertyName("t"); WriteStringArray(writer, row, "MachineTags");
                    writer.WriteBoolean("ob", Boolean(row, "IsOnboarded")); writer.WriteEndObject(); writer.Flush();
                }
                return Utf8.GetString(memory.ToArray());
            }
        }
        private static string ContentJson(JsonElement row)
        {
            using (var memory = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(memory, WriterOptions))
                {
                    writer.WriteStartObject();
                    WriteString(writer, "c", row, "CveId"); WriteString(writer, "sv", row, "SoftwareVendor"); WriteString(writer, "sn", row, "SoftwareName"); WriteString(writer, "ver", row, "SoftwareVersion");
                    WriteString(writer, "sev", row, "VulnerabilitySeverityLevel"); writer.WritePropertyName("sc"); WriteScalar(writer, row, "CvssScore"); WriteString(writer, "ex", row, "ExploitabilityLevel");
                    WriteString(writer, "rr", row, "RecommendationReference"); WriteString(writer, "ru", row, "RecommendedSecurityUpdate"); WriteString(writer, "rid", row, "RecommendedSecurityUpdateId");
                    WriteString(writer, "url", row, "RecommendedSecurityUpdateUrl"); writer.WriteBoolean("ua", Boolean(row, "SecurityUpdateAvailable"));
                    writer.WritePropertyName("dp"); WriteStringArray(writer, row, "DiskPaths"); writer.WritePropertyName("rp"); WriteStringArray(writer, row, "RegistryPaths");
                    WriteString(writer, "bt", row, "CveBatchTitle"); WriteString(writer, "bu", row, "CveBatchUrl"); writer.WriteEndObject(); writer.Flush();
                }
                return Utf8.GetString(memory.ToArray());
            }
        }
        private static void WriteString(Utf8JsonWriter writer, string output, JsonElement row, string input) => writer.WriteString(output, String(row, input));
        private static void WriteScalar(Utf8JsonWriter writer, JsonElement row, string name)
        {
            if (!Try(row, name, out var value) || value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Undefined) { writer.WriteNullValue(); return; }
            if (value.ValueKind == JsonValueKind.Number) { value.WriteTo(writer); return; }
            if (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False) { writer.WriteBooleanValue(value.GetBoolean()); return; }
            writer.WriteStringValue(value.ValueKind == JsonValueKind.String ? value.GetString() : value.GetRawText());
        }
        private static void WriteStringArray(Utf8JsonWriter writer, JsonElement row, string name)
        {
            writer.WriteStartArray();
            if (Try(row, name, out var value))
            {
                if (value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in value.EnumerateArray())
                    {
                        if (item.ValueKind != JsonValueKind.Null) writer.WriteStringValue(item.ValueKind == JsonValueKind.String ? item.GetString() : item.GetRawText());
                    }
                }
                else if (value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())) writer.WriteStringValue(value.GetString());
            }
            writer.WriteEndArray();
        }
        private static void WriteRef(Stream output, string id, int deviceIndex, int contentIndex, string firstSeen, string lastSeen)
        {
            using (var writer = new Utf8JsonWriter(output, WriterOptions))
            {
                writer.WriteStartArray(); writer.WriteStringValue(id); writer.WriteNumberValue(deviceIndex); writer.WriteNumberValue(contentIndex); writer.WriteStringValue(firstSeen); writer.WriteStringValue(lastSeen); writer.WriteEndArray(); writer.Flush();
            }
            output.WriteByte(10);
        }
        private static void WriteDictionary(string path, string deviceFragment, string contentFragment)
        {
            using (var gzip = CreateGzip(path)) using (var writer = new StreamWriter(gzip, Utf8, 65536))
            {
                writer.Write("{\"version\":\"content-dictionary-v1\",\"deviceProfiles\":["); CopyLines(writer, deviceFragment); writer.Write("],\"contentTemplates\":["); CopyLines(writer, contentFragment); writer.Write("]}");
            }
        }
        private static void CopyLines(StreamWriter writer, string path)
        {
            var first = true;
            foreach (var line in File.ReadLines(path, Utf8)) { if (!first) writer.Write(','); writer.Write(line); first = false; }
        }
    }

    public static class MachineTupleBucketProjector
    {
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);
        private static readonly string[] TupleProperties = new[] {
            "lastIpAddress", "lastExternalIpAddress", "healthStatus", "riskScore",
            "exposureLevel", "deviceValue", "managedBy", "isAadJoined", "lastSeen",
            "firstSeen", "osVersion", "computerDnsName", "rbacGroupName", "osPlatform"
        };

        public static long Project(string inputPath, string bucketDirectory, int bucketCount)
        {
            Directory.CreateDirectory(bucketDirectory);
            var writers = new StreamWriter[bucketCount];
            long count = 0;
            try
            {
                for (var i = 0; i < bucketCount; i++)
                    writers[i] = new StreamWriter(Path.Combine(bucketDirectory, "bucket-" + i.ToString("D3") + ".ndjson"), false, Utf8, 65536);

                using (var input = OpenInput(inputPath))
                using (var reader = new StreamReader(input, Utf8, true, 65536))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (String.IsNullOrWhiteSpace(line)) continue;
                        using (var document = JsonDocument.Parse(line))
                        {
                            var root = document.RootElement;
                            JsonElement idElement;
                            if (!root.TryGetProperty("id", out idElement) || idElement.ValueKind != JsonValueKind.String) continue;
                            var id = idElement.GetString();
                            if (String.IsNullOrWhiteSpace(id)) continue;
                            JsonElement removed;
                            if (root.TryGetProperty("removed", out removed) && removed.ValueKind == JsonValueKind.True) continue;

                            var writer = writers[GetBucketId(id, bucketCount)];
                            writer.Write(id);
                            writer.Write('\t');
                            using (var buffer = new MemoryStream(512))
                            {
                                using (var json = new Utf8JsonWriter(buffer, new JsonWriterOptions { SkipValidation = true }))
                                {
                                    json.WriteStartArray();
                                    foreach (var propertyName in TupleProperties) WritePropertyValue(json, root, propertyName);
                                    JsonElement tags;
                                    if (root.TryGetProperty("machineTags", out tags) && tags.ValueKind == JsonValueKind.Array) tags.WriteTo(json);
                                    else json.WriteStartArray();
                                    if (!root.TryGetProperty("machineTags", out tags) || tags.ValueKind != JsonValueKind.Array) json.WriteEndArray();
                                    json.WriteEndArray();
                                }
                                writer.Write(Utf8.GetString(buffer.GetBuffer(), 0, checked((int)buffer.Length)));
                            }
                            writer.WriteLine();
                            count++;
                        }
                    }
                }
            }
            finally
            {
                foreach (var writer in writers) if (writer != null) writer.Dispose();
            }
            return count;
        }

        private static Stream OpenInput(string path)
        {
            var file = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)
                ? (Stream)new GZipStream(file, CompressionMode.Decompress)
                : file;
        }

        private static int GetBucketId(string id, int count)
        {
            var hash = StringComparer.OrdinalIgnoreCase.GetHashCode(id);
            if (hash == Int32.MinValue) hash = 0;
            else if (hash < 0) hash = -hash;
            return hash % count;
        }

        private static void WritePropertyValue(Utf8JsonWriter writer, JsonElement root, string name)
        {
            JsonElement value;
            if (root.TryGetProperty(name, out value) && value.ValueKind != JsonValueKind.Undefined) value.WriteTo(writer);
            else writer.WriteNullValue();
        }
    }

    public sealed class MachineTupleIndexedLookup : IDisposable
    {
        private struct Entry { public long Offset; public int Length; public Entry(long offset, int length) { Offset = offset; Length = length; } }
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);
        private static readonly string[] TupleProperties = new[] {
            "lastIpAddress", "lastExternalIpAddress", "healthStatus", "riskScore",
            "exposureLevel", "deviceValue", "managedBy", "isAadJoined", "lastSeen",
            "firstSeen", "osVersion", "computerDnsName", "rbacGroupName", "osPlatform"
        };
        private readonly Dictionary<string, Entry> entries;
        private readonly FileStream stream;
        private readonly object gate = new object();
        public int Count { get { return entries.Count; } }
        public string Path { get; private set; }

        private MachineTupleIndexedLookup(string path, Dictionary<string, Entry> index)
        {
            Path = path;
            entries = index;
            stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        }

        public static MachineTupleIndexedLookup Create(string inputPath, string outputPath)
        {
            var index = new Dictionary<string, Entry>(StringComparer.Ordinal);
            using (var output = File.Open(outputPath, FileMode.Create, FileAccess.Write, FileShare.Read))
            using (var input = OpenInput(inputPath))
            using (var reader = new StreamReader(input, Utf8, true, 65536))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (String.IsNullOrWhiteSpace(line)) continue;
                    using (var document = JsonDocument.Parse(line))
                    {
                        var root = document.RootElement;
                        JsonElement idElement;
                        if (!root.TryGetProperty("id", out idElement) || idElement.ValueKind != JsonValueKind.String) continue;
                        var id = idElement.GetString();
                        if (String.IsNullOrWhiteSpace(id)) continue;
                        JsonElement removed;
                        if (root.TryGetProperty("removed", out removed) && removed.ValueKind == JsonValueKind.True) { index.Remove(id); continue; }

                        byte[] tuple;
                        using (var buffer = new MemoryStream(512))
                        {
                            using (var json = new Utf8JsonWriter(buffer, new JsonWriterOptions { SkipValidation = true }))
                            {
                                json.WriteStartArray();
                                foreach (var propertyName in TupleProperties) WritePropertyValue(json, root, propertyName);
                                JsonElement tags;
                                if (root.TryGetProperty("machineTags", out tags) && tags.ValueKind == JsonValueKind.Array) tags.WriteTo(json);
                                else
                                {
                                    json.WriteStartArray();
                                    // The canonical machine format intentionally accepts both an array and a
                                    // scalar tag. Preserve the scalar as a one-element tuple just as the
                                    // PowerShell normalization reader does.
                                    if (tags.ValueKind != JsonValueKind.Undefined && tags.ValueKind != JsonValueKind.Null)
                                        tags.WriteTo(json);
                                    json.WriteEndArray();
                                }
                                json.WriteEndArray();
                            }
                            tuple = buffer.ToArray();
                        }
                        var offset = output.Position;
                        output.Write(tuple, 0, tuple.Length);
                        index[id] = new Entry(offset, tuple.Length);
                    }
                }
            }
            return new MachineTupleIndexedLookup(outputPath, index);
        }

        public object[] ReadTuple(string id)
        {
            Entry entry;
            if (String.IsNullOrWhiteSpace(id) || !entries.TryGetValue(id, out entry)) return null;
            var bytes = new byte[entry.Length];
            lock (gate)
            {
                stream.Position = entry.Offset;
                var read = 0;
                while (read < bytes.Length) { var n = stream.Read(bytes, read, bytes.Length - read); if (n <= 0) throw new EndOfStreamException(); read += n; }
            }
            using (var document = JsonDocument.Parse(bytes))
            {
                var values = new List<object>();
                foreach (var element in document.RootElement.EnumerateArray()) values.Add(ConvertValue(element));
                return values.ToArray();
            }
        }

        public void Dispose() { stream.Dispose(); }

        private static Stream OpenInput(string path)
        {
            var file = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? (Stream)new GZipStream(file, CompressionMode.Decompress) : file;
        }
        private static void WritePropertyValue(Utf8JsonWriter writer, JsonElement root, string name)
        {
            JsonElement value; if (root.TryGetProperty(name, out value)) value.WriteTo(writer); else writer.WriteNullValue();
        }
        private static object ConvertValue(JsonElement value)
        {
            switch (value.ValueKind)
            {
                case JsonValueKind.String: return value.GetString();
                case JsonValueKind.True: return true;
                case JsonValueKind.False: return false;
                case JsonValueKind.Number: long integer; return value.TryGetInt64(out integer) ? (object)integer : value.GetDouble();
                case JsonValueKind.Array:
                    var items = new List<object>(); foreach (var item in value.EnumerateArray()) items.Add(ConvertValue(item)); return items.ToArray();
                default: return null;
            }
        }
    }
}
'@

function Initialize-CompiledVulnContentProjector {
    [CmdletBinding()]
    param()

    if ($null -eq ('DefenderReporting.Store.VulnContentProjector' -as [type])) {
        Add-Type -TypeDefinition $Script:CompiledVulnContentProjectorSource -Language CSharp -CompilerOptions '/unsafe'
    }
}
