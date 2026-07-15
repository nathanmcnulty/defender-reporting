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
using System.Text.Json;
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
            if (timer != null) timer.Dispose(); process.Dispose(); return result;
        }

        public void Dispose() { if (Interlocked.Exchange(ref completed, 1) == 0) { if (timer != null) timer.Dispose(); process.Dispose(); } }
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
                workingSet = process.WorkingSet64;
                privateMemory = process.PrivateMemorySize64;
            }
            catch {
                workingSet = 0; privateMemory = 0;
            }
            if (workingSet <= 0) workingSet = Environment.WorkingSet;
            if (privateMemory <= 0) privateMemory = workingSet;
        }
    }

    public sealed class CompiledNormalizationResult
    {
        public long ProcessedCount { get; set; }
        public int DeviceCount { get; set; }
        public int CveCount { get; set; }
        public int SoftwareCount { get; set; }
        public int VendorCount { get; set; }
        public CompiledMemoryTelemetry MemoryTelemetry { get; set; }
    }

    public static class BoundedContentNormalizer
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessWorkingSetSize(IntPtr process, IntPtr minimumWorkingSetSize, IntPtr maximumWorkingSetSize);
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);
        private static readonly JsonWriterOptions WriterOptions = new JsonWriterOptions { SkipValidation = true };
        private sealed class Device { public string Id, Name, OsVersion, MachineInfoJson; public int Group, Platform; public int[] Tags; public bool Onboarded; }
        private sealed class MachineOverlay { public string Name, Group, Platform, OsVersion, MachineInfoJson; public string[] Tags; }
        private sealed class Software { public int Vendor; public string Name, Reference, InventoryIdentity; }
        private sealed class Update { public string Name, Id, Url; }
        private sealed class CveEnrichment { public string PublishedDate, Description, EpssJson, ExploitAvailableJson, NvdLastModified, NvdBaseScoreJson, NvdBaseSeverity, NvdVector, NvdKevDate, NvdActionDue, NvdRequiredAction; public string[] AffectedSoftware, Weaknesses; }
        private sealed class Cve { public string Id, Url; public double? Score; public int Severity, Exploit, BatchTitle; public CveEnrichment Enrichment; public int[] AffectedSoftware; }
        private sealed class InventoryRecord { public string Cpe, EndOfSupportStatus, EndOfSupportDate; }
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
            if (refPaths == null) throw new ArgumentNullException("refPaths");
            if (telemetry == null) throw new ArgumentNullException("telemetry");
            telemetry.SetStage("template-interning");
            var expectedTemplates = Directory.Exists(dictionaryPath) ? File.ReadLines(Path.Combine(dictionaryPath, "contentTemplates.ndjson"), Utf8).Count() : 1024;
            var machineOverlays = ReadMachineOverlays(Path.Combine(dictionaryPath, "machines.ndjson"));
            var cveEnrichment = ReadCveEnrichment(Path.Combine(dictionaryPath, "cveEnrichment.ndjson"));
            var inventorySource = ReadInventory(Path.Combine(dictionaryPath, "inventory.ndjson"));
            var vendors = new List<string>(); var vendorMap = Map();
            var exploits = new List<string>(); var exploitMap = Map();
            var groups = new List<string>(); var groupMap = Map();
            var platforms = new List<string>(); var platformMap = Map();
            var tags = new List<string>(); var tagMap = Map();
            var versions = new List<string>(); var versionMap = Map();
            var dates = new List<string>(); var dateMap = Map();
            var diskPaths = new List<string>(); var diskMap = Map();
            var registryPaths = new List<string>(); var registryMap = Map();
            var batchTitles = new List<string>(); var batchMap = Map();
            var affectedSoftware = new List<string>(); var affectedSoftwareMap = Map();
            var softwareMap = HashMap(expectedTemplates); var softwareCount = 0;
            var updateMap = HashMap(expectedTemplates); var updateCount = 0;
            var cveMap = HashMap(expectedTemplates); var cveCount = 0;
            var deviceOnboarded = new List<bool>();
            var deviceIds = new List<string>();
            var softwareIdentities = new List<string>();
            var inventoryValues = new List<InventoryRecord>(); var inventoryValueMap = Map();
            var templateList = new List<Template>();
            var templateDiskIndexes = new List<int>(); var templateRegistryIndexes = new List<int>();
            var stageRoot = Path.Combine(Path.GetTempPath(), "bounded-normalizer-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(stageRoot);
            var deviceFragment = Path.Combine(stageRoot, "devices.ndjson"); var softwareFragment = Path.Combine(stageRoot, "software.ndjson"); var updateFragment = Path.Combine(stageRoot, "updates.ndjson"); var cveFragment = Path.Combine(stageRoot, "cves.ndjson"); var vulnFragment = Path.Combine(stageRoot, "vulns.ndjson");
            using (var deviceOutput = new StreamWriter(deviceFragment, false, Utf8, 65536))
            using (var softwareOutput = new StreamWriter(softwareFragment, false, Utf8, 65536))
            using (var updateOutput = new StreamWriter(updateFragment, false, Utf8, 65536))
            using (var cveOutput = new StreamWriter(cveFragment, false, Utf8, 65536))
            {

            ReadDictionaryArray(dictionaryPath, "deviceProfiles", item =>
                {
                    var tagIndexes = new List<int>();
                    var deviceId = Value(item, "id"); MachineOverlay overlay = null;
                    var hasOverlay = !String.IsNullOrWhiteSpace(deviceId) && machineOverlays.TryGetValue(deviceId, out overlay);
                    JsonElement tagValues;
                    if (hasOverlay && overlay.Tags != null && overlay.Tags.Length > 0)
                        foreach (var value in overlay.Tags) { var index = Intern(value, tags, tagMap); if (index >= 0) tagIndexes.Add(index); }
                    else if (item.TryGetProperty("t", out tagValues) && tagValues.ValueKind == JsonValueKind.Array)
                        foreach (var tag in tagValues.EnumerateArray()) { var value = ScalarString(tag); var index = Intern(value, tags, tagMap); if (index >= 0) tagIndexes.Add(index); }
                    var group = hasOverlay && !String.IsNullOrWhiteSpace(overlay.Group) ? overlay.Group : Value(item, "g"); if (String.IsNullOrWhiteSpace(group)) group = "(none)";
                    var platform = hasOverlay && !String.IsNullOrWhiteSpace(overlay.Platform) ? overlay.Platform : Value(item, "o");
                    var name = hasOverlay && !String.IsNullOrWhiteSpace(overlay.Name) ? overlay.Name : Value(item, "n");
                    var osVersion = hasOverlay && !String.IsNullOrWhiteSpace(overlay.OsVersion) ? overlay.OsVersion : Value(item, "ov");
                    var device = new Device {
                        Id = deviceId, Name = EmptyFallback(name, "(no machine data)"), OsVersion = NullIfEmpty(osVersion), MachineInfoJson = hasOverlay ? overlay.MachineInfoJson : null,
                        Group = Intern(group, groups, groupMap), Platform = Intern(platform, platforms, platformMap), Tags = tagIndexes.ToArray(), Onboarded = Boolean(item, "ob")
                    };
                    deviceIds.Add(device.Id); deviceOnboarded.Add(device.Onboarded); WriteDeviceFragment(deviceOutput, device);
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
                        softwareIdentities.Add(software.InventoryIdentity); WriteSoftwareFragment(softwareOutput, software);
                    }

                    var cveId = Value(item, "c"); var scoreText = Value(item, "sc"); var severity = Value(item, "sev"); var exploit = Value(item, "ex"); var url = ConvertCveUrl(Value(item, "bu")); var batch = Value(item, "bt");
                    var cveKey = GetHashKey(cveId, scoreText, severity, exploit, url, batch);
                    int cveIndex;
                    if (!cveMap.TryGetValue(cveKey, out cveIndex)) {
                        cveIndex = cveCount++; cveMap.Add(cveKey, cveIndex);
                        double parsedScore; double? score = Double.TryParse(scoreText, NumberStyles.Float, CultureInfo.InvariantCulture, out parsedScore) ? parsedScore : (double?)null;
                        CveEnrichment enrichment; cveEnrichment.TryGetValue(cveId, out enrichment);
                        var affectedIndexes = new List<int>();
                        if (enrichment != null && enrichment.AffectedSoftware != null) foreach (var affected in enrichment.AffectedSoftware) { var affectedIndex = Intern(affected, affectedSoftware, affectedSoftwareMap); if (affectedIndex >= 0) affectedIndexes.Add(affectedIndex); }
                        WriteCveFragment(cveOutput, new Cve { Id = cveId, Score = score, Severity = SeverityIndex(severity), Exploit = Intern(exploit, exploits, exploitMap), Url = url, BatchTitle = Intern(batch, batchTitles, batchMap), Enrichment = enrichment, AffectedSoftware = affectedIndexes.Count > 0 ? affectedIndexes.ToArray() : null });
                    }

                    var updateName = Value(item, "ru"); var updateIndex = -1;
                    if (!String.IsNullOrWhiteSpace(updateName) && updateName != "--") {
                        var updateId = Value(item, "rid"); var updateUrl = Value(item, "url"); var updateKey = GetHashKey(updateName, updateId, updateUrl);
                        if (!updateMap.TryGetValue(updateKey, out updateIndex)) { updateIndex = updateCount++; updateMap.Add(updateKey, updateIndex); WriteUpdateFragment(updateOutput, new Update { Name = updateName, Id = updateId, Url = updateUrl }); }
                    }
                    int diskStart, diskCount, registryStart, registryCount;
                    InternFlatArray(item, "dp", diskPaths, diskMap, templateDiskIndexes, out diskStart, out diskCount);
                    InternFlatArray(item, "rp", registryPaths, registryMap, templateRegistryIndexes, out registryStart, out registryCount);
                    templateList.Add(new Template {
                        Software = softwareIndex, Cve = cveIndex, Version = Intern(Value(item, "ver"), versions, versionMap), Update = updateIndex,
                        UpdateAvailable = Boolean(item, "ua") ? 1 : 0, DiskStart = diskStart, DiskCount = diskCount, RegistryStart = registryStart, RegistryCount = registryCount
                    });
                });
            }
            foreach (var map in new[] { vendorMap, exploitMap, groupMap, platformMap, tagMap, versionMap, diskMap, registryMap, batchMap, affectedSoftwareMap }) map.Clear();
            softwareMap.Clear(); updateMap.Clear(); cveMap.Clear();
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true); GC.WaitForPendingFinalizers();

            telemetry.SetStage("ref-projection");
            long processed = 0;
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
                                if (String.CompareOrdinal(first, last) > 0) { var swap = first; first = last; last = swap; }
                                var template = templateList[templateIndex];
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
                                try { WriteVulnFragment(vulnOutput, deviceIndex, template, firstIndex, lastIndex, inventoryIndex, templateDiskIndexes, templateRegistryIndexes); }
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
            var resultDeviceCount = deviceOnboarded.Count;
            var resultVendorCount = vendors.Count;
            templateList = null; deviceOnboarded = null; deviceIds = null; softwareIdentities = null; inventorySource.Clear(); inventoryValueMap.Clear(); templateDiskIndexes = null; templateRegistryIndexes = null; dateMap.Clear();
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true); GC.WaitForPendingFinalizers(); TrimCurrentProcessWorkingSet();
            telemetry.SetStage("lookup-and-payload-assembly");
            using (var file = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 65536, FileOptions.SequentialScan))
            using (var gzip = new GZipStream(file, CompressionLevel.Fastest, false))
            using (var writer = new Utf8JsonWriter(gzip, WriterOptions))
            {
                writer.WriteStartObject(); writer.WriteString("vulnsFormat", "rows-v1"); writer.WritePropertyName("lookups"); writer.WriteStartObject();
                WriteStrings(writer, "vendors", vendors); vendors = null; WriteFixedStrings(writer, "severities", new[] { "Critical", "High", "Medium", "Low", "None" }); WriteStrings(writer, "exploitLevels", exploits); exploits = null;
                WriteStrings(writer, "groups", groups); groups = null; WriteStrings(writer, "platforms", platforms); platforms = null; WriteStrings(writer, "tags", tags); tags = null;
                writer.WritePropertyName("updates"); CopyJsonLines(writer, updateFragment);
                WriteStrings(writer, "versions", versions); versions = null; WriteStrings(writer, "dates", dates); dates = null; WriteStrings(writer, "diskPaths", diskPaths); diskPaths = null; WriteStrings(writer, "regPaths", registryPaths); registryPaths = null;
                WriteStrings(writer, "affSoftware", affectedSoftware); affectedSoftware = null; WriteStrings(writer, "batchTitles", batchTitles); batchTitles = null;
                writer.WritePropertyName("devices"); CopyJsonLines(writer, deviceFragment);
                writer.WritePropertyName("inventory"); writer.WriteStartArray(); foreach (var inventory in inventoryValues) { writer.WriteStartObject(); WriteNullableString(writer, "cpe", inventory.Cpe); WriteNullableString(writer, "eos", inventory.EndOfSupportStatus); WriteNullableString(writer, "eod", inventory.EndOfSupportDate); writer.WriteEndObject(); } writer.WriteEndArray(); inventoryValues = null;
                writer.WritePropertyName("software"); CopyJsonLines(writer, softwareFragment);
                writer.WritePropertyName("cves"); CopyJsonLines(writer, cveFragment);
                writer.WriteNull("noTagsIdx"); writer.WriteEndObject();
                telemetry.SetStage("pre-vulnerability-assembly-cleanup");
                GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
                GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true, true); GC.WaitForPendingFinalizers(); TrimCurrentProcessWorkingSet();
                telemetry.SetStage("vulnerability-assembly");
                writer.WritePropertyName("vulns"); CopyJsonLines(writer, vulnFragment); writer.WriteEndObject();
            }
            try { Directory.Delete(stageRoot, true); } catch { }
            var result = new CompiledNormalizationResult { ProcessedCount = processed, DeviceCount = resultDeviceCount, CveCount = cveCount, SoftwareCount = softwareCount, VendorCount = resultVendorCount };
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
        private static Dictionary<string, MachineOverlay> ReadMachineOverlays(string path)
        {
            var result = new Dictionary<string, MachineOverlay>(StringComparer.Ordinal); if (!File.Exists(path)) return result;
            foreach (var line in File.ReadLines(path, Utf8)) { if (String.IsNullOrWhiteSpace(line)) continue; using (var document = JsonDocument.Parse(line)) { var item = document.RootElement; var id = Value(item, "id"); if (String.IsNullOrWhiteSpace(id)) continue; result[id] = new MachineOverlay { Name = Value(item, "n"), Group = Value(item, "g"), Platform = Value(item, "o"), OsVersion = Value(item, "ov"), Tags = StringArray(item, "t"), MachineInfoJson = RawValue(item, "m") }; } }
            return result;
        }
        private static Dictionary<string, CveEnrichment> ReadCveEnrichment(string path)
        {
            var result = new Dictionary<string, CveEnrichment>(StringComparer.OrdinalIgnoreCase); if (!File.Exists(path)) return result;
            foreach (var line in File.ReadLines(path, Utf8)) { if (String.IsNullOrWhiteSpace(line)) continue; using (var document = JsonDocument.Parse(line)) { var item = document.RootElement; var id = Value(item, "id"); if (String.IsNullOrWhiteSpace(id)) continue; result[id] = new CveEnrichment { PublishedDate = NullIfEmpty(Value(item, "pd")), Description = NullIfEmpty(Value(item, "desc")), EpssJson = RawValue(item, "ep"), AffectedSoftware = StringArray(item, "as"), ExploitAvailableJson = RawValue(item, "ea"), NvdLastModified = NullIfEmpty(Value(item, "nlm")), NvdBaseScoreJson = RawValue(item, "nbs"), NvdBaseSeverity = NullIfEmpty(Value(item, "nsv")), NvdVector = NullIfEmpty(Value(item, "nvec")), NvdKevDate = NullIfEmpty(Value(item, "nkev")), NvdActionDue = NullIfEmpty(Value(item, "ndu")), NvdRequiredAction = NullIfEmpty(Value(item, "nact")), Weaknesses = StringArray(item, "nw") }; } }
            return result;
        }
        private static Dictionary<string, InventoryRecord> ReadInventory(string path)
        {
            var result = new Dictionary<string, InventoryRecord>(StringComparer.Ordinal); if (!File.Exists(path)) return result;
            foreach (var line in File.ReadLines(path, Utf8)) { if (String.IsNullOrWhiteSpace(line)) continue; using (var document = JsonDocument.Parse(line)) { var item = document.RootElement; var key = Value(item, "k"); if (String.IsNullOrWhiteSpace(key)) continue; result[key] = new InventoryRecord { Cpe = NullIfEmpty(Value(item, "cpe")), EndOfSupportStatus = NullIfEmpty(Value(item, "eos")), EndOfSupportDate = NullIfEmpty(Value(item, "eod")) }; } }
            return result;
        }
        private static string[] StringArray(JsonElement item, string name) { JsonElement value; if (!item.TryGetProperty(name, out value) || value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Undefined) return null; var values = new List<string>(); if (value.ValueKind == JsonValueKind.Array) { foreach (var element in value.EnumerateArray()) { var text = ScalarString(element); if (!String.IsNullOrWhiteSpace(text)) values.Add(text); } } else { var text = ScalarString(value); if (!String.IsNullOrWhiteSpace(text)) values.Add(text); } return values.Count == 0 ? null : values.ToArray(); }
        private static string RawValue(JsonElement item, string name) { JsonElement value; if (!item.TryGetProperty(name, out value) || value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Undefined) return null; return value.GetRawText(); }
        private static Stream OpenInput(string path) { var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.SequentialScan); return path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? (Stream)new GZipStream(file, CompressionMode.Decompress, false) : file; }
        private static string Value(JsonElement item, string name) { JsonElement value; return item.TryGetProperty(name, out value) ? ScalarString(value) : String.Empty; }
        private static string ScalarString(JsonElement value) { if (value.ValueKind == JsonValueKind.Null || value.ValueKind == JsonValueKind.Undefined) return String.Empty; return value.ValueKind == JsonValueKind.String ? value.GetString() ?? String.Empty : value.GetRawText().Trim('"'); }
        private static bool Boolean(JsonElement item, string name) { JsonElement value; if (!item.TryGetProperty(name, out value)) return false; return value.ValueKind == JsonValueKind.True || (value.ValueKind == JsonValueKind.String && String.Equals(value.GetString(), "true", StringComparison.OrdinalIgnoreCase)); }
        private static int Intern(string value, List<string> values, Dictionary<string, int> map) { if (String.IsNullOrEmpty(value)) return -1; int index; if (!map.TryGetValue(value, out index)) { index = values.Count; map.Add(value, index); values.Add(value); } return index; }
        private static void InternFlatArray(JsonElement item, string name, List<string> values, Dictionary<string, int> map, List<int> flattened, out int start, out int count) { start = flattened.Count; JsonElement array; if (item.TryGetProperty(name, out array)) { if (array.ValueKind == JsonValueKind.Array) foreach (var element in array.EnumerateArray()) { var index = Intern(ScalarString(element), values, map); if (index >= 0) flattened.Add(index); } else { var index = Intern(ScalarString(array), values, map); if (index >= 0) flattened.Add(index); } } count = flattened.Count - start; }
        private static string NormalizeDate(string value) { if (String.IsNullOrWhiteSpace(value)) return String.Empty; if (value.Length >= 10 && value[4] == '-' && value[7] == '-') return value.Substring(0, 10); DateTime parsed; return DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out parsed) ? parsed.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : value; }
        private static int SeverityIndex(string value) { switch (value) { case "Critical": return 0; case "High": return 1; case "Medium": return 2; case "Low": return 3; case "None": return 4; default: return -1; } }
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
        private static void WriteCveFragment(StreamWriter output, Cve value) { WriteFragment(output, writer => { writer.WriteStartObject(); writer.WriteString("id", value.Id); if (value.Score.HasValue) writer.WriteNumber("sc", value.Score.Value); else writer.WriteNull("sc"); writer.WriteNumber("sv", value.Severity); writer.WriteNumber("ex", value.Exploit); writer.WriteString("u", value.Url); writer.WriteNumber("bt", value.BatchTitle); var e = value.Enrichment; WriteNullableString(writer, "pd", e == null ? null : e.PublishedDate); WriteNullableString(writer, "desc", e == null ? null : e.Description); writer.WritePropertyName("ep"); WriteRawNullable(writer, e == null ? null : e.EpssJson); writer.WritePropertyName("as"); WriteNullableIntArray(writer, value.AffectedSoftware); writer.WritePropertyName("ea"); WriteRawNullable(writer, e == null ? null : e.ExploitAvailableJson); WriteNullableString(writer, "nlm", e == null ? null : e.NvdLastModified); writer.WritePropertyName("nbs"); WriteRawNullable(writer, e == null ? null : e.NvdBaseScoreJson); WriteNullableString(writer, "nsv", e == null ? null : e.NvdBaseSeverity); WriteNullableString(writer, "nvec", e == null ? null : e.NvdVector); WriteNullableString(writer, "nkev", e == null ? null : e.NvdKevDate); WriteNullableString(writer, "ndu", e == null ? null : e.NvdActionDue); WriteNullableString(writer, "nact", e == null ? null : e.NvdRequiredAction); writer.WritePropertyName("nw"); WriteNullableStringArray(writer, e == null ? null : e.Weaknesses); writer.WriteEndObject(); }); }
        private static void WriteVulnFragment(StreamWriter output, int deviceIndex, Template template, int firstIndex, int lastIndex, int inventoryIndex, List<int> diskIndexes, List<int> registryIndexes)
        {
            output.Write('['); WriteInteger(output, deviceIndex); output.Write(','); WriteInteger(output, template.Cve); output.Write(','); WriteInteger(output, template.Software); output.Write(','); WriteInteger(output, template.Version);
            output.Write(','); WriteInteger(output, firstIndex); output.Write(','); WriteInteger(output, lastIndex); output.Write(','); WriteInteger(output, template.UpdateAvailable); output.Write(','); WriteInteger(output, template.Update); output.Write(',');
            WriteNullableIntegerRange(output, diskIndexes, template.DiskStart, template.DiskCount); output.Write(','); WriteNullableIntegerRange(output, registryIndexes, template.RegistryStart, template.RegistryCount); output.Write(','); WriteInteger(output, inventoryIndex); output.Write(']'); output.WriteLine();
        }
        private static void WriteInteger(StreamWriter output, int value) { output.Write(value.ToString(CultureInfo.InvariantCulture)); }
        private static void WriteNullableIntegerRange(StreamWriter output, List<int> values, int start, int count) { if (count <= 0) { output.Write("null"); return; } output.Write('['); for (var index = 0; index < count; index++) { if (index > 0) output.Write(','); WriteInteger(output, values[start + index]); } output.Write(']'); }
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
                                var deviceId = String(row, "DeviceId");
                                var deviceKey = string.IsNullOrWhiteSpace(deviceId) ? Hash(deviceJson) : deviceId;
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
                if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) if (item.ValueKind != JsonValueKind.Null) writer.WriteStringValue(item.ValueKind == JsonValueKind.String ? item.GetString() : item.GetRawText());
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
        Add-Type -TypeDefinition $Script:CompiledVulnContentProjectorSource -Language CSharp
    }
}
