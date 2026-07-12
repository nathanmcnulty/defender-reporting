using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DefenderReporting.Synthetic
{
    public sealed class GenerationResult
    {
        public int DeviceCount { get; set; }
        public int CurrentRows { get; set; }
        public int HistoryRows { get; set; }
        public int ContentTemplateCount { get; set; }
        public int CveCount { get; set; }
        public string[] HistoryPeriods { get; set; } = Array.Empty<string>();
        public int AddedRows { get; set; }
        public int ChangedRows { get; set; }
        public int RemovedRows { get; set; }
        public int ReopenedRows { get; set; }
    }

    public static class SyntheticDatasetWriter
    {
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);
        private static readonly string[] Vendors = { "microsoft", "google", "mozilla", "adobe", "oracle", "openssl", "canonical", "apple" };
        private static readonly string[] Products = { "windows_11", "edge_chromium-based", "chrome", "firefox", "acrobat_reader", "java", "openssl", "ubuntu", "macos", "office" };
        private static readonly string[] Platforms = { "Windows11", "WindowsServer2022", "Linux", "macOS" };
        private static readonly string[] Groups = { "Endpoints", "Servers", "Developers", "Kiosks", "Legacy" };
        private static readonly string[] Severities = { "Low", "Medium", "High", "Critical" };

        public static GenerationResult Generate(
            string outputPath,
            int deviceCount,
            int totalRows,
            int seed,
            string generationDate,
            int snapshotCount,
            int contentTemplateCount,
            double churnRate,
            double sparsityRate,
            bool includeRawRows)
        {
            if (deviceCount < 1 || totalRows < 1) throw new ArgumentOutOfRangeException();
            Directory.CreateDirectory(outputPath);
            var date = DateTime.ParseExact(generationDate, "yyyy-MM-dd", CultureInfo.InvariantCulture);
            contentTemplateCount = Math.Max(1, Math.Min(contentTemplateCount, totalRows));
            snapshotCount = Math.Max(1, snapshotCount);
            var currentRows = (int)Math.Round(totalRows * 0.80, MidpointRounding.AwayFromZero);
            var historyRows = totalRows - currentRows;
            var historySpanDays = Math.Max(90, Math.Min(1440, snapshotCount * 90));
            var historyByPeriod = new Dictionary<string, List<int>>(StringComparer.Ordinal);
            for (var ordinal = currentRows; ordinal < totalRows; ordinal++)
            {
                var observed = date.AddDays(-1 - ordinal % historySpanDays);
                var period = Quarter(observed);
                if (!historyByPeriod.TryGetValue(period, out var rows)) historyByPeriod[period] = rows = new List<int>();
                rows.Add(ordinal);
            }

            WriteMachines(Path.Combine(outputPath, "Machines_Current.json.gz"), deviceCount, seed, date, sparsityRate);
            WriteDictionary(Path.Combine(outputPath, "VulnContentDictionary.json.gz"), deviceCount, contentTemplateCount, seed, sparsityRate);
            WriteRefs(Path.Combine(outputPath, "VulnCurrentRefs.json.gz"), 0, currentRows, deviceCount, contentTemplateCount, seed, date, false);
            if (includeRawRows) WriteRows(Path.Combine(outputPath, "VulnExport_current.json.gz"), 0, currentRows, deviceCount, contentTemplateCount, seed, date, false, churnRate, sparsityRate);

            foreach (var pair in historyByPeriod)
            {
                WriteHistoryRefs(Path.Combine(outputPath, "VulnHistoryRefs_" + pair.Key + ".json.gz"), pair.Value, deviceCount, contentTemplateCount, seed, date, historySpanDays);
                if (includeRawRows) WriteSelectedRows(Path.Combine(outputPath, "VulnHistoryRows_" + pair.Key + ".json.gz"), pair.Value, deviceCount, contentTemplateCount, seed, date, churnRate, sparsityRate, true, historySpanDays);
                var latest = date.AddDays(-1 - MinimumModulo(pair.Value, historySpanDays));
                WriteHistoryDocument(Path.Combine(outputPath, "VulnHistory_" + pair.Key + ".json.gz"), pair.Key, latest);
            }
            WriteAdvancedHunting(Path.Combine(outputPath, "AdvancedHunting_Current.json.gz"), Math.Min(contentTemplateCount, 5000), seed, date);

            return new GenerationResult
            {
                DeviceCount = deviceCount,
                CurrentRows = currentRows,
                HistoryRows = historyRows,
                ContentTemplateCount = contentTemplateCount,
                CveCount = Math.Min(contentTemplateCount, 5000),
                HistoryPeriods = new List<string>(historyByPeriod.Keys).ToArray()
            };
        }

        public static GenerationResult AdvanceSnapshot(string outputPath, int deviceCount, int currentRows, int contentTemplateCount, int seed, string targetDate, int snapshotOrdinal, double churnRate, double sparsityRate)
        {
            Directory.CreateDirectory(outputPath);
            var date = DateTime.ParseExact(targetDate, "yyyy-MM-dd", CultureInfo.InvariantCulture);
            WriteMachines(Path.Combine(outputPath, "Machines_Current.json.gz"), deviceCount, seed, date, sparsityRate);
            var groups = new Dictionary<int, List<int>>();
            var added = 0; var changed = 0; var removed = 0; var reopened = 0;
            for (var ordinal = 0; ordinal < currentRows; ordinal++)
            {
                var category = Unit(seed + snapshotOrdinal * 7919, ordinal, 81);
                var projectedOrdinal = ordinal;
                if (category < churnRate * 0.20) { removed++; added++; projectedOrdinal = currentRows + ordinal; }
                else if (category < churnRate * 0.55) changed++;
                else if (category < churnRate * 0.70) reopened++;
                var device = DeviceForRow(seed, projectedOrdinal, deviceCount);
                var group = device % Groups.Length;
                if (!groups.TryGetValue(group, out var rows)) groups[group] = rows = new List<int>();
                rows.Add(projectedOrdinal);
            }
            foreach (var pair in groups)
            {
                var path = Path.Combine(outputPath, "VulnExport_" + (100 + pair.Key).ToString(CultureInfo.InvariantCulture) + "_" + targetDate + ".json.gz");
                WriteSelectedRows(path, pair.Value, deviceCount, contentTemplateCount, seed, date, churnRate, sparsityRate, false, 365, snapshotOrdinal);
            }
            return new GenerationResult { DeviceCount = deviceCount, CurrentRows = currentRows, ContentTemplateCount = contentTemplateCount, CveCount = Math.Min(contentTemplateCount, 5000), AddedRows = added, ChangedRows = changed, RemovedRows = removed, ReopenedRows = reopened };
        }

        private static FileStream FileForGzip(string path) => new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 65536, FileOptions.SequentialScan);
        private static GZipStream Gzip(string path) => new GZipStream(FileForGzip(path), CompressionLevel.Optimal, false);
        private static JsonWriterOptions JsonOptions => new JsonWriterOptions { Indented = false, SkipValidation = true };

        private static void JsonLine(Stream stream, Action<Utf8JsonWriter> write)
        {
            using (var writer = new Utf8JsonWriter(stream, JsonOptions)) { write(writer); writer.Flush(); }
            stream.WriteByte(10);
        }

        private static uint Hash(int seed, int ordinal, int salt)
        {
            unchecked
            {
                uint x = (uint)(seed ^ (ordinal * 0x45d9f3b) ^ (salt * 0x27d4eb2d));
                x ^= x >> 16; x *= 0x7feb352d; x ^= x >> 15; x *= 0x846ca68b; x ^= x >> 16;
                return x;
            }
        }

        private static double Unit(int seed, int ordinal, int salt) => Hash(seed, ordinal, salt) / (double)uint.MaxValue;
        private static string Quarter(DateTime value) => value.Year.ToString(CultureInfo.InvariantCulture) + "Q" + (((value.Month - 1) / 3) + 1).ToString(CultureInfo.InvariantCulture);
        private static string DeviceId(int ordinal) => "sim-" + ordinal.ToString("D7", CultureInfo.InvariantCulture);
        private static int DeviceForRow(int seed, int row, int count)
        {
            var h = Hash(seed, row, 11);
            var hot = Math.Max(1, count / 10);
            return h % 100 < 65 ? (int)(Hash(seed, row, 12) % (uint)hot) : (int)(Hash(seed, row, 13) % (uint)count);
        }
        private static int ContentForRow(int seed, int row, int count)
        {
            var u = Unit(seed, row, 21);
            return Math.Min(count - 1, (int)(count * u * u));
        }

        private static void WriteMachines(string path, int count, int seed, DateTime date, double sparsity)
        {
            using (var stream = Gzip(path))
            for (var i = 0; i < count; i++) JsonLine(stream, w =>
            {
                var platform = Platforms[(int)(Hash(seed, i, 31) % (uint)Platforms.Length)];
                w.WriteStartObject();
                w.WriteString("id", DeviceId(i)); w.WriteString("computerDnsName", "device-" + i.ToString("D7") + ".synthetic.test");
                w.WriteString("rbacGroupName", Groups[(int)(Hash(seed, i, 32) % (uint)Groups.Length)]); w.WriteString("osPlatform", platform);
                if (Unit(seed, i, 33) >= sparsity) w.WriteString("osVersion", platform.StartsWith("Windows", StringComparison.Ordinal) ? "10.0." + (22000 + i % 6000) : "1." + i % 20);
                w.WritePropertyName("machineTags"); w.WriteStartArray(); if (i % 3 == 0) w.WriteStringValue("Pilot"); if (i % 11 == 0) w.WriteStringValue("HighValue"); w.WriteEndArray();
                w.WriteString("healthStatus", i % 17 == 0 ? "Inactive" : "Active"); w.WriteString("riskScore", i % 10 == 0 ? "High" : "Low");
                w.WriteString("exposureLevel", i % 7 == 0 ? "High" : "Medium"); w.WriteString("deviceValue", i % 19 == 0 ? "High" : "Normal");
                w.WriteString("managedBy", i % 4 == 0 ? "Intune" : "Unknown"); w.WriteBoolean("isAadJoined", i % 5 != 0);
                w.WriteString("firstSeen", date.AddDays(-(30 + i % 720)).ToString("yyyy-MM-ddTHH:mm:ssZ"));
                w.WriteString("lastSeen", date.AddDays(-(i % 8)).ToString("yyyy-MM-ddTHH:mm:ssZ")); w.WriteString("observedOn", date.ToString("yyyy-MM-dd"));
                w.WriteString("stateHash", Convert.ToHexString(SHA256.HashData(Utf8.GetBytes(DeviceId(i) + date.ToString("yyyy-MM-dd")))).ToLowerInvariant()); w.WriteEndObject();
            });
        }

        private static void WriteDictionary(string path, int devices, int contents, int seed, double sparsity)
        {
            using (var stream = Gzip(path)) using (var w = new Utf8JsonWriter(stream, JsonOptions))
            {
                w.WriteStartObject(); w.WriteString("version", "content-dictionary-v1"); w.WriteString("generatorModel", "procedural-v1");
                w.WritePropertyName("deviceProfiles"); w.WriteStartArray();
                for (var i = 0; i < devices; i++) { w.WriteStartObject(); w.WriteString("id", DeviceId(i)); w.WriteString("n", "device-" + i.ToString("D7")); w.WriteString("g", Groups[i % Groups.Length]); w.WriteString("o", Platforms[i % Platforms.Length]); if (Unit(seed, i, 41) >= sparsity) w.WriteString("ov", "10.0." + (22000 + i % 6000)); w.WritePropertyName("t"); w.WriteStartArray(); if (i % 11 == 0) w.WriteStringValue("HighValue"); w.WriteEndArray(); w.WriteBoolean("ob", i % 97 != 0); w.WriteEndObject(); }
                w.WriteEndArray(); w.WritePropertyName("contentTemplates"); w.WriteStartArray();
                for (var i = 0; i < contents; i++) WriteContent(w, i, seed, sparsity);
                w.WriteEndArray(); w.WriteEndObject(); w.Flush();
            }
        }

        private static void WriteContent(Utf8JsonWriter w, int i, int seed, double sparsity)
        {
            var vendor = Vendors[i % Vendors.Length]; var product = Products[(i * 3 + i / Vendors.Length) % Products.Length]; var severity = Severities[(int)(Hash(seed, i, 51) % 100 < 8 ? 3 : Hash(seed, i, 52) % 100 < 28 ? 2 : Hash(seed, i, 53) % 100 < 70 ? 1 : 0)];
            w.WriteStartObject(); w.WriteString("c", "CVE-" + (2020 + i % 7) + "-" + (1000 + i % 48000)); w.WriteString("sv", vendor); w.WriteString("sn", product); w.WriteString("ver", (1 + i % 20) + "." + (i % 13) + "." + (i % 31)); w.WriteString("sev", severity);
            w.WriteNumber("sc", severity == "Critical" ? 9.8 : severity == "High" ? 8.1 : severity == "Medium" ? 5.6 : 3.2); w.WriteString("ex", severity == "Critical" || i % 29 == 0 ? "ExploitAvailable" : "NoKnownExploit");
            w.WriteString("rr", "REC-" + (i % 10000)); w.WriteString("ru", "Update " + (i % 5000)); w.WriteString("rid", "KB" + (5000000 + i % 99999)); if (Unit(seed, i, 54) >= sparsity) w.WriteString("url", "https://example.invalid/update/" + i); w.WriteBoolean("ua", i % 5 != 0);
            w.WritePropertyName("dp"); w.WriteStartArray(); if (i % 4 == 0) w.WriteStringValue("C:\\Program Files\\Synthetic " + (i % 100)); if (i % 997 == 0) w.WriteStringValue("C:\\Δοκιμή\\非常に長いパス\\" + i); w.WriteEndArray();
            w.WritePropertyName("rp"); w.WriteStartArray(); if (i % 6 == 0) w.WriteStringValue("HKLM\\Software\\Synthetic\\" + i); w.WriteEndArray(); w.WriteString("bt", "Synthetic advisory " + i); w.WriteString("bu", "https://example.invalid/cve/" + i); w.WriteEndObject();
        }

        private static void WriteRefs(string path, int start, int count, int devices, int contents, int seed, DateTime date, bool history)
        { using (var stream = Gzip(path)) for (var row = start; row < start + count; row++) WriteRef(stream, row, devices, contents, seed, date, history); }
        private static void WriteHistoryRefs(string path, List<int> rows, int devices, int contents, int seed, DateTime date, int historySpanDays)
        { using (var stream = Gzip(path)) foreach (var row in rows) WriteRef(stream, row, devices, contents, seed, date, true, historySpanDays); }
        private static void WriteRef(Stream stream, int row, int devices, int contents, int seed, DateTime date, bool history, int historySpanDays = 365)
        {
            var device = DeviceForRow(seed, row, devices); var content = ContentForRow(seed, row, contents); var last = history ? date.AddDays(-1 - row % historySpanDays) : date.AddDays(-(row % 3)); var first = last.AddDays(-(row % 180));
            JsonLine(stream, w => { w.WriteStartArray(); w.WriteStringValue(DeviceId(device) + "_" + content + "_" + row); w.WriteNumberValue(device); w.WriteNumberValue(content); w.WriteStringValue(first.ToString("yyyy-MM-dd")); w.WriteStringValue(last.ToString("yyyy-MM-dd")); w.WriteEndArray(); });
        }

        private static void WriteRows(string path, int start, int count, int devices, int contents, int seed, DateTime date, bool history, double churn, double sparsity)
        { using (var stream = Gzip(path)) for (var row = start; row < start + count; row++) WriteRow(stream, row, devices, contents, seed, date, history, churn, sparsity); }
        private static void WriteSelectedRows(string path, List<int> rows, int devices, int contents, int seed, DateTime date, double churn, double sparsity, bool history, int historySpanDays, int snapshotOrdinal = 0)
        { using (var stream = Gzip(path)) foreach (var row in rows) WriteRow(stream, row, devices, contents, seed, date, history, churn, sparsity, historySpanDays, snapshotOrdinal); }
        private static void WriteRow(Stream stream, int row, int devices, int contents, int seed, DateTime date, bool history, double churn, double sparsity, int historySpanDays = 365, int snapshotOrdinal = 0)
        {
            var device = DeviceForRow(seed, row, devices); var content = ContentForRow(seed, row, contents); var vendor = Vendors[content % Vendors.Length]; var product = Products[(content * 3 + content / Vendors.Length) % Products.Length]; var last = history ? date.AddDays(-1 - row % historySpanDays) : date; var category = Unit(seed + snapshotOrdinal * 7919, row, 81); var changed = snapshotOrdinal > 0 && category < churn * 0.55; var reopened = snapshotOrdinal > 0 && category >= churn * 0.55 && category < churn * 0.70;
            JsonLine(stream, w => { w.WriteStartObject(); w.WriteString("Id", DeviceId(device) + "_" + content + "_" + row); w.WriteString("DeviceId", DeviceId(device)); w.WriteString("DeviceName", "device-" + device.ToString("D7")); w.WriteString("RbacGroupName", Groups[device % Groups.Length]); w.WriteNumber("RbacGroupId", 100 + device % Groups.Length); w.WriteString("OSPlatform", Platforms[device % Platforms.Length]); if (Unit(seed, row, 62) >= sparsity) w.WriteString("OSVersion", "10.0." + (22000 + device % 6000)); w.WritePropertyName("MachineTags"); w.WriteStartArray(); if (device % 11 == 0) w.WriteStringValue("HighValue"); w.WriteEndArray(); w.WriteString("CveId", "CVE-" + (2020 + content % 7) + "-" + (1000 + content % 48000)); w.WriteString("SoftwareVendor", vendor); w.WriteString("SoftwareName", product); w.WriteString("SoftwareVersion", (1 + content % 20) + "." + (changed ? snapshotOrdinal : 0)); w.WriteString("VulnerabilitySeverityLevel", Severities[content % Severities.Length]); w.WriteNumber("CvssScore", 3.2 + content % 67 / 10.0); w.WriteString("ExploitabilityLevel", content % 29 == 0 ? "ExploitAvailable" : "NoKnownExploit"); w.WriteString("RecommendationReference", "REC-" + content); w.WriteString("RecommendedSecurityUpdate", "Update " + content); w.WriteString("RecommendedSecurityUpdateId", "KB" + (5000000 + content % 99999)); w.WriteString("RecommendedSecurityUpdateUrl", "https://example.invalid/update/" + content); w.WriteBoolean("SecurityUpdateAvailable", content % 5 != 0); w.WritePropertyName("DiskPaths"); w.WriteStartArray(); if (content % 4 == 0) w.WriteStringValue("C:\\Program Files\\Synthetic"); w.WriteEndArray(); w.WritePropertyName("RegistryPaths"); w.WriteStartArray(); w.WriteEndArray(); w.WriteString("CveBatchTitle", "Synthetic advisory " + content); w.WriteString("CveBatchUrl", "https://example.invalid/cve/" + content); w.WriteBoolean("IsOnboarded", device % 97 != 0); w.WriteString("FirstSeenTimestamp", (reopened ? last : last.AddDays(-(row % 180))).ToString("yyyy-MM-dd")); w.WriteString("LastSeenTimestamp", last.ToString("yyyy-MM-dd")); w.WriteEndObject(); });
        }

        private static void WriteHistoryDocument(string path, string period, DateTime latest)
        { using (var stream = Gzip(path)) using (var w = new Utf8JsonWriter(stream, JsonOptions)) { w.WriteStartObject(); w.WriteNumber("year", int.Parse(period.Substring(0, 4), CultureInfo.InvariantCulture)); w.WriteNumber("quarter", int.Parse(period.Substring(5, 1), CultureInfo.InvariantCulture)); w.WriteString("period", period); w.WriteString("latestDate", latest.ToString("yyyy-MM-dd")); w.WritePropertyName("snapshots"); w.WriteStartArray(); w.WriteEndArray(); w.WriteEndObject(); w.Flush(); } }
        private static void WriteAdvancedHunting(string path, int count, int seed, DateTime date)
        { using (var stream = Gzip(path)) for (var i = 0; i < count; i++) JsonLine(stream, w => { w.WriteStartObject(); w.WriteString("CveId", "CVE-" + (2020 + i % 7) + "-" + (1000 + i % 48000)); w.WriteString("PublishedDate", date.AddDays(-(i % 720)).ToString("yyyy-MM-dd")); w.WriteString("VulnerabilityDescription", "Deterministic synthetic vulnerability " + i); w.WriteNumber("EpssScore", Unit(seed, i, 71)); w.WritePropertyName("AffectedSoftware"); w.WriteStartArray(); w.WriteStringValue(Vendors[i % Vendors.Length] + ":" + Products[i % Products.Length]); w.WriteEndArray(); w.WriteNumber("IsExploitAvailable", i % 29 == 0 ? 1 : 0); w.WriteString("LastModifiedTime", date.ToString("yyyy-MM-ddTHH:mm:ssZ")); w.WriteString("RecordType", "Cve"); w.WriteEndObject(); }); }

        private static int MinimumModulo(List<int> values, int modulus)
        {
            var minimum = modulus;
            foreach (var value in values) minimum = Math.Min(minimum, value % modulus);
            return minimum;
        }
    }
}
