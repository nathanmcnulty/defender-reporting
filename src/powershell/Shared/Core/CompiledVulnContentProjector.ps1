$Script:CompiledVulnContentProjectorSource = @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DefenderReporting.Store
{
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
                                else { json.WriteStartArray(); json.WriteEndArray(); }
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
