using System.Text;
using PeNet;

namespace Warden.Ml;

/// <summary>
/// Extracts a feature vector from a PE image. Implemented per docs/phase3-research/ember-v2-spec.md.
/// </summary>
public interface IPeFeatureExtractor
{
    /// <summary>Length of the produced vector.</summary>
    int Dimension { get; }

    /// <summary>Produces the feature vector for the given file bytes.</summary>
    float[] Extract(ReadOnlySpan<byte> bytes);
}

/// <summary>
/// EMBER v2 (2381-dim) feature extractor, ported to C#. The byte-only groups (histogram, byte-entropy,
/// strings = 616 dims) are byte-for-byte identical to the Python reference and covered by a parity test.
/// The PE-parsed groups (general, header, section, imports, exports, data-directories) use PeNet; their
/// full byte-for-byte parity against the LIEF-based trainer is validated on the training box (the
/// ml-training parity harness) — see docs/phase3-research/ember-v2-spec.md §"C# parity checklist".
/// </summary>
public sealed class EmberFeatureExtractor : IPeFeatureExtractor
{
    public const int EmberDimension = 2381;

    public int Dimension => EmberDimension;

    public float[] Extract(ReadOnlySpan<byte> bytes)
    {
        byte[] data = bytes.ToArray();
        var vector = new float[EmberDimension];
        int offset = 0;

        offset = Write(vector, offset, ByteHistogram(data));           // 256
        offset = Write(vector, offset, ByteEntropyHistogram(data));    // 256
        offset = Write(vector, offset, StringFeatures(data));          // 104

        PeFile? pe = TryParse(data);
        offset = Write(vector, offset, GeneralInfo(data, pe));         // 10
        offset = Write(vector, offset, HeaderInfo(pe));                // 62
        offset = Write(vector, offset, SectionInfo(data, pe));         // 255
        offset = Write(vector, offset, ImportsInfo(pe));               // 1280
        offset = Write(vector, offset, ExportsInfo(pe));               // 128
        offset = Write(vector, offset, DataDirectories(pe));           // 30

        return vector; // offset == 2381
    }

    // ---------- byte-only groups (exact parity) ----------

    public static double[] ByteHistogram(ReadOnlySpan<byte> data)
    {
        var counts = new double[256];
        foreach (byte b in data)
        {
            counts[b]++;
        }
        return L1Normalize(counts);
    }

    public static double[] ByteEntropyHistogram(ReadOnlySpan<byte> data)
    {
        const int window = 2048;
        const int step = 1024;
        var output = new double[256]; // 16 entropy bins x 16 nibble bins, row-major

        if (data.Length < window)
        {
            Accumulate(output, data);
        }
        else
        {
            for (int start = 0; start + window <= data.Length; start += step)
            {
                Accumulate(output, data.Slice(start, window));
            }
        }
        return L1Normalize(output);

        static void Accumulate(double[] output, ReadOnlySpan<byte> block)
        {
            Span<int> c = stackalloc int[16];
            foreach (byte b in block)
            {
                c[b >> 4]++;
            }
            // EMBER computes this in float32 (numpy): p and the entropy sum are float32, log base 2.
            float h = 0f;
            for (int i = 0; i < 16; i++)
            {
                if (c[i] != 0)
                {
                    float p = (float)c[i] / window;
                    h += -p * MathF.Log2(p);
                }
            }
            h *= 2f;
            int hbin = (int)(h * 2f);
            if (hbin == 16)
            {
                hbin = 15;
            }
            for (int nibble = 0; nibble < 16; nibble++)
            {
                output[(hbin * 16) + nibble] += c[nibble];
            }
        }
    }

    public static double[] StringFeatures(ReadOnlySpan<byte> data)
    {
        var result = new double[104];
        var printable = new long[96];
        long numStrings = 0;
        long totalLen = 0;
        long printables = 0;

        int runStart = -1;
        for (int i = 0; i <= data.Length; i++)
        {
            bool isPrintable = i < data.Length && data[i] >= 0x20 && data[i] <= 0x7f;
            if (isPrintable)
            {
                if (runStart < 0)
                {
                    runStart = i;
                }
            }
            else
            {
                if (runStart >= 0)
                {
                    int len = i - runStart;
                    if (len >= 5)
                    {
                        numStrings++;
                        totalLen += len;
                        for (int j = runStart; j < i; j++)
                        {
                            printable[data[j] - 0x20]++;
                            printables++;
                        }
                    }
                    runStart = -1;
                }
            }
        }

        double avlength = numStrings > 0 ? (double)totalLen / numStrings : 0d;

        // entropy over the printable-char distribution (no x2 here)
        double entropy = 0d;
        if (printables > 0)
        {
            for (int k = 0; k < 96; k++)
            {
                if (printable[k] != 0)
                {
                    float p = (float)printable[k] / printables;
                    entropy += -p * Math.Log2(p);
                }
            }
        }

        double histDivisor = printables > 0 ? printables : 1.0;

        result[0] = numStrings;
        result[1] = avlength;
        result[2] = printables;
        for (int k = 0; k < 96; k++)
        {
            result[3 + k] = printable[k] / histDivisor;
        }
        result[99] = entropy;
        result[100] = CountOccurrences(data, "c:\\", ignoreCase: true);
        result[101] = CountRegex(data, urls: true);
        result[102] = CountOccurrences(data, "HKEY_", ignoreCase: false);
        result[103] = CountOccurrences(data, "MZ", ignoreCase: false);
        return result;
    }

    // ---------- PE-parsed groups (PeNet; parity validated on the training box) ----------

    private static PeFile? TryParse(byte[] data)
    {
        try
        {
            return PeFile.IsPeFile(data) ? new PeFile(data) : null;
        }
        catch
        {
            return null;
        }
    }

    private static double[] GeneralInfo(byte[] data, PeFile? pe)
    {
        var g = new double[10];
        g[0] = data.Length;
        if (pe is null)
        {
            return g;
        }
        try
        {
            g[1] = pe.ImageNtHeaders?.OptionalHeader?.SizeOfImage ?? 0;
            g[2] = pe.ImageDebugDirectory is { Length: > 0 } ? 1 : 0;
            g[3] = pe.ExportedFunctions?.Length ?? 0;
            g[4] = pe.ImportedFunctions?.Length ?? 0;
            g[5] = pe.ImageRelocationDirectory?.Length > 0 ? 1 : 0;
            g[6] = pe.ImageResourceDirectory is not null ? 1 : 0;
            g[7] = pe.IsAuthenticodeSigned ? 1 : 0;
            g[8] = pe.ImageTlsDirectory is not null ? 1 : 0;
            g[9] = 0; // symbol table count (rarely present in modern PEs)
        }
        catch { /* leave zeros */ }
        return g;
    }

    private static double[] HeaderInfo(PeFile? pe)
    {
        var h = new double[62];
        if (pe?.ImageNtHeaders is null)
        {
            return h;
        }
        try
        {
            var file = pe.ImageNtHeaders.FileHeader;
            var opt = pe.ImageNtHeaders.OptionalHeader;

            h[0] = file.TimeDateStamp;
            Copy(h, 1, Hashing.HashStrings(new[] { file.Machine.ToString() }, 10));
            Copy(h, 11, Hashing.HashStrings(FlagTokens(file.Characteristics), 10));
            Copy(h, 21, Hashing.HashStrings(new[] { opt.Subsystem.ToString() }, 10));
            Copy(h, 31, Hashing.HashStrings(FlagTokens(opt.DllCharacteristics), 10));
            Copy(h, 41, Hashing.HashStrings(new[] { opt.Magic.ToString() }, 10));
            h[51] = opt.MajorImageVersion;
            h[52] = opt.MinorImageVersion;
            h[53] = opt.MajorLinkerVersion;
            h[54] = opt.MinorLinkerVersion;
            h[55] = opt.MajorOperatingSystemVersion;
            h[56] = opt.MinorOperatingSystemVersion;
            h[57] = opt.MajorSubsystemVersion;
            h[58] = opt.MinorSubsystemVersion;
            h[59] = opt.SizeOfCode;
            h[60] = opt.SizeOfHeaders;
            h[61] = opt.SizeOfHeapCommit;
        }
        catch { /* leave zeros */ }
        return h;
    }

    private static double[] SectionInfo(byte[] data, PeFile? pe)
    {
        var result = new double[255];
        var sections = pe?.ImageSectionHeaders;
        if (sections is null || sections.Length == 0)
        {
            return result;
        }

        try
        {
            var infos = sections.Select(s =>
            {
                string name = SectionName(s.Name);
                uint rawSize = s.SizeOfRawData;
                double entropy = SectionEntropy(data, s.PointerToRawData, rawSize);
                var props = SectionProps((uint)s.Characteristics).ToList();
                return (name, size: (double)rawSize, entropy, vsize: (double)s.VirtualSize, props);
            }).ToList();

            result[0] = infos.Count;
            result[1] = infos.Where(s => s.size == 0).Count();
            result[2] = infos.Where(s => s.name.Length == 0).Count();
            result[3] = infos.Where(s => s.props.Contains("MEM_READ") && s.props.Contains("MEM_EXECUTE")).Count();
            result[4] = infos.Where(s => s.props.Contains("MEM_WRITE")).Count();

            Copy(result, 5, Hashing.HashPairs(infos.Select(s => (s.name, s.size)), 50));
            Copy(result, 55, Hashing.HashPairs(infos.Select(s => (s.name, s.entropy)), 50));
            Copy(result, 105, Hashing.HashPairs(infos.Select(s => (s.name, s.vsize)), 50));

            string entry = EntrySectionName(pe, infos.Select(s => (s.name, s.props)).ToList());
            Copy(result, 155, Hashing.HashCharacters(entry, 50));

            var characteristics = infos.Where(s => s.name == entry).SelectMany(s => s.props);
            Copy(result, 205, Hashing.HashStrings(characteristics, 50));
        }
        catch { /* leave partial */ }
        return result;
    }

    private static double[] ImportsInfo(PeFile? pe)
    {
        var result = new double[1280];
        var imports = pe?.ImportedFunctions;
        if (imports is null || imports.Length == 0)
        {
            return result;
        }
        try
        {
            var libraries = imports
                .Select(i => (i.DLL ?? string.Empty).ToLowerInvariant())
                .Where(l => l.Length > 0)
                .Distinct();
            Copy(result, 0, Hashing.HashStrings(libraries, 256));

            var tokens = imports.Select(i =>
            {
                string lib = (i.DLL ?? string.Empty).ToLowerInvariant();
                string entry = !string.IsNullOrEmpty(i.Name) ? i.Name : "ordinal" + i.Hint;
                return lib + ":" + entry;
            });
            Copy(result, 256, Hashing.HashStrings(tokens, 1024));
        }
        catch { /* leave partial */ }
        return result;
    }

    private static double[] ExportsInfo(PeFile? pe)
    {
        var result = new double[128];
        var exports = pe?.ExportedFunctions;
        if (exports is null || exports.Length == 0)
        {
            return result;
        }
        try
        {
            var names = exports.Where(e => !string.IsNullOrEmpty(e.Name)).Select(e => e.Name!);
            Copy(result, 0, Hashing.HashStrings(names, 128));
        }
        catch { /* leave partial */ }
        return result;
    }

    private static double[] DataDirectories(PeFile? pe)
    {
        var result = new double[30];
        var dirs = pe?.ImageNtHeaders?.OptionalHeader?.DataDirectory;
        if (dirs is null)
        {
            return result;
        }
        try
        {
            int count = Math.Min(15, dirs.Length);
            for (int i = 0; i < count; i++)
            {
                result[(2 * i) + 0] = dirs[i].Size;
                result[(2 * i) + 1] = dirs[i].VirtualAddress;
            }
        }
        catch { /* leave partial */ }
        return result;
    }

    // ---------- helpers ----------

    private static int Write(float[] target, int offset, double[] group)
    {
        for (int i = 0; i < group.Length; i++)
        {
            target[offset + i] = (float)group[i];
        }
        return offset + group.Length;
    }

    private static void Copy(double[] target, int offset, double[] source)
    {
        Array.Copy(source, 0, target, offset, source.Length);
    }

    private static double[] L1Normalize(double[] counts)
    {
        double sum = 0d;
        foreach (double c in counts)
        {
            sum += c;
        }
        if (sum <= 0d)
        {
            return counts;
        }
        for (int i = 0; i < counts.Length; i++)
        {
            counts[i] = (float)counts[i] / (float)sum; // match numpy float32 histogram / float32 sum
        }
        return counts;
    }

    private static long CountOccurrences(ReadOnlySpan<byte> data, string needle, bool ignoreCase)
    {
        ReadOnlySpan<byte> pat = Encoding.ASCII.GetBytes(needle);
        long count = 0;
        for (int i = 0; i + pat.Length <= data.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pat.Length; j++)
            {
                byte a = data[i + j];
                byte b = pat[j];
                if (ignoreCase)
                {
                    a = ToLowerAscii(a);
                    b = ToLowerAscii(b);
                }
                if (a != b)
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                count++;
            }
        }
        return count;
    }

    // http:// or https:// (case-insensitive), counted as non-overlapping regex findall would.
    private static long CountRegex(ReadOnlySpan<byte> data, bool urls)
    {
        _ = urls;
        long count = 0;
        int i = 0;
        while (i < data.Length)
        {
            int matchLen = MatchUrl(data, i);
            if (matchLen > 0)
            {
                count++;
                i += matchLen;
            }
            else
            {
                i++;
            }
        }
        return count;
    }

    private static int MatchUrl(ReadOnlySpan<byte> data, int i)
    {
        // http:// (7) or https:// (8), case-insensitive
        if (StartsWithIgnoreCase(data, i, "https://"))
        {
            return 8;
        }
        if (StartsWithIgnoreCase(data, i, "http://"))
        {
            return 7;
        }
        return 0;
    }

    private static bool StartsWithIgnoreCase(ReadOnlySpan<byte> data, int i, string s)
    {
        if (i + s.Length > data.Length)
        {
            return false;
        }
        for (int j = 0; j < s.Length; j++)
        {
            if (ToLowerAscii(data[i + j]) != (byte)char.ToLowerInvariant(s[j]))
            {
                return false;
            }
        }
        return true;
    }

    private static byte ToLowerAscii(byte b) => (b >= 'A' && b <= 'Z') ? (byte)(b + 32) : b;

    private static string SectionName(string raw) => raw?.TrimEnd('\0') ?? string.Empty;

    private static double SectionEntropy(byte[] data, uint pointer, uint size)
    {
        if (size == 0 || pointer >= (uint)data.Length)
        {
            return 0d;
        }
        long end = Math.Min((long)pointer + size, data.Length);
        var counts = new int[256];
        long total = 0;
        for (long i = pointer; i < end; i++)
        {
            counts[data[i]]++;
            total++;
        }
        if (total == 0)
        {
            return 0d;
        }
        double h = 0d;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] != 0)
            {
                double p = (double)counts[i] / total;
                h += -p * Math.Log2(p);
            }
        }
        return h;
    }

    private static IEnumerable<string> SectionProps(uint characteristics)
    {
        var props = new List<string>();
        void Add(uint flag, string name)
        {
            if ((characteristics & flag) != 0)
            {
                props.Add(name);
            }
        }
        Add(0x00000020, "CNT_CODE");
        Add(0x00000040, "CNT_INITIALIZED_DATA");
        Add(0x00000080, "CNT_UNINITIALIZED_DATA");
        Add(0x20000000, "MEM_EXECUTE");
        Add(0x40000000, "MEM_READ");
        Add(0x80000000, "MEM_WRITE");
        Add(0x02000000, "MEM_DISCARDABLE");
        Add(0x04000000, "MEM_NOT_CACHED");
        Add(0x08000000, "MEM_NOT_PAGED");
        Add(0x10000000, "MEM_SHARED");
        return props;
    }

    private static string EntrySectionName(PeFile? pe, List<(string name, List<string> props)> infos)
    {
        try
        {
            uint entryRva = pe?.ImageNtHeaders?.OptionalHeader?.AddressOfEntryPoint ?? 0;
            var sections = pe?.ImageSectionHeaders;
            if (sections is not null && entryRva != 0)
            {
                foreach (var s in sections)
                {
                    if (entryRva >= s.VirtualAddress && entryRva < s.VirtualAddress + s.VirtualSize)
                    {
                        return SectionName(s.Name);
                    }
                }
            }
        }
        catch { /* fall through */ }

        foreach (var s in infos)
        {
            if (s.props.Contains("MEM_EXECUTE"))
            {
                return s.name;
            }
        }
        return string.Empty;
    }

    private static IEnumerable<string> FlagTokens<TEnum>(TEnum flags) where TEnum : struct, Enum
    {
        // LIEF emits the last dotted component of each set flag. Enum.ToString on a [Flags] enum yields
        // "A, B, C"; split to individual tokens to approximate that.
        string s = flags.ToString();
        if (string.IsNullOrEmpty(s) || s == "0")
        {
            yield break;
        }
        foreach (string part in s.Split(", ", StringSplitOptions.RemoveEmptyEntries))
        {
            yield return part;
        }
    }
}
