using System.Buffers.Binary;
using System.Text;

namespace Warden.Ml;

/// <summary>
/// MurmurHash3 (x86 32-bit, seed 0, signed) and the sklearn <c>FeatureHasher</c> hashing trick, ported
/// to match scikit-learn byte-for-byte so the C# EMBER feature vector equals the Python one that trains
/// the model. See docs/phase3-research/featurehasher-murmurhash3.md and ember-v2-spec.md.
/// </summary>
public static class Hashing
{
    /// <summary>MurmurHash3 x86_32 (Austin Appleby reference), returned as a SIGNED int32 (sklearn's convention).</summary>
    public static int MurmurHash3_x86_32(ReadOnlySpan<byte> data, uint seed = 0)
    {
        const uint c1 = 0xcc9e2d51;
        const uint c2 = 0x1b873593;

        uint h1 = seed;
        int len = data.Length;
        int nblocks = len / 4;

        for (int i = 0; i < nblocks; i++)
        {
            uint k1 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(i * 4, 4));
            k1 *= c1;
            k1 = RotL(k1, 15);
            k1 *= c2;
            h1 ^= k1;
            h1 = RotL(h1, 13);
            h1 = (h1 * 5) + 0xe6546b64;
        }

        int tail = nblocks * 4;
        uint k = 0;
        switch (len & 3)
        {
            case 3:
                k ^= (uint)data[tail + 2] << 16;
                goto case 2;
            case 2:
                k ^= (uint)data[tail + 1] << 8;
                goto case 1;
            case 1:
                k ^= data[tail];
                k *= c1;
                k = RotL(k, 15);
                k *= c2;
                h1 ^= k;
                break;
        }

        h1 ^= (uint)len;
        h1 = Fmix32(h1);
        return unchecked((int)h1);
    }

    /// <summary>MurmurHash3 over the UTF-8 bytes of a string (seed 0), signed.</summary>
    public static int MurmurHash3(string token) => MurmurHash3_x86_32(Encoding.UTF8.GetBytes(token));

    /// <summary>
    /// sklearn FeatureHasher(n_features, input_type="string"). Each token contributes value 1 (signed by
    /// the hash) into <c>abs(hash) % n</c>; collisions sum. Accumulated in double (numpy casts to float32
    /// at the group boundary).
    /// </summary>
    public static double[] HashStrings(IEnumerable<string> tokens, int n, bool alternateSign = true)
    {
        var vec = new double[n];
        foreach (string token in tokens)
        {
            int h = MurmurHash3(token);
            int index = IndexOf(h, n);
            vec[index] += Sign(h, alternateSign);
        }
        return vec;
    }

    /// <summary>
    /// sklearn FeatureHasher(n_features, input_type="pair"). Hashes each pair's name; contributes the
    /// pair's value (signed by the hash) into the bucket; collisions sum.
    /// </summary>
    public static double[] HashPairs(IEnumerable<(string Name, double Value)> pairs, int n, bool alternateSign = true)
    {
        var vec = new double[n];
        foreach ((string name, double value) in pairs)
        {
            int h = MurmurHash3(name);
            int index = IndexOf(h, n);
            vec[index] += alternateSign ? value * (h >= 0 ? 1.0 : -1.0) : value;
        }
        return vec;
    }

    /// <summary>
    /// EMBER quirk: FeatureHasher(n,"string").transform([someString]) iterates the STRING, so each
    /// CHARACTER is a token. Used for the section entry-name sub-vector.
    /// </summary>
    public static double[] HashCharacters(string s, int n, bool alternateSign = true)
    {
        var vec = new double[n];
        foreach (char c in s)
        {
            int h = MurmurHash3(c.ToString());
            int index = IndexOf(h, n);
            vec[index] += Sign(h, alternateSign);
        }
        return vec;
    }

    private static int IndexOf(int h, int n)
    {
        // sklearn: INT_MIN cannot be abs()'d, so it is special-cased.
        if (h == int.MinValue)
        {
            return (int)((2147483647L - (n - 1)) % n);
        }
        return Math.Abs(h) % n;
    }

    private static double Sign(int h, bool alternateSign) =>
        alternateSign ? (h >= 0 ? 1.0 : -1.0) : 1.0;

    private static uint RotL(uint x, int r) => (x << r) | (x >> (32 - r));

    private static uint Fmix32(uint h)
    {
        h ^= h >> 16;
        h *= 0x85ebca6b;
        h ^= h >> 13;
        h *= 0xc2b2ae35;
        h ^= h >> 16;
        return h;
    }
}
