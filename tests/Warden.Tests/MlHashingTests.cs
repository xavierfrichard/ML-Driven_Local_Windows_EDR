using Warden.Ml;

namespace Warden.Tests;

/// <summary>
/// Parity tests for the MurmurHash3 + FeatureHasher port against reference values produced by the real
/// scikit-learn 1.9 (sklearn.utils.murmurhash.murmurhash3_bytes_s32 and FeatureHasher). If these drift,
/// the whole EMBER feature vector drifts.
/// </summary>
public sealed class MlHashingTests
{
    [Theory]
    [InlineData("", 0)]
    [InlineData("a", 1009084850)]
    [InlineData("abc", -1277324294)]
    [InlineData("kernel32.dll", 814237301)]
    [InlineData("CreateFileW", 2080031441)]
    [InlineData("kernel32.dll:CreateFileW", -523189509)]
    [InlineData("MEM_EXECUTE", -430565613)]
    [InlineData("AMD64", -923883536)]
    public void MurmurHash3_matches_sklearn(string input, int expected)
    {
        Assert.Equal(expected, Hashing.MurmurHash3(input));
    }

    [Fact]
    public void FeatureHasher_strings_matches_sklearn()
    {
        // sklearn FeatureHasher(10, "string").transform([["a","b","a","kernel32.dll"]]) -> [2,0,...]
        double[] v = Hashing.HashStrings(new[] { "a", "b", "a", "kernel32.dll" }, 10);
        Assert.Equal(new double[] { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, v);
    }

    [Fact]
    public void FeatureHasher_pairs_matches_sklearn()
    {
        // sklearn FeatureHasher(8, "pair").transform([[("kernel32.dll",3.0),("advapi32.dll",1.5)]])
        //   -> [0,0,0,0,-1.5,3.0,0,0]
        double[] v = Hashing.HashPairs(new[] { ("kernel32.dll", 3.0), ("advapi32.dll", 1.5) }, 8);
        Assert.Equal(new double[] { 0, 0, 0, 0, -1.5, 3.0, 0, 0 }, v);
    }
}
