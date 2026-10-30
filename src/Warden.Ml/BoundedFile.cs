namespace Warden.Ml;

/// <summary>
/// Reads a whole file through <b>one</b> handle with a hard size cap. Checking the size with one call and
/// reading with another lets the file be swapped or grown in between; here the size check and the read use
/// the same handle, writers are shut out while it is open (<see cref="FileShare.Read"/>), and the read never
/// returns more than the cap even if the length changes.
/// </summary>
public static class BoundedFile
{
    /// <summary>
    /// Returns the file's bytes, or null when it is larger than <paramref name="maxBytes"/>. Throws the usual
    /// I/O exceptions for a missing or locked file.
    /// </summary>
    /// <param name="length">The length seen on the open handle (also set when the file is too large).</param>
    public static byte[]? ReadAll(string path, long maxBytes, out long length)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentOutOfRangeException.ThrowIfNegative(maxBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxBytes, (long)Array.MaxLength);

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 1, FileOptions.SequentialScan);
        length = fs.Length;
        if (length > maxBytes)
        {
            return null;
        }

        byte[] buffer = new byte[length];
        int read = 0;
        while (read < buffer.Length)
        {
            int n = fs.Read(buffer, read, buffer.Length - read);
            if (n == 0)
            {
                throw new IOException("The file shrank while it was being read.");
            }
            read += n;
        }
        if (fs.ReadByte() != -1)
        {
            // Grew while open: never return a partial view of a changing file.
            throw new IOException("The file grew while it was being read.");
        }
        return buffer;
    }
}
