using System.Security.Cryptography;
using System.Text;

namespace CryptL.Hash;

/// <summary>
/// Hashes data based on SHA256.
/// </summary>
public class HashSHA256 : IHash
{
    /// <inheritdoc/>
    public byte[] GetHash(byte[] originalData)
    {
        if (originalData == null || originalData.Length == 0)
            throw new ArgumentNullException(nameof(originalData));

        using var sha256 = SHA256.Create();

        return sha256.ComputeHash(originalData);
    }

    /// <inheritdoc/>
    public byte[] GetHash(string originalData)
    {
        var origonalDataBytes = Encoding.UTF8.GetBytes(originalData);
        return GetHash(origonalDataBytes);
    }
}
