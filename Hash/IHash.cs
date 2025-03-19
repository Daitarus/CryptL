namespace CryptL.Hash;

/// <summary>
/// Interface for working with hashing data.
/// </summary>
public interface IHash
{
    /// <summary>
    /// Hashes the data.
    /// </summary>
    /// <param name="originalData">Hashed data in the form of an array of bytes.</param>
    /// <returns>Hash of data in the form of an array of bytes.</returns>
    byte[] GetHash(byte[] originalData);

    /// <summary>
    /// Hashes the data.
    /// </summary>
    /// <param name="originalData">Hashed data in the form of a string.</param>
    /// <returns>Hash of data in the form of an array of bytes.</returns>
    byte[] GetHash(string originalData);
}
