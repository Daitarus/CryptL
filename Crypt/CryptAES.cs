using System.Security.Cryptography;

namespace CryptL.Crypt;

/// <summary>
/// AES data encryptor.
/// </summary>
public sealed class CryptAES : ICrypt, IDisposable
{
    #region Fields
    private const int keyStandardLength = 32;
    private const int ivStandardLength = 16;

    private readonly Aes _aes = Aes.Create();

    /// <summary>
    /// Secret key for the symmetric algorithm.
    /// </summary>
    public byte[] Key { get => _aes.Key; }

    /// <summary>
    /// Initialization vector for the symmetric algorithm.
    /// </summary>
    public byte[] IV { get => _aes.IV; }
    #endregion

    #region Constructors
    public CryptAES() { }

    /// <param name="unionKeyIv">Union key based on the secret key and initialization vector.</param>
    public CryptAES(byte[] unionKeyIv)
    {
        if (unionKeyIv == null)
            throw new ArgumentNullException(nameof(unionKeyIv));

        if (unionKeyIv.Length != keyStandardLength + ivStandardLength)
            throw new ArgumentException($"{nameof(unionKeyIv)} size not equal {keyStandardLength + ivStandardLength}");

        PartitionKeyIV(unionKeyIv, out byte[] key, out byte[] iv);

        _aes.Key = key;
        _aes.IV = iv;
    }

    /// <param name="key">Secret key for the symmetric algorithm.</param>
    /// <param name="iv">Initialization vector for the symmetric algorithm.</param>
    public CryptAES(byte[] key, byte[] iv)
    {
        if (key == null || key.Length != keyStandardLength)
            throw new ArgumentException($"AES {nameof(key)} must be {keyStandardLength} bytes");

        if (iv == null || iv.Length != ivStandardLength)
            throw new ArgumentException($"AES {nameof(iv)} must be {ivStandardLength} bytes");

        _aes.Key = key;
        _aes.IV = iv;
    }
    #endregion

    #region Public methods
    /// <inheritdoc/>
    public byte[] Encrypt(byte[] originalData)
    {
        if (originalData == null || originalData.Length == 0)
            throw new ArgumentNullException(nameof(originalData));

        return _aes.EncryptCbc(originalData, _aes.IV);
    }

    /// <inheritdoc/>
    public byte[] Decrypt(byte[] encryptData)
    {
        if (encryptData == null || encryptData.Length == 0)
            throw new ArgumentNullException(nameof(encryptData));

        return _aes.DecryptCbc(encryptData, _aes.IV);
    }

    /// <summary>
    /// Creates union key based on the secret key and initialization vector.
    /// </summary>
    /// <returns>Union key.</returns>
    public byte[] GetUnionKeyIV()
    {
        byte[] result = new byte[keyStandardLength + ivStandardLength];
        Array.Copy(_aes.Key,0,result,0,keyStandardLength);
        Array.Copy(_aes.IV,0,result,keyStandardLength,ivStandardLength);

        return result;
    }

    /// <inheritdoc/>
    public void Dispose()
        => _aes?.Dispose();
    #endregion

    #region Private methods
    private static void PartitionKeyIV(byte[] unionKeyIv, out byte[] key, out byte[] iv)
    {
        key = new byte[keyStandardLength];
        iv = new byte[ivStandardLength];

        Array.Copy(unionKeyIv, 0, key,0, keyStandardLength);
        Array.Copy(unionKeyIv, keyStandardLength, iv, 0, ivStandardLength);
    }
    #endregion
}
