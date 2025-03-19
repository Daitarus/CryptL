using System.Security.Cryptography;

namespace CryptL.Crypt;

/// <summary>
/// RSA data encryptor.
/// </summary>
public sealed class CryptRSA : ICrypt, IDisposable
{
    #region Fields
    private const int _allKeyStandardLength = 2324;
    private const int _publicKeyStandardLength = 532;

    private readonly RSACryptoServiceProvider _rsa = new(4096);

    /// <summary>
    /// Key information with private parameters;
    /// </summary>
    public byte[] AllKey
    {
        get => _rsa.ExportCspBlob(true);
        set => _rsa.ImportCspBlob(value);
    }

    /// <summary>
    /// Key information without private parameters;
    /// </summary>
    public byte[] PublicKey
    {
        get => _rsa.ExportCspBlob(false);
        set => _rsa.ImportCspBlob(value);
    }
    #endregion

    #region Constructors
    public CryptRSA() { }

    /// <param name="key">Key information.</param>
    /// <param name="isAllKey">Flag indicates the inclusion of private parameters in the key.</param>
    public CryptRSA(byte[] key, bool isAllKey)
    {
        CheckExeptionKey(key, isAllKey);

        if (isAllKey)
            AllKey = key;
        else
            PublicKey = key;
    }
    #endregion

    #region Public methods
    /// <inheritdoc/>
    public byte[] Encrypt(byte[] originalData)
    {
        if (originalData == null || originalData.Length == 0)
            throw new ArgumentNullException(nameof(originalData));

        return _rsa.Encrypt(originalData, false);
    }

    /// <inheritdoc/>
    public byte[] Decrypt(byte[] encryptData)
    {
        if (encryptData == null || encryptData.Length == 0)
            throw new ArgumentNullException(nameof(encryptData));

        return _rsa.Decrypt(encryptData, false);
    }

    /// <inheritdoc/>
    public void Dispose() => _rsa.Dispose();
    #endregion

    #region Private methods
    private static void CheckExeptionKey(byte[] key, bool isAllKey)
    {
        int keyStandardLength;

        if (isAllKey)
            keyStandardLength = _allKeyStandardLength;
        else
            keyStandardLength = _publicKeyStandardLength;

        if (key == null || key.Length != keyStandardLength)
            throw new ArgumentException($"{nameof(key)} size must be {keyStandardLength}");
    }
    #endregion
}
