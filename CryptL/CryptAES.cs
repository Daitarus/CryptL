using System.Security.Cryptography;

namespace CryptL
{
    public sealed class CryptAES : ICrypt
    {

        private Aes aes;

        private int keyStandardLength = 32;
        private int ivStandardLength = 16;

        public byte[] Key { get { return aes.Key; } }
        public byte[] IV { get { return aes.IV; } }

        public CryptAES() 
        {
            aes = Aes.Create();
        }
        public CryptAES(byte[] key, byte[] iv)
        {
            aes = Aes.Create();

            if (key == null || key.Length != keyStandardLength)
                throw new Exception($"AES {nameof(key)} must be {keyStandardLength} bytes");
            if (iv == null || iv.Length != ivStandardLength)
                throw new Exception($"AES {nameof(iv)} must be {ivStandardLength} bytes");

            aes.Key = key;
            aes.IV = iv;
        }

        public byte[] Encrypt(byte[] originalData)
        {
            if (originalData == null || originalData.Length == 0)
                throw new ArgumentNullException(nameof(originalData));

            return UseCryptoStream(aes.CreateEncryptor(aes.Key, aes.IV), originalData);
        }

        public byte[] Decrypt(byte[] encryptData)
        {
            if (encryptData == null || encryptData.Length == 0)
                throw new ArgumentNullException(nameof(encryptData));

            return UseCryptoStream(aes.CreateDecryptor(aes.Key, aes.IV), encryptData);
        }

        private byte[] UseCryptoStream(ICryptoTransform cryptoTransform, byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentNullException(nameof(data));

            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write);

            cryptoStream.Write(data, 0, data.Length);
            cryptoStream.FlushFinalBlock();

            return memoryStream.ToArray();
        }
    }
}
