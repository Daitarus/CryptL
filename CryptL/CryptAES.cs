using System.Security.Cryptography;

namespace CryptL
{
    public sealed class CryptAES : ICrypt
    {

        private Aes aes;

        public byte[] Key { get { return aes.Key; } }
        public byte[] IV { get { return aes.IV; } }

        public CryptAES() 
        {
            aes = Aes.Create();
        }
        public CryptAES(byte[] key, byte[] IV)
        {
            aes = Aes.Create();

            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            aes.Key = key;
            aes.IV = IV;
        }

        public byte[] Encrypt(byte[] originalData)
        {
            if (originalData == null || originalData.Length <= 0)
                throw new ArgumentNullException("originalData");

            return UseCryptoStream(aes.CreateEncryptor(aes.Key, aes.IV), originalData);
        }

        public byte[] Decrypt(byte[] encryptData)
        {
            if (encryptData == null || encryptData.Length <= 0)
                throw new ArgumentNullException("encryptData");

            return UseCryptoStream(aes.CreateDecryptor(aes.Key, aes.IV), encryptData);
        }

        private byte[] UseCryptoStream(ICryptoTransform cryptoTransform, byte[] data)
        {
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write);

            cryptoStream.Write(data, 0, data.Length);
            cryptoStream.FlushFinalBlock();

            return memoryStream.ToArray();
        }
    }
}
