using System.Security.Cryptography;

namespace CryptL
{
    public abstract class CryptBase
    {
        public abstract byte[] Encrypt(byte[] originalData);
        public abstract byte[] Decrypt(byte[] encryptData);

        protected byte[] UseCryptoStream(ICryptoTransform cryptoTransform, byte[] data)
        {
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write);

            cryptoStream.Write(data, 0, data.Length);
            cryptoStream.FlushFinalBlock();

            return memoryStream.ToArray();
        }
    }
}
