using System.Security.Cryptography;

namespace CryptL
{

    public sealed class CryptRSA : ICrypt
    {
        private RSACryptoServiceProvider rsa;
        
        public CryptRSA() 
        {
            rsa = new RSACryptoServiceProvider();
        }
        public CryptRSA(byte[] keys)
        {
            if (keys == null || keys.Length <= 0)
                throw new ArgumentNullException("keys");

            rsa = new RSACryptoServiceProvider();
            rsa.ImportCspBlob(keys); 
        }

        public byte[] GetKeys(bool withPrivateKey)
        {
            return rsa.ExportCspBlob(withPrivateKey);
        }

        public void SetKeys(byte[] keys)
        {
            if (keys == null || keys.Length <= 0)
                throw new ArgumentNullException("keys");

            rsa.ImportCspBlob(keys);
        }

        public byte[] Encrypt(byte[] originalData)
        {
            if (originalData == null || originalData.Length <= 0)
                throw new ArgumentNullException("originalData");

            return rsa.Encrypt(originalData, false);
        }
        public byte[] Decrypt(byte[] encryptData)
        {
            if (encryptData == null || encryptData.Length <= 0)
                throw new ArgumentNullException("encryptData");

            return rsa.Decrypt(encryptData, false);
        }
    }

}
