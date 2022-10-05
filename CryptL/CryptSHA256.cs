using System.Security.Cryptography;


namespace CryptL
{
    public static class CryptSHA256
    {
        public static byte[] GetHash(byte[] originalData)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(originalData);
            }
        }
    }
}
