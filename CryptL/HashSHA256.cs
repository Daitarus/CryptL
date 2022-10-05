using System.Security.Cryptography;


namespace CryptL
{
    public static class HashSHA256
    {
        public static byte[] GetHash(byte[] originalData)
        {
            if (originalData == null || originalData.Length <= 0)
                throw new ArgumentNullException("originalData");

            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(originalData);
            }
        }
    }
}
