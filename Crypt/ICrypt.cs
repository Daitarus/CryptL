namespace CryptL.Crypt
{
    /// <summary>
    /// Interface for working with encryption.
    /// </summary>
    public interface ICrypt
    {
        /// <summary>
        /// Encrypts data.
        /// </summary>
        /// <param name="originalData">Original data in the form of a byte array.</param>
        /// <returns>Encrypted data in the form of a byte array.</returns>
        public byte[] Encrypt(byte[] originalData);

        /// <summary>
        /// Decrypt data.
        /// </summary>
        /// <param name="encryptData">Encrypted data in the form of a byte array.</param>
        /// <returns>Decrypted data in the form of a byte array.</returns>
        public byte[] Decrypt(byte[] encryptData);        
    }
}
