namespace CryptL.Crypt
{
    public interface ICrypt
    {
        public abstract byte[] Encrypt(byte[] originalData);
        public abstract byte[] Decrypt(byte[] encryptData);        
    }
}
