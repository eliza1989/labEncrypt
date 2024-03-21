using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace FileDecryption
{
    class Program
    {
        static void Main()
        {
            string filePath = "PO-encrypted.pdf"; // Path to the encrypted file
            string decryptedFilePath = "PO-decrypted.pdf"; // Path for the decrypted file
            string password = "whodrinksroots"; // Password used for encryption

            // Nonce/IV
            byte[] nonce = Encoding.ASCII.GetBytes("abcdefgh");

            // Read the encrypted file
            byte[] encryptedData = File.ReadAllBytes(filePath);

            // Decrypt the file
            byte[] decryptedData = ChaCha20Decrypt(encryptedData, nonce, password);

            // Write the decrypted data to a new file
            File.WriteAllBytes(decryptedFilePath, decryptedData);

            Console.WriteLine("File decrypted successfully.");
        }

        private static byte[] ChaCha20Decrypt(byte[] ciphertext, byte[] nonce, string password)
        {
            const int keySizeInBits = 256;
            const int blockSizeInBits = 128;

            // Derive the key using the provided password and KDF
            byte[] key = DeriveKey(password, keySizeInBits);

            // Setup ChaCha20 cipher
            ChaChaEngine cipher = new ChaChaEngine();
            KeyParameter keyParam = new KeyParameter(key);
            ParametersWithIV parameters = new ParametersWithIV(keyParam, nonce);
            cipher.Init(false, parameters);

            // Decrypt the ciphertext
            byte[] decryptedData = new byte[ciphertext.Length];
            cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, decryptedData, 0);

            return decryptedData;
        }

        private static byte[] DeriveKey(string password, int keySizeInBits)
        {
            const string salt = "12345678"; // Salt used for key derivation
            const int iterationCount = 500;

            // Convert salt to bytes
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);

            // Derive key using PBKDF2 with SHA256
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, iterationCount);
            return pbkdf2.GetBytes(keySizeInBits / 8); // Key size is specified in bytes
        }
    }
}