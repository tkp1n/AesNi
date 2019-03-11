using System;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;

namespace AesNi
{
    public static partial class Aes
    {
        public static void Encrypt(ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> iv,
            AesKey key,
            CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (cipherMode != CipherMode.ECB && cipherMode != CipherMode.CBC) throw new NotImplementedException();
            if (paddingMode != PaddingMode.None) throw new NotImplementedException();
            if (cipherMode == CipherMode.CBC && iv == null) throw new ArgumentException();
            if (plaintext.Length % 16 != 0) throw new ArgumentException();
            if (ciphertext.Length < plaintext.Length) throw new ArgumentException();

            switch (cipherMode)
            {
                case CipherMode.ECB:
                    DispatchEncryptEcb(plaintext, ciphertext, iv, key, paddingMode);
                    return;
                case CipherMode.CBC:
                    DispatchEncryptCbc(plaintext, ciphertext, iv, key, paddingMode);
                    return; 
            }
           
            throw new NotImplementedException();
        }

        private static void DispatchEncryptEcb(ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> iv,
            AesKey key,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            switch (key)
            {
                case Aes128Key aes128Key:
                    EncryptEcb(plaintext, ciphertext, aes128Key);
                    return;
                case Aes192Key aes192Key:
                    EncryptEcb(plaintext, ciphertext, aes192Key);
                    return;
                case Aes256Key aes256Key:
                    EncryptEcb(plaintext, ciphertext, aes256Key);
                    return;
            }
        }
        
        private static void DispatchEncryptCbc(ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> iv,
            AesKey key,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            switch (key)
            {
                case Aes128Key aes128Key:
                    EncryptCbc(plaintext, ciphertext, iv, aes128Key);
                    return;
                case Aes192Key aes192Key:
                    EncryptCbc(plaintext, ciphertext, iv, aes192Key);
                    return;
                case Aes256Key aes256Key:
                    EncryptCbc(plaintext, ciphertext, iv, aes256Key);
                    return;
            }
        }
    }
}