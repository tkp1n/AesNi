using System;
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
            if (cipherMode != CipherMode.ECB) throw new NotImplementedException();
            if (paddingMode != PaddingMode.None) throw new NotImplementedException();
            if (iv != null) throw new ArgumentException();
            if (plaintext.Length % 16 != 0) throw new ArgumentException();
            if (ciphertext.Length < plaintext.Length) throw new ArgumentException();

            switch (key)
            {
                case Aes128Key aes128Key:
                    Encrypt(plaintext, ciphertext, aes128Key);
                    return;
                case Aes192Key aes192Key:
                    Encrypt(plaintext, ciphertext, aes192Key);
                    return;
                case Aes256Key aes256Key:
                    Encrypt(plaintext, ciphertext, aes256Key);
                    return;
            }

            throw new NotImplementedException();
        }
    }
}