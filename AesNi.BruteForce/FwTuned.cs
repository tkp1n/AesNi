using System;
using System.Security.Cryptography;
using System.Text;

namespace AesNi.BruteForce
{
    class FwTuned
    {
        private static readonly AesManaged aes = new AesManaged { BlockSize = 128, KeySize = 256, Padding = PaddingMode.Zeros };       
        private static ReadOnlySpan<byte> trust => 
            new byte[] {0x74, 0x72, 0x75, 0x73, 0x74};

        private static bool ContainsTrust(byte[] plaintext) =>
            plaintext.AsSpan().IndexOf(trust) >= 0;

        private static void Decrypt(byte[] cipherText, byte[] plaintext, byte[] key, byte[] iv)
        {
            var decryptor = aes.CreateDecryptor(key, iv);
            decryptor.TransformBlock(cipherText, 0, cipherText.Length, plaintext, 0);
        }

        public static void Run()
        {
            var cipherText = Convert.FromBase64String("yptyoDdVBdQtGhgoePppYHnWyugGmy0j81sf3zBeUXEO/LYRw+2XmVa0/v6YiSy9Kj8gMn/gNu2I7dPmfgSEHPUDJpNpiOWmmW1/jw/Pt29Are5tumWmnfkazcAb23xe7B4ruPZVxUEhfn/IrZPNZdr4cQNrHNgEv2ts8gVFuOBU+p792UPy8/mEIhW5ECppxGIb7Yrpg4w7IYNeFtX5d9W4W1t2e+6PcdcjkBK4a8y1cjEtuQ07RpPChOvLcSzlB/Bg7UKntzorRsn+y/d72qD2QxRzcXgbynCNalF7zaT6pEnwKB4i05fTQw6nB7SU1w2/EvCGlfiyR2Ia08mA0GikqegYA6xG/EAGs3ZJ0aQUGt0YZz0P7uBsQKdmCg7jzzEMHyGZDNGTj0F2dOFHLSOTT2/GGSht8eD/Ae7u/xnJj0bGgAKMtNttGFlNyvKpt2vDDT3Orfk6Jk/rD4CIz6O/Tnt0NkJLucHtIyvBYGtQR4+mhbfUELkczeDSxTXGDLaiU3de6tPaa0/vjzizoUbNFdfkIly/HWINdHoO83E=");
            var plaintext = new byte[cipherText.Length];
            var iv = Convert.FromBase64String("DkBbcmQo1QH+ed1wTyBynA==");
            var key = new byte[32];

            for (byte a = 0; a <= 16; a++)
                for (byte b = 0; b <= 16; b++)
                    for (byte c = 0; c <= 16; c++)
                        for (byte d = 0; d <= 16; d++)
                            for (byte e = 0; e <= 16; e++)
                                for (byte f = 0; f <= 16; f++)
                                {
                                    key[0] = a;
                                    key[1] = b;
                                    key[2] = c;
                                    key[3] = d;
                                    key[4] = e;
                                    key[5] = f;

                                    Decrypt(cipherText, plaintext, key, iv);                                    
                                    if (ContainsTrust(plaintext))
                                        return;
                                }
        }
}
}