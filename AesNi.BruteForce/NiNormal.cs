using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;

namespace AesNi.BruteForce
{
    static class NiNormal
    {
        private static ReadOnlySpan<byte> Trust => new byte[] {0x74, 0x72, 0x75, 0x73, 0x74};

        public static void Run()
        {
            var cipherText = Convert.FromBase64String(
                "yptyoDdVBdQtGhgoePppYHnWyugGmy0j81sf3zBeUXEO/LYRw+2XmVa0/v6YiSy9Kj8gMn/gNu2I7dPmfgSEHPUDJpNpiOWmmW1/jw/Pt29Are5tumWmnfkazcAb23xe7B4ruPZVxUEhfn/IrZPNZdr4cQNrHNgEv2ts8gVFuOBU+p792UPy8/mEIhW5ECppxGIb7Yrpg4w7IYNeFtX5d9W4W1t2e+6PcdcjkBK4a8y1cjEtuQ07RpPChOvLcSzlB/Bg7UKntzorRsn+y/d72qD2QxRzcXgbynCNalF7zaT6pEnwKB4i05fTQw6nB7SU1w2/EvCGlfiyR2Ia08mA0GikqegYA6xG/EAGs3ZJ0aQUGt0YZz0P7uBsQKdmCg7jzzEMHyGZDNGTj0F2dOFHLSOTT2/GGSht8eD/Ae7u/xnJj0bGgAKMtNttGFlNyvKpt2vDDT3Orfk6Jk/rD4CIz6O/Tnt0NkJLucHtIyvBYGtQR4+mhbfUELkczeDSxTXGDLaiU3de6tPaa0/vjzizoUbNFdfkIly/HWINdHoO83E=").AsSpan();
            var iv = Convert.FromBase64String("DkBbcmQo1QH+ed1wTyBynA==").AsSpan();

            var plaintext = new byte[cipherText.Length].AsSpan();
            var keyBuffer = new byte[32].AsSpan();
            var key = AesKey.Create(keyBuffer);

            ref var a = ref keyBuffer[0];
            ref var b = ref keyBuffer[1];
            ref var c = ref keyBuffer[2];
            ref var d = ref keyBuffer[3];
            ref var e = ref keyBuffer[4];
            ref var f = ref keyBuffer[5];

            for (a = 0; a <= 16; a++)
            for (b = 0; b <= 16; b++)
            for (c = 0; c <= 16; c++)
            for (d = 0; d <= 16; d++)
            for (e = 0; e <= 16; e++)
            for (f = 0; f <= 16; f++)
            {
                key.ReKey(keyBuffer);

                Aes.Decrypt(cipherText, plaintext, iv, key, CipherMode.CBC, PaddingMode.None);
                if (plaintext.IndexOf(Trust) >= 0)
                {
                    return;
                }
            }
        }
    }
}