using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;

namespace AesNi.Benchmarks
{
    [MemoryDiagnoser]
    public class Program
    {
        private static readonly byte[] KeyArray128 =
        {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        };

        private static readonly byte[] KeyArray192 =
        {
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
        };

        private static readonly byte[] KeyArray256 =
        {
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
        };

        private AesKey aesKey;

        private ICryptoTransform frameworkTransform;
        private byte[] input;
        private byte[] iv;
        private byte[] output;

        [Params(CipherMode.ECB, CipherMode.CBC)]
        public CipherMode CipherMode { get; set; }

        [Params(PaddingMode.None, PaddingMode.Zeros, PaddingMode.PKCS7, PaddingMode.ANSIX923)]
        public PaddingMode PaddingMode { get; set; }

        [Params(128, 192, 256)] public int KeySize { get; set; }

        [Params(16, 1024, 1024 * 1024)] public int DataSize { get; set; }

        private byte[] KeyBytes
        {
            get
            {
                switch (KeySize)
                {
                    case 128: return KeyArray128;
                    case 192: return KeyArray192;
                    case 256: return KeyArray256;
                    default: throw new InvalidDataException();
                }
            }
        }

        private AesKey AesKey
        {
            get
            {
                switch (KeySize)
                {
                    case 128: return new Aes128Key(KeyBytes);
                    case 192: return new Aes192Key(KeyBytes);
                    case 256: return new Aes256Key(KeyBytes);
                    default: throw new InvalidDataException();
                }
            }
        }

        private static ReadOnlySpan<byte> trust => new byte[] {0x74, 0x72, 0x75, 0x73, 0x74};

        [GlobalSetup]
        public void Setup()
        {
            aesKey = AesKey;
            input = new byte[DataSize];
            output = new byte[DataSize];
            iv = new byte[16];

            var r = new Random(42);
            r.NextBytes(input);
            r.NextBytes(output);
            r.NextBytes(iv);

            var aesFw = System.Security.Cryptography.Aes.Create();
            aesFw.Key = KeyBytes;
            aesFw.Mode = CipherMode;
            aesFw.Padding = PaddingMode;
            aesFw.IV = iv;
            frameworkTransform = aesFw.CreateEncryptor();
        }

        [Benchmark]
        public void AesNi()
        {
            Aes.Encrypt(input, output, iv, aesKey, CipherMode, PaddingMode);
        }

        [Benchmark(Baseline = true)]
        public void Framework()
        {
            frameworkTransform.TransformBlock(input, 0, input.Length, output, 0);
        }

        public static void Main()
        {
            // var summary = BenchmarkRunner.Run<Program>();

            var sw = new Stopwatch();
            sw.Start();

            var cipherText = Convert.FromBase64String(
                "yptyoDdVBdQtGhgoePppYHnWyugGmy0j81sf3zBeUXEO/LYRw+2XmVa0/v6YiSy9Kj8gMn/gNu2I7dPmfgSEHPUDJpNpiOWmmW1/jw/Pt29Are5tumWmnfkazcAb23xe7B4ruPZVxUEhfn/IrZPNZdr4cQNrHNgEv2ts8gVFuOBU+p792UPy8/mEIhW5ECppxGIb7Yrpg4w7IYNeFtX5d9W4W1t2e+6PcdcjkBK4a8y1cjEtuQ07RpPChOvLcSzlB/Bg7UKntzorRsn+y/d72qD2QxRzcXgbynCNalF7zaT6pEnwKB4i05fTQw6nB7SU1w2/EvCGlfiyR2Ia08mA0GikqegYA6xG/EAGs3ZJ0aQUGt0YZz0P7uBsQKdmCg7jzzEMHyGZDNGTj0F2dOFHLSOTT2/GGSht8eD/Ae7u/xnJj0bGgAKMtNttGFlNyvKpt2vDDT3Orfk6Jk/rD4CIz6O/Tnt0NkJLucHtIyvBYGtQR4+mhbfUELkczeDSxTXGDLaiU3de6tPaa0/vjzizoUbNFdfkIly/HWINdHoO83E=");
            var iv = Convert.FromBase64String("DkBbcmQo1QH+ed1wTyBynA==");
            var plaintext = new byte[cipherText.Length];
            var key = new byte[32];
            var k = new Aes256Key(key);

            ref var a = ref key[0];
            ref var b = ref key[1];
            ref var c = ref key[2];
            ref var d = ref key[3];
            ref var e = ref key[4];
            ref var f = ref key[5];

            for (a = 0; a <= 16; a++)
            for (b = 0; b <= 16; b++)
            for (c = 0; c <= 16; c++)
            for (d = 0; d <= 16; d++)
            for (e = 0; e <= 16; e++)
            for (f = 0; f <= 16; f++)
            {
                k.ReKey(key);

                Aes.DecryptCbc(cipherText, plaintext, iv, k);
                if (plaintext.AsSpan().IndexOf(trust) >= 0)
                {
                    Console.WriteLine(sw.ElapsedMilliseconds);
                    Console.WriteLine($"{a} {b} {c} {d} {e} {f}\n{Encoding.ASCII.GetString(plaintext)}");
                    return;
                }
            }
        }
    }
}