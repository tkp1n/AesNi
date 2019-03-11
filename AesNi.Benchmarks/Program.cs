using System;
using System.IO;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

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
        private byte[] output;
        private byte[] iv;

        [Params(CipherMode.ECB, CipherMode.CBC)] 
        public CipherMode CipherMode { get; set; }

        [Params(PaddingMode.None)] 
        public PaddingMode PaddingMode { get; set; }

        [Params(128, 192, 256)] 
        public int KeySize { get; set; }

        [Params(16, 1024, 1024 * 1024)] 
        public int DataSize { get; set; }

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
            var summary = BenchmarkRunner.Run<Program>();
        }
    }
}