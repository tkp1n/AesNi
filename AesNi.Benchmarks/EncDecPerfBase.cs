using System;
using System.IO;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using static AesNi.Benchmarks.TestKeys;

namespace AesNi.Benchmarks
{
    public abstract class EncDecPerfBase
    {
        protected  ICryptoTransform frameworkEncryptTransform;
        protected  ICryptoTransform frameworkDecryptTransform;
        protected  byte[] input;
        protected  byte[] iv;
        protected  byte[] output;

        [Params(CipherMode.ECB, CipherMode.CBC)]
        public CipherMode CipherMode { get; set; }

        [Params(128, 192, 256)] public int KeySize { get; set; }

        [Params(16, 1024, 1024 * 1024)] public int DataSize { get; set; }

        private ReadOnlySpan<byte> KeyBytes
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

        private AesKey AesKey => AesKey.Create(KeyBytes);
        protected AesKey aesKey;

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
            aesFw.Key = new byte[KeySize/8];
            KeyBytes.CopyTo(aesFw.Key);
            aesFw.Mode = CipherMode;
            aesFw.Padding = PaddingMode.None;
            aesFw.IV = iv;
            frameworkEncryptTransform = aesFw.CreateEncryptor();
            frameworkDecryptTransform = aesFw.CreateDecryptor();
        }
    }
}