using System;
using System.IO;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using static AesNi.Benchmarks.TestKeys;

namespace AesNi.Benchmarks
{
    public class EncryptPerfGcm
    {
        [Benchmark]
        public void AesNi()
        {
            Aes.Encrypt(input, output, nonce, aad, tag, aesKey);
        }

        [Benchmark(Baseline = true)]
        public void Framework()
        {
            frameworkGcm.Encrypt(nonce, input, output, tag, aad);
        }

        protected AesGcm frameworkGcm;
        protected byte[] input;
        protected byte[] nonce;
        protected byte[] output;
        protected byte[] tag;
        protected byte[] aad;

        [Params(128, 192, 256)] public int KeySize { get; set; }
        [Params(16, 1024, 1024 * 1024)] public int DataSize { get; set; }
        [Params(0, 16, 1024, 1024 * 1024)] public int AadDataSize { get; set; }

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
            aad = new byte[AadDataSize];
            nonce = new byte[12];
            tag = new byte[16];
            var r = new Random(42);
            r.NextBytes(input);
            r.NextBytes(output);
            r.NextBytes(nonce);
            r.NextBytes(aad);
            frameworkGcm = new AesGcm(KeyBytes);
        }
    }
}