using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace AesNi.Benchmarks
{
    public class DecryptPerf : EncDecPerfBase
    {
        [Benchmark]
        public void AesNi()
        {
            Aes.Decrypt(input, output, iv, aesKey, CipherMode, PaddingMode.None);
        }

        [Benchmark(Baseline = true)]
        public void Framework()
        {
            frameworkDecryptTransform.TransformBlock(input, 0, input.Length, output, 0);
        }
    }
}