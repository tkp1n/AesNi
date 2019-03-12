using BenchmarkDotNet.Attributes;

namespace AesNi.Benchmarks
{
    public class EncryptPerf : EncDecPerfBase
    {
        [Benchmark]
        public void AesNi()
        {
            Aes.Encrypt(input, output, iv, aesKey, CipherMode, PaddingMode);
        }

        [Benchmark(Baseline = true)]
        public void Framework()
        {
            frameworkEncryptTransform.TransformBlock(input, 0, input.Length, output, 0);
        }
    }
}