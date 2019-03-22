using BenchmarkDotNet.Attributes;

namespace AesNi.Benchmarks
{
    public class KeyExpansionPerf : TestKeysBase
    {
        [Benchmark]
        public AesKey Aes128BitKeyExpansion() => AesKey.Create(KeyArray128);
        
        [Benchmark]        
        public AesKey Aes192BitKeyExpansion() => AesKey.Create(KeyArray192);
        
        [Benchmark]        
        public AesKey Aes256BitKeyExpansion() => AesKey.Create(KeyArray256);        
    }
}