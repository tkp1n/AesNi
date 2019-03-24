using BenchmarkDotNet.Attributes;

namespace AesNi.Benchmarks
{
    public class KeyExpansionPerf : TestKeysBase
    {
        [Benchmark]
        public AesKey Aes128BitKeyExpansion() => new Aes128Key(KeyArray128);
        
        [Benchmark]        
        public AesKey Aes192BitKeyExpansion() => new Aes192Key(KeyArray192);
        
        [Benchmark]        
        public AesKey Aes256BitKeyExpansion() => new Aes256Key(KeyArray256);        
    }
}