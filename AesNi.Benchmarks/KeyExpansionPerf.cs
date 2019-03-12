using BenchmarkDotNet.Attributes;

namespace AesNi.Benchmarks
{
    public class KeyExpansionPerf : TestKeysBase
    {
        [Benchmark]
        public Aes128Key Aes128BitKeyExpansion() => new Aes128Key(KeyArray128);
        
        [Benchmark]        
        public Aes192Key Aes192BitKeyExpansion() => new Aes192Key(KeyArray192);
        
        [Benchmark]        
        public Aes256Key Aes256BitKeyExpansion() => new Aes256Key(KeyArray256);        
    }
}