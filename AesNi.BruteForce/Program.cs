using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

namespace AesNi.BruteForce
{
    [DryJob]
    public class Program
    {
        [Benchmark(Baseline = true)]
        public void FwOriginal() => FwBaseline.Run();

        [Benchmark]
        public void FwOptimized() => FwTuned.Run();

        [Benchmark]
        public void AesNiOriginal() => NiNormal.Run();

        [Benchmark]
        public void AesNiParallel() => NiParallel.Run();

        public static void Main(string[] args)
        {
            BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly)
                .Run(args);
        }
    }
}