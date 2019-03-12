using BenchmarkDotNet.Running;

namespace AesNi.Benchmarks
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly)
                .Run(args);
        }
    }
}