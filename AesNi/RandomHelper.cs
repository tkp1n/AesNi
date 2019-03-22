using System;
using System.Threading;

namespace AesNi
{
    internal static class RandomHelper
    {
        private static int seed = Environment.TickCount;

        private static readonly ThreadLocal<Random> random =
            new ThreadLocal<Random>(() => new Random(Interlocked.Increment(ref seed)));

        public static void NextBytes(Span<byte> buffer) 
            => random.Value.NextBytes(buffer);
    }
}