using System;
using System.Threading;

namespace AesNi
{
    internal static class RandomHelper
    {
        private static int _seed = Environment.TickCount;

        private static readonly ThreadLocal<Random> Random =
            new ThreadLocal<Random>(() => new Random(Interlocked.Increment(ref _seed)));

        public static void NextBytes(Span<byte> buffer) 
            => Random.Value.NextBytes(buffer);
    }
}