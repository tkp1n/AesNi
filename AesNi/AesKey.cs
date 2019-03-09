using System;

namespace AesNi
{
    public abstract class AesKey
    {
        internal abstract ReadOnlySpan<int> ExpandedKey { get; }
    }
}