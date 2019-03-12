using System;

namespace AesNi
{
    public abstract class AesKey
    {
        internal abstract ReadOnlySpan<int> ExpandedKey { get; }

        public static AesKey Create(ReadOnlySpan<byte> key)
        {
            if (key.Length == 16) return new Aes128Key(key);
            if (key.Length == 24) return new Aes192Key(key);
            if (key.Length == 32) return new Aes256Key(key);

            throw new ArgumentException();
        }
    }
}