using System;
using System.Runtime.CompilerServices;

namespace AesNi
{
    // TODO: Consider using separate key classes for algorithms using AES only in the encrypt direction to avoid
    //  second half of key expansion
    public abstract class AesKey
    {
        protected const nint BytesPerRoundKey = 16;

        internal abstract ReadOnlySpan<byte> ExpandedKey { get; }

        public abstract void ReKey(ReadOnlySpan<byte> key);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static AesKey Create(ReadOnlySpan<byte> key)
        {
            switch (key.Length)
            {
                case 16: return new Aes128Key(key);
                case 24: return new Aes192Key(key);
                case 32: return new Aes256Key(key);
            }

            ThrowHelper.ThrowUnknownKeySizeException(nameof(key), key.Length);
            return null;
        }
    }
}