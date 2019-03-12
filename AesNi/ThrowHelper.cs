using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace AesNi
{
    internal static class ThrowHelper
    {
        // TODO: i18n

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void ThrowPaddingNotSupportedException(PaddingMode paddingMode)
        {
            throw new NotSupportedException($"Padding mode not supported: {paddingMode}");
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void ThrowNotImplementedException()
        {
            throw new NotImplementedException();
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void ThrowArgumentNullException(string argument)
        {
            throw new ArgumentNullException(argument);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void ThrowInputNotMultipleOfBlockSizeException(string argument)
        {
            throw new ArgumentOutOfRangeException(argument, "Input length not a multiple of the block size");
        }

        public static void ThrowDestinationBufferTooSmallException(string argument)
        {
            throw new ArgumentOutOfRangeException(argument, "Destination buffer too small");
        }
    }
}