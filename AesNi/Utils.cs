using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace AesNi
{
    internal static class Utils
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static Vector128<int> ReadUnaligned(ReadOnlySpan<byte> source)
        {
            return Unsafe.ReadUnaligned<Vector128<int>>(ref MemoryMarshal.GetReference(source));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static Vector128<byte> ReadUnalignedOffset(ref int source, int offset)
        {
            return Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.As<int, byte>(ref Unsafe.Add(ref source, offset)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static Vector128<byte> ReadUnalignedOffset(ref byte source, int offset)
        {
            return Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref source, (IntPtr) offset));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteUnalignedOffset(ref byte target, int offset, Vector128<byte> value)
        {
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref target, (IntPtr) offset), value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteUnalignedOffset(ref int target, int offset, Vector128<int> vec)
        {
            Unsafe.WriteUnaligned(ref Unsafe.As<int, byte>(ref Unsafe.Add(ref target, offset)), vec);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void WriteUnalignedOffset(ref int target, int offset, Vector128<byte> vec)
        {
            Unsafe.WriteUnaligned(ref Unsafe.As<int, byte>(ref Unsafe.Add(ref target, offset)), vec);
        }
    }
}