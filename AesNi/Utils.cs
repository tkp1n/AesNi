using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using static System.Runtime.Intrinsics.X86.Sse2;

namespace AesNi
{
    internal static class Utils
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> ReadUnaligned(ref byte source) 
            => Unsafe.ReadUnaligned<Vector128<byte>>(ref source);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> ReadUnalignedOffset(ref int source, int offset) 
            => Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.As<int, byte>(ref Unsafe.Add(ref source, offset)));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> ReadUnalignedOffset(ref byte source, int offset) 
            => Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref source, (IntPtr) offset));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> ReadUnalignedOffset(ref byte source, IntPtr offset) 
            => Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.AddByteOffset(ref source, offset));
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteUnaligned(ref byte target, Vector128<byte> value) 
            => Unsafe.WriteUnaligned(ref target, value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteUnalignedOffset(ref byte target, int offset, Vector128<byte> value) 
            => Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref target, (IntPtr) offset), value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteUnalignedOffset(ref byte target, IntPtr offset, Vector128<byte> value) 
            => Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref target, offset), value);
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool Equal(Vector128<byte> a, Vector128<byte> b)
            => MoveMask(CompareEqual(a, b)) == 0xffff;
    }
}