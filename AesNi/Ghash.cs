using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using static System.Runtime.Intrinsics.X86.Pclmulqdq;
using static System.Runtime.Intrinsics.X86.Sse2;

namespace AesNi
{
    /// <summary>
    /// TODO: TEST!!
    /// https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf
    /// </summary>
    internal static class Ghash
    {
        /// <summary>
        /// Figure 5. Code Sample - Performing Ghash Using Algorithms 1 and 5 (C)
        /// </summary>
        public static Vector128<ulong> Gfmul(Vector128<ulong> a, Vector128<ulong> b)
        {
            Vector128<ulong> tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;

            tmp3 = CarrylessMultiply(a, b, 0x00);
            tmp4 = CarrylessMultiply(a, b, 0x10);
            tmp5 = CarrylessMultiply(a, b, 0x01);
            tmp6 = CarrylessMultiply(a, b, 0x11);

            tmp4 = Xor(tmp4, tmp5);
            tmp5 = ShiftLeftLogical128BitLane(tmp4, 8);
            tmp4 = ShiftRightLogical128BitLane(tmp4, 8);
            tmp3 = Xor(tmp3, tmp5);
            tmp6 = Xor(tmp6, tmp4);

            tmp7 = ShiftRightLogical(tmp3, 31);
            tmp8 = ShiftRightLogical(tmp6, 31);
            tmp3 = ShiftLeftLogical(tmp3, 1);
            tmp6 = ShiftLeftLogical(tmp6, 1);

            tmp9 = ShiftRightLogical128BitLane(tmp7, 12);
            tmp8 = ShiftLeftLogical128BitLane(tmp8, 4);
            tmp7 = ShiftLeftLogical128BitLane(tmp7, 4);
            tmp3 = Or(tmp3, tmp7);
            tmp6 = Or(tmp6, tmp8);
            tmp6 = Or(tmp6, tmp9);

            tmp7 = ShiftLeftLogical(tmp3, 31);
            tmp8 = ShiftLeftLogical(tmp3, 30);
            tmp9 = ShiftLeftLogical(tmp3, 25);

            tmp7 = Xor(tmp7, tmp8);
            tmp7 = Xor(tmp7, tmp9);
            tmp8 = ShiftRightLogical128BitLane(tmp7, 4);
            tmp7 = ShiftLeftLogical128BitLane(tmp7, 12);
            tmp3 = Xor(tmp3, tmp7);

            tmp2 = ShiftRightLogical(tmp3, 1);
            tmp4 = ShiftRightLogical(tmp3, 2);
            tmp5 = ShiftRightLogical(tmp3, 7);
            tmp2 = Xor(tmp2, tmp4);
            tmp2 = Xor(tmp2, tmp5);
            tmp2 = Xor(tmp2, tmp8);
            tmp3 = Xor(tmp3, tmp2);
            tmp6 = Xor(tmp6, tmp3);

            return tmp6;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Gfmul(Vector128<byte> a, Vector128<byte> b)
            => Gfmul(a.AsUInt64(), b.AsUInt64()).AsByte();

        /// <summary>
        /// Figure 7. Code Sample - Performing Ghash Using Algorithms 2 and 4 with Reflected Input and Output
        /// </summary>
        public static Vector128<ulong> GfmulReflected(Vector128<ulong> a, Vector128<ulong> b)
        {
            Vector128<ulong> tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9, tmp10, tmp11, tmp12;
            Vector128<ulong> mask = Vector128.Create(0x0, 0x0, 0x0, 0xffffffff).AsUInt64();

            tmp3 = CarrylessMultiply(a, b, 0x00);
            tmp6 = CarrylessMultiply(a, b, 0x11);

            tmp4 = Shuffle(a.AsUInt32(), 78).AsUInt64();
            tmp5 = Shuffle(b.AsUInt32(), 78).AsUInt64();
            tmp4 = Xor(tmp4, a);
            tmp5 = Xor(tmp5, b);

            tmp4 = CarrylessMultiply(tmp4, tmp5, 0x00);
            tmp4 = Xor(tmp4, tmp3);
            tmp4 = Xor(tmp4, tmp6);

            tmp5 = ShiftLeftLogical128BitLane(tmp4, 8);
            tmp4 = ShiftRightLogical128BitLane(tmp4, 8);
            tmp3 = Xor(tmp3, tmp5);
            tmp6 = Xor(tmp6, tmp4);

            tmp7 = ShiftRightLogical(tmp6, 31);
            tmp8 = ShiftRightLogical(tmp6, 30);
            tmp9 = ShiftRightLogical(tmp6, 25);

            tmp7 = Xor(tmp7, tmp8);
            tmp7 = Xor(tmp7, tmp9);

            tmp8 = Shuffle(tmp7.AsUInt32(), 147).AsUInt64();

            tmp7 = And(mask, tmp8);
            tmp8 = AndNot(mask, tmp8);
            tmp3 = Xor(tmp3, tmp8);
            tmp6 = Xor(tmp6, tmp7);

            tmp10 = ShiftLeftLogical(tmp6, 1);
            tmp3 = Xor(tmp3, tmp10);
            tmp11 = ShiftLeftLogical(tmp6, 2);
            tmp3 = Xor(tmp3, tmp11);
            tmp12 = ShiftLeftLogical(tmp6, 7);
            tmp3 = Xor(tmp3, tmp12);

            return Xor(tmp3, tmp6);
        }

        /// <summary>
        /// Figure 8. Code Sample -Performing GhashUsing an Aggregated Reduction Method
        /// Algorithm by Krzysztof Jankowski,  Pierre Laurent - Intel
        /// </summary>
        public static Vector128<ulong> Reduce4(
            Vector128<ulong> h1, Vector128<ulong> h2, Vector128<ulong> h3, Vector128<ulong> h4,
            Vector128<ulong> x1, Vector128<ulong> x2, Vector128<ulong> x3, Vector128<ulong> x4)
        {
            Vector128<ulong> h1x1Lo, h1x1Hi,
                             h2x2Lo, h2x2Hi,
                             h3x3Lo, h3x3Hi,
                             h4x4Lo, h4x4Hi,
                             lo, hi;
            Vector128<ulong> tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;

            h1x1Lo = CarrylessMultiply(h1, x1, 0x00);
            h2x2Lo = CarrylessMultiply(h2, x2, 0x00);
            h3x3Lo = CarrylessMultiply(h3, x3, 0x00);
            h4x4Lo = CarrylessMultiply(h4, x4, 0x00);

            lo = Xor(h1x1Lo, h2x2Lo);
            lo = Xor(lo, h3x3Lo);
            lo = Xor(lo, h4x4Lo);

            h1x1Hi = CarrylessMultiply(h1, x1, 0x11);
            h2x2Hi = CarrylessMultiply(h2, x2, 0x11);
            h3x3Hi = CarrylessMultiply(h3, x3, 0x11);
            h4x4Hi = CarrylessMultiply(h4, x4, 0x11);

            hi = Xor(h1x1Hi, h2x2Hi);
            hi = Xor(hi, h3x3Hi);
            hi = Xor(hi, h4x4Hi);

            tmp0 = Shuffle(h1.AsUInt32(), 78).AsUInt64();
            tmp4 = Shuffle(x1.AsUInt32(), 78).AsUInt64();
            tmp0 = Xor(tmp0, h1);
            tmp4 = Xor(tmp4, x1);
            tmp1 = Shuffle(h2.AsUInt32(), 78).AsUInt64();
            tmp5 = Shuffle(x2.AsUInt32(), 78).AsUInt64();
            tmp1 = Xor(tmp1, h2);
            tmp5 = Xor(tmp5, x2);
            tmp2 = Shuffle(h3.AsUInt32(), 78).AsUInt64();
            tmp6 = Shuffle(x3.AsUInt32(), 78).AsUInt64();
            tmp2 = Xor(tmp2, h3);
            tmp6 = Xor(tmp6, x3);
            tmp3 = Shuffle(h4.AsUInt32(), 78).AsUInt64();
            tmp7 = Shuffle(x4.AsUInt32(), 78).AsUInt64();
            tmp3 = Xor(tmp3, h4);
            tmp7 = Xor(tmp7, x4);

            tmp0 = CarrylessMultiply(tmp0, tmp4, 0x00);
            tmp1 = CarrylessMultiply(tmp1, tmp5, 0x00);
            tmp2 = CarrylessMultiply(tmp2, tmp6, 0x00);
            tmp3 = CarrylessMultiply(tmp3, tmp7, 0x00);

            tmp0 = Xor(tmp0, lo);
            tmp0 = Xor(tmp0, hi);
            tmp0 = Xor(tmp1, tmp0);
            tmp0 = Xor(tmp2, tmp0);
            tmp0 = Xor(tmp3, tmp0);

            tmp4 = ShiftLeftLogical128BitLane(tmp0, 8);
            tmp0 = ShiftRightLogical128BitLane(tmp0, 8);

            lo = Xor(tmp4, lo);
            hi = Xor(tmp0, hi);

            tmp3 = lo;
            tmp6 = hi;

            tmp7 = ShiftRightLogical(tmp3, 31);
            tmp8 = ShiftRightLogical(tmp6, 31);
            tmp3 = ShiftLeftLogical(tmp3, 1);
            tmp6 = ShiftLeftLogical(tmp6, 1);

            tmp9 = ShiftRightLogical128BitLane(tmp7, 12);
            tmp8 = ShiftLeftLogical128BitLane(tmp8, 4);
            tmp7 = ShiftLeftLogical128BitLane(tmp7, 4);
            tmp3 = Or(tmp3, tmp7);
            tmp6 = Or(tmp6, tmp8);
            tmp6 = Or(tmp6, tmp9);

            tmp7 = ShiftLeftLogical(tmp3, 31);
            tmp8 = ShiftLeftLogical(tmp3, 30);
            tmp9 = ShiftLeftLogical(tmp3, 25);

            tmp7 = Xor(tmp7, tmp8);
            tmp7 = Xor(tmp7, tmp9);
            tmp8 = ShiftRightLogical128BitLane(tmp7, 4);
            tmp7 = ShiftLeftLogical128BitLane(tmp7, 12);
            tmp3 = Xor(tmp3, tmp7);

            tmp2 = ShiftRightLogical(tmp3, 1);
            tmp4 = ShiftRightLogical(tmp3, 2);
            tmp5 = ShiftRightLogical(tmp3, 7);
            tmp2 = Xor(tmp2, tmp4);
            tmp2 = Xor(tmp2, tmp5);
            tmp2 = Xor(tmp2, tmp8);
            tmp3 = Xor(tmp3, tmp2);
            tmp6 = Xor(tmp6, tmp3);

            return tmp6;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<byte> Reduce4(
            Vector128<byte> h1, Vector128<byte> h2, Vector128<byte> h3, Vector128<byte> h4,
            Vector128<byte> x1, Vector128<byte> x2, Vector128<byte> x3, Vector128<byte> x4) =>
            Reduce4(h1.AsUInt64(), h2.AsUInt64(), h3.AsUInt64(), h4.AsUInt64(),
                    x1.AsUInt64(), x2.AsUInt64(), x3.AsUInt64(), x4.AsUInt64()).AsByte();
    }
}