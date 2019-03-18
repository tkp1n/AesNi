using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static AesNi.Utils;
using static System.Runtime.Intrinsics.X86.Aes;
using static System.Runtime.Intrinsics.X86.Sse2;

namespace AesNi
{
    // TODO: Consider using seperate key classes for algorithms using AES only in the encrypt direction to avoid 
    public sealed class Aes256Key : AesKey
    {
        private const int Nb = 4;
        private const int Nk = 8;
        private const int Nr = 14;

        // Saving some space, as the actual key is stored only once (at [0]) and [10] is shared between enc and dec 
        // inspiration drawn from https://github.com/sebastien-riou/aes-brute-force/blob/master/include/aes_ni.h
        private readonly int[] _expandedKey = new int[2 * Nb * Nr];

        // TODO: validation
        public Aes256Key(ReadOnlySpan<byte> key)
        {
            KeyExpansion(key, _expandedKey);
        }

        internal override ReadOnlySpan<int> ExpandedKey => _expandedKey;

        // TODO: validation
        public void ReKey(ReadOnlySpan<byte> newKey)
        {
            KeyExpansion(newKey, _expandedKey);
        }

        // TODO: Verify whether calculating decryption key expansion after encryption key expansion is faster (locality)
        private static void KeyExpansion(ReadOnlySpan<byte> key, Span<int> keySchedule)
        {
            ref var expandedKey = ref MemoryMarshal.GetReference(keySchedule);

            var tmp1 = ReadUnaligned(key);
            var tmp3 = Unsafe.ReadUnaligned<Vector128<int>>(
                ref Unsafe.AddByteOffset(ref MemoryMarshal.GetReference(key), (IntPtr) 16));

            WriteUnalignedOffset(ref expandedKey, 0 * Nb, tmp1);

            WriteUnalignedOffset(ref expandedKey, 1 * Nb, tmp3);
            WriteUnalignedOffset(ref expandedKey, 27 * Nb, InverseMixColumns(tmp3.AsByte()));

            Aes256KeyExp1(ref tmp1, tmp3, 0x01);
            WriteUnalignedOffset(ref expandedKey, 2 * Nb, tmp1);
            WriteUnalignedOffset(ref expandedKey, 26 * Nb, InverseMixColumns(tmp1.AsByte()));

            Aes256KeyExp2(tmp1, ref tmp3);
            WriteUnalignedOffset(ref expandedKey, 3 * Nb, tmp3);
            WriteUnalignedOffset(ref expandedKey, 25 * Nb, InverseMixColumns(tmp3.AsByte()));

            Aes256KeyExp1(ref tmp1, tmp3, 0x02);
            WriteUnalignedOffset(ref expandedKey, 4 * Nb, tmp1);
            WriteUnalignedOffset(ref expandedKey, 24 * Nb, InverseMixColumns(tmp1.AsByte()));

            Aes256KeyExp2(tmp1, ref tmp3);
            WriteUnalignedOffset(ref expandedKey, 5 * Nb, tmp3);
            WriteUnalignedOffset(ref expandedKey, 23 * Nb, InverseMixColumns(tmp3.AsByte()));

            Aes256KeyExp1(ref tmp1, tmp3, 0x04);
            WriteUnalignedOffset(ref expandedKey, 6 * Nb, tmp1);
            WriteUnalignedOffset(ref expandedKey, 22 * Nb, InverseMixColumns(tmp1.AsByte()));

            Aes256KeyExp2(tmp1, ref tmp3);
            WriteUnalignedOffset(ref expandedKey, 7 * Nb, tmp3);
            WriteUnalignedOffset(ref expandedKey, 21 * Nb, InverseMixColumns(tmp3.AsByte()));

            Aes256KeyExp1(ref tmp1, tmp3, 0x08);
            WriteUnalignedOffset(ref expandedKey, 8 * Nb, tmp1);
            WriteUnalignedOffset(ref expandedKey, 20 * Nb, InverseMixColumns(tmp1.AsByte()));

            Aes256KeyExp2(tmp1, ref tmp3);
            WriteUnalignedOffset(ref expandedKey, 9 * Nb, tmp3);
            WriteUnalignedOffset(ref expandedKey, 19 * Nb, InverseMixColumns(tmp3.AsByte()));

            Aes256KeyExp1(ref tmp1, tmp3, 0x10);
            WriteUnalignedOffset(ref expandedKey, 10 * Nb, tmp1);
            WriteUnalignedOffset(ref expandedKey, 18 * Nb, InverseMixColumns(tmp1.AsByte()));

            Aes256KeyExp2(tmp1, ref tmp3);
            WriteUnalignedOffset(ref expandedKey, 11 * Nb, tmp3);
            WriteUnalignedOffset(ref expandedKey, 17 * Nb, InverseMixColumns(tmp3.AsByte()));

            Aes256KeyExp1(ref tmp1, tmp3, 0x20);
            WriteUnalignedOffset(ref expandedKey, 12 * Nb, tmp1);
            WriteUnalignedOffset(ref expandedKey, 16 * Nb, InverseMixColumns(tmp1.AsByte()));

            Aes256KeyExp2(tmp1, ref tmp3);
            WriteUnalignedOffset(ref expandedKey, 13 * Nb, tmp3);
            WriteUnalignedOffset(ref expandedKey, 15 * Nb, InverseMixColumns(tmp3.AsByte()));

            Aes256KeyExp1(ref tmp1, tmp3, 0x40);
            WriteUnalignedOffset(ref expandedKey, 14 * Nb, tmp1);
        }

        // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Aes256KeyExp1(ref Vector128<int> tmp1, Vector128<int> tmp3, byte rcon)
        {
            var tmp2 = KeygenAssist(tmp3.AsByte(), rcon).AsInt32();
            tmp2 = Shuffle(tmp2, 0xFF);
            var tmp4 = ShiftLeftLogical128BitLane(tmp1, 0x04);
            tmp1 = Xor(tmp1, tmp4);
            tmp4 = ShiftLeftLogical128BitLane(tmp4, 0x04);
            tmp1 = Xor(tmp1, tmp4);
            tmp4 = ShiftLeftLogical128BitLane(tmp4, 0x04);
            tmp1 = Xor(tmp1, tmp4);
            tmp1 = Xor(tmp1, tmp2);
        }

        // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Aes256KeyExp2(Vector128<int> tmp1, ref Vector128<int> tmp3)
        {
            var tmp4 = KeygenAssist(tmp1.AsByte(), 0x00).AsInt32();
            var tmp2 = Shuffle(tmp4, 0xAA);
            tmp4 = ShiftLeftLogical128BitLane(tmp3, 0x04);
            tmp3 = Xor(tmp3, tmp4);
            tmp4 = ShiftLeftLogical128BitLane(tmp4, 0x04);
            tmp3 = Xor(tmp3, tmp4);
            tmp4 = ShiftLeftLogical128BitLane(tmp4, 0x04);
            tmp3 = Xor(tmp3, tmp4);
            tmp3 = Xor(tmp3, tmp2);
        }
    }
}