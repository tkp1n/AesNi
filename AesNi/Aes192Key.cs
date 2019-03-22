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
    public class Aes192Key : AesKey
    {
        private const int Nb = 4;
        private const int Nk = 6;
        private const int Nr = 12;

        // Saving some space, as the actual key is stored only once (at [0]) and [12] is shared between enc and dec 
        // inspiration drawn from https://github.com/sebastien-riou/aes-brute-force/blob/master/include/aes_ni.h
        private readonly int[] _expandedKey = new int[2 * Nb * Nr];

        // TODO: validation
        public Aes192Key(ReadOnlySpan<byte> key)
        {
            KeyExpansion(key, _expandedKey);
        }

        internal override ReadOnlySpan<int> ExpandedKey => _expandedKey;

        // TODO: validation
        public override void ReKey(ReadOnlySpan<byte> newKey)
        {
            KeyExpansion(newKey, _expandedKey);
        }

        // TODO: Verify whether calculating decryption key expansion after encryption key expansion is faster (locality)
        private void KeyExpansion(ReadOnlySpan<byte> key, Span<int> keySchedule)
        {
            ref var expandedKey = ref MemoryMarshal.GetReference(keySchedule);

            var tmp1 = ReadUnaligned(key);
            var tmp3 = Unsafe.ReadUnaligned<Vector128<int>>(
                ref Unsafe.AddByteOffset(ref MemoryMarshal.GetReference(key),
                    (IntPtr) 16)); // TODO: address out of bounds read!

            // 0 (shared)
            WriteUnalignedOffset(ref expandedKey, 0, tmp1);
            WriteUnalignedOffset(ref expandedKey, 1 * Nb, tmp3);

            // 1, 2 / 23, 22
            Aes192KeyExp(ref tmp1, ref tmp3, 0x01);
            var tmp2 = Shuffle(ReadUnalignedOffset(ref expandedKey, Nb * 1).AsDouble(), tmp1.AsDouble(), 0).AsInt32();
            WriteUnalignedOffset(ref expandedKey, Nb * 1, tmp2);
            WriteUnalignedOffset(ref expandedKey, Nb * 23, InverseMixColumns(tmp2.AsByte()));
            tmp2 = Shuffle(tmp1.AsDouble(), tmp3.AsDouble(), 1).AsInt32();
            WriteUnalignedOffset(ref expandedKey, Nb * 2, tmp2);
            WriteUnalignedOffset(ref expandedKey, Nb * 22, InverseMixColumns(tmp2.AsByte()));

            // 3 / 21
            Aes192KeyExp(ref tmp1, ref tmp3, 0x02);
            WriteUnalignedOffset(ref expandedKey, Nb * 3, tmp1);
            WriteUnalignedOffset(ref expandedKey, Nb * 21, InverseMixColumns(tmp1.AsByte()));
            WriteUnalignedOffset(ref expandedKey, Nb * 4, tmp3);

            // 4, 5 / 20, 19
            Aes192KeyExp(ref tmp1, ref tmp3, 0x04);
            tmp2 = Shuffle(ReadUnalignedOffset(ref expandedKey, Nb * 4).AsDouble(), tmp1.AsDouble(), 0).AsInt32();
            WriteUnalignedOffset(ref expandedKey, Nb * 4, tmp2);
            WriteUnalignedOffset(ref expandedKey, Nb * 20, InverseMixColumns(tmp2.AsByte()));
            tmp2 = Shuffle(tmp1.AsDouble(), tmp3.AsDouble(), 1).AsInt32();
            WriteUnalignedOffset(ref expandedKey, Nb * 5, tmp2);
            WriteUnalignedOffset(ref expandedKey, Nb * 19, InverseMixColumns(tmp2.AsByte()));

            // 6 / 18
            Aes192KeyExp(ref tmp1, ref tmp3, 0x08);
            WriteUnalignedOffset(ref expandedKey, Nb * 6, tmp1);
            WriteUnalignedOffset(ref expandedKey, Nb * 18, InverseMixColumns(tmp1.AsByte()));
            WriteUnalignedOffset(ref expandedKey, Nb * 7, tmp3);

            // 7, 8 / 17, 16
            Aes192KeyExp(ref tmp1, ref tmp3, 0x10);
            tmp2 = Shuffle(ReadUnalignedOffset(ref expandedKey, Nb * 7).AsDouble(), tmp1.AsDouble(), 0).AsInt32();
            WriteUnalignedOffset(ref expandedKey, Nb * 7, tmp2);
            WriteUnalignedOffset(ref expandedKey, Nb * 17, InverseMixColumns(tmp2.AsByte()));
            tmp2 = Shuffle(tmp1.AsDouble(), tmp3.AsDouble(), 1).AsInt32();
            WriteUnalignedOffset(ref expandedKey, Nb * 8, tmp2);
            WriteUnalignedOffset(ref expandedKey, Nb * 16, InverseMixColumns(tmp2.AsByte()));

            // 9 / 15
            Aes192KeyExp(ref tmp1, ref tmp3, 0x20);
            WriteUnalignedOffset(ref expandedKey, Nb * 9, tmp1);
            WriteUnalignedOffset(ref expandedKey, Nb * 15, InverseMixColumns(tmp1.AsByte()));
            WriteUnalignedOffset(ref expandedKey, Nb * 10, tmp3);

            // 10, 11 / 14, 13
            Aes192KeyExp(ref tmp1, ref tmp3, 0x40);
            tmp2 = Shuffle(ReadUnalignedOffset(ref expandedKey, Nb * 10).AsDouble(), tmp1.AsDouble(), 0).AsInt32();
            WriteUnalignedOffset(ref expandedKey, Nb * 10, tmp2);
            WriteUnalignedOffset(ref expandedKey, Nb * 14, InverseMixColumns(tmp2.AsByte()));
            tmp2 = Shuffle(tmp1.AsDouble(), tmp3.AsDouble(), 1).AsInt32();
            WriteUnalignedOffset(ref expandedKey, Nb * 11, tmp2);
            WriteUnalignedOffset(ref expandedKey, Nb * 13, InverseMixColumns(tmp2.AsByte()));

            // 12 (shared)
            Aes192KeyExp(ref tmp1, ref tmp3, 0x80);
            WriteUnalignedOffset(ref expandedKey, Nb * 12, tmp1);
        }

        // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Aes192KeyExp(ref Vector128<int> tmp1, ref Vector128<int> tmp3, byte rcon)
        {
            var tmp2 = KeygenAssist(tmp3.AsByte(), rcon).AsInt32();
            tmp2 = Shuffle(tmp2, 0x55);
            tmp1 = Xor(tmp1, ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Xor(tmp1, ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Xor(tmp1, ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Xor(tmp1, tmp2);
            tmp2 = Shuffle(tmp1, 0xFF);
            tmp3 = Xor(tmp3, ShiftLeftLogical128BitLane(tmp3, 4));
            tmp3 = Xor(tmp3, tmp2);
        }
    }
}