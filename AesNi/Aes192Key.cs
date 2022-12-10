using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static AesNi.Utils;
using static System.Runtime.Intrinsics.X86.Aes;
using static System.Runtime.Intrinsics.X86.Sse2;

namespace AesNi
{
    internal class Aes192Key : AesKey
    {
        private const int NumberOfRoundKeys = 12;

        // Saving some space, as the actual key is stored only once (at [0]) and [12] is shared between enc and dec 
        // inspiration drawn from https://github.com/sebastien-riou/aes-brute-force/blob/master/include/aes_ni.h
        private readonly byte[] _expandedKey = new byte[2 * BytesPerRoundKey * NumberOfRoundKeys];

        // TODO: validation
        public Aes192Key(ReadOnlySpan<byte> key)
        {
            KeyExpansion(key, _expandedKey);
        }

        internal override ReadOnlySpan<byte> ExpandedKey => _expandedKey;

        // TODO: validation
        public override void ReKey(ReadOnlySpan<byte> newKey)
        {
            KeyExpansion(newKey, _expandedKey);
        }

        // TODO: Verify whether calculating decryption key expansion after encryption key expansion is faster (locality)
        private static void KeyExpansion(ReadOnlySpan<byte> key, Span<byte> keySchedule)
        {
            ref var expandedKey = ref MemoryMarshal.GetReference(keySchedule);
            ref var keyRef = ref MemoryMarshal.GetReference(key);

            // 0 (shared)
            var tmp1 = ReadUnaligned(ref keyRef);
            WriteUnaligned(ref expandedKey, tmp1);
            Unsafe.WriteUnaligned(ref Unsafe.AddByteOffset(ref expandedKey, (IntPtr) 16),
                Unsafe.ReadUnaligned<Vector64<byte>>(ref Unsafe.AddByteOffset(ref keyRef, (IntPtr) 16)));

            var tmp3 = ReadUnalignedOffset(ref expandedKey, 1 * BytesPerRoundKey);

            // 1, 2 / 23, 22
            var tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x01);
            var tmp2 = Shufpd(tmp3, tmp1, 0);
            WriteUnalignedOffset(ref expandedKey, 1 * BytesPerRoundKey, tmp2);
            WriteUnalignedOffset(ref expandedKey, 23 * BytesPerRoundKey, InverseMixColumns(tmp2));
            tmp2 = Shufpd(tmp1, tmp4, 1);
            WriteUnalignedOffset(ref expandedKey, 2 * BytesPerRoundKey, tmp2);
            WriteUnalignedOffset(ref expandedKey, 22 * BytesPerRoundKey, InverseMixColumns(tmp2));

            // 3 / 21
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x02);
            WriteUnalignedOffset(ref expandedKey, 3 * BytesPerRoundKey, tmp1);
            WriteUnalignedOffset(ref expandedKey, 21 * BytesPerRoundKey, InverseMixColumns(tmp1));
            WriteUnalignedOffset(ref expandedKey, 4 * BytesPerRoundKey, tmp3);

            // 4, 5 / 20, 19
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x04);
            tmp2 = Shufpd(tmp3, tmp1, 0);
            WriteUnalignedOffset(ref expandedKey, 4 * BytesPerRoundKey, tmp2);
            WriteUnalignedOffset(ref expandedKey, 20 * BytesPerRoundKey, InverseMixColumns(tmp2));
            tmp2 = Shufpd(tmp1, tmp4, 1);
            WriteUnalignedOffset(ref expandedKey, 5 * BytesPerRoundKey, tmp2);
            WriteUnalignedOffset(ref expandedKey, 19 * BytesPerRoundKey, InverseMixColumns(tmp2));

            // 6 / 18
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x08);
            WriteUnalignedOffset(ref expandedKey, 6 * BytesPerRoundKey, tmp1);
            WriteUnalignedOffset(ref expandedKey, 18 * BytesPerRoundKey, InverseMixColumns(tmp1));
            WriteUnalignedOffset(ref expandedKey, 7 * BytesPerRoundKey, tmp3);

            // 7, 8 / 17, 16
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x10);
            tmp2 = Shufpd(tmp3, tmp1, 0);
            WriteUnalignedOffset(ref expandedKey, 7 * BytesPerRoundKey, tmp2);
            WriteUnalignedOffset(ref expandedKey, 17 * BytesPerRoundKey, InverseMixColumns(tmp2));
            tmp2 = Shufpd(tmp1, tmp4, 1);
            WriteUnalignedOffset(ref expandedKey, 8 * BytesPerRoundKey, tmp2);
            WriteUnalignedOffset(ref expandedKey, 16 * BytesPerRoundKey, InverseMixColumns(tmp2));

            // 9 / 15
            tmp3 = Aes192KeyExp(ref tmp1, tmp4, 0x20);
            WriteUnalignedOffset(ref expandedKey, 9 * BytesPerRoundKey, tmp1);
            WriteUnalignedOffset(ref expandedKey, 15 * BytesPerRoundKey, InverseMixColumns(tmp1));
            WriteUnalignedOffset(ref expandedKey, 10 * BytesPerRoundKey, tmp3);

            // 10, 11 / 14, 13
            tmp4 = Aes192KeyExp(ref tmp1, tmp3, 0x40);
            tmp2 = Shufpd(tmp3, tmp1, 0);
            WriteUnalignedOffset(ref expandedKey, 10 * BytesPerRoundKey, tmp2);
            WriteUnalignedOffset(ref expandedKey, 14 * BytesPerRoundKey, InverseMixColumns(tmp2));
            tmp2 = Shufpd(tmp1, tmp4, 1);
            WriteUnalignedOffset(ref expandedKey, 11 * BytesPerRoundKey, tmp2);
            WriteUnalignedOffset(ref expandedKey, 13 * BytesPerRoundKey, InverseMixColumns(tmp2));

            // 12 (shared)
            Aes192KeyExp(ref tmp1, tmp4, 0x80);
            WriteUnalignedOffset(ref expandedKey, 12 * BytesPerRoundKey, tmp1);
        }

        // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Aes192KeyExp(ref Vector128<byte> tmp1, Vector128<byte> tmp3, byte rcon)
        {
            var tmp2 = KeygenAssist(tmp3, rcon);
            tmp2 = Shuffle(tmp2.AsInt32(), 0x55).AsByte();
            tmp1 = Xor(tmp1, ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Xor(tmp1, ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Xor(tmp1, ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Xor(tmp1, tmp2);
            tmp2 = Shuffle(tmp1.AsInt32(), 0xFF).AsByte();
            var tmp4 = Xor(tmp3, ShiftLeftLogical128BitLane(tmp3, 4));
            return Xor(tmp4, tmp2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Shufpd(Vector128<byte> left, Vector128<byte> right, byte control) 
            => Shuffle(left.AsDouble(), right.AsDouble(), control).AsByte();
    }
}