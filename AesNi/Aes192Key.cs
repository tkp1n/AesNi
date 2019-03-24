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
        private readonly int[] _expandedKey = new int[2 * IntsPerRoundKey * NumberOfRoundKeys];

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
            ref var expandedKey = ref Unsafe.As<int, byte>(ref MemoryMarshal.GetReference(keySchedule));
            ref var keyRef = ref MemoryMarshal.GetReference(key);
            
            // 0 (shared)
            Unsafe.CopyBlock(
                ref expandedKey, 
                ref keyRef,
                192 / 8);

            var tmp1 = ReadUnaligned(ref expandedKey);
            var tmp3 = ReadUnalignedOffset(ref expandedKey, 1 * BytesPerRoundKey);

            // 1, 2 / 23, 22
            Aes192KeyExp(ref tmp1, ref tmp3, 0x01);
            var tmp2 = Shufpd(ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 1), tmp1, 0);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 1, tmp2);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 23, InverseMixColumns(tmp2));
            tmp2 = Shufpd(tmp1, tmp3, 1);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 2, tmp2);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 22, InverseMixColumns(tmp2));

            // 3 / 21
            Aes192KeyExp(ref tmp1, ref tmp3, 0x02);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 3, tmp1);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 21, InverseMixColumns(tmp1));
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 4, tmp3);

            // 4, 5 / 20, 19
            Aes192KeyExp(ref tmp1, ref tmp3, 0x04);
            tmp2 = Shufpd(ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 4), tmp1, 0);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 4, tmp2);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 20, InverseMixColumns(tmp2));
            tmp2 = Shufpd(tmp1, tmp3, 1);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 5, tmp2);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 19, InverseMixColumns(tmp2));

            // 6 / 18
            Aes192KeyExp(ref tmp1, ref tmp3, 0x08);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 6, tmp1);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 18, InverseMixColumns(tmp1.AsByte()));
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 7, tmp3);

            // 7, 8 / 17, 16
            Aes192KeyExp(ref tmp1, ref tmp3, 0x10);
            tmp2 = Shufpd(ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 7), tmp1, 0);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 7, tmp2);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 17, InverseMixColumns(tmp2));
            tmp2 = Shufpd(tmp1, tmp3, 1);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 8, tmp2);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 16, InverseMixColumns(tmp2));

            // 9 / 15
            Aes192KeyExp(ref tmp1, ref tmp3, 0x20);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 9, tmp1);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 15, InverseMixColumns(tmp1));
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 10, tmp3);

            // 10, 11 / 14, 13
            Aes192KeyExp(ref tmp1, ref tmp3, 0x40);
            tmp2 = Shufpd(ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 10), tmp1, 0);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 10, tmp2);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 14, InverseMixColumns(tmp2));
            tmp2 = Shufpd(tmp1, tmp3, 1);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 11, tmp2);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 13, InverseMixColumns(tmp2));

            // 12 (shared)
            Aes192KeyExp(ref tmp1, ref tmp3, 0x80);
            WriteUnalignedOffset(ref expandedKey, BytesPerRoundKey * 12, tmp1);
        }
        
        // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Aes192KeyExp(ref Vector128<byte> tmp1, ref Vector128<byte> tmp3, byte rcon)
        {
            var tmp2 = KeygenAssist(tmp3, rcon);
            tmp2 = Shuffle(tmp2.AsInt32(), 0x55).AsByte();
            tmp1 = Xor(tmp1, ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Xor(tmp1, ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Xor(tmp1, ShiftLeftLogical128BitLane(tmp1, 4));
            tmp1 = Xor(tmp1, tmp2);
            tmp2 = Shuffle(tmp1.AsInt32(), 0xFF).AsByte();
            tmp3 = Xor(tmp3, ShiftLeftLogical128BitLane(tmp3, 4));
            tmp3 = Xor(tmp3, tmp2);
        }

        private static Vector128<byte> Shufpd(Vector128<byte> left, Vector128<byte> right, byte control)
            => Shuffle(left.AsDouble(), right.AsDouble(), control).AsByte();
    }
}