using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static AesNi.Utils;
using static System.Runtime.Intrinsics.X86.Aes;
using static System.Runtime.Intrinsics.X86.Sse2;

namespace AesNi
{
    internal sealed class Aes256Key : AesKey
    {
        private const int NumberOfRoundKeys = 14;

        // Saving some space, as the actual key is stored only once (at [0]) and [10] is shared between enc and dec 
        // inspiration drawn from https://github.com/sebastien-riou/aes-brute-force/blob/master/include/aes_ni.h
        private readonly byte[] _expandedKey = new byte[2 * BytesPerRoundKey * NumberOfRoundKeys];

        // TODO: validation
        public Aes256Key(ReadOnlySpan<byte> key)
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

            var tmp1 = ReadUnaligned(ref keyRef);
            var tmp3 = ReadUnalignedOffset(ref keyRef, (IntPtr) (1 * BytesPerRoundKey));

            WriteUnalignedOffset(ref expandedKey, (IntPtr) (0 * BytesPerRoundKey), tmp1);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (1 * BytesPerRoundKey), tmp3);

            WriteUnalignedOffset(ref expandedKey, (IntPtr) (27 * BytesPerRoundKey), InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x01);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (2 * BytesPerRoundKey), tmp1);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (26 * BytesPerRoundKey), InverseMixColumns(tmp1));

            Aes256KeyExp2(tmp1, ref tmp3);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (3 * BytesPerRoundKey), tmp3);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (25 * BytesPerRoundKey), InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x02);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (4 * BytesPerRoundKey), tmp1);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (24 * BytesPerRoundKey), InverseMixColumns(tmp1));

            Aes256KeyExp2(tmp1, ref tmp3);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (5 * BytesPerRoundKey), tmp3);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (23 * BytesPerRoundKey), InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x04);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (6 * BytesPerRoundKey), tmp1);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (22 * BytesPerRoundKey), InverseMixColumns(tmp1));

            Aes256KeyExp2(tmp1, ref tmp3);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (7 * BytesPerRoundKey), tmp3);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (21 * BytesPerRoundKey), InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x08);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (8 * BytesPerRoundKey), tmp1);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (20 * BytesPerRoundKey), InverseMixColumns(tmp1));

            Aes256KeyExp2(tmp1, ref tmp3);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (9 * BytesPerRoundKey), tmp3);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (19 * BytesPerRoundKey), InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x10);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (10 * BytesPerRoundKey), tmp1);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (18 * BytesPerRoundKey), InverseMixColumns(tmp1));

            Aes256KeyExp2(tmp1, ref tmp3);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (11 * BytesPerRoundKey), tmp3);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (17 * BytesPerRoundKey), InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x20);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (12 * BytesPerRoundKey), tmp1);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (16 * BytesPerRoundKey), InverseMixColumns(tmp1));

            Aes256KeyExp2(tmp1, ref tmp3);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (13 * BytesPerRoundKey), tmp3);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (15 * BytesPerRoundKey), InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x40);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (14 * BytesPerRoundKey), tmp1);
        }

        // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Aes256KeyExp1(ref Vector128<byte> tmp1, Vector128<byte> tmp3, byte rcon)
        {
            var tmp2 = KeygenAssist(tmp3, rcon);
            tmp2 = Shuffle(tmp2.AsInt32(), 0xFF).AsByte();
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
        private static void Aes256KeyExp2(Vector128<byte> tmp1, ref Vector128<byte> tmp3)
        {
            var tmp4 = KeygenAssist(tmp1, 0x00);
            var tmp2 = Shuffle(tmp4.AsInt32(), 0xAA).AsByte();
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