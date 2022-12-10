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
            var tmp3 = ReadUnalignedOffset(ref keyRef, 1 * BytesPerRoundKey);

            WriteUnalignedOffset(ref expandedKey, 0 * BytesPerRoundKey, tmp1);
            WriteUnalignedOffset(ref expandedKey, 1 * BytesPerRoundKey, tmp3);

            WriteUnalignedOffset(ref expandedKey, 27 * BytesPerRoundKey, InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x01);
            WriteUnalignedOffset(ref expandedKey, 2 * BytesPerRoundKey, tmp1);
            WriteUnalignedOffset(ref expandedKey, 26 * BytesPerRoundKey, InverseMixColumns(tmp1));

            Aes256KeyExp2(ref tmp3, tmp1);
            WriteUnalignedOffset(ref expandedKey, 3 * BytesPerRoundKey, tmp3);
            WriteUnalignedOffset(ref expandedKey, 25 * BytesPerRoundKey, InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x02);
            WriteUnalignedOffset(ref expandedKey, 4 * BytesPerRoundKey, tmp1);
            WriteUnalignedOffset(ref expandedKey, 24 * BytesPerRoundKey, InverseMixColumns(tmp1));

            Aes256KeyExp2(ref tmp3, tmp1);
            WriteUnalignedOffset(ref expandedKey, 5 * BytesPerRoundKey, tmp3);
            WriteUnalignedOffset(ref expandedKey, 23 * BytesPerRoundKey, InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x04);
            WriteUnalignedOffset(ref expandedKey, 6 * BytesPerRoundKey, tmp1);
            WriteUnalignedOffset(ref expandedKey, 22 * BytesPerRoundKey, InverseMixColumns(tmp1));

            Aes256KeyExp2(ref tmp3, tmp1);
            WriteUnalignedOffset(ref expandedKey, 7 * BytesPerRoundKey, tmp3);
            WriteUnalignedOffset(ref expandedKey, 21 * BytesPerRoundKey, InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x08);
            WriteUnalignedOffset(ref expandedKey, 8 * BytesPerRoundKey, tmp1);
            WriteUnalignedOffset(ref expandedKey, 20 * BytesPerRoundKey, InverseMixColumns(tmp1));

            Aes256KeyExp2(ref tmp3, tmp1);
            WriteUnalignedOffset(ref expandedKey, 9 * BytesPerRoundKey, tmp3);
            WriteUnalignedOffset(ref expandedKey, 19 * BytesPerRoundKey, InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x10);
            WriteUnalignedOffset(ref expandedKey, 10 * BytesPerRoundKey, tmp1);
            WriteUnalignedOffset(ref expandedKey, 18 * BytesPerRoundKey, InverseMixColumns(tmp1));

            Aes256KeyExp2(ref tmp3, tmp1);
            WriteUnalignedOffset(ref expandedKey, 11 * BytesPerRoundKey, tmp3);
            WriteUnalignedOffset(ref expandedKey, 17 * BytesPerRoundKey, InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x20);
            WriteUnalignedOffset(ref expandedKey, 12 * BytesPerRoundKey, tmp1);
            WriteUnalignedOffset(ref expandedKey, 16 * BytesPerRoundKey, InverseMixColumns(tmp1));

            Aes256KeyExp2(ref tmp3, tmp1);
            WriteUnalignedOffset(ref expandedKey, 13 * BytesPerRoundKey, tmp3);
            WriteUnalignedOffset(ref expandedKey, 15 * BytesPerRoundKey, InverseMixColumns(tmp3));

            Aes256KeyExp1(ref tmp1, tmp3, 0x40);
            WriteUnalignedOffset(ref expandedKey, 14 * BytesPerRoundKey, tmp1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Aes256KeyExp1(ref Vector128<byte> key, Vector128<byte> input, byte rcon)
        {
            var temp = KeygenAssist(input, rcon);
            temp = Shuffle(temp.AsInt32(), 0xFF).AsByte();
            key = Xor(key, ShiftLeftLogical128BitLane(key, 8));
            key = Xor(key, ShiftLeftLogical128BitLane(key, 4));
            key = Xor(key, temp);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Aes256KeyExp2(ref Vector128<byte> key, Vector128<byte> input)
        {
            var temp = KeygenAssist(input, 0x00);
            temp = Shuffle(temp.AsInt32(), 0xAA).AsByte();
            key = Xor(key, ShiftLeftLogical128BitLane(key, 8));
            key = Xor(key, ShiftLeftLogical128BitLane(key, 4));
            key = Xor(key, temp);
        }
    }
}