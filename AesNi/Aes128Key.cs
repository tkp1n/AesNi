using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static AesNi.Utils;
using static System.Runtime.Intrinsics.X86.Aes;
using static System.Runtime.Intrinsics.X86.Sse2;

namespace AesNi
{
    internal sealed class Aes128Key : AesKey
    {
        private const int NumberOfRoundKeys = 10;

        // Saving some space, as the actual key is stored only once (at [0]) and [10] is shared between enc and dec 
        // inspiration drawn from https://github.com/sebastien-riou/aes-brute-force/blob/master/include/aes_ni.h
        private readonly byte[] _expandedKey = new byte[2 * BytesPerRoundKey * NumberOfRoundKeys];

        // TODO: validation
        public Aes128Key(ReadOnlySpan<byte> key)
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

            var tmp = ReadUnaligned(ref keyRef);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (0 * BytesPerRoundKey), tmp);

            tmp = Aes128KeyExp(tmp, 0x01);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (1 * BytesPerRoundKey), tmp);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (19 * BytesPerRoundKey), InverseMixColumns(tmp));

            tmp = Aes128KeyExp(tmp, 0x02);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (2 * BytesPerRoundKey), tmp);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (18 * BytesPerRoundKey), InverseMixColumns(tmp));

            tmp = Aes128KeyExp(tmp, 0x04);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (3 * BytesPerRoundKey), tmp);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (17 * BytesPerRoundKey), InverseMixColumns(tmp));

            tmp = Aes128KeyExp(tmp, 0x08);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (4 * BytesPerRoundKey), tmp);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (16 * BytesPerRoundKey), InverseMixColumns(tmp));

            tmp = Aes128KeyExp(tmp, 0x10);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (5 * BytesPerRoundKey), tmp);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (15 * BytesPerRoundKey), InverseMixColumns(tmp));

            tmp = Aes128KeyExp(tmp, 0x20);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (6 * BytesPerRoundKey), tmp);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (14 * BytesPerRoundKey), InverseMixColumns(tmp));

            tmp = Aes128KeyExp(tmp, 0x40);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (7 * BytesPerRoundKey), tmp);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (13 * BytesPerRoundKey), InverseMixColumns(tmp));

            tmp = Aes128KeyExp(tmp, 0x80);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (8 * BytesPerRoundKey), tmp);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (12 * BytesPerRoundKey), InverseMixColumns(tmp));

            tmp = Aes128KeyExp(tmp, 0x1B);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (9 * BytesPerRoundKey), tmp);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (11 * BytesPerRoundKey), InverseMixColumns(tmp));

            tmp = Aes128KeyExp(tmp, 0x36);
            WriteUnalignedOffset(ref expandedKey, (IntPtr) (10 * BytesPerRoundKey), tmp);
        }

        // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Aes128KeyExp(Vector128<byte> key, byte rcon)
        {
            var temp = KeygenAssist(key, rcon);
            temp = Shuffle(temp.AsInt32(), 0xFF).AsByte();
            key = Xor(key, ShiftLeftLogical128BitLane(key, 4));
            key = Xor(key, ShiftLeftLogical128BitLane(key, 4));
            key = Xor(key, ShiftLeftLogical128BitLane(key, 4));
            return Xor(key, temp);
        }

        // Alternative implementation of the key expansion used in linux
        // Below implementation is tested and working, but benched slightly worse than the above
        // See: http://lxr.linux.no/#linux+v3.7.4/arch/x86/crypto/aesni-intel_asm.S#L1707
        // [MethodImpl(MethodImplOptions.AggressiveInlining)]
        // private static Vector128<byte> Aes128KeyExp(Vector128<byte> xmm0, byte rcon)
        // {
        //     Vector128<byte> xmm4 = Vector128<byte>.Zero;
        //     Vector128<byte> xmm1 = KeygenAssist(xmm0, rcon); 
        //     
        //     xmm1 = Shuffle(xmm1.AsInt32(), 0xFF).AsByte();
        //     xmm4 = System.Runtime.Intrinsics.X86.Sse.Shuffle(xmm4.AsSingle(), xmm0.AsSingle(), 0x10).AsByte();
        //     xmm0 = Xor(xmm0, xmm4);
        //     xmm4 = System.Runtime.Intrinsics.X86.Sse.Shuffle(xmm4.AsSingle(), xmm0.AsSingle(), 0x8C).AsByte();
        //     xmm0 = Xor(xmm0, xmm4);
        //     return Xor(xmm0, xmm1);
        // }
    }
}