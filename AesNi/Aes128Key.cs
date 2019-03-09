using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static AesNi.Utils;
using static System.Runtime.Intrinsics.X86.Aes;
using static System.Runtime.Intrinsics.X86.Sse2;

namespace AesNi
{
    public sealed class Aes128Key : AesKey
    {
        private const int Nb = 4;
        private const int Nk = 4; // 192->6, 256->8
        private const int Nr = 10; // 192->12, 256->14

        // Saving some space, as the actual key is stored only once (at [0]) and [10] is shared between enc and dec 
        // inspiration drawn from https://github.com/sebastien-riou/aes-brute-force/blob/master/include/aes_ni.h
        private readonly int[] _expandedKey = new int[Nb * (Nr + Nr + 1)];

        // TODO: validation
        public Aes128Key(ReadOnlySpan<byte> key)
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

            var tmp = ReadUnaligned(key);
            WriteUnalignedOffset(ref expandedKey, Nb * 0, tmp);

            tmp = Aes128KeyExp(tmp, 0x01);
            WriteUnalignedOffset(ref expandedKey, Nb * 1, tmp);
            WriteUnalignedOffset(ref expandedKey, Nb * 19, InverseMixColumns(tmp.AsByte()));

            tmp = Aes128KeyExp(tmp, 0x02);
            WriteUnalignedOffset(ref expandedKey, Nb * 2, tmp);
            WriteUnalignedOffset(ref expandedKey, Nb * 18, InverseMixColumns(tmp.AsByte()));

            tmp = Aes128KeyExp(tmp, 0x04);
            WriteUnalignedOffset(ref expandedKey, Nb * 3, tmp);
            WriteUnalignedOffset(ref expandedKey, Nb * 17, InverseMixColumns(tmp.AsByte()));

            tmp = Aes128KeyExp(tmp, 0x08);
            WriteUnalignedOffset(ref expandedKey, Nb * 4, tmp);
            WriteUnalignedOffset(ref expandedKey, Nb * 16, InverseMixColumns(tmp.AsByte()));

            tmp = Aes128KeyExp(tmp, 0x10);
            WriteUnalignedOffset(ref expandedKey, Nb * 5, tmp);
            WriteUnalignedOffset(ref expandedKey, Nb * 15, InverseMixColumns(tmp.AsByte()));

            tmp = Aes128KeyExp(tmp, 0x20);
            WriteUnalignedOffset(ref expandedKey, Nb * 6, tmp);
            WriteUnalignedOffset(ref expandedKey, Nb * 14, InverseMixColumns(tmp.AsByte()));

            tmp = Aes128KeyExp(tmp, 0x40);
            WriteUnalignedOffset(ref expandedKey, Nb * 7, tmp);
            WriteUnalignedOffset(ref expandedKey, Nb * 13, InverseMixColumns(tmp.AsByte()));

            tmp = Aes128KeyExp(tmp, 0x80);
            WriteUnalignedOffset(ref expandedKey, Nb * 8, tmp);
            WriteUnalignedOffset(ref expandedKey, Nb * 12, InverseMixColumns(tmp.AsByte()));

            tmp = Aes128KeyExp(tmp, 0x1B);
            WriteUnalignedOffset(ref expandedKey, Nb * 9, tmp);
            WriteUnalignedOffset(ref expandedKey, Nb * 11, InverseMixColumns(tmp.AsByte()));

            tmp = Aes128KeyExp(tmp, 0x36);
            WriteUnalignedOffset(ref expandedKey, Nb * 10, tmp);
        }

        // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<int> Aes128KeyExp(Vector128<int> key, byte rcon)
        {
            var temp = KeygenAssist(key.AsByte(), rcon).AsInt32();
            temp = Shuffle(temp, 0xFF);
            key = Xor(key, ShiftLeftLogical128BitLane(key, 4));
            key = Xor(key, ShiftLeftLogical128BitLane(key, 4));
            key = Xor(key, ShiftLeftLogical128BitLane(key, 4));
            return Xor(key, temp);
        }

        // Alternative implementation of the key expansion used in linux
        // Below implementation is tested and working, but benched slightly worse than the above
        // See: http://lxr.linux.no/#linux+v3.7.4/arch/x86/crypto/aesni-intel_asm.S#L1707
        // [MethodImpl(MethodImplOptions.AggressiveInlining)]
        // private static Vector128<int> Aes128KeyExp(Vector128<int> xmm0, byte rcon)
        // {
        //     Vector128<int> xmm4 = Vector128<int>.Zero;
        //     Vector128<int> xmm1 = KeygenAssist(xmm0.AsByte(), rcon).AsInt32(); 
        //     
        //     xmm1 = Shuffle(xmm1, 0xFF);
        //     xmm4 = Sse.Shuffle(xmm4.AsSingle(), xmm0.AsSingle(), 0x10).AsInt32();
        //     xmm0 = Xor(xmm0, xmm4);
        //     xmm4 = Sse.Shuffle(xmm4.AsSingle(), xmm0.AsSingle(), 0x8C).AsInt32();
        //     xmm0 = Xor(xmm0, xmm4);
        //     return Xor(xmm0, xmm1);
        // }
    }
}