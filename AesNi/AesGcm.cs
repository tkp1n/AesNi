using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static AesNi.Utils;
using static System.Runtime.Intrinsics.X86.Sse2;
using static System.Runtime.Intrinsics.X86.Aes;
using static System.Runtime.Intrinsics.X86.Sse41;
using static System.Runtime.Intrinsics.X86.Sse41.X64;
using static System.Runtime.Intrinsics.X86.Ssse3;

namespace AesNi
{
    public static class AesGcm
    {
        private const int Kn = 4;
        private const int BlockSize = 16;

        private static readonly Vector128<byte> One = Vector128.Create(0, 0, 1, 0).AsByte();
        private static readonly Vector128<byte> Four = Vector128.Create(0, 0, 4, 0).AsByte();
        private static readonly Vector128<byte> BswapEpi64
            = Vector128.Create((byte)7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
        private static readonly Vector128<byte> BswapMask 
            = Vector128.Create((byte)15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

        public static void EncryptGcm(
            ReadOnlySpan<byte> input,
            Span<byte> output,
            ReadOnlySpan<byte> addt,
            ReadOnlySpan<byte> iv,
            Span<byte> tag,
            Aes128Key key)
        {
            int left, position = 0;
            Vector128<byte> tmp1, tmp2, tmp3, tmp4;
            Vector128<byte> h, h2, h3, h4, t;
            Vector128<byte> ctr1, ctr2, ctr3, ctr4;
            Vector128<byte> one = One;
            Vector128<byte> four = Four;
            Vector128<byte> bswapEpi64 = BswapEpi64;
            Vector128<byte> bswapMask = BswapMask;
            Vector128<byte> x = Vector128<byte>.Zero;
            Vector128<byte> y = Vector128<byte>.Zero;
            Span<byte> lastBlock = stackalloc byte[BlockSize];

            ref var expandedKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref var ivRef = ref MemoryMarshal.GetReference(iv);
            ref var inputRef = ref MemoryMarshal.GetReference(input);
            ref var outputRef = ref MemoryMarshal.GetReference(output);
            ref var addtRef = ref MemoryMarshal.GetReference(addt);
            ref var lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);
            ref var tagRef = ref MemoryMarshal.GetReference(tag);

            var key0 = ReadUnalignedOffset(ref expandedKey, Kn * 0);
            var key1 = ReadUnalignedOffset(ref expandedKey, Kn * 1);
            var key2 = ReadUnalignedOffset(ref expandedKey, Kn * 2);
            var key3 = ReadUnalignedOffset(ref expandedKey, Kn * 3);
            var key4 = ReadUnalignedOffset(ref expandedKey, Kn * 4);
            var key5 = ReadUnalignedOffset(ref expandedKey, Kn * 5);
            var key6 = ReadUnalignedOffset(ref expandedKey, Kn * 6);
            var key7 = ReadUnalignedOffset(ref expandedKey, Kn * 7);
            var key8 = ReadUnalignedOffset(ref expandedKey, Kn * 8);
            var key9 = ReadUnalignedOffset(ref expandedKey, Kn * 9);
            var key10 = ReadUnalignedOffset(ref expandedKey, Kn * 10);

            if (iv.Length == 96 / 8)
            {
                y = ReadUnaligned(ref ivRef);
                y = Insert(y.AsUInt32(), 0x1000000, 3).AsByte();

                tmp1 = Xor(x, key0);
                tmp2 = Xor(y, key0);

                tmp1 = Encrypt(tmp1, key1);
                tmp2 = Encrypt(tmp2, key1);

                tmp1 = Encrypt(tmp1, key2);
                tmp2 = Encrypt(tmp2, key2);

                tmp1 = Encrypt(tmp1, key3);
                tmp2 = Encrypt(tmp2, key3);

                tmp1 = Encrypt(tmp1, key4);
                tmp2 = Encrypt(tmp2, key4);

                tmp1 = Encrypt(tmp1, key5);
                tmp2 = Encrypt(tmp2, key5);

                tmp1 = Encrypt(tmp1, key6);
                tmp2 = Encrypt(tmp2, key6);

                tmp1 = Encrypt(tmp1, key7);
                tmp2 = Encrypt(tmp2, key7);

                tmp1 = Encrypt(tmp1, key8);
                tmp2 = Encrypt(tmp2, key8);

                tmp1 = Encrypt(tmp1, key9);
                tmp2 = Encrypt(tmp2, key9);

                h = EncryptLast(tmp1, key10);
                t = EncryptLast(tmp2, key10);

                h = Shuffle(h, bswapMask);
            }
            else
            {
                tmp1 = Xor(x, key0);
                tmp1 = Encrypt(tmp1, key1);
                tmp1 = Encrypt(tmp1, key2);
                tmp1 = Encrypt(tmp1, key3);
                tmp1 = Encrypt(tmp1, key4);
                tmp1 = Encrypt(tmp1, key5);
                tmp1 = Encrypt(tmp1, key6);
                tmp1 = Encrypt(tmp1, key7);
                tmp1 = Encrypt(tmp1, key8);
                tmp1 = Encrypt(tmp1, key9);
                h = EncryptLast(tmp1, key10);
                h = Shuffle(h, bswapMask);

                left = iv.Length;
                while (left >= BlockSize)
                {
                    tmp1 = ReadUnalignedOffset(ref ivRef, position);
                    tmp1 = Shuffle(tmp1, bswapMask);
                    y = Xor(y, tmp1);
                    y = Ghash.Gfmul(y, h);

                    position += BlockSize;
                    left -= BlockSize;
                }

                if (left > 0)
                {
                    lastBlock.Clear();
                    iv.Slice(position).CopyTo(lastBlock);
                    tmp1 = ReadUnaligned(ref lastBlockRef);
                    tmp1 = Shuffle(tmp1, bswapMask);
                    y = Xor(y, tmp1);
                    y = Ghash.Gfmul(y, h);
                }

                tmp1 = Insert(tmp1.AsInt64(), iv.Length * 8, 0).AsByte();
                tmp1 = Insert(tmp1.AsInt64(), 0, 1).AsByte();

                y = Xor(y, tmp1);
                y = Ghash.Gfmul(y, h);
                y = Shuffle(y, bswapMask);

                /*Compute E(K, Y0)*/
                tmp1 = Xor(y, key0);
                tmp1 = Encrypt(tmp1, key1);
                tmp1 = Encrypt(tmp1, key2);
                tmp1 = Encrypt(tmp1, key3);
                tmp1 = Encrypt(tmp1, key4);
                tmp1 = Encrypt(tmp1, key5);
                tmp1 = Encrypt(tmp1, key6);
                tmp1 = Encrypt(tmp1, key7);
                tmp1 = Encrypt(tmp1, key8);
                tmp1 = Encrypt(tmp1, key9);
                t = EncryptLast(tmp1, key10);

                position = 0;
                lastBlock.Clear();
            }

            h2 = Ghash.Gfmul(h, h);
            h3 = Ghash.Gfmul(h, h2);
            h4 = Ghash.Gfmul(h, h3);

            left = addt.Length;
            while (left >= BlockSize * 4)
            {
                tmp1 = ReadUnalignedOffset(ref addtRef, position + 0 * BlockSize);
                tmp2 = ReadUnalignedOffset(ref addtRef, position + 1 * BlockSize);
                tmp3 = ReadUnalignedOffset(ref addtRef, position + 2 * BlockSize);
                tmp4 = ReadUnalignedOffset(ref addtRef, position + 3 * BlockSize);

                tmp1 = Shuffle(tmp1, bswapMask);
                tmp2 = Shuffle(tmp2, bswapMask);
                tmp3 = Shuffle(tmp3, bswapMask);
                tmp4 = Shuffle(tmp4, bswapMask);

                tmp1 = Xor(x, tmp1);

                x = Ghash.Reduce4(h, h2, h3, h4, tmp4, tmp3, tmp2, tmp1);

                position += BlockSize * 4;
                left -= BlockSize * 4;
            }

            while (left >= BlockSize)
            {
                tmp1 = ReadUnalignedOffset(ref addtRef, position);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul(x, h);

                position += BlockSize;
                left -= BlockSize;
            }

            if (left > 0)
            {
                addt.Slice(position).CopyTo(lastBlock);
                tmp1 = ReadUnaligned(ref lastBlockRef);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul(x, h);
            }

            ctr1 = Shuffle(y, bswapEpi64);
            ctr1 = Add(ctr1, one);
            ctr2 = Add(ctr1, one);
            ctr3 = Add(ctr2, one);
            ctr4 = Add(ctr3, one);

            position = 0;
            left = input.Length;

            while (left >= BlockSize * 4)
            {
                tmp1 = Shuffle(ctr1, bswapEpi64);
                tmp2 = Shuffle(ctr2, bswapEpi64);
                tmp3 = Shuffle(ctr3, bswapEpi64);
                tmp4 = Shuffle(ctr4, bswapEpi64);

                ctr1 = Add(ctr1, four);
                ctr2 = Add(ctr2, four);
                ctr3 = Add(ctr3, four);
                ctr4 = Add(ctr4, four);

                tmp1 = Xor(tmp1, key0);
                tmp2 = Xor(tmp2, key0);
                tmp3 = Xor(tmp3, key0);
                tmp4 = Xor(tmp4, key0);

                tmp1 = Encrypt(tmp1, key1);
                tmp2 = Encrypt(tmp2, key1);
                tmp3 = Encrypt(tmp3, key1);
                tmp4 = Encrypt(tmp4, key1);

                tmp1 = Encrypt(tmp1, key2);
                tmp2 = Encrypt(tmp2, key2);
                tmp3 = Encrypt(tmp3, key2);
                tmp4 = Encrypt(tmp4, key2);

                tmp1 = Encrypt(tmp1, key3);
                tmp2 = Encrypt(tmp2, key3);
                tmp3 = Encrypt(tmp3, key3);
                tmp4 = Encrypt(tmp4, key3);

                tmp1 = Encrypt(tmp1, key4);
                tmp2 = Encrypt(tmp2, key4);
                tmp3 = Encrypt(tmp3, key4);
                tmp4 = Encrypt(tmp4, key4);

                tmp1 = Encrypt(tmp1, key5);
                tmp2 = Encrypt(tmp2, key5);
                tmp3 = Encrypt(tmp3, key5);
                tmp4 = Encrypt(tmp4, key5);

                tmp1 = Encrypt(tmp1, key6);
                tmp2 = Encrypt(tmp2, key6);
                tmp3 = Encrypt(tmp3, key6);
                tmp4 = Encrypt(tmp4, key6);

                tmp1 = Encrypt(tmp1, key7);
                tmp2 = Encrypt(tmp2, key7);
                tmp3 = Encrypt(tmp3, key7);
                tmp4 = Encrypt(tmp4, key7);

                tmp1 = Encrypt(tmp1, key8);
                tmp2 = Encrypt(tmp2, key8);
                tmp3 = Encrypt(tmp3, key8);
                tmp4 = Encrypt(tmp4, key8);

                tmp1 = Encrypt(tmp1, key9);
                tmp2 = Encrypt(tmp2, key9);
                tmp3 = Encrypt(tmp3, key9);
                tmp4 = Encrypt(tmp4, key9);

                tmp1 = EncryptLast(tmp1, key10);
                tmp2 = EncryptLast(tmp2, key10);
                tmp3 = EncryptLast(tmp3, key10);
                tmp4 = EncryptLast(tmp4, key10);

                tmp1 = Xor(tmp1, ReadUnalignedOffset(ref inputRef, position + 0 * BlockSize));
                tmp2 = Xor(tmp2, ReadUnalignedOffset(ref inputRef, position + 1 * BlockSize));
                tmp3 = Xor(tmp3, ReadUnalignedOffset(ref inputRef, position + 2 * BlockSize));
                tmp4 = Xor(tmp4, ReadUnalignedOffset(ref inputRef, position + 3 * BlockSize));

                WriteUnalignedOffset(ref outputRef, position + 0 * BlockSize, tmp1);
                WriteUnalignedOffset(ref outputRef, position + 1 * BlockSize, tmp2);
                WriteUnalignedOffset(ref outputRef, position + 2 * BlockSize, tmp3);
                WriteUnalignedOffset(ref outputRef, position + 3 * BlockSize, tmp4);

                tmp1 = Shuffle(tmp1, bswapMask);
                tmp2 = Shuffle(tmp2, bswapMask);
                tmp3 = Shuffle(tmp3, bswapMask);
                tmp4 = Shuffle(tmp4, bswapMask);

                tmp1 = Xor(x, tmp1);

                x = Ghash.Reduce4(h, h2, h3, h4, tmp4, tmp3, tmp2, tmp1);

                position += BlockSize * 4;
                left -= BlockSize * 4;
            }

            while (left >= BlockSize)
            {
                tmp1 = Shuffle(ctr1, bswapEpi64);
                ctr1 = Add(ctr1, one);
                tmp1 = Xor(tmp1, key0);
                tmp1 = Encrypt(tmp1, key1);
                tmp1 = Encrypt(tmp1, key2);
                tmp1 = Encrypt(tmp1, key3);
                tmp1 = Encrypt(tmp1, key4);
                tmp1 = Encrypt(tmp1, key5);
                tmp1 = Encrypt(tmp1, key6);
                tmp1 = Encrypt(tmp1, key7);
                tmp1 = Encrypt(tmp1, key8);
                tmp1 = Encrypt(tmp1, key9);
                tmp1 = EncryptLast(tmp1, key10);

                tmp1 = Xor(tmp1, ReadUnalignedOffset(ref inputRef, position));
                WriteUnalignedOffset(ref outputRef, position, tmp1);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul(x, h);

                position += BlockSize;
                left -= BlockSize;
            }

            if (left > 0)
            {
                tmp1 = Shuffle(ctr1, bswapEpi64);
                tmp1 = Xor(tmp1, key0);
                tmp1 = Encrypt(tmp1, key1);
                tmp1 = Encrypt(tmp1, key2);
                tmp1 = Encrypt(tmp1, key3);
                tmp1 = Encrypt(tmp1, key4);
                tmp1 = Encrypt(tmp1, key5);
                tmp1 = Encrypt(tmp1, key6);
                tmp1 = Encrypt(tmp1, key7);
                tmp1 = Encrypt(tmp1, key8);
                tmp1 = Encrypt(tmp1, key9);
                tmp1 = EncryptLast(tmp1, key10);
                
                tmp1 = Xor(tmp1,  ReadUnalignedOffset(ref inputRef, position));
                WriteUnalignedOffset(ref lastBlockRef, 0, tmp1);
                int u;
                for (u = 0; u < input.Length % 16; u++)
                {
                    output[position + u] = lastBlock[u];
                }
                for (; u < 16; u++)
                {
                    lastBlock[u] = 0;
                }
                tmp1 = ReadUnaligned(ref lastBlockRef);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul(x, h);
            }
            
            tmp1 = Insert(tmp1.AsUInt64(), (ulong)input.Length * 8, 0).AsByte();
            tmp1 = Insert(tmp1.AsUInt64(), (ulong)addt.Length * 8, 1).AsByte();
            
            x = Xor(x, tmp1);
            x = Ghash.Gfmul(x, h);
            x = Shuffle(x, bswapMask);
            t = Xor(x, t);
            WriteUnaligned(ref tagRef, t);
        }
    }
}