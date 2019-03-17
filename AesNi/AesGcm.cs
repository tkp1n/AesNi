using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static AesNi.Utils;
using static System.Runtime.Intrinsics.X86.Sse2;
using static System.Runtime.Intrinsics.X86.Aes;
using static System.Runtime.Intrinsics.X86.Sse41;
using static System.Runtime.Intrinsics.X86.Ssse3;

namespace AesNi
{
    public static class AesGcm
    {
        private const int Kn = 4;
        private const int BlockSize = 16;

        private static readonly Vector128<byte> One = Vector128.Create(0, 1, 0, 0).AsByte();
        private static readonly Vector128<byte> Four = Vector128.Create(0, 4, 0, 0).AsByte();
        private static readonly Vector128<byte> BswapEpi64
            = Vector128.Create(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7).AsByte();
        private static readonly Vector128<byte> BswapMask 
            = Vector128.Create(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15).AsByte();

        public static void EncryptGcm(
            ReadOnlySpan<byte> input,
            Span<byte> output,
            ReadOnlySpan<byte> addt,
            ReadOnlySpan<byte> iv,
            Span<byte> tag,
            Aes128Key key)
        {
            int i, j, k;
            Vector128<byte> tmp1, tmp2, tmp3, tmp4;
            Vector128<byte> h, h2, h3, h4, y, t;
            Vector128<byte> ctr1, ctr2, ctr3, ctr4;
            Vector128<byte> one = One;
            Vector128<byte> four = Four;
            Vector128<byte> bswapEpi64 = BswapEpi64;
            Vector128<byte> bswapMask = BswapMask;
            Vector128<byte> x = Vector128<byte>.Zero;
            Span<byte> lastBlock = stackalloc byte[BlockSize];

            ref var expandedKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref var ivRef = ref MemoryMarshal.GetReference(iv);
            ref var inputRef = ref MemoryMarshal.GetReference(input);
            ref var outputRef = ref MemoryMarshal.GetReference(output);
            ref var addtRef = ref MemoryMarshal.GetReference(addt);
            ref var lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);

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
                y = Vector128<byte>.Zero;

                for (i = 0; i < iv.Length / 16; i++)
                {
                    tmp1 = ReadUnalignedOffset(ref ivRef, i * Kn);
                    tmp1 = Shuffle(tmp1, bswapMask);
                    y = Xor(y, tmp1);
                    y = Ghash.Gfmul15(y.AsUInt64(), h.AsUInt64()).AsByte();
                }

                if (iv.Length % 16 != 0)
                {
                    for (j = 0; j < iv.Length % 16; j++)
                    {
                        lastBlock[j] = iv[i * 16 + j];
                    }

                    tmp1 = ReadUnaligned(ref lastBlockRef);
                    tmp1 = Shuffle(tmp1, bswapMask);
                    y = Xor(y, tmp1);
                    y = Ghash.Gfmul15(y.AsUInt64(), h.AsUInt64()).AsByte();
                }

                tmp1 = Insert(tmp1.AsUInt32(), (uint)iv.Length * 8, 0).AsByte();
                tmp1 = Insert(tmp1, 0, 1);

                y = Xor(y, tmp1);
                y = Ghash.Gfmul15(y.AsUInt64(), h.AsUInt64()).AsByte();
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
            }

            h2 = Ghash.Gfmul15(h.AsUInt64(), h.AsUInt64()).AsByte();
            h3 = Ghash.Gfmul15(h.AsUInt64(), h2.AsUInt64()).AsByte();
            h4 = Ghash.Gfmul15(h.AsUInt64(), h3.AsUInt64()).AsByte();

            for (i = 0; i < addt.Length / 16 / 4; i++)
            {
                tmp1 = ReadUnalignedOffset(ref addtRef, Kn * i + 0);
                tmp2 = ReadUnalignedOffset(ref addtRef, Kn * i + 1);
                tmp3 = ReadUnalignedOffset(ref addtRef, Kn * i + 2);
                tmp4 = ReadUnalignedOffset(ref addtRef, Kn * i + 3);

                tmp1 = Shuffle(tmp1, bswapMask);
                tmp2 = Shuffle(tmp2, bswapMask);
                tmp3 = Shuffle(tmp3, bswapMask);
                tmp4 = Shuffle(tmp4, bswapMask);

                tmp1 = Xor(x, tmp1);

                x = Ghash.Reduce4(h.AsUInt64(), h2.AsUInt64(), h3.AsUInt64(), h4.AsUInt64(),
                    tmp4.AsUInt64(), tmp3.AsUInt64(), tmp2.AsUInt64(), tmp1.AsUInt64()).AsByte();
            }

            for (i = i * Kn; i < addt.Length / 16; i++)
            {
                tmp1 = ReadUnalignedOffset(ref addtRef,i * Kn);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul15(x.AsUInt64(), h.AsUInt64()).AsByte();
            }

            if (addt.Length % 16 != 0)
            {
                lastBlock.Clear();
                for (j = 0; j < addt.Length % 16; j++)
                {
                    lastBlock[j] = addt[i * 16 + j];
                }

                tmp1 = ReadUnaligned(ref lastBlockRef);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul15(x.AsUInt64(), h.AsUInt64()).AsByte();
            }

            ctr1 = Shuffle(y, bswapEpi64);
            ctr1 = Add(ctr1, one);
            ctr2 = Add(ctr1, one);
            ctr3 = Add(ctr2, one);
            ctr4 = Add(ctr3, one);

            for (i = 0; i < input.Length / 16 / 4; i++)
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

                tmp1 = Encrypt(tmp1, key10);
                tmp2 = Encrypt(tmp2, key10);
                tmp3 = Encrypt(tmp3, key10);
                tmp4 = Encrypt(tmp4, key10);

                tmp1 = Xor(tmp1, ReadUnalignedOffset(ref inputRef, i * Kn + 0));
                tmp2 = Xor(tmp2, ReadUnalignedOffset(ref inputRef, i * Kn + 1));
                tmp3 = Xor(tmp3, ReadUnalignedOffset(ref inputRef, i * Kn + 2));
                tmp4 = Xor(tmp4, ReadUnalignedOffset(ref inputRef, i * Kn + 3));

                WriteUnalignedOffset(ref outputRef, i * Kn + 0, tmp1);
                WriteUnalignedOffset(ref outputRef, i * Kn + 1, tmp2);
                WriteUnalignedOffset(ref outputRef, i * Kn + 2, tmp3);
                WriteUnalignedOffset(ref outputRef, i * Kn + 3, tmp4);
                
                tmp1 = Shuffle(tmp1, bswapMask);
                tmp2 = Shuffle(tmp2, bswapMask);
                tmp3 = Shuffle(tmp3, bswapMask);
                tmp4 = Shuffle(tmp4, bswapMask);

                tmp1 = Xor(x, tmp1);

                x = Ghash.Reduce4(h.AsUInt64(), h2.AsUInt64(), h3.AsUInt64(), h4.AsUInt64(),
                    tmp4.AsUInt64(), tmp3.AsUInt64(), tmp2.AsUInt64(), tmp1.AsUInt64()).AsByte();
            }

            for (k = i * 4; k < input.Length / 16; k++)
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
                
                tmp1 = Xor(tmp1, ReadUnalignedOffset(ref inputRef, k * Kn));
                WriteUnalignedOffset(ref outputRef, k * Kn, tmp1);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul15(x.AsUInt64(), h.AsUInt64()).AsByte();
            }

            if (input.Length % 16 != 0)
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
                
                tmp1 = Xor(tmp1,  ReadUnalignedOffset(ref inputRef, k * Kn));
                lastBlock.Clear();
                WriteUnalignedOffset(ref lastBlockRef, 0, tmp1);
                for (j = 0; j < input.Length % 16; j++)
                {
                    output[k * 16 + j] = lastBlock[j];
                }

                for (; j < 16; j++)
                {
                    lastBlock[j] = 0;
                }

                tmp1 = ReadUnaligned(ref lastBlockRef);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul15(x.AsUInt64(), h.AsUInt64()).AsByte();
            }
            
            tmp1 = Insert(tmp1.AsUInt32(), (uint)input.Length * 8, 0).AsByte();
            tmp1 = Insert(tmp1.AsUInt32(), (uint)addt.Length * 8, 1).AsByte();
            
            x = Xor(x, tmp1);
            x = Ghash.Gfmul15(x.AsUInt64(), h.AsUInt64()).AsByte();
            x = Shuffle(x, bswapMask);
            t = Xor(x, t);
            WriteUnaligned(ref MemoryMarshal.GetReference(tag), t);
        }
    }
}