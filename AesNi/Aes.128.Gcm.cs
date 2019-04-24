using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static AesNi.Utils;
using static System.Runtime.Intrinsics.X86.Sse2;
using static System.Runtime.Intrinsics.X86.Sse41;
using static System.Runtime.Intrinsics.X86.Sse41.X64;
using static System.Runtime.Intrinsics.X86.Ssse3;
using AesIntrin = System.Runtime.Intrinsics.X86.Aes;

namespace AesNi
{
    public static partial class Aes
    {
        internal static void EncryptGcm(
            ReadOnlySpan<byte> input,
            Span<byte> output,
            ReadOnlySpan<byte> addt,
            ReadOnlySpan<byte> iv,
            Span<byte> tag,
            Aes128Key key)
        {
            Vector128<byte> tmp1, tmp2, tmp3, tmp4;
            Vector128<byte> h, h2, h3, h4, t;
            Vector128<byte> ctr1, ctr2, ctr3, ctr4;
            var one = One;
            var four = Four;
            var bswapEpi64 = BswapEpi64;
            var bswapMask = BswapMask;
            var x = Vector128<byte>.Zero;
            Vector128<byte> y;
            Span<byte> lastBlock = stackalloc byte[BlockSize];

            ref var expandedKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref var ivRef = ref MemoryMarshal.GetReference(iv);
            ref var inputRef = ref MemoryMarshal.GetReference(input);
            ref var outputRef = ref MemoryMarshal.GetReference(output);
            ref var addtRef = ref MemoryMarshal.GetReference(addt);
            ref var lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);
            ref var tagRef = ref MemoryMarshal.GetReference(tag);

            int ivLeft = iv.Length;
            var addtLeft = addt.Length;
            var left = input.Length;

            var key0 = ReadUnaligned(ref expandedKey);
            var key1 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 1));
            var key2 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 2));
            var key3 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 3));
            var key4 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 4));
            var key5 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 5));
            var key6 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 6));
            var key7 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 7));
            var key8 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 8));
            var key9 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 9));
            var key10 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 10));

            if (ivLeft == 96 / 8)
            {
                y = ReadUnaligned(ref ivRef);
                y = Insert(y.AsUInt32(), 0x1000000, 3).AsByte();
                /*(Compute E[ZERO, KS] and E[Y0, KS] together*/
                tmp1 = Xor(x, key0);
                tmp2 = Xor(y, key0);

                tmp1 = AesIntrin.Encrypt(tmp1, key1);
                tmp2 = AesIntrin.Encrypt(tmp2, key1);

                tmp1 = AesIntrin.Encrypt(tmp1, key2);
                tmp2 = AesIntrin.Encrypt(tmp2, key2);

                tmp1 = AesIntrin.Encrypt(tmp1, key3);
                tmp2 = AesIntrin.Encrypt(tmp2, key3);

                tmp1 = AesIntrin.Encrypt(tmp1, key4);
                tmp2 = AesIntrin.Encrypt(tmp2, key4);

                tmp1 = AesIntrin.Encrypt(tmp1, key5);
                tmp2 = AesIntrin.Encrypt(tmp2, key5);

                tmp1 = AesIntrin.Encrypt(tmp1, key6);
                tmp2 = AesIntrin.Encrypt(tmp2, key6);

                tmp1 = AesIntrin.Encrypt(tmp1, key7);
                tmp2 = AesIntrin.Encrypt(tmp2, key7);

                tmp1 = AesIntrin.Encrypt(tmp1, key8);
                tmp2 = AesIntrin.Encrypt(tmp2, key8);

                tmp1 = AesIntrin.Encrypt(tmp1, key9);
                tmp2 = AesIntrin.Encrypt(tmp2, key9);

                h = AesIntrin.EncryptLast(tmp1, key10);
                t = AesIntrin.EncryptLast(tmp2, key10);

                h = Shuffle(h, bswapMask);
            }
            else
            {
                tmp1 = Xor(x, key0);
                tmp1 = AesIntrin.Encrypt(tmp1, key1);
                tmp1 = AesIntrin.Encrypt(tmp1, key2);
                tmp1 = AesIntrin.Encrypt(tmp1, key3);
                tmp1 = AesIntrin.Encrypt(tmp1, key4);
                tmp1 = AesIntrin.Encrypt(tmp1, key5);
                tmp1 = AesIntrin.Encrypt(tmp1, key6);
                tmp1 = AesIntrin.Encrypt(tmp1, key7);
                tmp1 = AesIntrin.Encrypt(tmp1, key8);
                tmp1 = AesIntrin.Encrypt(tmp1, key9);
                h = AesIntrin.EncryptLast(tmp1, key10);

                h = Shuffle(h, bswapMask);
                y = Vector128<byte>.Zero;

                while (ivLeft >= BlockSize)
                {
                    tmp1 = ReadUnaligned(ref ivRef);
                    tmp1 = Shuffle(tmp1, bswapMask);
                    y = Xor(y, tmp1);
                    y = Ghash.Gfmul(y, h);

                    ivRef = ref Unsafe.AddByteOffset(ref ivRef, (IntPtr) BlockSize);
                    ivLeft -= BlockSize;
                }

                if (ivLeft != 0)
                {
                    iv.Slice(iv.Length - ivLeft).CopyTo(lastBlock);
                    tmp1 = ReadUnaligned(ref lastBlockRef);
                    tmp1 = Shuffle(tmp1, bswapMask);
                    y = Xor(y, tmp1);
                    y = Ghash.Gfmul(y, h);
                }

                tmp1 = Insert(tmp1.AsUInt64(), (ulong) iv.Length * 8, 0).AsByte();
                tmp1 = Insert(tmp1.AsUInt64(), 0, 1).AsByte();

                y = Xor(y, tmp1);
                y = Ghash.Gfmul(y, h);
                y = Shuffle(y, bswapMask); /*Compute E(K, Y0)*/
                tmp1 = Xor(y, key0);
                tmp1 = AesIntrin.Encrypt(tmp1, key1);
                tmp1 = AesIntrin.Encrypt(tmp1, key2);
                tmp1 = AesIntrin.Encrypt(tmp1, key3);
                tmp1 = AesIntrin.Encrypt(tmp1, key4);
                tmp1 = AesIntrin.Encrypt(tmp1, key5);
                tmp1 = AesIntrin.Encrypt(tmp1, key6);
                tmp1 = AesIntrin.Encrypt(tmp1, key7);
                tmp1 = AesIntrin.Encrypt(tmp1, key8);
                tmp1 = AesIntrin.Encrypt(tmp1, key9);
                t = AesIntrin.EncryptLast(tmp1, key10);
            }

            h2 = Ghash.Gfmul(h, h);
            h3 = Ghash.Gfmul(h, h2);
            h4 = Ghash.Gfmul(h, h3);

            while (addtLeft >= BlockSize * 4)
            {
                tmp1 = ReadUnaligned(ref addtRef);
                tmp2 = ReadUnalignedOffset(ref addtRef, (IntPtr) (1 * BlockSize));
                tmp3 = ReadUnalignedOffset(ref addtRef, (IntPtr) (2 * BlockSize));
                tmp4 = ReadUnalignedOffset(ref addtRef, (IntPtr) (3 * BlockSize));

                tmp1 = Shuffle(tmp1, bswapMask);
                tmp2 = Shuffle(tmp2, bswapMask);
                tmp3 = Shuffle(tmp3, bswapMask);
                tmp4 = Shuffle(tmp4, bswapMask);
                tmp1 = Xor(x, tmp1);

                x = Ghash.Reduce4(h, h2, h3, h4, tmp4, tmp3, tmp2, tmp1);

                addtRef = ref Unsafe.AddByteOffset(ref addtRef, (IntPtr) (4 * BlockSize));
                addtLeft -= BlockSize * 4;
            }

            while (addtLeft >= BlockSize)
            {
                tmp1 = ReadUnaligned(ref addtRef);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul(x, h);

                addtRef = ref Unsafe.AddByteOffset(ref addtRef, (IntPtr) BlockSize);
                addtLeft -= BlockSize;
            }

            if (addtLeft != 0)
            {
                lastBlock.Clear();
                addt.Slice(addt.Length - addtLeft).CopyTo(lastBlock);
                tmp1 = ReadUnaligned(ref lastBlockRef);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul(x, h);
            }

            ctr1 = Shuffle(y, bswapEpi64);
            ctr1 = Add(ctr1.AsUInt64(), one.AsUInt64()).AsByte();
            ctr2 = Add(ctr1.AsUInt64(), one.AsUInt64()).AsByte();
            ctr3 = Add(ctr2.AsUInt64(), one.AsUInt64()).AsByte();
            ctr4 = Add(ctr3.AsUInt64(), one.AsUInt64()).AsByte();

            while (left >= BlockSize * 4)
            {
                tmp1 = Shuffle(ctr1, bswapEpi64);
                tmp2 = Shuffle(ctr2, bswapEpi64);
                tmp3 = Shuffle(ctr3, bswapEpi64);
                tmp4 = Shuffle(ctr4, bswapEpi64);

                ctr1 = Add(ctr1.AsUInt64(), four.AsUInt64()).AsByte();
                ctr2 = Add(ctr2.AsUInt64(), four.AsUInt64()).AsByte();
                ctr3 = Add(ctr3.AsUInt64(), four.AsUInt64()).AsByte();
                ctr4 = Add(ctr4.AsUInt64(), four.AsUInt64()).AsByte();

                tmp1 = Xor(tmp1, key0);
                tmp2 = Xor(tmp2, key0);
                tmp3 = Xor(tmp3, key0);
                tmp4 = Xor(tmp4, key0);

                tmp1 = AesIntrin.Encrypt(tmp1, key1);
                tmp2 = AesIntrin.Encrypt(tmp2, key1);
                tmp3 = AesIntrin.Encrypt(tmp3, key1);
                tmp4 = AesIntrin.Encrypt(tmp4, key1);

                tmp1 = AesIntrin.Encrypt(tmp1, key2);
                tmp2 = AesIntrin.Encrypt(tmp2, key2);
                tmp3 = AesIntrin.Encrypt(tmp3, key2);
                tmp4 = AesIntrin.Encrypt(tmp4, key2);

                tmp1 = AesIntrin.Encrypt(tmp1, key3);
                tmp2 = AesIntrin.Encrypt(tmp2, key3);
                tmp3 = AesIntrin.Encrypt(tmp3, key3);
                tmp4 = AesIntrin.Encrypt(tmp4, key3);

                tmp1 = AesIntrin.Encrypt(tmp1, key4);
                tmp2 = AesIntrin.Encrypt(tmp2, key4);
                tmp3 = AesIntrin.Encrypt(tmp3, key4);
                tmp4 = AesIntrin.Encrypt(tmp4, key4);

                tmp1 = AesIntrin.Encrypt(tmp1, key5);
                tmp2 = AesIntrin.Encrypt(tmp2, key5);
                tmp3 = AesIntrin.Encrypt(tmp3, key5);
                tmp4 = AesIntrin.Encrypt(tmp4, key5);

                tmp1 = AesIntrin.Encrypt(tmp1, key6);
                tmp2 = AesIntrin.Encrypt(tmp2, key6);
                tmp3 = AesIntrin.Encrypt(tmp3, key6);
                tmp4 = AesIntrin.Encrypt(tmp4, key6);

                tmp1 = AesIntrin.Encrypt(tmp1, key7);
                tmp2 = AesIntrin.Encrypt(tmp2, key7);
                tmp3 = AesIntrin.Encrypt(tmp3, key7);
                tmp4 = AesIntrin.Encrypt(tmp4, key7);

                tmp1 = AesIntrin.Encrypt(tmp1, key8);
                tmp2 = AesIntrin.Encrypt(tmp2, key8);
                tmp3 = AesIntrin.Encrypt(tmp3, key8);
                tmp4 = AesIntrin.Encrypt(tmp4, key8);

                tmp1 = AesIntrin.Encrypt(tmp1, key9);
                tmp2 = AesIntrin.Encrypt(tmp2, key9);
                tmp3 = AesIntrin.Encrypt(tmp3, key9);
                tmp4 = AesIntrin.Encrypt(tmp4, key9);

                tmp1 = AesIntrin.EncryptLast(tmp1, key10);
                tmp2 = AesIntrin.EncryptLast(tmp2, key10);
                tmp3 = AesIntrin.EncryptLast(tmp3, key10);
                tmp4 = AesIntrin.EncryptLast(tmp4, key10);

                tmp1 = Xor(tmp1, ReadUnaligned(ref inputRef));
                tmp2 = Xor(tmp2, ReadUnalignedOffset(ref inputRef, (IntPtr) (1 * BlockSize)));
                tmp3 = Xor(tmp3, ReadUnalignedOffset(ref inputRef, (IntPtr) (2 * BlockSize)));
                tmp4 = Xor(tmp4, ReadUnalignedOffset(ref inputRef, (IntPtr) (3 * BlockSize)));

                WriteUnaligned(ref outputRef, tmp1);
                WriteUnalignedOffset(ref outputRef, (IntPtr) (1 * BlockSize), tmp2);
                WriteUnalignedOffset(ref outputRef, (IntPtr) (2 * BlockSize), tmp3);
                WriteUnalignedOffset(ref outputRef, (IntPtr) (3 * BlockSize), tmp4);

                tmp1 = Shuffle(tmp1, bswapMask);
                tmp2 = Shuffle(tmp2, bswapMask);
                tmp3 = Shuffle(tmp3, bswapMask);
                tmp4 = Shuffle(tmp4, bswapMask);

                tmp1 = Xor(x, tmp1);

                x = Ghash.Reduce4(h, h2, h3, h4, tmp4, tmp3, tmp2, tmp1);

                inputRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr) (4 * BlockSize));
                outputRef = ref Unsafe.AddByteOffset(ref outputRef, (IntPtr) (4 * BlockSize));
                left -= BlockSize * 4;
            }

            while (left >= BlockSize)
            {
                tmp1 = Shuffle(ctr1, bswapEpi64);
                ctr1 = Add(ctr1.AsUInt64(), one.AsUInt64()).AsByte();
                tmp1 = Xor(tmp1, key0);
                tmp1 = AesIntrin.Encrypt(tmp1, key1);
                tmp1 = AesIntrin.Encrypt(tmp1, key2);
                tmp1 = AesIntrin.Encrypt(tmp1, key3);
                tmp1 = AesIntrin.Encrypt(tmp1, key4);
                tmp1 = AesIntrin.Encrypt(tmp1, key5);
                tmp1 = AesIntrin.Encrypt(tmp1, key6);
                tmp1 = AesIntrin.Encrypt(tmp1, key7);
                tmp1 = AesIntrin.Encrypt(tmp1, key8);
                tmp1 = AesIntrin.Encrypt(tmp1, key9);
                tmp1 = AesIntrin.EncryptLast(tmp1, key10);
                tmp1 = Xor(tmp1, ReadUnaligned(ref inputRef));
                WriteUnaligned(ref outputRef, tmp1);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul(x, h);

                inputRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr) BlockSize);
                outputRef = ref Unsafe.AddByteOffset(ref outputRef, (IntPtr) BlockSize);
                left -= BlockSize;
            }

            //If remains one incomplete block
            if (left != 0)
            {
                tmp1 = Shuffle(ctr1, bswapEpi64);
                tmp1 = Xor(tmp1, key0);
                tmp1 = AesIntrin.Encrypt(tmp1, key1);
                tmp1 = AesIntrin.Encrypt(tmp1, key2);
                tmp1 = AesIntrin.Encrypt(tmp1, key3);
                tmp1 = AesIntrin.Encrypt(tmp1, key4);
                tmp1 = AesIntrin.Encrypt(tmp1, key5);
                tmp1 = AesIntrin.Encrypt(tmp1, key6);
                tmp1 = AesIntrin.Encrypt(tmp1, key7);
                tmp1 = AesIntrin.Encrypt(tmp1, key8);
                tmp1 = AesIntrin.Encrypt(tmp1, key9);
                tmp1 = AesIntrin.EncryptLast(tmp1, key10);
                tmp1 = Xor(tmp1, ReadUnaligned(ref inputRef));
                WriteUnaligned(ref lastBlockRef, tmp1);
                // using input length here as output may be over-sized    vvvvv
                lastBlock.Slice(0, left).CopyTo(output.Slice(input.Length - left));
                lastBlock.Slice(left).Clear();

                tmp1 = ReadUnaligned(ref lastBlockRef);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul(x, h);
            }

            tmp1 = Insert(tmp1.AsUInt64(), (ulong) input.Length * 8, 0).AsByte();
            tmp1 = Insert(tmp1.AsUInt64(), (ulong) addt.Length * 8, 1).AsByte();

            x = Xor(x, tmp1);
            x = Ghash.Gfmul(x, h);
            x = Shuffle(x, bswapMask);
            t = Xor(x, t);
            WriteUnaligned(ref tagRef, t);
        }

        // https://github.com/freebsd/freebsd/blob/master/sys/crypto/aesni/aesni_ghash.c
        internal static bool DecryptGcm(
            ReadOnlySpan<byte> input,
            Span<byte> output,
            ReadOnlySpan<byte> addt,
            ReadOnlySpan<byte> iv,
            ReadOnlySpan<byte> tag,
            Aes128Key key)
        {
            int i, j, k;
            Vector128<byte> tmp1, tmp2, tmp3, tmp4;
            Vector128<byte> h, h2, h3, h4, t;
            Vector128<byte> ctr1, ctr2, ctr3, ctr4;
            var one = One;
            var four = Four;
            var bswapEpi64 = BswapEpi64;
            var bswapMask = BswapMask;
            var x = Vector128<byte>.Zero;
            Vector128<byte> y;
            Span<byte> lastBlock = stackalloc byte[BlockSize];
            Span<byte> actual = stackalloc byte[BlockSize];
            Span<byte> expected = stackalloc byte[BlockSize];

            ref var expandedKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref var ivRef = ref MemoryMarshal.GetReference(iv);
            ref var inputRef = ref MemoryMarshal.GetReference(input);
            ref var outputRef = ref MemoryMarshal.GetReference(output);
            ref var addtRef = ref MemoryMarshal.GetReference(addt);
            ref var lastBlockRef = ref MemoryMarshal.GetReference(lastBlock);
            ref var actualRef = ref MemoryMarshal.GetReference(actual);
            ref var expectedRef = ref MemoryMarshal.GetReference(expected);

            var key0 = ReadUnaligned(ref expandedKey);
            var key1 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 1));
            var key2 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 2));
            var key3 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 3));
            var key4 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 4));
            var key5 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 5));
            var key6 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 6));
            var key7 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 7));
            var key8 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 8));
            var key9 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 9));
            var key10 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 10));

            if (iv.Length == 96 / 8)
            {
                y = ReadUnaligned(ref ivRef);
                y = Insert(y.AsUInt32(), 0x1000000, 3).AsByte();
                /*(Compute E[ZERO, KS] and E[Y0, KS] together*/
                tmp1 = Xor(x, key0);
                tmp2 = Xor(y, key0);

                tmp1 = AesIntrin.Encrypt(tmp1, key1);
                tmp2 = AesIntrin.Encrypt(tmp2, key1);

                tmp1 = AesIntrin.Encrypt(tmp1, key2);
                tmp2 = AesIntrin.Encrypt(tmp2, key2);

                tmp1 = AesIntrin.Encrypt(tmp1, key3);
                tmp2 = AesIntrin.Encrypt(tmp2, key3);

                tmp1 = AesIntrin.Encrypt(tmp1, key4);
                tmp2 = AesIntrin.Encrypt(tmp2, key4);

                tmp1 = AesIntrin.Encrypt(tmp1, key5);
                tmp2 = AesIntrin.Encrypt(tmp2, key5);

                tmp1 = AesIntrin.Encrypt(tmp1, key6);
                tmp2 = AesIntrin.Encrypt(tmp2, key6);

                tmp1 = AesIntrin.Encrypt(tmp1, key7);
                tmp2 = AesIntrin.Encrypt(tmp2, key7);

                tmp1 = AesIntrin.Encrypt(tmp1, key8);
                tmp2 = AesIntrin.Encrypt(tmp2, key8);

                tmp1 = AesIntrin.Encrypt(tmp1, key9);
                tmp2 = AesIntrin.Encrypt(tmp2, key9);

                h = AesIntrin.EncryptLast(tmp1, key10);
                t = AesIntrin.EncryptLast(tmp2, key10);

                h = Shuffle(h, bswapMask);
            }
            else
            {
                tmp1 = Xor(x, key0);
                tmp1 = AesIntrin.Encrypt(tmp1, key1);
                tmp1 = AesIntrin.Encrypt(tmp1, key2);
                tmp1 = AesIntrin.Encrypt(tmp1, key3);
                tmp1 = AesIntrin.Encrypt(tmp1, key4);
                tmp1 = AesIntrin.Encrypt(tmp1, key5);
                tmp1 = AesIntrin.Encrypt(tmp1, key6);
                tmp1 = AesIntrin.Encrypt(tmp1, key7);
                tmp1 = AesIntrin.Encrypt(tmp1, key8);
                tmp1 = AesIntrin.Encrypt(tmp1, key9);
                h = AesIntrin.EncryptLast(tmp1, key10);

                h = Shuffle(h, bswapMask);
                y = Vector128<byte>.Zero;

                for (i = 0; i < iv.Length / 16; i++)
                {
                    tmp1 = ReadUnalignedOffset(ref ivRef, i * 16);
                    tmp1 = Shuffle(tmp1, bswapMask);
                    y = Xor(y, tmp1);
                    y = Ghash.Gfmul(y, h);
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
                    y = Ghash.Gfmul(y, h);
                }

                tmp1 = Insert(tmp1.AsUInt64(), (ulong) iv.Length * 8, 0).AsByte();
                tmp1 = Insert(tmp1.AsUInt64(), 0, 1).AsByte();

                y = Xor(y, tmp1);
                y = Ghash.Gfmul(y, h);
                y = Shuffle(y, bswapMask); /*Compute E(K, Y0)*/
                tmp1 = Xor(y, key0);
                tmp1 = AesIntrin.Encrypt(tmp1, key1);
                tmp1 = AesIntrin.Encrypt(tmp1, key2);
                tmp1 = AesIntrin.Encrypt(tmp1, key3);
                tmp1 = AesIntrin.Encrypt(tmp1, key4);
                tmp1 = AesIntrin.Encrypt(tmp1, key5);
                tmp1 = AesIntrin.Encrypt(tmp1, key6);
                tmp1 = AesIntrin.Encrypt(tmp1, key7);
                tmp1 = AesIntrin.Encrypt(tmp1, key8);
                tmp1 = AesIntrin.Encrypt(tmp1, key9);
                t = AesIntrin.EncryptLast(tmp1, key10);
            }

            h2 = Ghash.Gfmul(h, h);
            h3 = Ghash.Gfmul(h, h2);
            h4 = Ghash.Gfmul(h, h3);

            for (i = 0; i < addt.Length / 16 / 4; i++)
            {
                tmp1 = ReadUnalignedOffset(ref addtRef, 16 * (i * 4 + 0));
                tmp2 = ReadUnalignedOffset(ref addtRef, 16 * (i * 4 + 1));
                tmp3 = ReadUnalignedOffset(ref addtRef, 16 * (i * 4 + 2));
                tmp4 = ReadUnalignedOffset(ref addtRef, 16 * (i * 4 + 3));

                tmp1 = Shuffle(tmp1, bswapMask);
                tmp2 = Shuffle(tmp2, bswapMask);
                tmp3 = Shuffle(tmp3, bswapMask);
                tmp4 = Shuffle(tmp4, bswapMask);
                tmp1 = Xor(x, tmp1);

                x = Ghash.Reduce4(h, h2, h3, h4, tmp4, tmp3, tmp2, tmp1);
            }

            for (i = i * 4; i < addt.Length / 16; i++)
            {
                tmp1 = ReadUnalignedOffset(ref addtRef, 16 * i);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul(x, h);
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
                x = Ghash.Gfmul(x, h);
            }

            /* Verify integrity of input before actual decrypt */
            for (i = 0; i < input.Length / 16 / 4; i++)
            {
                tmp1 = ReadUnalignedOffset(ref inputRef, 16 * (i * 4 + 0));
                tmp2 = ReadUnalignedOffset(ref inputRef, 16 * (i * 4 + 1));
                tmp3 = ReadUnalignedOffset(ref inputRef, 16 * (i * 4 + 2));
                tmp4 = ReadUnalignedOffset(ref inputRef, 16 * (i * 4 + 3));

                tmp1 = Shuffle(tmp1, bswapMask);
                tmp2 = Shuffle(tmp2, bswapMask);
                tmp3 = Shuffle(tmp3, bswapMask);
                tmp4 = Shuffle(tmp4, bswapMask);

                tmp1 = Xor(x, tmp1);

                x = Ghash.Reduce4(h, h2, h3, h4, tmp4, tmp3, tmp2, tmp1);
            }

            for (i = i * 4; i < input.Length / 16; i++)
            {
                tmp1 = ReadUnalignedOffset(ref inputRef, 16 * i);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul(x, h);
            }

            if (input.Length % 16 != 0)
            {
                lastBlock.Clear();
                for (j = 0; j < input.Length % 16; j++)
                {
                    lastBlock[j] = input[i * 16 + j];
                }

                tmp1 = ReadUnaligned(ref lastBlockRef);
                tmp1 = Shuffle(tmp1, bswapMask);
                x = Xor(x, tmp1);
                x = Ghash.Gfmul(x, h);
            }

            tmp1 = Insert(tmp1.AsUInt64(), (ulong) input.Length * 8, 0).AsByte();
            tmp1 = Insert(tmp1.AsUInt64(), (ulong) addt.Length * 8, 1).AsByte();

            x = Xor(x, tmp1);
            x = Ghash.Gfmul(x, h);
            x = Shuffle(x, bswapMask);
            t = Xor(x, t);

            WriteUnaligned(ref actualRef, t);

            tag.CopyTo(expected);
            actual.Slice(tag.Length).Clear();

            if (!Equal(ReadUnaligned(ref expectedRef), ReadUnaligned(ref actualRef))) return false;

            ctr1 = Shuffle(y, bswapEpi64);
            ctr1 = Add(ctr1.AsUInt64(), one.AsUInt64()).AsByte();
            ctr2 = Add(ctr1.AsUInt64(), one.AsUInt64()).AsByte();
            ctr3 = Add(ctr2.AsUInt64(), one.AsUInt64()).AsByte();
            ctr4 = Add(ctr3.AsUInt64(), one.AsUInt64()).AsByte();

            for (i = 0; i < input.Length / 16 / 4; i++)
            {
                tmp1 = Shuffle(ctr1, bswapEpi64);
                tmp2 = Shuffle(ctr2, bswapEpi64);
                tmp3 = Shuffle(ctr3, bswapEpi64);
                tmp4 = Shuffle(ctr4, bswapEpi64);

                ctr1 = Add(ctr1.AsUInt64(), four.AsUInt64()).AsByte();
                ctr2 = Add(ctr2.AsUInt64(), four.AsUInt64()).AsByte();
                ctr3 = Add(ctr3.AsUInt64(), four.AsUInt64()).AsByte();
                ctr4 = Add(ctr4.AsUInt64(), four.AsUInt64()).AsByte();

                tmp1 = Xor(tmp1, key0);
                tmp2 = Xor(tmp2, key0);
                tmp3 = Xor(tmp3, key0);
                tmp4 = Xor(tmp4, key0);

                tmp1 = AesIntrin.Encrypt(tmp1, key1);
                tmp2 = AesIntrin.Encrypt(tmp2, key1);
                tmp3 = AesIntrin.Encrypt(tmp3, key1);
                tmp4 = AesIntrin.Encrypt(tmp4, key1);

                tmp1 = AesIntrin.Encrypt(tmp1, key2);
                tmp2 = AesIntrin.Encrypt(tmp2, key2);
                tmp3 = AesIntrin.Encrypt(tmp3, key2);
                tmp4 = AesIntrin.Encrypt(tmp4, key2);

                tmp1 = AesIntrin.Encrypt(tmp1, key3);
                tmp2 = AesIntrin.Encrypt(tmp2, key3);
                tmp3 = AesIntrin.Encrypt(tmp3, key3);
                tmp4 = AesIntrin.Encrypt(tmp4, key3);

                tmp1 = AesIntrin.Encrypt(tmp1, key4);
                tmp2 = AesIntrin.Encrypt(tmp2, key4);
                tmp3 = AesIntrin.Encrypt(tmp3, key4);
                tmp4 = AesIntrin.Encrypt(tmp4, key4);

                tmp1 = AesIntrin.Encrypt(tmp1, key5);
                tmp2 = AesIntrin.Encrypt(tmp2, key5);
                tmp3 = AesIntrin.Encrypt(tmp3, key5);
                tmp4 = AesIntrin.Encrypt(tmp4, key5);

                tmp1 = AesIntrin.Encrypt(tmp1, key6);
                tmp2 = AesIntrin.Encrypt(tmp2, key6);
                tmp3 = AesIntrin.Encrypt(tmp3, key6);
                tmp4 = AesIntrin.Encrypt(tmp4, key6);

                tmp1 = AesIntrin.Encrypt(tmp1, key7);
                tmp2 = AesIntrin.Encrypt(tmp2, key7);
                tmp3 = AesIntrin.Encrypt(tmp3, key7);
                tmp4 = AesIntrin.Encrypt(tmp4, key7);

                tmp1 = AesIntrin.Encrypt(tmp1, key8);
                tmp2 = AesIntrin.Encrypt(tmp2, key8);
                tmp3 = AesIntrin.Encrypt(tmp3, key8);
                tmp4 = AesIntrin.Encrypt(tmp4, key8);

                tmp1 = AesIntrin.Encrypt(tmp1, key9);
                tmp2 = AesIntrin.Encrypt(tmp2, key9);
                tmp3 = AesIntrin.Encrypt(tmp3, key9);
                tmp4 = AesIntrin.Encrypt(tmp4, key9);

                tmp1 = AesIntrin.EncryptLast(tmp1, key10);
                tmp2 = AesIntrin.EncryptLast(tmp2, key10);
                tmp3 = AesIntrin.EncryptLast(tmp3, key10);
                tmp4 = AesIntrin.EncryptLast(tmp4, key10);

                tmp1 = Xor(tmp1, ReadUnalignedOffset(ref inputRef, 16 * (i * 4 + 0)));
                tmp2 = Xor(tmp2, ReadUnalignedOffset(ref inputRef, 16 * (i * 4 + 1)));
                tmp3 = Xor(tmp3, ReadUnalignedOffset(ref inputRef, 16 * (i * 4 + 2)));
                tmp4 = Xor(tmp4, ReadUnalignedOffset(ref inputRef, 16 * (i * 4 + 3)));

                WriteUnalignedOffset(ref outputRef, 16 * (i * 4 + 0), tmp1);
                WriteUnalignedOffset(ref outputRef, 16 * (i * 4 + 1), tmp2);
                WriteUnalignedOffset(ref outputRef, 16 * (i * 4 + 2), tmp3);
                WriteUnalignedOffset(ref outputRef, 16 * (i * 4 + 3), tmp4);
            }

            for (k = i * 4; k < input.Length / 16; k++)
            {
                tmp1 = Shuffle(ctr1, bswapEpi64);
                ctr1 = Add(ctr1.AsUInt64(), one.AsUInt64()).AsByte();
                tmp1 = Xor(tmp1, key0);
                tmp1 = AesIntrin.Encrypt(tmp1, key1);
                tmp1 = AesIntrin.Encrypt(tmp1, key2);
                tmp1 = AesIntrin.Encrypt(tmp1, key3);
                tmp1 = AesIntrin.Encrypt(tmp1, key4);
                tmp1 = AesIntrin.Encrypt(tmp1, key5);
                tmp1 = AesIntrin.Encrypt(tmp1, key6);
                tmp1 = AesIntrin.Encrypt(tmp1, key7);
                tmp1 = AesIntrin.Encrypt(tmp1, key8);
                tmp1 = AesIntrin.Encrypt(tmp1, key9);
                tmp1 = AesIntrin.EncryptLast(tmp1, key10);
                tmp1 = Xor(tmp1, ReadUnalignedOffset(ref inputRef, 16 * k));
                WriteUnalignedOffset(ref outputRef, 16 * k, tmp1);
            }

            //If remains one incomplete block
            if (input.Length % 16 != 0)
            {
                tmp1 = Shuffle(ctr1, bswapEpi64);
                tmp1 = Xor(tmp1, key0);
                tmp1 = AesIntrin.Encrypt(tmp1, key1);
                tmp1 = AesIntrin.Encrypt(tmp1, key2);
                tmp1 = AesIntrin.Encrypt(tmp1, key3);
                tmp1 = AesIntrin.Encrypt(tmp1, key4);
                tmp1 = AesIntrin.Encrypt(tmp1, key5);
                tmp1 = AesIntrin.Encrypt(tmp1, key6);
                tmp1 = AesIntrin.Encrypt(tmp1, key7);
                tmp1 = AesIntrin.Encrypt(tmp1, key8);
                tmp1 = AesIntrin.Encrypt(tmp1, key9);
                tmp1 = AesIntrin.EncryptLast(tmp1, key10);
                tmp1 = Xor(tmp1, ReadUnalignedOffset(ref inputRef, 16 * k));
                WriteUnalignedOffset(ref lastBlockRef, 0, tmp1);
                for (j = 0; j < input.Length % 16; j++)
                {
                    output[k * 16 + j] = lastBlock[j];
                }

                for (; j < 16; j++)
                {
                    lastBlock[j] = 0;
                }
            }

            return true;
        }
    }
}