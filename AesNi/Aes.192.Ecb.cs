using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static AesNi.Utils;
using static System.Runtime.Intrinsics.X86.Sse2;
using AesIntrin = System.Runtime.Intrinsics.X86.Aes;

namespace AesNi
{
    public static partial class Aes
    {
        internal static void EncryptEcb(
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Aes192Key key,
            PaddingMode paddingMode = PaddingMode.Zeros)
        {
            ref var expandedKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref var inputRef = ref MemoryMarshal.GetReference(plaintext);
            ref var outputRef = ref MemoryMarshal.GetReference(ciphertext);

            var left = plaintext.Length;

            var key0 = ReadUnaligned(ref expandedKey);
            var key1 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 1);
            var key2 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 2);
            var key3 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 3);
            var key4 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 4);
            var key5 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 5);
            var key6 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 6);
            var key7 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 7);
            var key8 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 8);
            var key9 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 9);
            var key10 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 10);
            var key11 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 11);
            var key12 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 12);

            while (left >= BlockSize * 8)
            {
                var block0 = ReadUnaligned(ref inputRef);
                var block1 = ReadUnalignedOffset(ref inputRef, 1 * BlockSize);
                var block2 = ReadUnalignedOffset(ref inputRef, 2 * BlockSize);
                var block3 = ReadUnalignedOffset(ref inputRef, 3 * BlockSize);
                var block4 = ReadUnalignedOffset(ref inputRef, 4 * BlockSize);
                var block5 = ReadUnalignedOffset(ref inputRef, 5 * BlockSize);
                var block6 = ReadUnalignedOffset(ref inputRef, 6 * BlockSize);
                var block7 = ReadUnalignedOffset(ref inputRef, 7 * BlockSize);

                // Round 0 - whitening
                block0 = Xor(block0, key0);
                block1 = Xor(block1, key0);
                block2 = Xor(block2, key0);
                block3 = Xor(block3, key0);
                block4 = Xor(block4, key0);
                block5 = Xor(block5, key0);
                block6 = Xor(block6, key0);
                block7 = Xor(block7, key0);

                // Round 1
                block0 = AesIntrin.Encrypt(block0, key1);
                block1 = AesIntrin.Encrypt(block1, key1);
                block2 = AesIntrin.Encrypt(block2, key1);
                block3 = AesIntrin.Encrypt(block3, key1);
                block4 = AesIntrin.Encrypt(block4, key1);
                block5 = AesIntrin.Encrypt(block5, key1);
                block6 = AesIntrin.Encrypt(block6, key1);
                block7 = AesIntrin.Encrypt(block7, key1);

                // Round 2
                block0 = AesIntrin.Encrypt(block0, key2);
                block1 = AesIntrin.Encrypt(block1, key2);
                block2 = AesIntrin.Encrypt(block2, key2);
                block3 = AesIntrin.Encrypt(block3, key2);
                block4 = AesIntrin.Encrypt(block4, key2);
                block5 = AesIntrin.Encrypt(block5, key2);
                block6 = AesIntrin.Encrypt(block6, key2);
                block7 = AesIntrin.Encrypt(block7, key2);

                // Round 3
                block0 = AesIntrin.Encrypt(block0, key3);
                block1 = AesIntrin.Encrypt(block1, key3);
                block2 = AesIntrin.Encrypt(block2, key3);
                block3 = AesIntrin.Encrypt(block3, key3);
                block4 = AesIntrin.Encrypt(block4, key3);
                block5 = AesIntrin.Encrypt(block5, key3);
                block6 = AesIntrin.Encrypt(block6, key3);
                block7 = AesIntrin.Encrypt(block7, key3);

                // Round 4
                block0 = AesIntrin.Encrypt(block0, key4);
                block1 = AesIntrin.Encrypt(block1, key4);
                block2 = AesIntrin.Encrypt(block2, key4);
                block3 = AesIntrin.Encrypt(block3, key4);
                block4 = AesIntrin.Encrypt(block4, key4);
                block5 = AesIntrin.Encrypt(block5, key4);
                block6 = AesIntrin.Encrypt(block6, key4);
                block7 = AesIntrin.Encrypt(block7, key4);

                // Round 5
                block0 = AesIntrin.Encrypt(block0, key5);
                block1 = AesIntrin.Encrypt(block1, key5);
                block2 = AesIntrin.Encrypt(block2, key5);
                block3 = AesIntrin.Encrypt(block3, key5);
                block4 = AesIntrin.Encrypt(block4, key5);
                block5 = AesIntrin.Encrypt(block5, key5);
                block6 = AesIntrin.Encrypt(block6, key5);
                block7 = AesIntrin.Encrypt(block7, key5);

                // Round 6
                block0 = AesIntrin.Encrypt(block0, key6);
                block1 = AesIntrin.Encrypt(block1, key6);
                block2 = AesIntrin.Encrypt(block2, key6);
                block3 = AesIntrin.Encrypt(block3, key6);
                block4 = AesIntrin.Encrypt(block4, key6);
                block5 = AesIntrin.Encrypt(block5, key6);
                block6 = AesIntrin.Encrypt(block6, key6);
                block7 = AesIntrin.Encrypt(block7, key6);

                // Round 7
                block0 = AesIntrin.Encrypt(block0, key7);
                block1 = AesIntrin.Encrypt(block1, key7);
                block2 = AesIntrin.Encrypt(block2, key7);
                block3 = AesIntrin.Encrypt(block3, key7);
                block4 = AesIntrin.Encrypt(block4, key7);
                block5 = AesIntrin.Encrypt(block5, key7);
                block6 = AesIntrin.Encrypt(block6, key7);
                block7 = AesIntrin.Encrypt(block7, key7);

                // Round 8
                block0 = AesIntrin.Encrypt(block0, key8);
                block1 = AesIntrin.Encrypt(block1, key8);
                block2 = AesIntrin.Encrypt(block2, key8);
                block3 = AesIntrin.Encrypt(block3, key8);
                block4 = AesIntrin.Encrypt(block4, key8);
                block5 = AesIntrin.Encrypt(block5, key8);
                block6 = AesIntrin.Encrypt(block6, key8);
                block7 = AesIntrin.Encrypt(block7, key8);

                // Round 9
                block0 = AesIntrin.Encrypt(block0, key9);
                block1 = AesIntrin.Encrypt(block1, key9);
                block2 = AesIntrin.Encrypt(block2, key9);
                block3 = AesIntrin.Encrypt(block3, key9);
                block4 = AesIntrin.Encrypt(block4, key9);
                block5 = AesIntrin.Encrypt(block5, key9);
                block6 = AesIntrin.Encrypt(block6, key9);
                block7 = AesIntrin.Encrypt(block7, key9);

                // Round 10
                block0 = AesIntrin.Encrypt(block0, key10);
                block1 = AesIntrin.Encrypt(block1, key10);
                block2 = AesIntrin.Encrypt(block2, key10);
                block3 = AesIntrin.Encrypt(block3, key10);
                block4 = AesIntrin.Encrypt(block4, key10);
                block5 = AesIntrin.Encrypt(block5, key10);
                block6 = AesIntrin.Encrypt(block6, key10);
                block7 = AesIntrin.Encrypt(block7, key10);

                // Round 11
                block0 = AesIntrin.Encrypt(block0, key11);
                block1 = AesIntrin.Encrypt(block1, key11);
                block2 = AesIntrin.Encrypt(block2, key11);
                block3 = AesIntrin.Encrypt(block3, key11);
                block4 = AesIntrin.Encrypt(block4, key11);
                block5 = AesIntrin.Encrypt(block5, key11);
                block6 = AesIntrin.Encrypt(block6, key11);
                block7 = AesIntrin.Encrypt(block7, key11);

                // Round 12
                block0 = AesIntrin.EncryptLast(block0, key12);
                block1 = AesIntrin.EncryptLast(block1, key12);
                block2 = AesIntrin.EncryptLast(block2, key12);
                block3 = AesIntrin.EncryptLast(block3, key12);
                block4 = AesIntrin.EncryptLast(block4, key12);
                block5 = AesIntrin.EncryptLast(block5, key12);
                block6 = AesIntrin.EncryptLast(block6, key12);
                block7 = AesIntrin.EncryptLast(block7, key12);

                WriteUnaligned(ref outputRef, block0);
                WriteUnalignedOffset(ref outputRef, 1 * BlockSize, block1);
                WriteUnalignedOffset(ref outputRef, 2 * BlockSize, block2);
                WriteUnalignedOffset(ref outputRef, 3 * BlockSize, block3);
                WriteUnalignedOffset(ref outputRef, 4 * BlockSize, block4);
                WriteUnalignedOffset(ref outputRef, 5 * BlockSize, block5);
                WriteUnalignedOffset(ref outputRef, 6 * BlockSize, block6);
                WriteUnalignedOffset(ref outputRef, 7 * BlockSize, block7);

                inputRef = ref Unsafe.AddByteOffset(ref inputRef, 8 * BlockSize);
                outputRef = ref Unsafe.AddByteOffset(ref outputRef, 8 * BlockSize);
                left -= BlockSizeInt * 8;
            }

            while (left >= BlockSize)
            {
                var block = ReadUnaligned(ref inputRef);

                block = Xor(block, key0);
                block = AesIntrin.Encrypt(block, key1);
                block = AesIntrin.Encrypt(block, key2);
                block = AesIntrin.Encrypt(block, key3);
                block = AesIntrin.Encrypt(block, key4);
                block = AesIntrin.Encrypt(block, key5);
                block = AesIntrin.Encrypt(block, key6);
                block = AesIntrin.Encrypt(block, key7);
                block = AesIntrin.Encrypt(block, key8);
                block = AesIntrin.Encrypt(block, key9);
                block = AesIntrin.Encrypt(block, key10);
                block = AesIntrin.Encrypt(block, key11);
                block = AesIntrin.EncryptLast(block, key12);

                WriteUnaligned(ref outputRef, block);

                inputRef = ref Unsafe.Add(ref inputRef, BlockSize);
                outputRef = ref Unsafe.Add(ref outputRef, BlockSize);
                left -= BlockSizeInt;
            }

            if (paddingMode == PaddingMode.None)
            {
                Debug.Assert(left == 0);
                return;
            }

            Span<byte> lastBlock = stackalloc byte[BlockSizeInt];
            var remainingPlaintext =
                left != 0 ? plaintext.Slice(plaintext.Length - left) : ReadOnlySpan<byte>.Empty;

            ApplyPadding(remainingPlaintext, lastBlock, paddingMode);

            var lBlock = ReadUnaligned(ref MemoryMarshal.GetReference(lastBlock));

            lBlock = Xor(lBlock, key0);
            lBlock = AesIntrin.Encrypt(lBlock, key1);
            lBlock = AesIntrin.Encrypt(lBlock, key2);
            lBlock = AesIntrin.Encrypt(lBlock, key3);
            lBlock = AesIntrin.Encrypt(lBlock, key4);
            lBlock = AesIntrin.Encrypt(lBlock, key5);
            lBlock = AesIntrin.Encrypt(lBlock, key6);
            lBlock = AesIntrin.Encrypt(lBlock, key7);
            lBlock = AesIntrin.Encrypt(lBlock, key8);
            lBlock = AesIntrin.Encrypt(lBlock, key9);
            lBlock = AesIntrin.Encrypt(lBlock, key10);
            lBlock = AesIntrin.Encrypt(lBlock, key11);
            lBlock = AesIntrin.EncryptLast(lBlock, key12);

            WriteUnaligned(ref outputRef, lBlock);
        }

        internal static void DecryptEcb(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            Aes192Key key,
            PaddingMode paddingMode = PaddingMode.Zeros)
        {
            ref var expandedKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref var inputRef = ref MemoryMarshal.GetReference(ciphertext);
            ref var outputRef = ref MemoryMarshal.GetReference(plaintext);

            var left = ciphertext.Length;

            var key0 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 12);
            var key1 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 13);
            var key2 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 14);
            var key3 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 15);
            var key4 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 16);
            var key5 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 17);
            var key6 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 18);
            var key7 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 19);
            var key8 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 20);
            var key9 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 21);
            var key10 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 22);
            var key11 = ReadUnalignedOffset(ref expandedKey, BytesPerRoundKey * 23);
            var key12 = ReadUnaligned(ref expandedKey);

            while (left >= BlockSize * 8)
            {
                var block0 = ReadUnaligned(ref inputRef);
                var block1 = ReadUnalignedOffset(ref inputRef, 1 * BlockSize);
                var block2 = ReadUnalignedOffset(ref inputRef, 2 * BlockSize);
                var block3 = ReadUnalignedOffset(ref inputRef, 3 * BlockSize);
                var block4 = ReadUnalignedOffset(ref inputRef, 4 * BlockSize);
                var block5 = ReadUnalignedOffset(ref inputRef, 5 * BlockSize);
                var block6 = ReadUnalignedOffset(ref inputRef, 6 * BlockSize);
                var block7 = ReadUnalignedOffset(ref inputRef, 7 * BlockSize);

                // Round 0 - whitening
                block0 = Xor(block0, key0);
                block1 = Xor(block1, key0);
                block2 = Xor(block2, key0);
                block3 = Xor(block3, key0);
                block4 = Xor(block4, key0);
                block5 = Xor(block5, key0);
                block6 = Xor(block6, key0);
                block7 = Xor(block7, key0);

                // Round 1
                block0 = AesIntrin.Decrypt(block0, key1);
                block1 = AesIntrin.Decrypt(block1, key1);
                block2 = AesIntrin.Decrypt(block2, key1);
                block3 = AesIntrin.Decrypt(block3, key1);
                block4 = AesIntrin.Decrypt(block4, key1);
                block5 = AesIntrin.Decrypt(block5, key1);
                block6 = AesIntrin.Decrypt(block6, key1);
                block7 = AesIntrin.Decrypt(block7, key1);

                // Round 2
                block0 = AesIntrin.Decrypt(block0, key2);
                block1 = AesIntrin.Decrypt(block1, key2);
                block2 = AesIntrin.Decrypt(block2, key2);
                block3 = AesIntrin.Decrypt(block3, key2);
                block4 = AesIntrin.Decrypt(block4, key2);
                block5 = AesIntrin.Decrypt(block5, key2);
                block6 = AesIntrin.Decrypt(block6, key2);
                block7 = AesIntrin.Decrypt(block7, key2);

                // Round 3
                block0 = AesIntrin.Decrypt(block0, key3);
                block1 = AesIntrin.Decrypt(block1, key3);
                block2 = AesIntrin.Decrypt(block2, key3);
                block3 = AesIntrin.Decrypt(block3, key3);
                block4 = AesIntrin.Decrypt(block4, key3);
                block5 = AesIntrin.Decrypt(block5, key3);
                block6 = AesIntrin.Decrypt(block6, key3);
                block7 = AesIntrin.Decrypt(block7, key3);

                // Round 4
                block0 = AesIntrin.Decrypt(block0, key4);
                block1 = AesIntrin.Decrypt(block1, key4);
                block2 = AesIntrin.Decrypt(block2, key4);
                block3 = AesIntrin.Decrypt(block3, key4);
                block4 = AesIntrin.Decrypt(block4, key4);
                block5 = AesIntrin.Decrypt(block5, key4);
                block6 = AesIntrin.Decrypt(block6, key4);
                block7 = AesIntrin.Decrypt(block7, key4);

                // Round 5
                block0 = AesIntrin.Decrypt(block0, key5);
                block1 = AesIntrin.Decrypt(block1, key5);
                block2 = AesIntrin.Decrypt(block2, key5);
                block3 = AesIntrin.Decrypt(block3, key5);
                block4 = AesIntrin.Decrypt(block4, key5);
                block5 = AesIntrin.Decrypt(block5, key5);
                block6 = AesIntrin.Decrypt(block6, key5);
                block7 = AesIntrin.Decrypt(block7, key5);

                // Round 6
                block0 = AesIntrin.Decrypt(block0, key6);
                block1 = AesIntrin.Decrypt(block1, key6);
                block2 = AesIntrin.Decrypt(block2, key6);
                block3 = AesIntrin.Decrypt(block3, key6);
                block4 = AesIntrin.Decrypt(block4, key6);
                block5 = AesIntrin.Decrypt(block5, key6);
                block6 = AesIntrin.Decrypt(block6, key6);
                block7 = AesIntrin.Decrypt(block7, key6);

                // Round 7
                block0 = AesIntrin.Decrypt(block0, key7);
                block1 = AesIntrin.Decrypt(block1, key7);
                block2 = AesIntrin.Decrypt(block2, key7);
                block3 = AesIntrin.Decrypt(block3, key7);
                block4 = AesIntrin.Decrypt(block4, key7);
                block5 = AesIntrin.Decrypt(block5, key7);
                block6 = AesIntrin.Decrypt(block6, key7);
                block7 = AesIntrin.Decrypt(block7, key7);

                // Round 8
                block0 = AesIntrin.Decrypt(block0, key8);
                block1 = AesIntrin.Decrypt(block1, key8);
                block2 = AesIntrin.Decrypt(block2, key8);
                block3 = AesIntrin.Decrypt(block3, key8);
                block4 = AesIntrin.Decrypt(block4, key8);
                block5 = AesIntrin.Decrypt(block5, key8);
                block6 = AesIntrin.Decrypt(block6, key8);
                block7 = AesIntrin.Decrypt(block7, key8);

                // Round 9
                block0 = AesIntrin.Decrypt(block0, key9);
                block1 = AesIntrin.Decrypt(block1, key9);
                block2 = AesIntrin.Decrypt(block2, key9);
                block3 = AesIntrin.Decrypt(block3, key9);
                block4 = AesIntrin.Decrypt(block4, key9);
                block5 = AesIntrin.Decrypt(block5, key9);
                block6 = AesIntrin.Decrypt(block6, key9);
                block7 = AesIntrin.Decrypt(block7, key9);

                // Round 10
                block0 = AesIntrin.Decrypt(block0, key10);
                block1 = AesIntrin.Decrypt(block1, key10);
                block2 = AesIntrin.Decrypt(block2, key10);
                block3 = AesIntrin.Decrypt(block3, key10);
                block4 = AesIntrin.Decrypt(block4, key10);
                block5 = AesIntrin.Decrypt(block5, key10);
                block6 = AesIntrin.Decrypt(block6, key10);
                block7 = AesIntrin.Decrypt(block7, key10);

                // Round 11
                block0 = AesIntrin.Decrypt(block0, key11);
                block1 = AesIntrin.Decrypt(block1, key11);
                block2 = AesIntrin.Decrypt(block2, key11);
                block3 = AesIntrin.Decrypt(block3, key11);
                block4 = AesIntrin.Decrypt(block4, key11);
                block5 = AesIntrin.Decrypt(block5, key11);
                block6 = AesIntrin.Decrypt(block6, key11);
                block7 = AesIntrin.Decrypt(block7, key11);

                // Round 12
                block0 = AesIntrin.DecryptLast(block0, key12);
                block1 = AesIntrin.DecryptLast(block1, key12);
                block2 = AesIntrin.DecryptLast(block2, key12);
                block3 = AesIntrin.DecryptLast(block3, key12);
                block4 = AesIntrin.DecryptLast(block4, key12);
                block5 = AesIntrin.DecryptLast(block5, key12);
                block6 = AesIntrin.DecryptLast(block6, key12);
                block7 = AesIntrin.DecryptLast(block7, key12);

                WriteUnaligned(ref outputRef, block0);
                WriteUnalignedOffset(ref outputRef, 1 * BlockSize, block1);
                WriteUnalignedOffset(ref outputRef, 2 * BlockSize, block2);
                WriteUnalignedOffset(ref outputRef, 3 * BlockSize, block3);
                WriteUnalignedOffset(ref outputRef, 4 * BlockSize, block4);
                WriteUnalignedOffset(ref outputRef, 5 * BlockSize, block5);
                WriteUnalignedOffset(ref outputRef, 6 * BlockSize, block6);
                WriteUnalignedOffset(ref outputRef, 7 * BlockSize, block7);

                inputRef = ref Unsafe.AddByteOffset(ref inputRef, 8 * BlockSize);
                outputRef = ref Unsafe.AddByteOffset(ref outputRef, 8 * BlockSize);
                left -= BlockSizeInt * 8;
            }

            while (left >= BlockSize)
            {
                var block = ReadUnaligned(ref inputRef);

                block = Xor(block, key0);
                block = AesIntrin.Decrypt(block, key1);
                block = AesIntrin.Decrypt(block, key2);
                block = AesIntrin.Decrypt(block, key3);
                block = AesIntrin.Decrypt(block, key4);
                block = AesIntrin.Decrypt(block, key5);
                block = AesIntrin.Decrypt(block, key6);
                block = AesIntrin.Decrypt(block, key7);
                block = AesIntrin.Decrypt(block, key8);
                block = AesIntrin.Decrypt(block, key9);
                block = AesIntrin.Decrypt(block, key10);
                block = AesIntrin.Decrypt(block, key11);
                block = AesIntrin.DecryptLast(block, key12);

                WriteUnaligned(ref outputRef, block);

                inputRef = ref Unsafe.Add(ref inputRef, BlockSize);
                outputRef = ref Unsafe.Add(ref outputRef, BlockSize);
                left -= BlockSizeInt;
            }
        }
    }
}