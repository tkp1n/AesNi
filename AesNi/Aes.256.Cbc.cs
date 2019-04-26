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
        internal static void EncryptCbc(
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> iv,
            Aes256Key key,
            PaddingMode paddingMode = PaddingMode.Zeros)
        {
            ref var expandedKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref var inputRef = ref MemoryMarshal.GetReference(plaintext);
            ref var outputRef = ref MemoryMarshal.GetReference(ciphertext);
            ref var ivRef = ref MemoryMarshal.GetReference(iv);

            var left = plaintext.Length;

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
            var key11 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 11));
            var key12 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 12));
            var key13 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 13));
            var key14 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 14));

            var feedback = ReadUnaligned(ref ivRef);
            var block = ReadUnaligned(ref inputRef);

            var tmp = Xor(block, key0);
            feedback = Xor(feedback, tmp);

            inputRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr) BlockSize); 

            while (left >= BlockSize * 2)
            {
                feedback = AesIntrin.Encrypt(feedback, key1);
                feedback = AesIntrin.Encrypt(feedback, key2);
                feedback = AesIntrin.Encrypt(feedback, key3);
                feedback = AesIntrin.Encrypt(feedback, key4);
                feedback = AesIntrin.Encrypt(feedback, key5);
                feedback = AesIntrin.Encrypt(feedback, key6);
                feedback = AesIntrin.Encrypt(feedback, key7);
                feedback = AesIntrin.Encrypt(feedback, key8);
                feedback = AesIntrin.Encrypt(feedback, key9);
                feedback = AesIntrin.Encrypt(feedback, key10);
                feedback = AesIntrin.Encrypt(feedback, key11);
                feedback = AesIntrin.Encrypt(feedback, key12);

                block = ReadUnaligned(ref inputRef);
                tmp = Xor(block, key0);

                var fake = Xor(tmp, key14);

                feedback = AesIntrin.Encrypt(feedback, key13);
                feedback = AesIntrin.EncryptLast(feedback, fake);

                var correct = Xor(feedback, tmp);

                WriteUnaligned(ref outputRef, correct);

                inputRef = ref Unsafe.Add(ref inputRef, (IntPtr) BlockSize);
                outputRef = ref Unsafe.Add(ref outputRef, (IntPtr) BlockSize);
                left -= BlockSize;
            }

            feedback = AesIntrin.Encrypt(feedback, key1);
            feedback = AesIntrin.Encrypt(feedback, key2);
            feedback = AesIntrin.Encrypt(feedback, key3);
            feedback = AesIntrin.Encrypt(feedback, key4);
            feedback = AesIntrin.Encrypt(feedback, key5);
            feedback = AesIntrin.Encrypt(feedback, key6);
            feedback = AesIntrin.Encrypt(feedback, key7);
            feedback = AesIntrin.Encrypt(feedback, key8);
            feedback = AesIntrin.Encrypt(feedback, key9);
            feedback = AesIntrin.Encrypt(feedback, key10);
            feedback = AesIntrin.Encrypt(feedback, key11);
            feedback = AesIntrin.Encrypt(feedback, key12);
            feedback = AesIntrin.Encrypt(feedback, key13);
            feedback = AesIntrin.EncryptLast(feedback, key14);

            WriteUnaligned(ref outputRef, feedback);

            left -= BlockSize;

            if (paddingMode == PaddingMode.None)
            {
                Debug.Assert(left == 0);
                return;
            }

            Span<byte> lastBlock = stackalloc byte[BlockSize];
            var remainingPlaintext =
                left != 0 ? plaintext.Slice(plaintext.Length - left) : ReadOnlySpan<byte>.Empty;

            ApplyPadding(remainingPlaintext, lastBlock, paddingMode);

            var lBlock = ReadUnaligned(ref MemoryMarshal.GetReference(lastBlock));

            feedback = Xor(lBlock, feedback);
            feedback = Xor(feedback, key0);

            feedback = AesIntrin.Encrypt(feedback, key1);
            feedback = AesIntrin.Encrypt(feedback, key2);
            feedback = AesIntrin.Encrypt(feedback, key3);
            feedback = AesIntrin.Encrypt(feedback, key4);
            feedback = AesIntrin.Encrypt(feedback, key5);
            feedback = AesIntrin.Encrypt(feedback, key6);
            feedback = AesIntrin.Encrypt(feedback, key7);
            feedback = AesIntrin.Encrypt(feedback, key8);
            feedback = AesIntrin.Encrypt(feedback, key9);
            feedback = AesIntrin.Encrypt(feedback, key10);
            feedback = AesIntrin.Encrypt(feedback, key11);
            feedback = AesIntrin.Encrypt(feedback, key12);
            feedback = AesIntrin.Encrypt(feedback, key13);
            feedback = AesIntrin.EncryptLast(feedback, key14);

            WriteUnaligned(ref outputRef, feedback);
        }

        internal static void DecryptCbc(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            ReadOnlySpan<byte> iv,
            Aes256Key key,
            PaddingMode paddingMode = PaddingMode.Zeros)
        {
            ref var expandedKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref var inputRef = ref MemoryMarshal.GetReference(ciphertext);
            ref var outputRef = ref MemoryMarshal.GetReference(plaintext);
            ref var ivRef = ref MemoryMarshal.GetReference(iv);

            var left = ciphertext.Length;

            var key0 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 14));
            var key1 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 15));
            var key2 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 16));
            var key3 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 17));
            var key4 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 18));
            var key5 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 19));
            var key6 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 20));
            var key7 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 21));
            var key8 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 22));
            var key9 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 23));
            var key10 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 24));
            var key11 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 25));
            var key12 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 26));
            var key13 = ReadUnalignedOffset(ref expandedKey, (IntPtr) (BytesPerRoundKey * 27));
            var key14 = ReadUnaligned(ref expandedKey);

            var feedback0 = ReadUnaligned(ref ivRef);

            while (left >= BlockSize * 8)
            {
                var block0 = ReadUnaligned(ref inputRef);
                var block1 = ReadUnalignedOffset(ref inputRef, (IntPtr) (1 * BlockSize));
                var block2 = ReadUnalignedOffset(ref inputRef, (IntPtr) (2 * BlockSize));
                var block3 = ReadUnalignedOffset(ref inputRef, (IntPtr) (3 * BlockSize));
                var block4 = ReadUnalignedOffset(ref inputRef, (IntPtr) (4 * BlockSize));
                var block5 = ReadUnalignedOffset(ref inputRef, (IntPtr) (5 * BlockSize));
                var block6 = ReadUnalignedOffset(ref inputRef, (IntPtr) (6 * BlockSize));
                var block7 = ReadUnalignedOffset(ref inputRef, (IntPtr) (7 * BlockSize));

                var feedback1 = block0;
                var feedback2 = block1;
                var feedback3 = block2;
                var feedback4 = block3;
                var feedback5 = block4;
                var feedback6 = block5;
                var feedback7 = block6;
                var lastIn = block7;

                block0 = Xor(block0, key0);
                block1 = Xor(block1, key0);
                block2 = Xor(block2, key0);
                block3 = Xor(block3, key0);
                block4 = Xor(block4, key0);
                block5 = Xor(block5, key0);
                block6 = Xor(block6, key0);
                block7 = Xor(block7, key0);

                block0 = AesIntrin.Decrypt(block0, key1);
                block1 = AesIntrin.Decrypt(block1, key1);
                block2 = AesIntrin.Decrypt(block2, key1);
                block3 = AesIntrin.Decrypt(block3, key1);
                block4 = AesIntrin.Decrypt(block4, key1);
                block5 = AesIntrin.Decrypt(block5, key1);
                block6 = AesIntrin.Decrypt(block6, key1);
                block7 = AesIntrin.Decrypt(block7, key1);

                block0 = AesIntrin.Decrypt(block0, key2);
                block1 = AesIntrin.Decrypt(block1, key2);
                block2 = AesIntrin.Decrypt(block2, key2);
                block3 = AesIntrin.Decrypt(block3, key2);
                block4 = AesIntrin.Decrypt(block4, key2);
                block5 = AesIntrin.Decrypt(block5, key2);
                block6 = AesIntrin.Decrypt(block6, key2);
                block7 = AesIntrin.Decrypt(block7, key2);

                block0 = AesIntrin.Decrypt(block0, key3);
                block1 = AesIntrin.Decrypt(block1, key3);
                block2 = AesIntrin.Decrypt(block2, key3);
                block3 = AesIntrin.Decrypt(block3, key3);
                block4 = AesIntrin.Decrypt(block4, key3);
                block5 = AesIntrin.Decrypt(block5, key3);
                block6 = AesIntrin.Decrypt(block6, key3);
                block7 = AesIntrin.Decrypt(block7, key3);

                block0 = AesIntrin.Decrypt(block0, key4);
                block1 = AesIntrin.Decrypt(block1, key4);
                block2 = AesIntrin.Decrypt(block2, key4);
                block3 = AesIntrin.Decrypt(block3, key4);
                block4 = AesIntrin.Decrypt(block4, key4);
                block5 = AesIntrin.Decrypt(block5, key4);
                block6 = AesIntrin.Decrypt(block6, key4);
                block7 = AesIntrin.Decrypt(block7, key4);

                block0 = AesIntrin.Decrypt(block0, key5);
                block1 = AesIntrin.Decrypt(block1, key5);
                block2 = AesIntrin.Decrypt(block2, key5);
                block3 = AesIntrin.Decrypt(block3, key5);
                block4 = AesIntrin.Decrypt(block4, key5);
                block5 = AesIntrin.Decrypt(block5, key5);
                block6 = AesIntrin.Decrypt(block6, key5);
                block7 = AesIntrin.Decrypt(block7, key5);

                block0 = AesIntrin.Decrypt(block0, key6);
                block1 = AesIntrin.Decrypt(block1, key6);
                block2 = AesIntrin.Decrypt(block2, key6);
                block3 = AesIntrin.Decrypt(block3, key6);
                block4 = AesIntrin.Decrypt(block4, key6);
                block5 = AesIntrin.Decrypt(block5, key6);
                block6 = AesIntrin.Decrypt(block6, key6);
                block7 = AesIntrin.Decrypt(block7, key6);

                block0 = AesIntrin.Decrypt(block0, key7);
                block1 = AesIntrin.Decrypt(block1, key7);
                block2 = AesIntrin.Decrypt(block2, key7);
                block3 = AesIntrin.Decrypt(block3, key7);
                block4 = AesIntrin.Decrypt(block4, key7);
                block5 = AesIntrin.Decrypt(block5, key7);
                block6 = AesIntrin.Decrypt(block6, key7);
                block7 = AesIntrin.Decrypt(block7, key7);

                block0 = AesIntrin.Decrypt(block0, key8);
                block1 = AesIntrin.Decrypt(block1, key8);
                block2 = AesIntrin.Decrypt(block2, key8);
                block3 = AesIntrin.Decrypt(block3, key8);
                block4 = AesIntrin.Decrypt(block4, key8);
                block5 = AesIntrin.Decrypt(block5, key8);
                block6 = AesIntrin.Decrypt(block6, key8);
                block7 = AesIntrin.Decrypt(block7, key8);

                block0 = AesIntrin.Decrypt(block0, key9);
                block1 = AesIntrin.Decrypt(block1, key9);
                block2 = AesIntrin.Decrypt(block2, key9);
                block3 = AesIntrin.Decrypt(block3, key9);
                block4 = AesIntrin.Decrypt(block4, key9);
                block5 = AesIntrin.Decrypt(block5, key9);
                block6 = AesIntrin.Decrypt(block6, key9);
                block7 = AesIntrin.Decrypt(block7, key9);

                block0 = AesIntrin.Decrypt(block0, key10);
                block1 = AesIntrin.Decrypt(block1, key10);
                block2 = AesIntrin.Decrypt(block2, key10);
                block3 = AesIntrin.Decrypt(block3, key10);
                block4 = AesIntrin.Decrypt(block4, key10);
                block5 = AesIntrin.Decrypt(block5, key10);
                block6 = AesIntrin.Decrypt(block6, key10);
                block7 = AesIntrin.Decrypt(block7, key10);

                block0 = AesIntrin.Decrypt(block0, key11);
                block1 = AesIntrin.Decrypt(block1, key11);
                block2 = AesIntrin.Decrypt(block2, key11);
                block3 = AesIntrin.Decrypt(block3, key11);
                block4 = AesIntrin.Decrypt(block4, key11);
                block5 = AesIntrin.Decrypt(block5, key11);
                block6 = AesIntrin.Decrypt(block6, key11);
                block7 = AesIntrin.Decrypt(block7, key11);

                block0 = AesIntrin.Decrypt(block0, key12);
                block1 = AesIntrin.Decrypt(block1, key12);
                block2 = AesIntrin.Decrypt(block2, key12);
                block3 = AesIntrin.Decrypt(block3, key12);
                block4 = AesIntrin.Decrypt(block4, key12);
                block5 = AesIntrin.Decrypt(block5, key12);
                block6 = AesIntrin.Decrypt(block6, key12);
                block7 = AesIntrin.Decrypt(block7, key12);

                block0 = AesIntrin.Decrypt(block0, key13);
                block1 = AesIntrin.Decrypt(block1, key13);
                block2 = AesIntrin.Decrypt(block2, key13);
                block3 = AesIntrin.Decrypt(block3, key13);
                block4 = AesIntrin.Decrypt(block4, key13);
                block5 = AesIntrin.Decrypt(block5, key13);
                block6 = AesIntrin.Decrypt(block6, key13);
                block7 = AesIntrin.Decrypt(block7, key13);

                block0 = AesIntrin.DecryptLast(block0, key14);
                block1 = AesIntrin.DecryptLast(block1, key14);
                block2 = AesIntrin.DecryptLast(block2, key14);
                block3 = AesIntrin.DecryptLast(block3, key14);
                block4 = AesIntrin.DecryptLast(block4, key14);
                block5 = AesIntrin.DecryptLast(block5, key14);
                block6 = AesIntrin.DecryptLast(block6, key14);
                block7 = AesIntrin.DecryptLast(block7, key14);

                block0 = Xor(block0, feedback0);
                block1 = Xor(block1, feedback1);
                block2 = Xor(block2, feedback2);
                block3 = Xor(block3, feedback3);
                block4 = Xor(block4, feedback4);
                block5 = Xor(block5, feedback5);
                block6 = Xor(block6, feedback6);
                block7 = Xor(block7, feedback7);

                WriteUnaligned(ref outputRef, block0);
                WriteUnalignedOffset(ref outputRef, (IntPtr) (1 * BlockSize), block1);
                WriteUnalignedOffset(ref outputRef, (IntPtr) (2 * BlockSize), block2);
                WriteUnalignedOffset(ref outputRef, (IntPtr) (3 * BlockSize), block3);
                WriteUnalignedOffset(ref outputRef, (IntPtr) (4 * BlockSize), block4);
                WriteUnalignedOffset(ref outputRef, (IntPtr) (5 * BlockSize), block5);
                WriteUnalignedOffset(ref outputRef, (IntPtr) (6 * BlockSize), block6);
                WriteUnalignedOffset(ref outputRef, (IntPtr) (7 * BlockSize), block7);

                feedback0 = lastIn;

                inputRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr) (8 * BlockSize));
                outputRef = ref Unsafe.AddByteOffset(ref outputRef, (IntPtr) (8 * BlockSize));
                left -= BlockSize * 8;
            }

            while (left >= BlockSize)
            {
                var block = ReadUnaligned(ref inputRef);
                var lastIn = block;
                var data = Xor(block, key0);

                data = AesIntrin.Decrypt(data, key1);
                data = AesIntrin.Decrypt(data, key2);
                data = AesIntrin.Decrypt(data, key3);
                data = AesIntrin.Decrypt(data, key4);
                data = AesIntrin.Decrypt(data, key5);
                data = AesIntrin.Decrypt(data, key6);
                data = AesIntrin.Decrypt(data, key7);
                data = AesIntrin.Decrypt(data, key8);
                data = AesIntrin.Decrypt(data, key9);
                data = AesIntrin.Decrypt(data, key10);
                data = AesIntrin.Decrypt(data, key11);
                data = AesIntrin.Decrypt(data, key12);
                data = AesIntrin.Decrypt(data, key13);
                data = AesIntrin.DecryptLast(data, Xor(key14, feedback0));

                WriteUnaligned(ref outputRef, data);

                feedback0 = lastIn;

                inputRef = ref Unsafe.AddByteOffset(ref inputRef, (IntPtr) BlockSize);
                outputRef = ref Unsafe.AddByteOffset(ref outputRef, (IntPtr) BlockSize);
                left -= BlockSize;
            }
        }
    }
}