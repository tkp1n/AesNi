using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static AesNi.Utils;
using static System.Runtime.Intrinsics.X86.Sse2;
using AesIntrin = System.Runtime.Intrinsics.X86.Aes;

namespace AesNi
{
    public static partial class Aes
    {
        public static void EncryptCbc(
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> iv,
            Aes256Key key,
            PaddingMode paddingMode = PaddingMode.Zeros)
        {
            ref var expandedKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref var inputRef = ref MemoryMarshal.GetReference(plaintext);
            ref var outputRef = ref MemoryMarshal.GetReference(ciphertext);

            var position = 0;
            var left = plaintext.Length;

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
            var key11 = ReadUnalignedOffset(ref expandedKey, Kn * 11);
            var key12 = ReadUnalignedOffset(ref expandedKey, Kn * 12);
            var key13 = ReadUnalignedOffset(ref expandedKey, Kn * 13);
            var key14 = ReadUnalignedOffset(ref expandedKey, Kn * 14);

            var feedback = ReadUnalignedOffset(ref MemoryMarshal.GetReference(iv), 0);

            while (left >= BlockSize)
            {
                var block = ReadUnalignedOffset(ref inputRef, position);

                feedback = Xor(block, feedback);
                feedback = Xor(feedback, key0);

                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key1);
                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key2);
                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key3);
                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key4);
                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key5);
                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key6);
                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key7);
                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key8);
                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key9);
                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key10);
                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key11);
                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key12);
                feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key13);
                feedback = System.Runtime.Intrinsics.X86.Aes.EncryptLast(feedback, key14);

                WriteUnalignedOffset(ref outputRef, position, feedback);

                position += BlockSize;
                left -= BlockSize;
            }

            if (paddingMode == PaddingMode.None)
            {
                Debug.Assert(left == 0);
                return;
            }

            Span<byte> lastBlock = stackalloc byte[BlockSize];
            var remainingPlaintext =
                left != 0 ? plaintext.Slice(plaintext.Length - left) : ReadOnlySpan<byte>.Empty;

            ApplyPadding(remainingPlaintext, lastBlock, paddingMode);

            var lBlock = ReadUnalignedOffset(ref MemoryMarshal.GetReference(lastBlock), 0);

            feedback = Xor(lBlock, feedback);
            feedback = Xor(feedback, key0);

            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key1);
            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key2);
            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key3);
            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key4);
            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key5);
            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key6);
            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key7);
            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key8);
            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key9);
            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key10);
            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key11);
            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key12);
            feedback = System.Runtime.Intrinsics.X86.Aes.Encrypt(feedback, key13);
            feedback = System.Runtime.Intrinsics.X86.Aes.EncryptLast(feedback, key14);

            WriteUnalignedOffset(ref outputRef, position, feedback);
        }
        
        public static void DecryptCbc(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            ReadOnlySpan<byte> iv,
            Aes256Key key,
            PaddingMode paddingMode = PaddingMode.Zeros)
        {
            ref var expandedKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref var inputRef = ref MemoryMarshal.GetReference(ciphertext);
            ref var outputRef = ref MemoryMarshal.GetReference(plaintext);

            var position = 0;
            var left = ciphertext.Length;

            var key0 = ReadUnalignedOffset(ref expandedKey, Kn * 14);
            var key1 = ReadUnalignedOffset(ref expandedKey, Kn * 15);
            var key2 = ReadUnalignedOffset(ref expandedKey, Kn * 16);
            var key3 = ReadUnalignedOffset(ref expandedKey, Kn * 17);
            var key4 = ReadUnalignedOffset(ref expandedKey, Kn * 18);
            var key5 = ReadUnalignedOffset(ref expandedKey, Kn * 19);
            var key6 = ReadUnalignedOffset(ref expandedKey, Kn * 20);
            var key7 = ReadUnalignedOffset(ref expandedKey, Kn * 21);
            var key8 = ReadUnalignedOffset(ref expandedKey, Kn * 22);
            var key9 = ReadUnalignedOffset(ref expandedKey, Kn * 23);
            var key10 = ReadUnalignedOffset(ref expandedKey, Kn * 24);
            var key11 = ReadUnalignedOffset(ref expandedKey, Kn * 25);
            var key12 = ReadUnalignedOffset(ref expandedKey, Kn * 26);
            var key13 = ReadUnalignedOffset(ref expandedKey, Kn * 27);
            var key14 = ReadUnalignedOffset(ref expandedKey, Kn * 0);

            var feedback = ReadUnalignedOffset(ref MemoryMarshal.GetReference(iv), 0);

            while (left >= BlockSize)
            {
                var block = ReadUnalignedOffset(ref inputRef, position);
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
                data = AesIntrin.DecryptLast(data, key14);

                data = Xor(data, feedback);

                WriteUnalignedOffset(ref outputRef, position, data);

                feedback = block;

                position += BlockSize;
                left -= BlockSize;
            }
        }
    }
}