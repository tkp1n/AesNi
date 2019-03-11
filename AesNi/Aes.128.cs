using System;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static AesNi.Utils;
using static System.Runtime.Intrinsics.X86.Sse2;
using AesIntrin = System.Runtime.Intrinsics.X86.Aes;

namespace AesNi
{
    // https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf    
    // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf 
    public static partial class Aes
    {
        private const int Kn = 4;
        private const int BlockSize = 16;

        public static void EncryptEcb(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Aes128Key key)
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

            while (left >= BlockSize * 8)
            {
                var block0 = ReadUnalignedOffset(ref inputRef, position + 0 * BlockSize);
                var block1 = ReadUnalignedOffset(ref inputRef, position + 1 * BlockSize);
                var block2 = ReadUnalignedOffset(ref inputRef, position + 2 * BlockSize);
                var block3 = ReadUnalignedOffset(ref inputRef, position + 3 * BlockSize);
                var block4 = ReadUnalignedOffset(ref inputRef, position + 4 * BlockSize);
                var block5 = ReadUnalignedOffset(ref inputRef, position + 5 * BlockSize);
                var block6 = ReadUnalignedOffset(ref inputRef, position + 6 * BlockSize);
                var block7 = ReadUnalignedOffset(ref inputRef, position + 7 * BlockSize);

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

                // Round 9
                block0 = AesIntrin.EncryptLast(block0, key10);
                block1 = AesIntrin.EncryptLast(block1, key10);
                block2 = AesIntrin.EncryptLast(block2, key10);
                block3 = AesIntrin.EncryptLast(block3, key10);
                block4 = AesIntrin.EncryptLast(block4, key10);
                block5 = AesIntrin.EncryptLast(block5, key10);
                block6 = AesIntrin.EncryptLast(block6, key10);
                block7 = AesIntrin.EncryptLast(block7, key10);

                WriteUnalignedOffset(ref outputRef, position + 0 * BlockSize, block0);
                WriteUnalignedOffset(ref outputRef, position + 1 * BlockSize, block1);
                WriteUnalignedOffset(ref outputRef, position + 2 * BlockSize, block2);
                WriteUnalignedOffset(ref outputRef, position + 3 * BlockSize, block3);
                WriteUnalignedOffset(ref outputRef, position + 4 * BlockSize, block4);
                WriteUnalignedOffset(ref outputRef, position + 5 * BlockSize, block5);
                WriteUnalignedOffset(ref outputRef, position + 6 * BlockSize, block6);
                WriteUnalignedOffset(ref outputRef, position + 7 * BlockSize, block7);

                position += BlockSize * 8;
                left -= BlockSize * 8;
            }

            while (left >= BlockSize)
            {
                var block = ReadUnalignedOffset(ref inputRef, position);

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
                block = AesIntrin.EncryptLast(block, key10);

                WriteUnalignedOffset(ref outputRef, position, block);

                position += BlockSize;
                left -= BlockSize;
            }
        }

        public static void EncryptCbc(
            ReadOnlySpan<byte> plaintext, 
            Span<byte> ciphertext, 
            ReadOnlySpan<byte> iv, 
            Aes128Key key)
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

            var feedback = ReadUnalignedOffset(ref MemoryMarshal.GetReference(iv), 0);

            while (left >= BlockSize)
            {
                var block = ReadUnalignedOffset(ref inputRef, position);

                feedback = Xor(block, feedback);
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
                feedback = AesIntrin.EncryptLast(feedback, key10);
                
                WriteUnalignedOffset(ref outputRef, position, feedback);
                
                position += BlockSize;
                left -= BlockSize;
            }
        }
        
        public static void DecryptEcb(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, Aes128Key key)
        {
            ref var expandedKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref var inputRef = ref MemoryMarshal.GetReference(ciphertext);
            ref var outputRef = ref MemoryMarshal.GetReference(plaintext);

            var position = 0;
            var left = ciphertext.Length;

            var key0 = ReadUnalignedOffset(ref expandedKey, Kn * 10);
            var key1 = ReadUnalignedOffset(ref expandedKey, Kn * 11);
            var key2 = ReadUnalignedOffset(ref expandedKey, Kn * 12);
            var key3 = ReadUnalignedOffset(ref expandedKey, Kn * 13);
            var key4 = ReadUnalignedOffset(ref expandedKey, Kn * 14);
            var key5 = ReadUnalignedOffset(ref expandedKey, Kn * 15);
            var key6 = ReadUnalignedOffset(ref expandedKey, Kn * 16);
            var key7 = ReadUnalignedOffset(ref expandedKey, Kn * 17);
            var key8 = ReadUnalignedOffset(ref expandedKey, Kn * 18);
            var key9 = ReadUnalignedOffset(ref expandedKey, Kn * 19);
            var key10 = ReadUnalignedOffset(ref expandedKey, Kn * 0);

            while (left >= BlockSize * 8)
            {
                var block0 = ReadUnalignedOffset(ref inputRef, position + 0 * BlockSize);
                var block1 = ReadUnalignedOffset(ref inputRef, position + 1 * BlockSize);
                var block2 = ReadUnalignedOffset(ref inputRef, position + 2 * BlockSize);
                var block3 = ReadUnalignedOffset(ref inputRef, position + 3 * BlockSize);
                var block4 = ReadUnalignedOffset(ref inputRef, position + 4 * BlockSize);
                var block5 = ReadUnalignedOffset(ref inputRef, position + 5 * BlockSize);
                var block6 = ReadUnalignedOffset(ref inputRef, position + 6 * BlockSize);
                var block7 = ReadUnalignedOffset(ref inputRef, position + 7 * BlockSize);

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

                // Round 9
                block0 = AesIntrin.DecryptLast(block0, key10);
                block1 = AesIntrin.DecryptLast(block1, key10);
                block2 = AesIntrin.DecryptLast(block2, key10);
                block3 = AesIntrin.DecryptLast(block3, key10);
                block4 = AesIntrin.DecryptLast(block4, key10);
                block5 = AesIntrin.DecryptLast(block5, key10);
                block6 = AesIntrin.DecryptLast(block6, key10);
                block7 = AesIntrin.DecryptLast(block7, key10);

                WriteUnalignedOffset(ref outputRef, position + 0 * BlockSize, block0);
                WriteUnalignedOffset(ref outputRef, position + 1 * BlockSize, block1);
                WriteUnalignedOffset(ref outputRef, position + 2 * BlockSize, block2);
                WriteUnalignedOffset(ref outputRef, position + 3 * BlockSize, block3);
                WriteUnalignedOffset(ref outputRef, position + 4 * BlockSize, block4);
                WriteUnalignedOffset(ref outputRef, position + 5 * BlockSize, block5);
                WriteUnalignedOffset(ref outputRef, position + 6 * BlockSize, block6);
                WriteUnalignedOffset(ref outputRef, position + 7 * BlockSize, block7);

                position += BlockSize * 8;
                left -= BlockSize * 8;
            }

            while (left >= BlockSize)
            {
                var block = ReadUnalignedOffset(ref inputRef, position);

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
                block = AesIntrin.DecryptLast(block, key10);

                WriteUnalignedOffset(ref outputRef, position, block);

                position += BlockSize;
                left -= BlockSize;
            }
        }

        public static void DecryptCbc(
            ReadOnlySpan<byte> ciphertext, 
            Span<byte> plaintext, 
            ReadOnlySpan<byte> iv,
            Aes128Key key)
        {
            ref var expandedKey = ref MemoryMarshal.GetReference(key.ExpandedKey);
            ref var inputRef = ref MemoryMarshal.GetReference(ciphertext);
            ref var outputRef = ref MemoryMarshal.GetReference(plaintext);

            var position = 0;
            var left = ciphertext.Length;

            var key0 = ReadUnalignedOffset(ref expandedKey, Kn * 10);
            var key1 = ReadUnalignedOffset(ref expandedKey, Kn * 11);
            var key2 = ReadUnalignedOffset(ref expandedKey, Kn * 12);
            var key3 = ReadUnalignedOffset(ref expandedKey, Kn * 13);
            var key4 = ReadUnalignedOffset(ref expandedKey, Kn * 14);
            var key5 = ReadUnalignedOffset(ref expandedKey, Kn * 15);
            var key6 = ReadUnalignedOffset(ref expandedKey, Kn * 16);
            var key7 = ReadUnalignedOffset(ref expandedKey, Kn * 17);
            var key8 = ReadUnalignedOffset(ref expandedKey, Kn * 18);
            var key9 = ReadUnalignedOffset(ref expandedKey, Kn * 19);
            var key10 = ReadUnalignedOffset(ref expandedKey, Kn * 0);

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
                data = AesIntrin.DecryptLast(data, key10);
                
                data = Xor(data, feedback);
                
                WriteUnalignedOffset(ref outputRef, position, data);

                feedback = block;
                
                position += BlockSize;
                left -= BlockSize;
            }
        }
    }
}