using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;

namespace AesNi
{
    // https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf    
    // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf 
    // https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf
    // http://www.rksm.me/papers/rmanley-indocrypt10.pdf
    public static partial class Aes
    {
        private const int Kn = 4;
        private const int BytesPerRoundKey = 16;
        private const int BlockSize = 16;

        private static readonly Vector128<byte> One = Vector128.Create(0, 0, 1, 0).AsByte();
        private static readonly Vector128<byte> Four = Vector128.Create(0, 0, 4, 0).AsByte();

        private static readonly Vector128<byte> BswapEpi64
            = Vector128.Create((byte) 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);

        private static readonly Vector128<byte> BswapMask
            = Vector128.Create((byte) 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

        // TODO: harmonize default parameter values (e.g. paddingMode)

        public static void Encrypt(ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> iv,
            AesKey key,
            CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (cipherMode != CipherMode.ECB && cipherMode != CipherMode.CBC)
                ThrowHelper.ThrowNotImplementedException();
            if (paddingMode == PaddingMode.None && plaintext.Length % BlockSize != 0)
                ThrowHelper.ThrowInputNotMultipleOfBlockSizeException(nameof(plaintext));
            if (cipherMode == CipherMode.CBC && iv == null)
                ThrowHelper.ThrowArgumentNullException(nameof(iv));
            // TODO: correctly validate ciphertext length
            if (ciphertext.Length < plaintext.Length)
                ThrowHelper.ThrowDestinationBufferTooSmallException(nameof(ciphertext));
            // TODO: moar validation

            switch (cipherMode)
            {
                case CipherMode.ECB:
                    DispatchEncryptEcb(plaintext, ciphertext, key, paddingMode);
                    return;
                case CipherMode.CBC:
                    DispatchEncryptCbc(plaintext, ciphertext, iv, key, paddingMode);
                    return;
            }

            ThrowHelper.ThrowNotImplementedException();
        }

        private static void DispatchEncryptEcb(ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            AesKey key,
            PaddingMode paddingMode)
        {
            switch (key)
            {
                case Aes128Key aes128Key:
                    EncryptEcb(plaintext, ciphertext, aes128Key, paddingMode);
                    return;
                case Aes192Key aes192Key:
                    EncryptEcb(plaintext, ciphertext, aes192Key, paddingMode);
                    return;
                case Aes256Key aes256Key:
                    EncryptEcb(plaintext, ciphertext, aes256Key, paddingMode);
                    return;
            }
        }

        private static void DispatchEncryptCbc(ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> iv,
            AesKey key,
            PaddingMode paddingMode)
        {
            switch (key)
            {
                case Aes128Key aes128Key:
                    EncryptCbc(plaintext, ciphertext, iv, aes128Key, paddingMode);
                    return;
                case Aes192Key aes192Key:
                    EncryptCbc(plaintext, ciphertext, iv, aes192Key, paddingMode);
                    return;
                case Aes256Key aes256Key:
                    EncryptCbc(plaintext, ciphertext, iv, aes256Key, paddingMode);
                    return;
            }
        }

        public static void Encrypt(ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> iv,
            ReadOnlySpan<byte> aad,
            Span<byte> tag,
            AesKey key)
        {
            // TODO: correctly validate ciphertext length
            if (ciphertext.Length < plaintext.Length)
                ThrowHelper.ThrowDestinationBufferTooSmallException(nameof(ciphertext));
            // TODO: moar validation

            switch (key)
            {
                case Aes128Key aes128Key:
                    EncryptGcm(plaintext, ciphertext, aad, iv, tag, aes128Key);
                    return;
                case Aes192Key aes192Key:
                    EncryptGcm(plaintext, ciphertext, aad, iv, tag, aes192Key);
                    return;
                case Aes256Key aes256Key:
                    EncryptGcm(plaintext, ciphertext, aad, iv, tag, aes256Key);
                    return;
            }

            ThrowHelper.ThrowNotImplementedException();
        }

        public static void Decrypt(ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            ReadOnlySpan<byte> iv,
            AesKey key,
            CipherMode cipherMode = CipherMode.CBC,
            PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (cipherMode != CipherMode.ECB && cipherMode != CipherMode.CBC)
                ThrowHelper.ThrowNotImplementedException();
            if (cipherMode == CipherMode.CBC && iv == null)
                ThrowHelper.ThrowArgumentNullException(nameof(iv));
            if (paddingMode != PaddingMode.None)
                ThrowHelper.ThrowPaddingNotSupportedException(paddingMode);
            // TODO: correctly validate plaintext length
            if (plaintext.Length < ciphertext.Length)
                ThrowHelper.ThrowDestinationBufferTooSmallException(nameof(plaintext));
            // TODO: moar validation

            switch (cipherMode)
            {
                case CipherMode.ECB:
                    DispatchDecryptEcb(ciphertext, plaintext, key, paddingMode);
                    return;
                case CipherMode.CBC:
                    DispatchDecryptCbc(ciphertext, plaintext, iv, key, paddingMode);
                    return;
            }

            ThrowHelper.ThrowNotImplementedException();
        }

        private static void DispatchDecryptEcb(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            AesKey key,
            PaddingMode paddingMode)
        {
            switch (key)
            {
                case Aes128Key aes128Key:
                    DecryptEcb(ciphertext, plaintext, aes128Key);
                    break;
                case Aes192Key aes192Key:
                    DecryptEcb(ciphertext, plaintext, aes192Key);
                    break;
                case Aes256Key aes256Key:
                    DecryptEcb(ciphertext, plaintext, aes256Key);
                    break;
            }
        }

        private static void DispatchDecryptCbc(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            ReadOnlySpan<byte> iv,
            AesKey key,
            PaddingMode paddingMode)
        {
            switch (key)
            {
                case Aes128Key aes128Key:
                    DecryptCbc(ciphertext, plaintext, iv, aes128Key);
                    break;
                case Aes192Key aes192Key:
                    DecryptCbc(ciphertext, plaintext, iv, aes192Key);
                    break;
                case Aes256Key aes256Key:
                    DecryptCbc(ciphertext, plaintext, iv, aes256Key);
                    break;
            }
        }

        public static bool Decrypt(ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext,
            ReadOnlySpan<byte> iv,
            ReadOnlySpan<byte> aad,
            ReadOnlySpan<byte> tag,
            AesKey key)
        {
            // TODO: correctly validate ciphertext length
            if (ciphertext.Length < plaintext.Length)
                ThrowHelper.ThrowDestinationBufferTooSmallException(nameof(ciphertext));
            // TODO: moar validation

            switch (key)
            {
                case Aes128Key aes128Key:
                    return DecryptGcm(ciphertext, plaintext, aad, iv, tag, aes128Key);
                case Aes192Key aes192Key:
                    return DecryptGcm(ciphertext, plaintext, aad, iv, tag, aes192Key);
                case Aes256Key aes256Key:
                    return DecryptGcm(ciphertext, plaintext, aad, iv, tag, aes256Key);
            }

            ThrowHelper.ThrowNotImplementedException();
            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyPadding(ReadOnlySpan<byte> remainingBytes, Span<byte> lastBlock,
            PaddingMode paddingMode)
        {
            remainingBytes.CopyTo(lastBlock); // fill last block with remainder of message
            var remainingBytesLength = (byte) remainingBytes.Length;

            switch (paddingMode)
            {
                case PaddingMode.ANSIX923: // fill with zeroes, length of padding in last byte
                    lastBlock[BlockSize - 1] = remainingBytesLength;
                    break;
                case PaddingMode.ISO10126: // fill with random, length of padding in last byte
                    RandomHelper.NextBytes(lastBlock.Slice(remainingBytes.Length)); // fill rest with random bytes
                    lastBlock[BlockSize - 1] = (byte) remainingBytes.Length; // set last byte to length
                    break;
                case PaddingMode.PKCS7: // fill with length of padding
                    lastBlock.Slice(remainingBytes.Length).Fill(remainingBytesLength);
                    break;
                case PaddingMode.Zeros: // fill with zeroes
                    break; // lastBlock assumed to be already zeroed out
                default:
                    ThrowHelper.ThrowPaddingNotSupportedException(paddingMode);
                    break; // unreachable
            }
        }
    }
}