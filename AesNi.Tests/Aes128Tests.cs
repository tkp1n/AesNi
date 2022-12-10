using System;
using System.Security.Cryptography;
using Xunit;
using AesManaged = System.Security.Cryptography.Aes;

namespace AesNi.Tests
{
    public class Aes128Tests
    {
        // TODO: test all padding modes
        private const int DataSize = 1040;

        [Fact]
        public void ReferenceTest()
        {
            var r = new Random(42);
            var bytes = new byte[DataSize];
            var key = new byte[16];
            r.NextBytes(bytes);
            r.NextBytes(key);

            var managed = AesManaged.Create();
            managed.Key = key;
            managed.Mode = CipherMode.ECB;
            managed.Padding = PaddingMode.None;
            var managedResult = managed.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);

            var niResult = new byte[DataSize];
            Aes.Encrypt(bytes, niResult, null, new Aes128Key(key), CipherMode.ECB, PaddingMode.None);

            Assert.Equal(managedResult, niResult);
        }

        [Fact]
        public void ReferenceTestCbc()
        {
            var r = new Random(42);
            var bytes = new byte[DataSize];
            var key = new byte[16];
            var iv = new byte[16];
            r.NextBytes(bytes);
            r.NextBytes(key);
            r.NextBytes(iv);

            var managed = AesManaged.Create();
            managed.Key = key;
            managed.IV = iv;
            managed.Mode = CipherMode.CBC;
            managed.Padding = PaddingMode.None;
            var managedResult = managed.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);

            var niResult = new byte[DataSize];
            Aes.EncryptCbc(bytes, niResult, iv, new Aes128Key(key), PaddingMode.None);

            Assert.Equal(managedResult, niResult);
        }

        [Fact]
        public void SelfTest()
        {
            var r = new Random(42);
            var plain = new byte[DataSize];
            var key = new byte[16];
            r.NextBytes(plain);
            r.NextBytes(key);

            var cipher = new byte[DataSize];
            var plainAgain = new byte[DataSize];
            var k = new Aes128Key(key);

            Aes.EncryptEcb(plain, cipher, k, PaddingMode.None);
            Aes.DecryptEcb(cipher, plainAgain, k, PaddingMode.None);

            Assert.Equal(plain, plainAgain);
        }

        [Fact]
        public void SelfTestCbc()
        {
            var r = new Random(42);
            var plain = new byte[DataSize];
            var key = new byte[16];
            var iv = new byte[16];
            r.NextBytes(plain);
            r.NextBytes(key);
            r.NextBytes(iv);

            var cipher = new byte[DataSize];
            var plainAgain = new byte[DataSize];
            var k = new Aes128Key(key);

            Aes.EncryptCbc(plain, cipher, iv, k, PaddingMode.None);
            Aes.DecryptCbc(cipher, plainAgain, iv, k, PaddingMode.None);

            Assert.Equal(plain, plainAgain);
        }
    }
}