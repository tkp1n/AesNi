using System;
using System.Security.Cryptography;
using Xunit;

namespace AesNi.Tests
{
    public class Aes192Tests
    {
        // TODO: test against NIST test vectors
        private const int DataSize = 1040;

        [Fact]
        public void ReferenceTest()
        {
            var r = new Random(42);
            var bytes = new byte[DataSize];
            var key = new byte[24];
            r.NextBytes(bytes);
            r.NextBytes(key);

            var managed = new AesManaged {Key = key, Mode = CipherMode.ECB, Padding = PaddingMode.None};
            var managedResult = managed.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);

            var niResult = new byte[DataSize];
            Aes.EncryptEcb(bytes, niResult, new Aes192Key(key));

            Assert.Equal(managedResult, niResult);
        }

        [Fact]
        public void ReferenceTestCbc()
        {
            var r = new Random(42);
            var bytes = new byte[DataSize];
            var key = new byte[24];
            var iv = new byte[16];
            r.NextBytes(bytes);
            r.NextBytes(key);
            r.NextBytes(iv);

            var managed = new AesManaged {Key = key, IV = iv, Mode = CipherMode.CBC, Padding = PaddingMode.None};
            var managedResult = managed.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);

            var niResult = new byte[DataSize];
            Aes.EncryptCbc(bytes, niResult, iv, new Aes192Key(key));

            Assert.Equal(managedResult, niResult);
        }

        [Fact]
        public void SelfTest()
        {
            var r = new Random(42);
            var plain = new byte[DataSize];
            var key = new byte[24];
            r.NextBytes(plain);
            r.NextBytes(key);

            var cipher = new byte[DataSize];
            var plainAgain = new byte[DataSize];
            var k = new Aes192Key(key);

            Aes.EncryptEcb(plain, cipher, k);
            Aes.DecryptEcb(cipher, plainAgain, k);

            Assert.Equal(plain, plainAgain);
        }
        
        [Fact]
        public void SelfTestCbc()
        {
            var r = new Random(42);
            var plain = new byte[DataSize];
            var key = new byte[24];
            var iv = new byte[16];
            r.NextBytes(plain);
            r.NextBytes(key);
            r.NextBytes(iv);

            var cipher = new byte[DataSize];
            var plainAgain = new byte[DataSize];
            var k = new Aes192Key(key);

            Aes.EncryptCbc(plain, cipher, iv, k);
            Aes.DecryptCbc(cipher, plainAgain, iv, k);

            Assert.Equal(plain, plainAgain);
        }
    }
}