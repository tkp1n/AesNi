using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace AesNi.Tests
{
    public class NistKnownAnswerTests
    {
        public static IEnumerable<object[]> GetKatVectors()
        {
            var files = Directory.EnumerateFiles(Path.Combine(Directory.GetCurrentDirectory(), "KAT"), "*.rsp");
            foreach (var file in files.Where(x => Path.GetFileName(x).StartsWith("CBC") || Path.GetFileName(x).StartsWith("ECB"))) // TODO: enable all modes
            {
                var encrypt = false;
                TestSet testSet = null;
                foreach (var line in File.ReadLines(file))
                {
                    if (line.StartsWith("#")) continue;
                    if (line.StartsWith("[ENCRYPT]")) encrypt = true;
                    if (line.StartsWith("[DECRYPT]")) encrypt = false;

                    if (line.StartsWith("COUNT"))
                    {
                        if (testSet != null) yield return new object[] {testSet};

                        testSet = new TestSet();
                        testSet.Name = Path.GetFileName(file).Split(".")[0];
                        testSet.Mode = Enum.Parse<CipherMode>(testSet.Name.Substring(0, 3));
                        testSet.Encrypt = encrypt;
                        testSet.Count = int.Parse(line.Split(" = ")[1]);
                    }

                    if (line.StartsWith("KEY")) testSet.Key = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("IV")) testSet.Iv = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("PLAINTEXT")) testSet.Plaintext = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("CIPHERTEXT")) testSet.Ciphertext = line.Split(" = ")[1].ToByteArray();
                }

                if (testSet != null) yield return new object[] {testSet};
            }
        }

        [Theory]
        [MemberData(nameof(GetKatVectors))]
        public void TestKatVector(TestSet testSet)
        {
            if (testSet.Encrypt)
            {
                var acutal = new byte[testSet.Ciphertext.Length];
                Aes.Encrypt(testSet.Plaintext, acutal, testSet.Iv, AesKey.Create(testSet.Key), testSet.Mode,
                    PaddingMode.None);
                Assert.Equal(testSet.Ciphertext, acutal);
            }
            else
            {
                var acutal = new byte[testSet.Plaintext.Length];
                Aes.Decrypt(testSet.Ciphertext, acutal, testSet.Iv, AesKey.Create(testSet.Key), testSet.Mode,
                    PaddingMode.None);
                Assert.Equal(testSet.Plaintext, acutal);
            }
        }

        public class TestSet
        {
            public string Name { get; set; }
            public bool Encrypt { get; set; }
            public int Count { get; set; }
            public CipherMode Mode { get; set; }
            public byte[] Key { get; set; }
            public byte[] Iv { get; set; }
            public byte[] Plaintext { get; set; }
            public byte[] Ciphertext { get; set; }

            public override string ToString()
            {
                return $"{Name} {(Encrypt ? "enc" : "dec")} {Count}";
            }
        }
    }
}