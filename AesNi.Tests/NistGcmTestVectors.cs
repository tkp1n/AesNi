using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace AesNi.Tests
{
    public class NistGcmTestVectors
    {
        public static IEnumerable<object[]> GetTestVectors()
        {
            foreach (var file in Directory.EnumerateFiles(Path.Combine(Directory.GetCurrentDirectory(), "GCMTestVectors"), "*.rsp"))
            {
                var encrypt = Path.GetFileName(file).Contains("Encrypt");
                TestSet testSet = null;
                foreach (var line in File.ReadLines(file))
                {
                    if (line.StartsWith("#")) continue;
                    if (line.StartsWith("Count"))
                    {
                        if (testSet != null) yield return new object[] {testSet};

                        testSet = new TestSet
                        {
                            Name = Path.GetFileName(file).Split(".")[0],
                            Encrypt = encrypt,
                            Pass = true,
                            Count = int.Parse(line.Split(" = ")[1])
                        };
                    }

                    if (line.StartsWith("Key")) testSet.Key = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("IV")) testSet.Iv = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("PT")) testSet.Plaintext = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("AAD")) testSet.Aad = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("CT")) testSet.Ciphertext = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("Tag")) testSet.Tag = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("FAIL")) testSet.Pass = false;
                }

                if (testSet != null) yield return new object[] {testSet};
            }
        }
        
        [Theory]
        [MemberData(nameof(GetTestVectors))]
        public void TestKatVector(TestSet testSet)
        {
            if (testSet.Encrypt)
            {
                var actualCt = new byte[testSet.Ciphertext?.Length ?? 0];
                var actualTag = new byte[testSet.Tag.Length];
                Aes.Encrypt(testSet.Plaintext, actualCt, testSet.Iv, testSet.Aad, actualTag, AesKey.Create(testSet.Key));
                Assert.Equal(testSet.Ciphertext, actualCt);
                Assert.Equal(testSet.Tag, actualTag);
            }
            else
            {
                var actualPt = new byte[testSet.Plaintext?.Length ?? 0];
                
                var result = Aes.Decrypt(testSet.Ciphertext, actualPt, testSet.Iv, testSet.Aad, testSet.Tag, AesKey.Create(testSet.Key));
                
                Assert.Equal(testSet.Pass, result);
                if (result)
                {
                    Assert.Equal(testSet.Plaintext, actualPt);                    
                }
            }
        }
        
        public class TestSet
        {
            public string Name { get; set; }
            public bool Encrypt { get; set; }
            public int Count { get; set; }
            public byte[] Iv { get; set; }
            public byte[] Key { get; set; }
            public byte[] Plaintext { get; set; }
            public byte[] Ciphertext { get; set; }
            public byte[] Aad { get; set; }
            public byte[] Tag { get; set; }
            public bool Pass { get; set; }
            
            public override string ToString()
            {
                return $"{Name} {(Encrypt ? "enc" : "dec")} {Count}";
            }
        }
    }
}