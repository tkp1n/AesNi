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
            var files = Directory.EnumerateFiles(Path.Combine(Directory.GetCurrentDirectory(), "GCMTestVectors"), "*.rsp");
            foreach (var file in files.Where(x => Path.GetFileName(x).Contains("Encrypt") && Path.GetFileName(x).Contains("128"))) // TODO: enable all modes
            {
                TestSet testSet = null;
                foreach (var line in File.ReadLines(file))
                {
                    if (line.StartsWith("#")) continue;
                    var encrypt = Path.GetFileName(file).Contains("Encrypt");

                    if (line.StartsWith("Count"))
                    {
                        if (testSet != null) yield return new object[] {testSet};

                        testSet = new TestSet();
                        testSet.Name = Path.GetFileName(file).Split(".")[0];
                        testSet.Encrypt = encrypt;
                        testSet.Count = int.Parse(line.Split(" = ")[1]);
                    }

                    if (line.StartsWith("Key")) testSet.Key = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("IV")) testSet.Iv = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("PT")) testSet.Plaintext = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("AAD")) testSet.Aad = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("CT")) testSet.Ciphertext = line.Split(" = ")[1].ToByteArray();
                    if (line.StartsWith("Tag")) testSet.Tag = line.Split(" = ")[1].ToByteArray();
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
                var acutalCt = new byte[testSet.Ciphertext.Length];
                var acutalTag = new byte[testSet.Tag.Length];
                Aes.EncryptGcm(testSet.Plaintext, acutalCt, testSet.Aad, testSet.Iv, acutalTag, new Aes128Key(testSet.Key));
                Assert.Equal(testSet.Ciphertext, acutalCt);
                Assert.Equal(testSet.Tag, acutalTag);
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
            
            public override string ToString()
            {
                return $"{Name} {(Encrypt ? "enc" : "dec")} {Count}";
            }
        }
    }
}