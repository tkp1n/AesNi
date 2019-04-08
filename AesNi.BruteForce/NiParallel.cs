using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;

namespace AesNi.BruteForce
{
    public class NiParallel
    {
        private static volatile bool _stop;

        private static ReadOnlySpan<byte> Trust => new byte[] {0x74, 0x72, 0x75, 0x73, 0x74};

        private static void BruteForce(object param)
        {
            var startEnd = (StartEnd) param;
            var cipherText = Convert.FromBase64String(
                "yptyoDdVBdQtGhgoePppYHnWyugGmy0j81sf3zBeUXEO/LYRw+2XmVa0/v6YiSy9Kj8gMn/gNu2I7dPmfgSEHPUDJpNpiOWmmW1/jw/Pt29Are5tumWmnfkazcAb23xe7B4ruPZVxUEhfn/IrZPNZdr4cQNrHNgEv2ts8gVFuOBU+p792UPy8/mEIhW5ECppxGIb7Yrpg4w7IYNeFtX5d9W4W1t2e+6PcdcjkBK4a8y1cjEtuQ07RpPChOvLcSzlB/Bg7UKntzorRsn+y/d72qD2QxRzcXgbynCNalF7zaT6pEnwKB4i05fTQw6nB7SU1w2/EvCGlfiyR2Ia08mA0GikqegYA6xG/EAGs3ZJ0aQUGt0YZz0P7uBsQKdmCg7jzzEMHyGZDNGTj0F2dOFHLSOTT2/GGSht8eD/Ae7u/xnJj0bGgAKMtNttGFlNyvKpt2vDDT3Orfk6Jk/rD4CIz6O/Tnt0NkJLucHtIyvBYGtQR4+mhbfUELkczeDSxTXGDLaiU3de6tPaa0/vjzizoUbNFdfkIly/HWINdHoO83E=");
            var iv = Convert.FromBase64String("DkBbcmQo1QH+ed1wTyBynA==");

            var plaintext = new byte[cipherText.Length];
            var key = new byte[32];
            var k = AesKey.Create(key);

            ref var a = ref key[0];
            ref var b = ref key[1];
            ref var c = ref key[2];
            ref var d = ref key[3];
            ref var e = ref key[4];
            ref var f = ref key[5];

            for (a = startEnd.Start; a <= startEnd.End; a++)
            for (b = 0; b <= 16; b++)
            for (c = 0; c <= 16; c++)
            for (d = 0; d <= 16; d++)
            for (e = 0; e <= 16; e++)
            for (f = 0; f <= 16; f++)
            {
                if (_stop) return;
                k.ReKey(key);

                Aes.Decrypt(cipherText, plaintext, iv, k, CipherMode.CBC, PaddingMode.None);
                if (plaintext.AsSpan().IndexOf(Trust) >= 0)
                {
                    _stop = true;
                    return;
                }
            }
        }

        private static StartEnd[] SplitWork(int threads)
        {
            Debug.Assert(16 % threads == 0);

            var workPerThread = 16 / threads;
            var parameters = new StartEnd[threads];
            int i;
            for (i = 0; i < parameters.Length - 1; i++)
                parameters[i] = new StartEnd((byte) (i * workPerThread), (byte) (i * workPerThread + workPerThread));

            parameters[i] = new StartEnd((byte) (i * workPerThread), 17);

            return parameters;
        }

        public static void Run()
        {
            var physicalCores = Environment.ProcessorCount / 2;
            var work = SplitWork(physicalCores > 16 ? 16 : physicalCores);
            var thread = new Thread[work.Length];

            // Using reverse loop to start thread with most work first
            for (var i = work.Length - 1; i >= 0; i--)
            {
                var t = new Thread(p => BruteForce(p));
                t.Start(work[i]);
                thread[i] = t;
            }

            for (var i = thread.Length - 1; i >= 0; i--) thread[i].Join();
        }
    }
    
    class StartEnd
    {
        public readonly byte End;
        public readonly byte Start;

        public StartEnd(byte start, byte end)
        {
            Start = start;
            End = end;
        }
    }
}