using System;

namespace AesNi.Tests
{
    public static class TestHelper
    {
        public static byte[] ToByteArray(this string hex)
        {
            if (hex.Length % 2 != 0) hex = "0" + hex;

            var NumberChars = hex.Length;
            var bytes = new byte[NumberChars / 2];
            for (var i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}