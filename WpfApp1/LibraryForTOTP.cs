using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;
using System.Linq;
namespace LibraryForTOTP
{
    public static class RFC6238andRFC4226
    {
        public static int GenTOTP(byte[] S, int adjust = 0, int span = 30)
        {
            TimeSpan time = DateTime.UtcNow - new DateTime(1970, 1, 1);
            var counter = (long)time.TotalSeconds / span;
            return GenHOTP(S, counter + adjust);
        }
        public static long GenCounter(long span = 30)
        {
            TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1);
            return (long)ts.TotalSeconds / span;
        }
        public static int GenHOTP(byte[] S, long C, int digit = 6)
        {
            var hmsha = new HMACSHA1();
            hmsha.Key = S;
            var counter = BitConverter.GetBytes(C);
            Array.Reverse(counter, 0, counter.Length);
            var hs = hmsha.ComputeHash(counter);
            return DTruncate(hs) % (int)(Math.Pow(10, digit));
        }
        static int DTruncate(byte[] vs)
        {
            var offset = vs[vs.Length - 1] & 15;
            var P = (vs[offset] << 24 | vs[offset + 1] << 16 | vs[offset + 2] << 8 | vs[offset + 3]) & 0x7fffffff;
            return P;
        }
    }
    public static class RFC4648Base32
    {
        //tuned up 20220312 by dekabutsu(testuser1111111-nd)
        private static readonly char[] table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();
        public static byte[] FromBase32String(string base32string, char padding = '=') => FromBase32CharArray(base32string.ToCharArray(), padding);
        public static string ToBase32String(in byte[] data, char padding = '=') => new(ToBase32CharArray(data, padding));

        public static byte[] FromBase32CharArray(in char[] base32textinput, char padding = '=')
        {
            if (base32textinput == null || base32textinput.Length == 0)
            {
                return Array.Empty<byte>();
            }
            int length = 0;
            for (int i = base32textinput.Length - 1; i >= 0; i--)
            {
                if (base32textinput[i] != padding) { length = i; break; }
            }
            int len2 = (length + 1) % 8 == 0 ? (length + 1) / 8 : ((length + 1) / 8) + 1;
            int len3 = 0;
            int len4 = length + 1 - (len2 - 1) * 8;
            switch (len4)
            {
                case 1: throw new FormatException("Base32 length not appropriate");
                case 2: len3 = 1; break;
                case 3: throw new FormatException("Base32 length not appropriate");
                case 4: len3 = 2; break;
                case 5: len3 = 3; break;
                case 6: throw new FormatException("Base32 length not appropriate");
                case 7: len3 = 4; break;
                case 8: len3 = 5; break;
            }
            byte[] decoded = new byte[len2 * 5 - 5 + len3];
            int index = 0;
            for (int i = 0; i < len2 - 1; i++)
            {
                ulong piece = 0;
                for (int j = 0; j < 8; j++)
                {
                    uint temp = base32textinput[i * 8 + j];
                    //unicodeを数値として扱っている
                    if (temp >= 65 && temp <= 90)
                    {
                        piece |= (ulong)(temp - 65) << 5 * (7 - j);
                    }
                    else if (temp >= 50 && temp <= 55)
                    {

                        piece |= (ulong)(temp - 24) << 5 * (7 - j);
                    }
                    else
                    {
                        throw new FormatException("Letter not appropriate");
                    }

                }
                for (int j = 32; j >= 0; j -= 8)
                {
                    decoded[index++] = (byte)(piece >> j);
                }
            }
            {
                ulong piece2 = 0;
                for (int j = 0; j < length + 1 - ((len2 - 1) * 8); j++)
                {
                    //unicodeを数値として扱っている
                    if (base32textinput[(len2 - 1) * 8 + j] >= 65 && base32textinput[(len2 - 1) * 8 + j] <= 90)
                    {
                        piece2 |= (ulong)(base32textinput[(len2 - 1) * 8 + j] - 65) << 5 * (7 - j);
                    }
                    else if (base32textinput[(len2 - 1) * 8 + j] >= 50 && base32textinput[(len2 - 1) * 8 + j] <= 55)
                    {

                        piece2 |= (ulong)(base32textinput[(len2 - 1) * 8 + j] - 24) << 5 * (7 - j);
                    }
                    else
                    {
                        throw new FormatException("Letter not appropriate");
                    }

                }
                for (int j = 0; j < len3; j++)
                {
                    decoded[index++] = (byte)(piece2 >> (4 - j) * 8);
                }
            }
            return decoded;
        }
        public static char[] ToBase32CharArray(in byte[] data, char padding = '=')
        {
            int divideinto = data.Length % 5 == 0 ? data.Length / 5 : data.Length / 5 + 1;
            if ((long)divideinto * 8 > ((long)1 << 31 - 1))
            {
                throw new ArgumentException("data length too long");
            }
            char[] encoded = new char[divideinto * 8];
            int index = 0;
            int finallength = 8;
            switch (data.Length % 5)
            {
                case 0: finallength = 8; break;
                case 1: finallength = 2; break;
                case 2: finallength = 4; break;
                case 3: finallength = 5; break;
                case 4: finallength = 7; break;
            }
            for (int i = 0; i < divideinto; i++)
            {
                ulong temp = 0;
                for (int j = 0; j < 5; j++)
                {
                    temp <<= 8;
                    if (i * 5 + j < data.Length)
                    {
                        temp |= data[i * 5 + j];
                    }
                }
                for (int j = 0; j < 8; j++)
                {
                    if (i != divideinto - 1 || j < finallength)
                    {
                        encoded[index++] = table[(int)((temp >> 5 * (7 - j)) & 31)];
                    }
                    else
                    {
                        encoded[index++] = padding;
                    }
                }
            }
            return encoded;
        }
    }
}