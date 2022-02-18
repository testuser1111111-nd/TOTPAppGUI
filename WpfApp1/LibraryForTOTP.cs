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
        const string tablestring = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        private static char[] table = tablestring.ToCharArray();
        public static int CharToInt(char c) => Array.IndexOf(table, Char.ToUpper(c));
        public static byte[] FromBase32String(string base32text, char padding = '=')
        {
            if (base32text == null || base32text.Length == 0)
            {
                return Array.Empty<byte>();
            }
            base32text = base32text.Trim().TrimEnd(padding);
            long len = base32text.Length;
            const int cutlength = 8;
            long len2 = len % cutlength == 0 ? len / cutlength : (len / cutlength) + 1;
            string[] splitedtext = new string[len2];
            for (int i = 0; i < splitedtext.Length; i++)
            {
                for (int j = i * 8; j < (base32text.Length > (i + 1) * 8 ? (i + 1) * 8 : base32text.Length); j++)
                {
                    splitedtext[i] += base32text[j];
                }
            }
            LinkedList<byte> decoded = new LinkedList<byte>();
            int len3 = 0;
            int len4 = splitedtext[splitedtext.Length - 1].Length;

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
            for (int i = 0; i < splitedtext.Length; i++)
            {
                ulong piece = 0;
                for (int j = 0; j < cutlength; j++)
                {
                    piece <<= 5;
                    if (j < splitedtext[i].Length)
                    {
                        if (CharToInt(splitedtext[i][j]) < 0)
                        {
                            throw new FormatException("Letter not appropriate");
                        }
                        else
                        {
                            piece |= (uint)CharToInt(splitedtext[i][j]);
                        }
                    }
                }
                for (int j = 0; j < 5; j++)
                {
                    ulong aaa = (piece >> (4 - j) * 8) & 255;
                    if (i != splitedtext.Length - 1 | j < len3)
                    {
                        decoded.AddLast((byte)aaa);
                    }
                }
            }
            return decoded.ToArray();
        }
        public static string ToBase32String(byte[] data, char padding = '=')
        {
            const uint mask = 31;
            int divideinto = data.Length % 5 == 0 ? data.Length / 5 : data.Length / 5 + 1;
            StringBuilder encoded = new StringBuilder(divideinto * 8);
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
                    if (i < divideinto - 1 | (i == divideinto - 1 && j < finallength))
                    {
                        encoded.Append(table[(int)((temp >> 5 * (7 - j)) & mask)]);
                    }
                    else
                    {
                        encoded.Append(padding);
                    }
                }
            }
            return encoded.ToString();
        }
    }
}