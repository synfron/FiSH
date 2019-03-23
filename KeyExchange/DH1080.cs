/*
 * MIT License
 * 
 * C# Implementation
 * 
 * Copyright (c) 2017 Daquanne Dwight
 * 
 * irccrypt.py - various cryptographic methods for IRC + IRCSRP reference
 * implementation.
 *
 * Copyright (c) 2009, Bjorn Edstrom <be@bjrn.se>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace FooIRC.Cryptography.KeyExchange
{
    public class DH1080
    {
        private int state = 0;
        BigInteger prime = new BigInteger(new byte[] {
            0xFB, 0xE1, 0x02, 0x2E, 0x23, 0xD2, 0x13, 0xE8,
            0xAC, 0xFA, 0x9A, 0xE8, 0xB9, 0xDF, 0xAD, 0xA3,
            0xEA, 0x6B, 0x7A, 0xC7, 0xA7, 0xB7, 0xE9, 0x5A,
            0xB5, 0xEB, 0x2D, 0xF8, 0x58, 0x92, 0x1F, 0xEA,
            0xDE, 0x95, 0xE6, 0xAC, 0x7B, 0xE7, 0xDE, 0x6A,
            0xDB, 0xAB, 0x8A, 0x78, 0x3E, 0x7A, 0xF7, 0xA7,
            0xFA, 0x6A, 0x2B, 0x7B, 0xEB, 0x1E, 0x72, 0xEA,
            0xE2, 0xB7, 0x2F, 0x9F, 0xA2, 0xBF, 0xB2, 0xA2,
            0xEF, 0xBE, 0xFA, 0xC8, 0x68, 0xBA, 0xDB, 0x3E,
            0x82, 0x8F, 0xA8, 0xBA, 0xDF, 0xAD, 0xA3, 0xE4,
            0xCC, 0x1B, 0xE7, 0xE8, 0xAF, 0xE8, 0x5E, 0x96,
            0x98, 0xA7, 0x83, 0xEB, 0x68, 0xFA, 0x07, 0xA7,
            0x7A, 0xB6, 0xAD, 0x7B, 0xEB, 0x61, 0x8A, 0xCF,
            0x9C, 0xA2, 0x89, 0x7E, 0xB2, 0x8A, 0x61, 0x89,
            0xEF, 0xA0, 0x7A, 0xB9, 0x9A, 0x8A, 0x7F, 0xA9,
            0xAE, 0x29, 0x9E, 0xFA, 0x7B, 0xA6, 0x6D, 0xEA,
            0xFE, 0xFB, 0xEF, 0xBF, 0x0B, 0x7D, 0x8B
        });
        readonly BigInteger q;
        readonly BigInteger g = 2;
        readonly BigInteger publicKey = 0;
        readonly BigInteger privateKey = 0;
        BigInteger secret = 0;

        public DH1080()
        {
            q = (prime - 1) / 2;
            while (true)
            {
                byte[] privateKeyBytes = new byte[prime.ToByteArray().Length];
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(privateKeyBytes);
                privateKey = Bytes2Int(privateKeyBytes);
                publicKey = BigInteger.ModPow(g, privateKey, prime);
                if (2 <= publicKey && ValidatePublicKey(publicKey, q, prime))
                {
                    break;
                }
            }
        }

        private bool ValidatePublicKey(BigInteger publicKey, BigInteger q, BigInteger p)
        {
            return 1 == BigInteger.ModPow(publicKey, q, p);
        }

        public string Pack()
        {
            string message;
            if (state == 0)
            {
                state = 1;
                message = "DH1080_INIT ";
            }
            else
            {
                message = "DH1080_FINISH ";
            }

            return message + Encode(Int2Bytes(publicKey));
        }

        public void Unpack(string message)
        {
            if (state == 0)
            {
                state = 1;
                string[] msg = message.Split(new[] { ' ' }, 2);
                string cmd = msg[0];
                string public_raw = msg[1];
                BigInteger publicKey = Bytes2Int(Decode(public_raw));

                if (!(1 < publicKey) || !(publicKey < prime))
                {
                    throw new Exception();
                }

                if (!ValidatePublicKey(publicKey, q, prime))
                {
                    throw new Exception();
                }

                secret = BigInteger.ModPow(publicKey, privateKey, prime);
            }
            else if (state == 1)
            {
                state = 1;
                string[] msg = message.Split(new[] { ' ' }, 2);
                string cmd = msg[0];
                string public_raw = msg[1];
                BigInteger publicKey = Bytes2Int(Decode(public_raw));

                if (!(1 < publicKey) || !(publicKey < prime))
                {
                    throw new Exception();
                }

                if (!ValidatePublicKey(publicKey, q, prime))
                {
                    throw new Exception();
                }

                secret = BigInteger.ModPow(publicKey, privateKey, prime);
            }
        }

        private string Int2Bytes(BigInteger n)
        {
            string b = "";
            if (n == 0)
            {
                return b;
            }
            while (n > 0)
            {
                b = (char)(n % 256) + b;
                n /= 256;
            }
            return b;
        }

        private BigInteger Bytes2Int(byte[] b)
        {
            BigInteger n = new BigInteger();
            foreach (byte p in b)
            {
                n *= 256;
                n += p;
            }
            return n;
        }

        private string Encode(string s)
        {
            string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            int[] d = new int[s.Length * 2];

            int L = s.Length * 8;
            int m = 0x80;
            int i = 0, j = 0, k = 0, t = 0;
            while (i < L)
            {
                if ((s[i >> 3] & m) != 0)
                {
                    t |= 1;
                }
                j += 1;
                m >>= 1;
                if (m == 0)
                {
                    m = 0x80;
                }
                if (j % 6 == 0)
                {
                    d[k] = b64[t];
                    t &= 0;
                    k++;
                }
                t <<= 1;
                t %= 0x100;
                i++;
            }
            m = 5 - j % 6;
            t <<= m;
            t %= 0x100;
            if (m != 0)
            {
                d[k] = b64[t];
                k += 1;
            }

            d[k] = 0;
            string res = "";
            foreach (int q in d)
            {
                if (q == 0)
                {
                    break;
                }
                res += (char)q;
            }
            return res;
        }


        private byte[] Decode(string str)
        {
            string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            int[] buffer = new int[256];
            for (int i = 0; i < 64; i++)
            {
                buffer[b64[i]] = i;
            }

            int L = str.Length;
            for (int i = L - 1; i >= 0; i++)
            {
                if (buffer[str[i]] == 0)
                {
                    L -= 1;
                }
                else
                {
                    break;
                }
            }
            int[] d = new int[L];
            {
                int i = 0;
                int k = 0;
                while (true)
                {
                    i += 1;
                    if (k + 1 < L)
                    {
                        d[i - 1] = buffer[(str[k])] << 2;
                        d[i - 1] %= 0x100;
                    }
                    else
                    {
                        break;
                    }
                    k++;
                    if (k < L)
                    {
                        d[i - 1] |= buffer[str[k]] >> 2;
                    }
                    else
                    {
                        break;
                    }
                    i++;
                    if (k + 1 < L)
                    {
                        d[i - 1] = buffer[str[k]] << 6;
                        d[i - 1] %= 0x100;
                    }
                    else
                    {
                        break;
                    }
                    k++;
                    if (k < L)
                    {
                        d[i - 1] |= buffer[str[k]] % 0x100;
                    }
                    else
                    {
                        break;
                    }
                    k += 1;
                }
                return d.Take(i - 1).Select(x => (byte)x).ToArray();
            }
        }

    }
}
