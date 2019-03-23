/*
 * MIT License
 * 
 * C# Implementation
 * 
 * Copyright (c) 2017 Daquanne Dwight
 * 
 * Based on Go implementation
 *
 * Copyright (c) 2013-2016 Martin Polden
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

namespace FooIRC.Cryptography.FiSH
{
	public class FishBase64
	{
		private const string Base64Charset = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		
		public static byte[] Encode(byte[] plainText)
		{
			plainText = plainText.Pad(8);

			byte[] buf = new byte[plainText.Length / 2 * 3];
			uint left = 0, right = 0;
			
			for (int j = 0, k = 0; k < plainText.Length;)
			{
				for (int i = 24; i >= 0; i = i - 8, k++)
				{
					left += (uint)plainText[k] << (byte)i;
				}
				for (int i = 24; i >= 0; i = i - 8, k++)
				{
					right += (uint)plainText[k] << (byte)i;
				}
				for (int i = 0; i < 6; i = i + 1, j++)
				{
					buf[j] = (byte)Base64Charset[(int)right & 0x3F];
					right >>= 6;
				}
				for (int i = 0; i < 6; i = i + 1, j++)
				{
					buf[j] = (byte)Base64Charset[(int)left & 0x3F];
					left >>= 6;
				}
			}
			return buf;
		}
		
		public static byte[] Decode(byte[] encodedText)
		{
			if (encodedText.Length > 0 && encodedText.Length < 12)
			{
				throw new ArgumentException("Invalid base64 input");
			}

			byte[] plainText = new byte[encodedText.Length / 2 * 3];

			for (int j = 0, k = 0; k < encodedText.Length;)
			{
				uint left = 0, right = 0;
				for (byte i = 0; i < 6; i = (byte)(i + 1), k = k + 1)
				{
					uint v = (uint)Base64Charset.IndexOf((char)encodedText[k]);
					right |= v << (i * 6);
				}
				for (byte i = 0; i < 6; i = (byte)(i + 1), k = k + 1)
				{
					uint v = (uint)Base64Charset.IndexOf((char)encodedText[k]);
					left |= v << (i * 6);
				}
				for (byte i = 0; i < 4; i = (byte)(i + 1), j = j + 1)
				{
					uint w = (uint)(left & (0xFF << ((3 - i) * 8)));
					uint z = w >> ((3 - i) * 8);
					plainText[j] = (byte)z;
				}
				for (byte i = 0; i < 4; i = (byte)(i + 1), j = j + 1)
				{
					uint w = (uint)(right & (0xFF << ((3 - i) * 8)));
					uint z = w >> ((3 - i) * 8);
					plainText[j] = (byte)z;
				}
			}
			return plainText.Trim((byte)0);
		}
	}
}
