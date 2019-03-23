using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace FooIRC.Cryptography.FiSH
{
	public class Fish
	{
		private readonly CipherMode _mode;
		private readonly Encoding _encoding;
		private readonly BlowfishManaged.BlowfishManaged _cipher;

		public int BlockSize { get; private set; }

		public Fish(string key, CipherMode mode = CipherMode.ECB, Encoding encoding = null)
		{
			if (mode != CipherMode.CBC && mode != CipherMode.ECB)
			{
				throw new ArgumentException("Cipher mode not supported.");
			}
			_mode = mode;
			_encoding = encoding ?? Encoding.UTF8;
			_cipher = new BlowfishManaged.BlowfishManaged(_encoding.GetBytes(key));
			_cipher.GenerateIV();
			BlockSize = _cipher.BlockSize / 8;
		}

		public string Encrypt(string message)
		{
			if (_mode == CipherMode.CBC)
			{
				byte[] enc = CbcEncrypt(_encoding.GetBytes(message).Pad(BlockSize));
				return "+OK *" + Convert.ToBase64String(enc);
			}
			else
			{
				byte[] enc = EcbEncrypt(_encoding.GetBytes(message).Pad(BlockSize));
				return "+OK " + _encoding.GetString(FishBase64.Encode(enc));
			}
		}

		public string Decrypt(string message)
		{
			if (message.StartsWith("+OK "))
			{
				message = message.Substring(4);
			}
			else if (message.StartsWith("mcps "))
			{
				message = message.Substring(5);
			}
			else
			{
				return message;
			}

			byte[] plainText;
			byte[] cipherText;
			if (message.StartsWith("*"))
			{
				cipherText = Convert.FromBase64String(message.Remove(0, 1));
				plainText = CbcDecrypt(cipherText.Pad(BlockSize));
			}
			else
			{
				cipherText = FishBase64.Decode(_encoding.GetBytes(message));
				plainText = EcbDecrypt(cipherText.Pad(BlockSize));
			}
			return _encoding.GetString(plainText);
		}

		private byte[] EcbEncrypt(byte[] plainText)
		{
			List<byte> cipherText = new List<byte>(plainText.Length);
			for (int i = 0; i < plainText.Length; i += BlockSize)
			{
				cipherText.AddRange(_cipher.EncryptSingleBlock(plainText, i));
			}
			return cipherText.ToArray();
		}

		private byte[] EcbDecrypt(byte[] cipherText)
		{
			List<byte> plainText = new List<byte>(cipherText.Length);
			for (int i = 0; i < cipherText.Length; i += BlockSize)
			{
				plainText.AddRange(_cipher.DecryptSingleBlock(cipherText, i));
			}
			return plainText.ToArray().Trim((byte)0);
		}
		
		private byte[] CbcEncrypt(byte[] plainText)
		{
			byte[] iv = _cipher.IV;
			List<byte> cipherText = new List<byte>(plainText.Length + BlockSize);
			byte[] xorData = new byte[BlockSize];
			cipherText.AddRange(iv);
			for (int offset = 0; offset < plainText.Length; offset += BlockSize)
			{
				for (int i = 0; i < BlockSize; i++)
				{
					xorData[i] = (byte)(plainText[i + offset] ^ iv[i]);
				}
				iv = _cipher.EncryptSingleBlock(xorData, 0);
				cipherText.AddRange(iv);
			}
			return cipherText.ToArray();
		}

		private byte[] CbcDecrypt(byte[] cipherText)
		{
			byte[] plainText = new byte[cipherText.Length - BlockSize];
			for (int offset = 0; offset < plainText.Length; offset += BlockSize)
			{
				byte[] decyptedBytes = _cipher.DecryptSingleBlock(cipherText, offset + BlockSize);
				for (int i = 0; i < BlockSize; i++)
				{
					plainText[offset + i] = (byte)(decyptedBytes[i] ^ cipherText[i + offset]);
				}
			}
			return plainText.Trim((byte)0);
		}
	}
}
