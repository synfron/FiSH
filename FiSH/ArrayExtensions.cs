using System;

namespace FooIRC.Cryptography.FiSH
{
	public static class ArrayExtensions
	{
		public static  T[] Pad<T>(this T[] array, int mod)
		{
			int remainder = array.Length % mod;
			if (remainder != 0)
			{
				Array.Resize(ref array, mod - remainder + array.Length);
			}
			return array;
		}

		public static T[] Trim<T>(this T[] array, T removeItem)
		{
			int newLength = array.Length;
			while (newLength > 0 && array[newLength - 1].Equals(removeItem))
			{
				newLength--;
			}
			Array.Resize(ref array, newLength);
			return array;
		}
	}
}
