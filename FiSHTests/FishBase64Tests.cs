using System.Text;
using FooIRC.Cryptography.FiSH;
using Xunit;

namespace FiSHTests
{
	public class FishBase64Tests
	{
		[Theory]
		[InlineData("egg spam", "H34qN/uqQnz/")]
		[InlineData("The quick brown fox jumps over the lazy dog", "xzkrL/ui4oi/uSQrJ/M746F/KPkrE/uuRpA/O/wqz/QX46N/uyBsv/G/gnC/.......qQpy/")]
		public void Encode(string text, string expected)
		{
			string encodedText = Encoding.UTF8.GetString(FishBase64.Encode(Encoding.UTF8.GetBytes(text)));
			Assert.Equal(expected, encodedText);
		}

		[Theory]
		[InlineData("H34qN/uqQnz/", "egg spam")]
		[InlineData("xzkrL/ui4oi/uSQrJ/M746F/KPkrE/uuRpA/O/wqz/QX46N/uyBsv/G/gnC/.......qQpy/", "The quick brown fox jumps over the lazy dog")]
		public void Decode(string text, string expected)
		{
			string decodedText = Encoding.UTF8.GetString(FishBase64.Decode(Encoding.UTF8.GetBytes(text)));
			Assert.Equal(expected, decodedText);
		}
	}
}
