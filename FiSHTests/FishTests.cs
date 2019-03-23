using System.Security.Cryptography;
using FooIRC.Cryptography.FiSH;
using Xunit;

namespace FiSHTests
{
	public class FishTests
	{
		[Theory]
		[InlineData("The quick brown fox jumps over the lazy dog", "unladen swallow", "+OK zT/uX.Z4Q3A/G4YzZ02hMhT1mAsBo.iVKz71YPSQz/trfT4/srrS611D5Qz.cnm/71snKIp0")]
		[InlineData("Automatically switch to any channel you are joined to that receives a new user message. The addin will switch servers as well if the channel with activity is on a different server view.To stop automatically switching at any time send the command /stay in a channel.", "123456781234567812345", "+OK KKI7d/iGdDj/EX3.u.s8Ned0257v903M9EP16EspO.FOWkX/t/5SK.1xZ.h.tln8D0Xdl5H00.Gqr.iBxtG/9bHwH0.mCrD.jfwmN0ibMvz.waDvm0POIlj.fc6dA1Fmz2I.VQbim/pc3EF1HDGJK1PRF9z1qCiQ11UADif1KKeMs0WQHDn1ee9eV/SQabp0vKCs8/3ossY1JzbOP1FFBxO.SyAjj1AzH0X/exDqZ00Wikc0RgqgS1ravYE.tg85Y/5XsW70JANk7.ul40Q.FxhPL/.xDW21NsdvD0KxeoT1s8TjL1QIf0M.TwZzy0QH.U11Byzm4.QjF2Z1OQj6F.gV/Ww/GVFQY07JoYk0exTpB.bu4y5.3sMrm10NQTK.KFr0z.Irpqs/Kf8J50Cqa56.")]
		public void EcbEncrypt(string text, string key, string expected)
		{
			Fish fishCipher = new Fish(key);
			Assert.Equal(expected, fishCipher.Encrypt(text));
		}

		[Theory]
		[InlineData("+OK zT/uX.Z4Q3A/G4YzZ02hMhT1mAsBo.iVKz71YPSQz/trfT4/srrS611D5Qz.cnm/71snKIp0", "unladen swallow", "The quick brown fox jumps over the lazy dog")]
		[InlineData("+OK KKI7d/iGdDj/EX3.u.s8Ned0257v903M9EP16EspO.FOWkX/t/5SK.1xZ.h.tln8D0Xdl5H00.Gqr.iBxtG/9bHwH0.mCrD.jfwmN0ibMvz.waDvm0POIlj.fc6dA1Fmz2I.VQbim/pc3EF1HDGJK1PRF9z1qCiQ11UADif1KKeMs0WQHDn1ee9eV/SQabp0vKCs8/3ossY1JzbOP1FFBxO.SyAjj1AzH0X/exDqZ00Wikc0RgqgS1ravYE.tg85Y/5XsW70JANk7.ul40Q.FxhPL/.xDW21NsdvD0KxeoT1s8TjL1QIf0M.TwZzy0QH.U11Byzm4.QjF2Z1OQj6F.gV/Ww/GVFQY07JoYk0exTpB.bu4y5.3sMrm10NQTK.KFr0z.Irpqs/Kf8J50Cqa56.", "123456781234567812345", "Automatically switch to any channel you are joined to that receives a new user message. The addin will switch servers as well if the channel with activity is on a different server view.To stop automatically switching at any time send the command /stay in a channel.")]
		public void EcbDecrypt(string text, string key, string expected)
		{
			Fish fishCipher = new Fish(key);
			Assert.Equal(expected, fishCipher.Decrypt(text));
		}

		[Theory]
		[InlineData("+OK *C/Tewfid2vcfWq0YpmVwnGMflO79MbkjHcOxW1T384H0lpP4PAf3bY1ctRjM+rPZmJkhf0GCtiE=", "unladen swallow", "The quick brown fox jumps over the lazy dog")]
		[InlineData("+OK *+JXLiMH79ZNZu49aKbY+VuuEMOCN1F6ZQ4QNMwxufw6hN6svepvfGb6l+s7+vVElVpYAThsy9MW8OxpiEO3iKepGW2tEZeicNoikG77d2phf2O+y3MrsAR0z7Iob/dqFkE0TtcKDU5aW1+UGL3hC44/FXkz6+twrDFDyQ5QXuVPXDn3dG7ep9WNBAhm+S76l2muZz6PGBbrcW+b/mWxBL9GiEfPZ361hKZgO5z9t/gqTwhBa85UPD5W0WdYxKT6I1K2GWzwE6iWRlZbtCfjf66PKbgf8Ea+nBeZNdytwVIY+AvDrXOFTuiv/VwmkyCH46WZw6VAZMmf71+Be98YoGzFaushw8l/sIs00OXvffeAUQWbdNP93mw==", "123456781234567812345", "Automatically switch to any channel you are joined to that receives a new user message. The addin will switch servers as well if the channel with activity is on a different server view.To stop automatically switching at any time send the command /stay in a channel.")]
		public void CbcDecrypt(string text, string key, string expected)
		{
			Fish fishCipher = new Fish(key, CipherMode.CBC);
			Assert.Equal(expected, fishCipher.Decrypt(text));
		}

		[Theory]
		[InlineData("The quick brown fox jumps over the lazy dog", "unladen swallow")]
		[InlineData("Automatically switch to any channel you are joined to that receives a new user message. The addin will switch servers as well if the channel with activity is on a different server view.To stop automatically switching at any time send the command /stay in a channel.", "123456781234567812345")]
		public void CbcEncyptDecrypt(string text, string key)
		{
			Fish fishCipher = new Fish(key, CipherMode.CBC);
			Assert.Equal(text, fishCipher.Decrypt(fishCipher.Encrypt(text)));
		}
	}
}
