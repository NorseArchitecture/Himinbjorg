using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace Norse.Identity.Web.Server.Tests;

public sealed class IdentityTokensTests
{
	[Fact]
	void A_Base64Url_code_decodes_to_the_token_it_encodes()
	{
		const string Token = "CfDJ8+token/with=padding";
		var code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(Token));

		IdentityTokens.TryDecode(code, out var decoded).ShouldBeTrue();
		decoded.ShouldBe(Token);
	}

	[Fact]
	void A_malformed_code_does_not_decode() =>
		IdentityTokens.TryDecode("not*base64url!", out _).ShouldBeFalse();
}
