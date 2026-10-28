using Norse.Abstractions.Contracts;
using Norse.Identity.Web.Server.Passkeys;

namespace Norse.Identity.Web.Server.Tests.Passkeys;

/// <summary>
///     <see cref="CredentialIds" />: a credential id crosses the wire base64url-encoded, and an id that does not decode is
///     a <see cref="ErrorCategory.Validation" /> on <c>CredentialId</c>, never an exception.
/// </summary>
public sealed class CredentialIdsTests
{
	[Fact]
	void An_id_round_trips_through_base64url()
	{
		// 0xFB 0xFF 0xBF is "+/+/" in base64 and "-_-_" in base64url.
		byte[] id = [0xFB, 0xFF, 0xBF, 0x01, 0x02];

		var encoded = CredentialIds.Encode(id);

		encoded.ShouldStartWith("-_-_");
		CredentialIds.TryDecode(encoded, out var decoded).ShouldBeTrue();
		decoded.ShouldBe(id);
	}

	[Theory]
	[InlineData("not base64url!")]
	[InlineData("+/+/")]
	[InlineData("A")]
	void A_malformed_id_does_not_decode(string credentialId)
	{
		CredentialIds.TryDecode(credentialId, out var decoded).ShouldBeFalse();
		decoded.ShouldBeEmpty();
	}

	[Fact]
	void A_malformed_id_answers_Validation_on_CredentialId()
	{
		var problem = CredentialIds.Invalid.Problem;

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors.ShouldContainKey("CredentialId");
		problem.Errors["CredentialId"].ShouldBe(["The passkey id is not valid."]);
	}
}
