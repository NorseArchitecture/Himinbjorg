using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary>
///     The recovery-codes handoff's own contract (T3-12): a <c>|</c>-delimited payload under a time-limited protector,
///     every field round-tripping with the payload bytes and the expiry the one-shot ledger keys on, and every refusal
///     (garbage, tampering, another purpose, expiry, another version or shape) answering <see langword="false" />
///     rather than throwing.
/// </summary>
public sealed class RecoveryCodesHandoffTests
{
	static readonly EphemeralDataProtectionProvider _provider = new();
	static readonly string[] _codes = ["aaaaa-11111", "bbbbb-22222", "ccccc-33333"];

	static ITimeLimitedDataProtector Protector(string purpose = RecoveryCodesHandoff.Purpose) =>
		_provider.CreateProtector(purpose).ToTimeLimitedDataProtector();

	[Fact]
	void A_handoff_round_trips_the_user_the_stamp_and_the_codes()
	{
		var before = DateTimeOffset.UtcNow;
		var handoff = RecoveryCodesHandoff.Protect(Protector(), "user-id", "stamp-1", _codes);

		RecoveryCodesHandoff.TryUnprotect(Protector(), handoff, out var opened).ShouldBeTrue();

		opened.UserId.ShouldBe("user-id");
		opened.SecurityStamp.ShouldBe("stamp-1");
		opened.Codes.ShouldBe(_codes);
		Encoding.UTF8.GetString(opened.Payload.Span).ShouldBe("v1|user-id|stamp-1|aaaaa-11111;bbbbb-22222;ccccc-33333");
		opened.ExpiresAt.ShouldBeInRange(before + RecoveryCodesHandoff.Lifetime - TimeSpan.FromMinutes(1),
			DateTimeOffset.UtcNow + RecoveryCodesHandoff.Lifetime);
	}

	[Fact]
	void The_lifetime_is_five_minutes() =>
		RecoveryCodesHandoff.Lifetime.ShouldBe(TimeSpan.FromMinutes(5));

	[Fact]
	void The_purpose_is_versioned() =>
		RecoveryCodesHandoff.Purpose.ShouldBe("Norse.Identity.RecoveryCodesHandoff.v1");

	[Fact]
	void A_tampered_handoff_is_refused()
	{
		var handoff = RecoveryCodesHandoff.Protect(Protector(), "user-id", "stamp-1", _codes);
		var tampered = $"{handoff[..^4]}{(handoff[^4] == 'A' ? 'B' : 'A')}{handoff[^3..]}";

		RecoveryCodesHandoff.TryUnprotect(Protector(), tampered, out _).ShouldBeFalse();
	}

	[Fact]
	void A_garbage_handoff_is_refused_without_throwing()
	{
		RecoveryCodesHandoff.TryUnprotect(Protector(), "not a handoff!", out _).ShouldBeFalse();
		RecoveryCodesHandoff.TryUnprotect(Protector(), "bm90LWEtaGFuZG9mZg", out _).ShouldBeFalse();
	}

	[Fact]
	void A_handoff_protected_under_another_purpose_is_refused()
	{
		var handoff = RecoveryCodesHandoff.Protect(Protector("Some.Other.Purpose"), "user-id", "stamp-1", _codes);

		RecoveryCodesHandoff.TryUnprotect(Protector(), handoff, out _).ShouldBeFalse();
	}

	[Fact]
	void An_expired_handoff_is_refused()
	{
		var handoff = RecoveryCodesHandoff.Protect(Protector(), "user-id", "stamp-1", _codes);
		var expired = Substitute.For<ITimeLimitedDataProtector>();
		expired.Unprotect(Arg.Any<byte[]>(), out Arg.Any<DateTimeOffset>())
			.Throws(new CryptographicException("The payload expired."));

		RecoveryCodesHandoff.TryUnprotect(expired, handoff, out _).ShouldBeFalse();
	}

	[Theory]
	[InlineData("v2|user-id|stamp-1|aaaaa-11111")]
	[InlineData("v1|user-id|stamp-1")]
	[InlineData("v1|user-id|stamp-1|")]
	[InlineData("v1||stamp-1|aaaaa-11111")]
	[InlineData("v1|user-id||aaaaa-11111")]
	void A_payload_of_another_version_or_shape_is_refused(string payload)
	{
		var handoff = Protector().Protect(payload, RecoveryCodesHandoff.Lifetime);

		RecoveryCodesHandoff.TryUnprotect(Protector(), handoff, out _).ShouldBeFalse();
	}
}
