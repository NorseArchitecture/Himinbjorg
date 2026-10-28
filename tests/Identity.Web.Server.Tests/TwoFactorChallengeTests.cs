using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The challenge token's own contract: a <c>|</c>-delimited payload under a time-limited protector,
///     every field round-tripping, and every refusal (garbage, another purpose, expiry) answering
///     <see langword="false" /> rather than throwing. The expiry clock itself is the framework's, so the
///     expired case substitutes the protector rather than waiting out the lifetime.
/// </summary>
public sealed class TwoFactorChallengeTests
{
	static readonly EphemeralDataProtectionProvider _provider = new();

	static ITimeLimitedDataProtector Protector(string purpose = TwoFactorChallenge.Purpose) =>
		_provider.CreateProtector(purpose).ToTimeLimitedDataProtector();

	[Fact]
	void A_token_round_trips_every_field()
	{
		TwoFactorChallenge challenge = new("user-id", "stamp-1", IsPersistent: true, LoginProvider: "Google",
			ReturnUrl: "/app/Account?x=1");

		var token = challenge.Protect(Protector());

		TwoFactorChallenge.TryUnprotect(Protector(), token, out var unprotected).ShouldBeTrue();
		unprotected.ShouldBe(challenge);
	}

	[Fact]
	void A_null_provider_round_trips_as_null()
	{
		TwoFactorChallenge challenge = new("user-id", "stamp-1", IsPersistent: false, LoginProvider: null,
			ReturnUrl: "/");

		var token = challenge.Protect(Protector());

		TwoFactorChallenge.TryUnprotect(Protector(), token, out var unprotected).ShouldBeTrue();
		unprotected.LoginProvider.ShouldBeNull();
		unprotected.IsPersistent.ShouldBeFalse();
	}

	// The landing is the payload's last field and is split off whole (split count 6), so a | inside it survives.
	[Fact]
	void A_v2_token_round_trips_a_landing_carrying_the_separator()
	{
		TwoFactorChallenge challenge = new("user-id", "stamp-1", IsPersistent: true, LoginProvider: null,
			ReturnUrl: "/app/Account?x=a|b#c|d");

		var token = challenge.Protect(Protector());

		Protector().Unprotect(token).ShouldStartWith("v2|");
		TwoFactorChallenge.TryUnprotect(Protector(), token, out var unprotected).ShouldBeTrue();
		unprotected.ShouldBe(challenge);
	}

	// T3-21: a v1 token (no landing) is refused like an expired one; it lives five minutes at most.
	[Fact]
	void A_v1_token_is_refused()
	{
		var token = Protector().Protect("v1|user-id|stamp-1|0|", TwoFactorChallenge.Lifetime);

		TwoFactorChallenge.TryUnprotect(Protector(), token, out _).ShouldBeFalse();
	}

	[Fact]
	void A_garbage_token_fails_to_unprotect_without_throwing()
	{
		TwoFactorChallenge.TryUnprotect(Protector(), "not a token!", out _).ShouldBeFalse();
		TwoFactorChallenge.TryUnprotect(Protector(), "bm90LWEtdG9rZW4", out _).ShouldBeFalse();
	}

	[Fact]
	void A_token_protected_under_another_purpose_is_refused()
	{
		var token = new TwoFactorChallenge("user-id", "stamp-1", IsPersistent: false, LoginProvider: null,
				ReturnUrl: "/")
			.Protect(Protector("Some.Other.Purpose"));

		TwoFactorChallenge.TryUnprotect(Protector(), token, out _).ShouldBeFalse();
	}

	[Fact]
	void The_lifetime_is_five_minutes() =>
		TwoFactorChallenge.Lifetime.ShouldBe(TimeSpan.FromMinutes(5));

	[Fact]
	void An_expired_token_is_refused()
	{
		var token = new TwoFactorChallenge("user-id", "stamp-1", IsPersistent: false, LoginProvider: null,
				ReturnUrl: "/")
			.Protect(Protector());
		var expired = Substitute.For<ITimeLimitedDataProtector>();
		expired.Unprotect(Arg.Any<byte[]>(), out Arg.Any<DateTimeOffset>())
			.Throws(new CryptographicException("The payload expired."));

		TwoFactorChallenge.TryUnprotect(expired, token, out _).ShouldBeFalse();
	}
}
