using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Time.Testing;
using Norse.Identity.Web.Server.OpenIddict;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     The <c>norse_reauth</c> marker (spec §5.2): data-protected under its own purpose, five minutes, and read from a
///     landing only when that landing is an authorize request under the live <c>PathBase</c>.
/// </summary>
public sealed class ReauthMarkersTests
{
	readonly EphemeralDataProtectionProvider _provider = new();
	readonly FakeTimeProvider _clock = new(DateTimeOffset.UtcNow);

	ReauthMarkers Markers =>
		new(_provider, _clock);

	[Fact]
	void A_protected_marker_round_trips()
	{
		var marker = Mint(Guid.NewGuid());

		Markers.TryUnprotect(Markers.Protect(marker), out var read).ShouldBeTrue();

		read.ShouldNotBeNull();
		read.MarkerId.ShouldBe(marker.MarkerId);
		read.UserId.ShouldBe(marker.UserId);
		read.TransactionHash.ShouldBe(marker.TransactionHash);
		read.ExpiresAt.ShouldBe(marker.ExpiresAt);
	}

	[Fact]
	void An_anonymous_marker_round_trips_without_a_user()
	{
		Markers.TryUnprotect(Markers.Protect(Mint(userId: null)), out var read).ShouldBeTrue();

		read.ShouldNotBeNull().UserId.ShouldBeNull();
	}

	[Fact]
	void The_protected_form_is_url_safe() =>
		Markers.Protect(Mint(Guid.NewGuid())).ShouldAllBe(static c => char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_');

	[Fact]
	void Lifetime_is_five_minutes() =>
		ReauthMarkers.Lifetime.ShouldBe(TimeSpan.FromMinutes(5));

	[Fact]
	void An_expired_marker_does_not_unprotect()
	{
		var protectedMarker = Markers.Protect(Mint(Guid.NewGuid()));
		_clock.Advance(ReauthMarkers.Lifetime - TimeSpan.FromSeconds(1));
		Markers.TryUnprotect(protectedMarker, out _).ShouldBeTrue();

		_clock.Advance(TimeSpan.FromSeconds(1));

		Markers.TryUnprotect(protectedMarker, out var read).ShouldBeFalse();
		read.ShouldBeNull();
	}

	[Theory]
	[InlineData("")]
	[InlineData("not-a-marker")]
	[InlineData("!!!")]
	void A_malformed_marker_does_not_unprotect(string value) =>
		Markers.TryUnprotect(value, out _).ShouldBeFalse();

	[Fact]
	void A_tampered_marker_does_not_unprotect()
	{
		var protectedMarker = Markers.Protect(Mint(Guid.NewGuid()));
		// A middle character: the last one can carry only padding bits.
		var middle = protectedMarker.Length / 2;
		var tampered = string.Concat(protectedMarker.AsSpan(0, middle), protectedMarker[middle] == 'A' ? "B" : "A",
			protectedMarker.AsSpan(middle + 1));

		Markers.TryUnprotect(tampered, out _).ShouldBeFalse();
	}

	[Fact]
	void A_value_protected_under_another_purpose_does_not_unprotect()
	{
		var foreign = WebEncoders.Base64UrlEncode(
			_provider.CreateProtector("Norse.Identity.Other.v1").Protect(new byte[64]));

		Markers.TryUnprotect(foreign, out _).ShouldBeFalse();
	}

	[Fact]
	void A_marker_from_another_key_ring_does_not_unprotect() =>
		Markers.TryUnprotect(new ReauthMarkers(new EphemeralDataProtectionProvider(), _clock).Protect(Mint(null)), out _)
			.ShouldBeFalse();

	[Theory]
	[InlineData("", "/connect/authorize?client_id=norse&norse_reauth={0}")]
	[InlineData("", "/connect/authorize?norse_reauth={0}")]
	[InlineData("", "/connect/authorize?client_id=norse&norse_reauth={0}#fragment")]
	[InlineData("/app", "/app/connect/authorize?client_id=norse&norse_reauth={0}")]
	// A differently cased spelling is an unknown parameter, never a second marker (ordinal, as the hash excludes it).
	[InlineData("", "/connect/authorize?NORSE_REAUTH=other&norse_reauth={0}")]
	void A_landing_on_the_authorize_endpoint_reads_its_marker(string pathBase, string landing)
	{
		var marker = Mint(Guid.NewGuid());

		Markers.TryReadFromLanding(Landing(landing, marker), new PathString(pathBase), out var read).ShouldBeTrue();

		read.ShouldNotBeNull().MarkerId.ShouldBe(marker.MarkerId);
	}

	[Theory]
	[InlineData("", "/")]
	[InlineData("", "/connect/authorize?client_id=norse")]
	[InlineData("", "/connect/authorize?client_id=norse&norse_reauth=")]
	[InlineData("", "/connect/authorize?norse_reauth={0}&norse_reauth={0}")]
	[InlineData("", "/connect/authorize?norse_reauth={0}&norse_reauth=other")]
	[InlineData("", "/connect/authorize?NORSE_REAUTH={0}")]
	[InlineData("", "/connect/authorize?Norse_Reauth={0}")]
	[InlineData("", "/connect/authorize/?norse_reauth={0}")]
	[InlineData("", "/Connect/Authorize?norse_reauth={0}")]
	[InlineData("", "/connect/token?norse_reauth={0}")]
	[InlineData("", "/Account/Login?returnUrl=%2Fconnect%2Fauthorize&norse_reauth={0}")]
	[InlineData("", "https://evil.example/connect/authorize?norse_reauth={0}")]
	[InlineData("", "/app/connect/authorize?norse_reauth={0}")]
	[InlineData("/app", "/connect/authorize?norse_reauth={0}")]
	[InlineData("/app", "/application/connect/authorize?norse_reauth={0}")]
	[InlineData("", "/connect/authorize#norse_reauth={0}")]
	void A_landing_that_is_not_an_authorize_request_under_the_path_base_reads_nothing(string pathBase, string landing)
	{
		Markers.TryReadFromLanding(Landing(landing, Mint(Guid.NewGuid())), new PathString(pathBase), out var read)
			.ShouldBeFalse();

		read.ShouldBeNull();
	}

	[Fact]
	void A_landing_with_an_expired_marker_reads_nothing()
	{
		var landing = Landing("/connect/authorize?norse_reauth={0}", Mint(Guid.NewGuid()));
		_clock.Advance(ReauthMarkers.Lifetime);

		Markers.TryReadFromLanding(landing, PathString.Empty, out _).ShouldBeFalse();
	}

	ReauthMarker Mint(Guid? userId) =>
		new(Guid.NewGuid(), userId, [.. Enumerable.Range(0, 32).Select(static i => (byte)i)],
			_clock.GetUtcNow() + ReauthMarkers.Lifetime);

	string Landing(string template, ReauthMarker marker) =>
		template.Replace("{0}", Markers.Protect(marker), StringComparison.Ordinal);
}
