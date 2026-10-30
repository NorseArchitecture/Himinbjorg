using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary>
///     What the authenticator setup renders, in the stock page's parity format: the key in lowercase groups of four,
///     the <c>otpauth://</c> URI with its issuer and account encoded, and a QR code an image can show but never run.
///     The issuer is required configuration (T3-27), so a host without one fails at startup, never at first use.
/// </summary>
public sealed class AuthenticatorSetupTests
{
	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	void The_key_is_shown_in_lowercase_groups_of_four() =>
		AuthenticatorSetup.FormatKey("ABCDEFGHIJKLMNOP").ShouldBe("abcd efgh ijkl mnop");

	[Fact]
	void A_key_with_a_short_last_group_keeps_it() =>
		AuthenticatorSetup.FormatKey("ABCDEFGHIJ").ShouldBe("abcd efgh ij");

	// UrlEncoder.Default, as the stock page uses it: '+' is encoded, '@' is left as is (authenticator apps accept both).
	[Fact]
	void The_uri_encodes_the_issuer_and_the_account_in_the_parity_format() =>
		AuthenticatorSetup.Uri("Norse", "a+b@example.com", "KEY")
			.ShouldBe("otpauth://totp/Norse:a%2Bb@example.com?secret=KEY&issuer=Norse&digits=6");

	[Fact]
	void The_uri_encodes_an_issuer_with_spaces() =>
		AuthenticatorSetup.Uri("Norse Dev", "user@example.com", "KEY")
			.ShouldBe("otpauth://totp/Norse%20Dev:user@example.com?secret=KEY&issuer=Norse%20Dev&digits=6");

	[Fact]
	void The_qr_code_is_an_svg_carrying_no_script()
	{
		var svg = AuthenticatorSetup.QrSvg("otpauth://totp/Norse:a%2Bb%40example.com?secret=KEY&issuer=Norse&digits=6");

		svg.ShouldStartWith("<svg");
		svg.ShouldNotContain("<script", Case.Insensitive);
	}

	[Fact]
	async Task A_missing_issuer_fails_at_startup()
	{
		using var certificate = IdentityTestCertificate.CreateFresh();
		using var host = BuildHost(issuer: null, certificate);

		var failure = await Should.ThrowAsync<OptionsValidationException>(() => host.StartAsync(Cancellation));

		failure.OptionsType.ShouldBe(typeof(AuthenticatorOptions));
	}

	[Fact]
	void The_issuer_binds_from_its_configuration_section()
	{
		using var certificate = IdentityTestCertificate.CreateFresh();
		using var host = BuildHost(issuer: "Norse", certificate);

		host.Services.GetRequiredService<IOptions<AuthenticatorOptions>>().Value.Issuer.ShouldBe("Norse");
	}

	// The caller owns the certificate and keeps it alive past StartAsync: OpenIddict's server options are validated on
	// start, and they read it.
	static IHost BuildHost(string? issuer, X509Certificate2 certificate)
	{
		var builder = Host.CreateApplicationBuilder();
		builder.Configuration["ConnectionStrings:test"] = "Host=localhost;Database=norse_identity_test";
		if (issuer is not null)
			builder.Configuration[$"{AuthenticatorOptions.Section}:{nameof(AuthenticatorOptions.Issuer)}"] = issuer;
		builder.AddNorseAuthenticationService("test", certificate);
		return builder.Build();
	}
}
