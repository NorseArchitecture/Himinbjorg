using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.OpenIddict;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using OpenIddict.Validation;

namespace Norse.Identity.Web.Server.Tests;

public sealed class IdentityBuilderExtensionsTests
{
	[Fact]
	void AddNorseIdentity_registers_NorseUserStore_as_IUserStore()
	{
		ServiceCollection services = new();
		using var certificate = IdentityTestCertificate.CreateFresh();

		services.AddNorseIdentity(certificate);

		var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IUserStore<NorseUser>));
		descriptor.ShouldNotBeNull();
		descriptor.ImplementationType.ShouldBe(typeof(NorseUserStore));
	}

	[Fact]
	void AddNorseIdentity_returns_the_identity_builder_wrapping_the_same_services()
	{
		ServiceCollection services = new();
		using var certificate = IdentityTestCertificate.CreateFresh();

		var result = services.AddNorseIdentity(certificate);

		result.Services.ShouldBeSameAs(services);
	}

	[Fact]
	void AddNorseIdentity_configures_SchemaVersion_to_Version3()
	{
		ServiceCollection services = new();
		services.AddDbContext<NorseIdentityDbContext>(o => o.UseSqlite("Data Source=:memory:"));
		using var certificate = IdentityTestCertificate.CreateFresh();

		services.AddNorseIdentity(certificate);

		using var provider = services.BuildServiceProvider();
		var options = provider.GetRequiredService<IOptions<IdentityOptions>>();

		options.Value.Stores.SchemaVersion.ShouldBe(IdentitySchemaVersions.Version3);
	}

	/// <summary>
	///     T3-33: without user verification a PIN-less key is possession only. The option is pinned explicitly (RC3's
	///     default happens to agree), and the real handler's creation and request options carry it to the browser.
	/// </summary>
	[Fact]
	async Task User_verification_is_required_for_passkeys()
	{
		ServiceCollection services = new();
		using var certificate = IdentityTestCertificate.CreateFresh();
		services.AddNorseIdentity(certificate);
		using var provider = services.BuildServiceProvider();
		var options = provider.GetRequiredService<IOptions<IdentityPasskeyOptions>>();
		using var userManager = MockUserManager.Create();
		PasskeyHandler<NorseUser> handler = new(userManager, options);
		DefaultHttpContext context = new();
		context.Request.Host = new HostString("example.test");

		var creation = await handler.MakeCreationOptionsAsync(
			new() { Id = Guid.CreateVersion7().ToString(), Name = "user@example.com", DisplayName = "user@example.com" },
			context);
		var request = await handler.MakeRequestOptionsAsync(null, context);

		options.Value.UserVerificationRequirement.ShouldBe("required");
		creation.CreationOptionsJson.ShouldContain("\"userVerification\":\"required\"");
		request.RequestOptionsJson.ShouldContain("\"userVerification\":\"required\"");
	}

	/// <summary>
	///     Spec §5.1: the core, server and validation options are validated on start, so a broken OpenIddict
	///     configuration fails the host before it serves rather than at the first token request. Each case breaks one
	///     options type and runs the startup validators the host runs.
	/// </summary>
	[Theory]
	[InlineData(typeof(OpenIddictCoreOptions))]
	[InlineData(typeof(OpenIddictServerOptions))]
	[InlineData(typeof(OpenIddictValidationOptions))]
	async Task OpenIddict_options_are_validated_on_start(Type broken)
	{
		ServiceCollection services = new();
		services.AddLogging();
		// Every host carries a configuration; the pruner's options, validated on start beside OpenIddict's, bind from it.
		services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
		using var certificate = IdentityTestCertificate.CreateFresh();
		services.AddNorseIdentity(certificate);
		if (broken == typeof(OpenIddictCoreOptions))
			services.Configure<OpenIddictCoreOptions>(static o => o.ClientSecretKeyDerivationIterations = 1);
		else if (broken == typeof(OpenIddictServerOptions))
			services.Configure<OpenIddictServerOptions>(static o => o.SigningCredentials.Clear());
		else
			services.Configure<OpenIddictValidationOptions>(static o => o.JsonWebTokenHandler = null!);
		using var provider = services.BuildServiceProvider();

		var validator = provider.GetService<IAsyncStartupValidator>();

		validator.ShouldNotBeNull();
		(await Should.ThrowAsync<Exception>(() => validator.ValidateAsync(TestContext.Current.CancellationToken))).ShouldSatisfyAllConditions(
			exception => Flatten(exception).OfType<OptionsValidationException>().Select(static e => e.OptionsType).ShouldContain(broken));
	}

	static IEnumerable<Exception> Flatten(Exception exception) =>
		exception is AggregateException aggregate ? aggregate.InnerExceptions.SelectMany(Flatten) : [exception];

	// Enforced through PostConfigure, so a host's own later Configure cannot relax it.
	[Fact]
	void A_host_configure_cannot_relax_user_verification()
	{
		ServiceCollection services = new();
		using var certificate = IdentityTestCertificate.CreateFresh();
		services.AddNorseIdentity(certificate);
		services.Configure<IdentityPasskeyOptions>(o => o.UserVerificationRequirement = "preferred");
		using var provider = services.BuildServiceProvider();

		provider.GetRequiredService<IOptions<IdentityPasskeyOptions>>().Value.UserVerificationRequirement.ShouldBe("required");
	}

	/// <summary>
	///     Spec §5.1, as composed: the three grants, S256 PKCE only, the three endpoints (relative, so each resolves under
	///     the live <c>PathBase</c>), the two scopes, the lifetimes, rolling refresh with zero leeway, both passthroughs,
	///     the grant boundary in place of OpenIddict's redemption, revocation left to OpenIddict, and error details suppressed
	///     on every server response and every bearer challenge (§5.7).
	/// </summary>
	[Fact]
	void The_server_is_configured_as_spec_5_1()
	{
		ServiceCollection services = new();
		using var certificate = IdentityTestCertificate.CreateFresh();
		services.AddNorseIdentity(certificate);
		using var provider = services.BuildServiceProvider();

		var server = provider.GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;
		var aspNetCore = provider.GetRequiredService<IOptions<OpenIddictServerAspNetCoreOptions>>().Value;

		server.GrantTypes.ShouldBe([
			OpenIddictConstants.GrantTypes.AuthorizationCode, OpenIddictConstants.GrantTypes.ClientCredentials,
			OpenIddictConstants.GrantTypes.RefreshToken
		], ignoreOrder: true);
		server.RequireProofKeyForCodeExchange.ShouldBeTrue();
		server.CodeChallengeMethods.ShouldBe([OpenIddictConstants.CodeChallengeMethods.Sha256]);
		server.AuthorizationEndpointUris.Select(static uri => uri.OriginalString).ShouldBe(["connect/authorize"]);
		server.TokenEndpointUris.Select(static uri => uri.OriginalString).ShouldBe(["connect/token"]);
		server.RevocationEndpointUris.Select(static uri => uri.OriginalString).ShouldBe(["connect/revoke"]);
		server.Scopes.ShouldContain(OpenIddictConstants.Scopes.OpenId);
		server.Scopes.ShouldContain(OpenIddictConstants.Scopes.OfflineAccess);
		server.AuthorizationCodeLifetime.ShouldBe(TimeSpan.FromMinutes(5));
		server.AccessTokenLifetime.ShouldBe(TimeSpan.FromMinutes(10));
		server.IdentityTokenLifetime.ShouldBe(TimeSpan.FromMinutes(10));
		server.RefreshTokenLifetime.ShouldBe(TimeSpan.FromDays(14));
		server.RefreshTokenReuseLeeway.ShouldBe(TimeSpan.Zero);
		server.DisableRollingRefreshTokens.ShouldBeFalse();
		server.DisableAccessTokenEncryption.ShouldBeTrue();
		aspNetCore.EnableAuthorizationEndpointPassthrough.ShouldBeTrue();
		aspNetCore.EnableTokenEndpointPassthrough.ShouldBeTrue();
		server.Handlers.ShouldContain(RedeemTokenEntryGuarded.Descriptor);
		server.Handlers.ShouldContain(EndGrantOnReuse.Descriptor);
		server.Handlers.ShouldNotContain(RedeemTokenEntry.Descriptor);
		server.Handlers.ShouldContain(SuppressErrorDetails<ApplyAuthorizationResponseContext>.Descriptor);
		server.Handlers.ShouldContain(SuppressErrorDetails<ApplyTokenResponseContext>.Descriptor);
		server.Handlers.ShouldContain(SuppressErrorDetails<ApplyRevocationResponseContext>.Descriptor);
		server.Handlers.ShouldContain(SuppressErrorDetails<ApplyConfigurationResponseContext>.Descriptor);
		// Revocation is OpenIddict's own (§5.1): v8 has no revocation passthrough to enable, and errors never pass through.
		aspNetCore.EnableErrorPassthrough.ShouldBeFalse();
		provider.GetRequiredService<IOptions<OpenIddictValidationOptions>>().Value.Handlers
			.ShouldContain(SuppressChallengeErrorDetails<OpenIddictValidationEvents.ProcessChallengeContext>.Descriptor);
		provider.GetRequiredService<IOptions<OpenIddictValidationOptions>>().Value.Handlers
			.ShouldContain(SuppressChallengeErrorDetails<OpenIddictValidationEvents.ProcessErrorContext>.Descriptor);
		server.Handlers.Count(static handler => handler == EndGrantOnReuse.Descriptor).ShouldBe(1, "registered once");
	}
}
