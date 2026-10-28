using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Norse.Identity.Web.Server.Tests.ExternalLogin;

/// <summary>
///     <see cref="ExternalProviders.AddNorseExternalProviders" /> over a built service provider: one typed OIDC scheme
///     per <c>Identity:ExternalProviders</c> child, signing into the external cookie with PKCE, validated at startup,
///     and every scheme sharing the one remote-failure handler.
/// </summary>
public sealed class ExternalProvidersTests
{
	const string Name = "Example";
	const string DisplayName = "Example Co";
	const string Vouched = "user@example.com";
	const string Victim = "victim@example.com";
	const string Subject = "provider-subject";
	const string Forged = "victim-subject";

	static readonly Dictionary<string, string?> _example = new()
	{
		["Identity:ExternalProviders:Example:DisplayName"] = DisplayName,
		["Identity:ExternalProviders:Example:Authority"] = "https://provider.test",
		["Identity:ExternalProviders:Example:ClientId"] = "norse-client",
		["Identity:ExternalProviders:Example:ClientSecret"] = "norse-secret"
	};

	[Fact]
	async Task No_section_registers_no_scheme()
	{
		await using var provider = Build([]);

		var schemes = await provider.GetRequiredService<IAuthenticationSchemeProvider>().GetAllSchemesAsync();

		schemes.ShouldBeEmpty();
	}

	[Fact]
	async Task A_section_registers_an_oidc_scheme_with_its_display_name()
	{
		await using var provider = Build(_example);

		var scheme = (await provider.GetRequiredService<IAuthenticationSchemeProvider>().GetSchemeAsync(Name))
			.ShouldNotBeNull();

		scheme.HandlerType.ShouldBe(typeof(OpenIdConnectHandler));
		scheme.DisplayName.ShouldBe(DisplayName);
	}

	[Fact]
	async Task The_scheme_signs_into_the_external_cookie_with_pkce()
	{
		await using var provider = Build(_example);

		var options = OptionsOf(provider);

		options.SignInScheme.ShouldBe(IdentityConstants.ExternalScheme);
		options.Authority.ShouldBe("https://provider.test");
		options.ClientId.ShouldBe("norse-client");
		options.ClientSecret.ShouldBe("norse-secret");
		options.RequireHttpsMetadata.ShouldBeTrue();
		options.ResponseType.ShouldBe("code");
		options.UsePkce.ShouldBeTrue();
		options.Scope.ShouldBe(["openid", "profile", "email"], ignoreOrder: true);
		options.CallbackPath.ShouldBe(new PathString("/signin-example"));
		options.RemoteSignOutPath.ShouldBe(new PathString("/signout-example"));
		options.SignedOutCallbackPath.ShouldBe(new PathString("/signout-callback-example"));
		options.MapInboundClaims.ShouldBeFalse();
		// The typed registration's post-configure ran: the state format and configuration manager exist.
		options.StateDataFormat.ShouldNotBeNull();
		options.ConfigurationManager.ShouldNotBeNull();
	}

	// One decision, by ordinal claim name over the token itself: exactly one string email and exactly one email_verified
	// reading true record the email; anything else records nothing and removes a stale item.
	[Theory]
	[MemberData(nameof(IdTokenVariants.Payloads), MemberType = typeof(IdTokenVariants))]
	void The_verified_email_is_recorded_only_for_one_email_the_token_vouched_for(string payload, bool registers)
	{
		AuthenticationProperties properties = new();
		properties.Items[ExternalProviders.VerifiedEmailItem] = "stale@example.com";

		ExternalProviders.RecordVerifiedEmail(Token(IdTokenVariants.Fill(payload, Vouched, Victim)), properties);

		if (registers)
			properties.Items[ExternalProviders.VerifiedEmailItem].ShouldBe(Vouched);
		else
			properties.Items.ShouldNotContainKey(ExternalProviders.VerifiedEmailItem);
	}

	// RFC 7519 section 4 lets a parser keep only the lexically last of duplicate member names, and IdentityModel does:
	// the token's one email is that last member, the same value the principal carries.
	[Theory]
	[InlineData("""{"email":"$VICTIM","email":"$VOUCHED","email_verified":true}""", Vouched)]
	[InlineData("""{"email":"$VOUCHED","email":"$VICTIM","email_verified":true}""", Victim)]
	void A_duplicate_email_member_resolves_to_the_lexically_last(string payload, string recorded)
	{
		AuthenticationProperties properties = new();

		ExternalProviders.RecordVerifiedEmail(Token(IdTokenVariants.Fill(payload, Vouched, Victim)), properties);

		properties.Items[ExternalProviders.VerifiedEmailItem].ShouldBe(recorded);
	}

	// RC3 GetExternalLoginInfoAsync keys the login on the first ClaimTypes.NameIdentifier ahead of sub. The OIDC handler's
	// identity matches claim types ordinally, but the external cookie round-trips into a plain ClaimsIdentity, which
	// ignores case: every spelling goes, from every identity, and the one key left is the token's sub.
	[Theory]
	[MemberData(nameof(IdTokenVariants.ForgedNameIdentifiers), MemberType = typeof(IdTokenVariants))]
	void The_provider_key_is_the_tokens_one_sub_whatever_a_forged_name_identifier_says(string forgedType)
	{
		var idToken = Token($$"""{"{{forgedType}}":"{{Forged}}","sub":"{{Subject}}"}""");
		ClaimsPrincipal principal = new(
		[
			new CaseSensitiveClaimsIdentity(idToken.Claims, "oidc"),
			new ClaimsIdentity([new Claim(forgedType, Forged), new Claim(ClaimTypes.NameIdentifier, Forged)], "other")
		]);

		ExternalProviders.BindProviderKey(idToken, principal).ShouldBeTrue();

		principal.Identities.SelectMany(NameIdentifiers).ShouldHaveSingleItem().Value.ShouldBe(Subject);
		RoundTrip(principal).FindFirstValue(ClaimTypes.NameIdentifier).ShouldBe(Subject);
	}

	// The key is the token's one sub, by ordinal claim name: absent, empty or spelled another way binds nothing, and no
	// name identifier survives to stand in for it.
	[Theory]
	[InlineData("""{"email":"user@example.com"}""")]
	[InlineData("""{"sub":""}""")]
	[InlineData("""{"SUB":"provider-subject"}""")]
	void A_token_without_exactly_one_string_sub_binds_no_provider_key(string payload)
	{
		ClaimsPrincipal principal = new(new CaseSensitiveClaimsIdentity(
			[new Claim(ClaimTypes.NameIdentifier, Forged), new Claim(ClaimTypes.NameIdentifier.ToUpperInvariant(), Forged)],
			"oidc"));

		ExternalProviders.BindProviderKey(Token(payload), principal).ShouldBeFalse();

		principal.Identities.SelectMany(NameIdentifiers).ShouldBeEmpty();
	}

	// Two sub values as a JSON array (or an object) never reach the event: IdentityModel reads sub only as a string or a
	// number and refuses the token outright, so the handler's validation fails and the remote failure handler answers.
	[Theory]
	[InlineData("""{"sub":["provider-subject","victim-subject"]}""")]
	[InlineData("""{"sub":{"id":"provider-subject"}}""")]
	void A_sub_that_is_neither_a_string_nor_a_number_makes_the_token_unreadable(string payload) =>
		Should.Throw<ArgumentException>(() => Token(payload));

	// IdentityModel reads a numeric sub as its string, the same value the handler's own sub comparison
	// (JwtSecurityToken.Subject) reads; telling 42 from "42" would need a raw JSON reader (NORSE070).
	[Fact]
	void A_numeric_sub_binds_as_its_string()
	{
		var idToken = Token("""{"sub":42}""");
		ClaimsPrincipal principal = new(new CaseSensitiveClaimsIdentity("oidc"));

		ExternalProviders.BindProviderKey(idToken, principal).ShouldBeTrue();

		principal.FindFirstValue(ClaimTypes.NameIdentifier).ShouldBe("42");
		new JwtSecurityToken(idToken.EncodedToken).Subject.ShouldBe("42");
	}

	// As for email: IdentityModel keeps the lexically last of duplicate sub members, and the OIDC handler's own
	// front-channel/back-channel sub comparison (JwtSecurityToken.Subject) reads that same last member.
	[Theory]
	[InlineData("""{"sub":"provider-subject","sub":"victim-subject"}""", Forged)]
	[InlineData("""{"sub":"victim-subject","sub":"provider-subject"}""", Subject)]
	void A_duplicate_sub_member_resolves_to_the_lexically_last(string payload, string bound)
	{
		var idToken = Token(payload);
		ClaimsPrincipal principal = new(new CaseSensitiveClaimsIdentity("oidc"));

		ExternalProviders.BindProviderKey(idToken, principal).ShouldBeTrue();

		principal.FindFirstValue(ClaimTypes.NameIdentifier).ShouldBe(bound);
		new JwtSecurityToken(idToken.EncodedToken).Subject.ShouldBe(bound);
	}

	// The wiring: the event reads the validated token it is handed, never the principal's claims, for the email; it
	// binds the provider key from the same token and leaves every other claim alone.
	[Fact]
	async Task The_scheme_decides_the_email_and_the_key_from_the_validated_id_token()
	{
		await using var provider = Build(_example);
		var options = OptionsOf(provider);
		ClaimsPrincipal principal = new(new ClaimsIdentity(
		[
			new Claim(ClaimTypes.Email, Victim),
			new Claim(ExternalProviders.VerifiedEmailItem, Victim),
			new Claim("email", Victim),
			new Claim("email_verified", "true"),
			new Claim(ClaimTypes.NameIdentifier.ToUpperInvariant(), Forged)
		], "oidc"));
		AuthenticationProperties properties = new();
		var context = Validated(options, principal, properties,
			new JwtSecurityToken(Token($$"""{"sub":"{{Subject}}","email":"{{Vouched}}","email_verified":true}""").EncodedToken));

		await options.Events.OnTokenValidated(context);

		context.Result.ShouldBeNull();
		properties.Items[ExternalProviders.VerifiedEmailItem].ShouldBe(Vouched);
		principal.Identities.SelectMany(NameIdentifiers).ShouldHaveSingleItem().Value.ShouldBe(Subject);
		principal.Claims.Count().ShouldBe(5, "only the forged name identifier is replaced");
	}

	[Fact]
	async Task A_validated_id_token_without_a_sub_fails_the_remote_sign_in()
	{
		await using var provider = Build(_example);
		var options = OptionsOf(provider);
		var context = Validated(options, new(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, Forged)], "oidc")),
			new(), new JwtSecurityToken(Token($$"""{"email":"{{Vouched}}","email_verified":true}""").EncodedToken));

		await options.Events.OnTokenValidated(context);

		context.Result.ShouldNotBeNull().Failure.ShouldNotBeNull();
		context.Principal.ShouldNotBeNull().Identities.SelectMany(NameIdentifiers).ShouldBeEmpty();
	}

	[Fact]
	async Task A_validated_context_without_a_token_records_nothing_and_fails()
	{
		await using var provider = Build(_example);
		var options = OptionsOf(provider);
		AuthenticationProperties properties = new();
		properties.Items[ExternalProviders.VerifiedEmailItem] = Victim;
		var context = Validated(options,
			new(new ClaimsIdentity([new Claim("email", Victim), new Claim("email_verified", "true")], "oidc")),
			properties, null);

		await options.Events.OnTokenValidated(context);

		properties.Items.ShouldNotContainKey(ExternalProviders.VerifiedEmailItem);
		context.Result.ShouldNotBeNull().Failure.ShouldNotBeNull();
	}

	// M2: an encrypted id token. The RC3 handler hands the event JwtSecurityTokenConverter.Convert(the validated
	// JsonWebToken), whose InnerToken is the decrypted JWS; the outer token's RawData is the JWE, which carries no
	// readable claims. Built and validated here exactly as the handler does, with no provider.
	[Fact]
	async Task An_encrypted_id_token_is_read_through_its_validated_inner_token()
	{
		await using var provider = Build(_example);
		var options = OptionsOf(provider);
		SymmetricSecurityKey signing = new([.. Enumerable.Repeat((byte)1, 32)]);
		SymmetricSecurityKey encrypting = new([.. Enumerable.Repeat((byte)2, 32)]);
		JsonWebTokenHandler handler = new();
		var jwe = handler.CreateToken(new SecurityTokenDescriptor
		{
			Issuer = "https://provider.test",
			Audience = "norse-client",
			Claims = new Dictionary<string, object> { ["sub"] = Subject, ["email"] = Vouched, ["email_verified"] = true },
			SigningCredentials = new(signing, SecurityAlgorithms.HmacSha256),
			EncryptingCredentials = new(encrypting, SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes128CbcHmacSha256)
		});
		var result = await handler.ValidateTokenAsync(jwe, new TokenValidationParameters
		{
			IssuerSigningKey = signing,
			TokenDecryptionKey = encrypting,
			ValidIssuer = "https://provider.test",
			ValidAudience = "norse-client"
		});
		result.IsValid.ShouldBeTrue();
		var converted = JwtSecurityTokenConverter.Convert((JsonWebToken)result.SecurityToken);
		converted.InnerToken.ShouldNotBeNull("the converted token carries the decrypted inner token");
		ClaimsPrincipal principal = new(result.ClaimsIdentity);
		AuthenticationProperties properties = new();
		var context = Validated(options, principal, properties, converted);

		await options.Events.OnTokenValidated(context);

		context.Result.ShouldBeNull();
		properties.Items[ExternalProviders.VerifiedEmailItem].ShouldBe(Vouched);
		principal.Identities.SelectMany(NameIdentifiers).ShouldHaveSingleItem().Value.ShouldBe(Subject);
	}

	[Fact]
	async Task A_provider_without_an_authority_fails_at_startup()
	{
		Dictionary<string, string?> settings = new(_example) { ["Identity:ExternalProviders:Example:Authority"] = null };
		await using var provider = Build(settings);

		Should.Throw<OptionsValidationException>(() => OptionsOf(provider));
	}

	/// <summary>The real host start, not an options read: <c>ValidateOnStart</c> fails <c>StartAsync</c> before serving.</summary>
	[Fact]
	async Task A_host_whose_provider_has_no_authority_fails_to_start()
	{
		var builder = WebApplication.CreateSlimBuilder();
		builder.WebHost.UseTestServer();
		builder.Configuration.AddInMemoryCollection(
			new Dictionary<string, string?>(_example) { ["Identity:ExternalProviders:Example:Authority"] = null });
		builder.Services.AddAuthentication().AddNorseExternalProviders(builder.Configuration);
		await using var app = builder.Build();

		var failure = await Should.ThrowAsync<OptionsValidationException>(
			() => app.StartAsync(TestContext.Current.CancellationToken));

		failure.Failures.ShouldContain("Identity:ExternalProviders:Example:Authority is required.");
	}

	[Fact]
	async Task A_provider_without_a_client_id_fails_at_startup()
	{
		Dictionary<string, string?> settings = new(_example) { ["Identity:ExternalProviders:Example:ClientId"] = null };
		await using var provider = Build(settings);

		Should.Throw<OptionsValidationException>(() => OptionsOf(provider));
	}

	[Fact]
	void A_provider_without_a_display_name_fails_at_registration()
	{
		Dictionary<string, string?> settings = new(_example) { ["Identity:ExternalProviders:Example:DisplayName"] = null };

		Should.Throw<InvalidOperationException>(() => Build(settings)).Message.ShouldContain("DisplayName");
	}

	[Fact]
	async Task Every_configured_scheme_uses_the_shared_remote_failure_handler()
	{
		await using var provider = Build(_example);

		OptionsOf(provider).Events.OnRemoteFailure
			.ShouldBe((Func<RemoteFailureContext, Task>)ExternalProviders.RedirectRemoteFailure);
	}

	[Fact]
	async Task The_remote_failure_handler_redirects_to_the_callback_page_with_the_fixed_message()
	{
		DefaultHttpContext context = new();
		context.Request.PathBase = "/app";
		RemoteFailureContext failure = new(context,
			new AuthenticationScheme(Name, DisplayName, typeof(OpenIdConnectHandler)), new OpenIdConnectOptions(),
			new AuthenticationFailureException("The provider said no."));

		await ExternalProviders.RedirectRemoteFailure(failure);

		context.Response.StatusCode.ShouldBe(StatusCodes.Status302Found);
		context.Response.Headers.Location.ToString().ShouldBe(
			"/app/Account/ExternalLogin?RemoteError=The%20sign-in%20provider%20did%20not%20complete%20the%20sign-in.");
		failure.Result.ShouldNotBeNull().Handled.ShouldBeTrue();
	}

	// The provider key and the email come only from the validated id token: no user-info call is made, and no claim
	// action could write either one, for every registered scheme.
	[Fact]
	async Task No_scheme_reads_user_info_or_maps_a_claim_onto_the_key_or_the_email()
	{
		Dictionary<string, string?> settings = new(_example)
		{
			["Identity:ExternalProviders:Second:DisplayName"] = "Second Co",
			["Identity:ExternalProviders:Second:Authority"] = "https://second.test",
			["Identity:ExternalProviders:Second:ClientId"] = "second-client",
		};
		await using var provider = Build(settings);

		var schemes = await provider.GetRequiredService<IAuthenticationSchemeProvider>().GetAllSchemesAsync();
		var oidc = schemes.Where(scheme => scheme.HandlerType == typeof(OpenIdConnectHandler)).ToList();
		oidc.Count.ShouldBe(2);
		foreach (var scheme in oidc)
		{
			var options = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(scheme.Name);
			options.GetClaimsFromUserInfoEndpoint.ShouldBeFalse(scheme.Name);
			options.ClaimActions.Select(action => action.ClaimType)
				.ShouldNotContain(type => type == ClaimTypes.NameIdentifier || type == ClaimTypes.Email ||
					string.Equals(type, "email", StringComparison.OrdinalIgnoreCase), scheme.Name);
		}
	}

	// A provider name becomes a scheme name, three URL path segments and a field of the pipe-joined challenge token,
	// so only a conservative character set is accepted, and the host refuses to start on anything else.
	[Theory]
	[InlineData("Acme|EU")]
	[InlineData("Acme EU")]
	[InlineData("Acme/EU")]
	[InlineData("Acme.EU")]
	[InlineData("Acmé")]
	[InlineData("Acme%2F")]
	// .NET's $ also matches before a final newline; the pattern must anchor with \z.
	[InlineData("Acme\n")]
	void A_provider_name_outside_the_safe_set_fails_at_registration(string name)
	{
		Dictionary<string, string?> settings = new()
		{
			[$"Identity:ExternalProviders:{name}:DisplayName"] = DisplayName,
			[$"Identity:ExternalProviders:{name}:Authority"] = "https://provider.test",
			[$"Identity:ExternalProviders:{name}:ClientId"] = "norse-client",
		};

		Should.Throw<InvalidOperationException>(() => Build(settings)).Message.ShouldContain(name);
	}

	[Theory]
	[InlineData("Acme")]
	[InlineData("acme-eu_2")]
	void A_provider_name_inside_the_safe_set_registers(string name)
	{
		Dictionary<string, string?> settings = new()
		{
			[$"Identity:ExternalProviders:{name}:DisplayName"] = DisplayName,
			[$"Identity:ExternalProviders:{name}:Authority"] = "https://provider.test",
			[$"Identity:ExternalProviders:{name}:ClientId"] = "norse-client",
		};

		Should.NotThrow(() => Build(settings).Dispose());
	}

	// "callback-example" would answer /signout-callback-example, which is "example"'s signed-out callback; "oidc" would
	// claim the framework's shared OIDC defaults a host's own scheme answers on.
	[Theory]
	[InlineData("callback-example")]
	[InlineData("oidc")]
	[InlineData("callback-oidc")]
	void A_provider_whose_paths_collide_fails_at_registration(string name)
	{
		Dictionary<string, string?> settings = new(_example)
		{
			[$"Identity:ExternalProviders:{name}:DisplayName"] = "Colliding Co",
			[$"Identity:ExternalProviders:{name}:Authority"] = "https://colliding.test",
			[$"Identity:ExternalProviders:{name}:ClientId"] = "colliding-client",
		};

		Should.Throw<InvalidOperationException>(() => Build(settings)).Message.ShouldContain("collides");
	}

	static JsonWebToken Token(string payload) =>
		new("""{"alg":"none"}""", payload);

	static TokenValidatedContext Validated(OpenIdConnectOptions options, ClaimsPrincipal principal,
		AuthenticationProperties properties, JwtSecurityToken? token) =>
		new(new DefaultHttpContext(), new AuthenticationScheme(Name, DisplayName, typeof(OpenIdConnectHandler)), options,
			principal, properties)
		{
			SecurityToken = token!
		};

	/// <summary>Every claim a case-insensitive lookup reads as <see cref="ClaimTypes.NameIdentifier" />.</summary>
	static IEnumerable<Claim> NameIdentifiers(ClaimsIdentity identity) =>
		identity.Claims.Where(static claim =>
			string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.OrdinalIgnoreCase));

	/// <summary>The principal as the external cookie hands it back: serialized and read into plain identities.</summary>
	static ClaimsPrincipal RoundTrip(ClaimsPrincipal principal) =>
		TicketSerializer.Default.Deserialize(TicketSerializer.Default.Serialize(new(principal, "external")))
			.ShouldNotBeNull().Principal;

	static ServiceProvider Build(Dictionary<string, string?> settings)
	{
		var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
		ServiceCollection services = new();
		services.AddLogging();
		services.AddDataProtection().UseEphemeralDataProtectionProvider();
		services.AddAuthentication().AddNorseExternalProviders(configuration);
		return services.BuildServiceProvider();
	}

	static OpenIdConnectOptions OptionsOf(ServiceProvider provider) =>
		provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(Name);
}
