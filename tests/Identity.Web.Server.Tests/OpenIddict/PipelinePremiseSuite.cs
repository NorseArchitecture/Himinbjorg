using System.Net;
using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.OpenIddict;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation;
using OpenIddict.Validation.AspNetCore;
using OpenIddict.Validation.ServerIntegration;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     The pipeline premises (2026-10-29 OpenIddict spec §5.5 "Unverified premises", §10.7 "Premises first"; halting
///     gates H2–H4), once per provider. Every premise but the first depends on the first: the resolved OpenIddict is
///     one version, Yggdrasil's pin. A failure here halts the train; the design is never changed to make one pass.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///     records: xUnit discovers them on each <see langword="sealed" /> provider class.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class PipelinePremiseSuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	/// <summary>Yggdrasil's pin; moving it is a deliberate act, so a float past it fails on purpose.</summary>
	const string PinnedVersion = "8.0.0-preview.4";

	/// <summary>One type from each OpenIddict assembly the realm composes, so each is loaded before it is read.</summary>
	static readonly Type[] _openIddictAssemblies =
	[
		typeof(OpenIddictConstants),
		typeof(OpenIddictCoreOptions),
		typeof(OpenIddictEntityFrameworkCoreOptions),
		typeof(OpenIddictServerOptions),
		typeof(OpenIddictServerAspNetCoreOptions),
		typeof(OpenIddictValidationOptions),
		typeof(OpenIddictValidationAspNetCoreOptions),
		typeof(OpenIddictValidationServerIntegrationOptions)
	];

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	/// <summary>How long a fact waits for a request to reach a pause point before failing instead of hanging.</summary>
	static readonly TimeSpan _pauseTimeout = TimeSpan.FromSeconds(30);

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected void Resolved_openiddict_is_one_v8_version()
	{
		var versions = ResolvedVersions();
		foreach (var (assembly, version) in versions)
			TestContext.Current.TestOutputHelper?.WriteLine($"{assembly} {version}");

		_openIddictAssemblies.Select(static anchor => anchor.Assembly.GetName().Name!).ShouldBeSubsetOf(versions.Keys);
		versions.Values.Distinct(StringComparer.Ordinal).ShouldHaveSingleItem().ShouldStartWith(PinnedVersion);
	}

	// H2: RemoveEventHandler removes the built-in redemption, and the guarded handler takes its order, alone.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Built_in_redeem_token_entry_is_absent()
	{
		RequirePinnedOpenIddict();
		fixture.SkipUnlessAvailable();
		await using var host = await OpenIddictTestHost.StartAsync(fixture);
		var signIn = host.Handlers.Where(static handler => handler.ContextType == typeof(ProcessSignInContext)).ToList();
		foreach (var handler in signIn)
			TestContext.Current.TestOutputHelper?.WriteLine($"{handler.Order} {handler.ServiceDescriptor.ServiceType.Name}");

		host.Handlers.ShouldNotContain(static handler => handler.ServiceDescriptor.ServiceType == typeof(RedeemTokenEntry));
		RedeemTokenEntryGuarded.Descriptor.Order.ShouldBe(RedeemTokenEntry.Descriptor.Order);
		signIn.Where(static handler => handler.Order == RedeemTokenEntry.Descriptor.Order)
			.ShouldHaveSingleItem()
			.ShouldBeSameAs(RedeemTokenEntryGuarded.Descriptor);
		// The after-redemption pause sits between the redemption and the successor's creation.
		(RedeemTokenEntryGuarded.Descriptor.Order + 1).ShouldBeLessThan(GenerateRefreshToken.Descriptor.Order);
	}

	// H3: EndGrantOnReuse runs immediately before ValidateTokenEntry, at the token endpoint and at the revocation endpoint.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task End_grant_on_reuse_runs_before_validate_token_entry_at_both_endpoints()
	{
		RequirePinnedOpenIddict();
		fixture.SkipUnlessAvailable();
		await using (var plain = await OpenIddictTestHost.StartAsync(fixture))
		{
			var validation = plain.Handlers.Where(static handler => handler.ContextType == typeof(ValidateTokenContext)).ToList();
			foreach (var handler in validation)
				TestContext.Current.TestOutputHelper?.WriteLine($"{handler.Order} {handler.ServiceDescriptor.ServiceType.Name}");
			var endGrant = validation.IndexOf(EndGrantOnReuse.Descriptor);
			endGrant.ShouldBeGreaterThanOrEqualTo(0);
			validation[endGrant + 1].ServiceDescriptor.ServiceType.ShouldBe(typeof(Protection.ValidateTokenEntry));
			EndGrantOnReuse.Descriptor.Order.ShouldBe(Protection.ValidateTokenEntry.Descriptor.Order - 1);
		}

		await using var host = await OpenIddictTestHost.StartAsync(fixture, recordValidation: true);
		var first = await host.SignInAsync(Cancellation);
		host.ClearJournal();

		// The filter no longer requires a resolved authorization (Task 4.6, fail-closed): the journal proves the one it saw.
		var authorization = (await host.ReadGrantsAsync(Cancellation)).ShouldHaveSingleItem().Id;
		using (var refresh = await host.RefreshAsync(first.RefreshToken, Cancellation))
		{
			var second = await OpenIddictTestHost.ReadTokensAsync(refresh, Cancellation);
			host.Journal.ShouldBe([Seen(nameof(EndGrantOnReuse), "Token"), Seen("ValidateTokenEntry", "Token")]);
			host.ClearJournal();

			// The same token, now redeemed, at /connect/revoke: EndGrantOnReuse sees it first and refuses it, so the
			// built-in entry check never runs, and neither does its sweep: the successor is still valid.
			using (var revoked = await host.RevokeAsync(first.RefreshToken, Cancellation))
				revoked.StatusCode.ShouldBe(HttpStatusCode.OK);
			host.Journal.ShouldBe([Seen(nameof(EndGrantOnReuse), "Revocation")]);
			var grant = (await host.ReadGrantsAsync(Cancellation)).ShouldHaveSingleItem();
			host.Termination.Ended.ShouldBe([grant.Id]);
			grant.Tokens.Where(static token => token.Type == TokenTypeIdentifiers.RefreshToken && token.Status == Statuses.Valid)
				.ShouldHaveSingleItem();
			host.ClearJournal();

			// A valid token at /connect/revoke passes both, in the same order.
			using (var revokedSuccessor = await host.RevokeAsync(second.RefreshToken, Cancellation))
				revokedSuccessor.StatusCode.ShouldBe(HttpStatusCode.OK);
			host.Journal.ShouldBe([Seen(nameof(EndGrantOnReuse), "Revocation"), Seen("ValidateTokenEntry", "Revocation")]);
		}

		string Seen(string handler, string endpoint) =>
			$"{handler} {endpoint} {TokenTypeIdentifiers.RefreshToken} {authorization}";
	}

	// H3: a redeemed code at /connect/revoke is seen during generic validation, before revocation's ValidateTokenType.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_redeemed_code_at_revoke_reaches_end_grant_on_reuse()
	{
		RequirePinnedOpenIddict();
		fixture.SkipUnlessAvailable();
		await using var host = await OpenIddictTestHost.StartAsync(fixture);
		var (code, verifier) = await host.AuthorizeAsync(Cancellation);
		using (var redeemed = await host.RedeemCodeAsync(code, verifier, Cancellation))
			await OpenIddictTestHost.ReadTokensAsync(redeemed, Cancellation);

		using var response = await host.RevokeAsync(code, Cancellation);

		response.StatusCode.ShouldBe(HttpStatusCode.OK);
		var grant = (await host.ReadGrantsAsync(Cancellation)).ShouldHaveSingleItem();
		host.Termination.Ended.ShouldBe([grant.Id]);
		// The stand-in ends nothing, and the built-in sweep never ran: the grant's refresh token is still valid.
		grant.Tokens.Where(static token => token.Type == TokenTypeIdentifiers.RefreshToken && token.Status == Statuses.Valid)
			.ShouldHaveSingleItem();
	}

	// H3: an access token, or an id token presented as a token or as a hint, is never EndGrantOnReuse's, even when its
	// entry is not valid; ValidateTokenEntry does see each one.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Filters_exclude_access_tokens_and_id_token_hints()
	{
		RequirePinnedOpenIddict();
		fixture.SkipUnlessAvailable();
		await using var host = await OpenIddictTestHost.StartAsync(fixture, recordValidation: true);
		var tokens = await host.SignInAsync(Cancellation);
		var grant = (await host.ReadGrantsAsync(Cancellation)).ShouldHaveSingleItem();
		// Every entry not valid, so a missing filter would end the grant.
		await host.SetTokenStatusAsync(grant.Id, Statuses.Redeemed, Cancellation);
		host.ClearJournal();

		using (await host.RevokeAsync(tokens.AccessToken, Cancellation))
			host.Journal.ShouldBe([$"ValidateTokenEntry Revocation {TokenTypeIdentifiers.AccessToken} {grant.Id}"]);
		host.ClearJournal();
		using (await host.RevokeAsync(tokens.IdentityToken, Cancellation))
			host.Journal.ShouldBe([$"ValidateTokenEntry Revocation {TokenTypeIdentifiers.IdentityToken} {grant.Id}"]);
		host.ClearJournal();
		// Whatever OpenIddict answers the hint, it is OpenIddict's answer: only who saw the hint is asserted.
		using (await host.RequestAuthorizationAsync(tokens.IdentityToken, Cancellation))
			host.Journal.ShouldBe([$"ValidateTokenEntry Authorization {TokenTypeIdentifiers.IdentityToken} {grant.Id}"]);

		host.Termination.Ended.ShouldBeEmpty();
	}

	// H4, and §10.7's SQL backstop, at statement level: one row for valid/valid, zero for every other case.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Guarded_statement_row_counts()
	{
		RequirePinnedOpenIddict();
		fixture.SkipUnlessAvailable();
		var now = DateTimeOffset.UtcNow;
		var (context, _) = await fixture.CreateScopeAsync();

		var (validAuthorization, validToken) = await SeedAsync(Statuses.Valid, Statuses.Valid);
		var concurrencyToken = await ReadTokenAsync(context, validToken);
		(await GrantStatements.RedeemAsync(context, validToken, validAuthorization, now, Cancellation)).ShouldBe(1);
		var redeemed = await ReadTokenAsync(context, validToken);
		redeemed.Status.ShouldBe(Statuses.Redeemed);
		redeemed.RedemptionDate.ShouldNotBeNull().ShouldBe(now.UtcDateTime, TimeSpan.FromMilliseconds(1));
		redeemed.ConcurrencyToken.ShouldNotBe(concurrencyToken.ConcurrencyToken);
		// Redeemed by the first statement, so a second presentation is reuse.
		(await GrantStatements.RedeemAsync(context, validToken, validAuthorization, now, Cancellation)).ShouldBe(0);

		var (authorization, alreadyRedeemed) = await SeedAsync(Statuses.Valid, Statuses.Redeemed);
		(await GrantStatements.RedeemAsync(context, alreadyRedeemed, authorization, now, Cancellation)).ShouldBe(0);
		var (revokedTokenAuthorization, revokedToken) = await SeedAsync(Statuses.Valid, Statuses.Revoked);
		(await GrantStatements.RedeemAsync(context, revokedToken, revokedTokenAuthorization, now, Cancellation)).ShouldBe(0);
		var (revokedAuthorization, tokenUnderRevoked) = await SeedAsync(Statuses.Revoked, Statuses.Valid);
		(await GrantStatements.RedeemAsync(context, tokenUnderRevoked, revokedAuthorization, now, Cancellation)).ShouldBe(0);
		(await ReadTokenAsync(context, tokenUnderRevoked)).Status.ShouldBe(Statuses.Valid);
		// The statement is bound to the token's own authorization: a valid authorization of another grant redeems nothing.
		var (_, otherGrantToken) = await SeedAsync(Statuses.Valid, Statuses.Valid);
		(await GrantStatements.RedeemAsync(context, otherGrantToken, validAuthorization, now, Cancellation)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Authorization_revocation_is_conditional_and_idempotent()
	{
		RequirePinnedOpenIddict();
		fixture.SkipUnlessAvailable();
		var (context, _) = await fixture.CreateScopeAsync();
		var (authorization, _) = await SeedAsync(Statuses.Valid, Statuses.Valid);
		var before = await ReadAuthorizationAsync(context, authorization);

		(await GrantStatements.RevokeAuthorizationAsync(context, authorization, Cancellation)).ShouldBe(1);
		var after = await ReadAuthorizationAsync(context, authorization);
		after.Status.ShouldBe(Statuses.Revoked);
		after.ConcurrencyToken.ShouldNotBe(before.ConcurrencyToken);
		(await GrantStatements.RevokeAuthorizationAsync(context, authorization, Cancellation)).ShouldBe(0);
	}

	// H4: a valid refresh token under a valid authorization passes OpenIddict's own validation and reaches the guarded
	// statement, which redeems it; the refresh then succeeds.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task OpenIddict_validation_accepts_what_the_statement_accepts()
	{
		RequirePinnedOpenIddict();
		fixture.SkipUnlessAvailable();
		await using var host = await OpenIddictTestHost.StartAsync(fixture);
		var tokens = await host.SignInAsync(Cancellation);
		var refreshTokenId = RefreshTokenOf((await host.ReadGrantsAsync(Cancellation)).ShouldHaveSingleItem()).Id;
		var validation = host.Arm(PausePoint.BeforeValidateTokenEntry);
		var beforeRedemption = host.Arm(PausePoint.BeforeRedemption);
		var afterRedemption = host.Arm(PausePoint.AfterRedemption);

		var refresh = host.RefreshAsync(tokens.RefreshToken, Cancellation);
		await validation.Reached.WaitAsync(_pauseTimeout, Cancellation);
		validation.Release();
		await beforeRedemption.Reached.WaitAsync(_pauseTimeout, Cancellation);
		(await TokenStatusAsync()).ShouldBe(Statuses.Valid);
		beforeRedemption.Release();
		await afterRedemption.Reached.WaitAsync(_pauseTimeout, Cancellation);
		(await TokenStatusAsync()).ShouldBe(Statuses.Redeemed);
		afterRedemption.Release();

		using var response = await refresh;
		var successor = await OpenIddictTestHost.ReadTokensAsync(response, Cancellation);
		successor.RefreshToken.ShouldNotBe(tokens.RefreshToken);
		var grant = (await host.ReadGrantsAsync(Cancellation)).ShouldHaveSingleItem();
		grant.Status.ShouldBe(Statuses.Valid);
		var presented = grant.Tokens.Single(token => token.Id == refreshTokenId);
		presented.RedemptionDate.ShouldNotBeNull().ShouldBe(host.Clock.GetUtcNow().UtcDateTime, TimeSpan.FromMilliseconds(1));
		host.Termination.Ended.ShouldBeEmpty();

		async Task<string?> TokenStatusAsync() =>
			(await host.ReadGrantsAsync(Cancellation)).Single().Tokens.Single(token => token.Id == refreshTokenId).Status;
	}

	/// <summary>The first premise, as a precondition of every other: they mean nothing on another OpenIddict.</summary>
	static void RequirePinnedOpenIddict()
	{
		var versions = ResolvedVersions().Values.Distinct(StringComparer.Ordinal).ToList();
		(versions is [var version] && version.StartsWith(PinnedVersion, StringComparison.Ordinal)).ShouldBeTrue(
			$"Premise Resolved_openiddict_is_one_v8_version fails ({string.Join(", ", versions)}); every other premise depends on it.");
	}

	/// <summary>
	///     Every loaded <c>OpenIddict.*</c> assembly's informational version, by assembly name, the anchored ones
	///     included whether or not anything has loaded them yet.
	/// </summary>
	static SortedDictionary<string, string> ResolvedVersions() =>
		new(AppDomain.CurrentDomain.GetAssemblies()
			.Concat(_openIddictAssemblies.Select(static anchor => anchor.Assembly))
			.Where(static assembly => assembly.GetName().Name?.StartsWith("OpenIddict.", StringComparison.Ordinal) is true)
			.DistinctBy(static assembly => assembly.GetName().Name)
			.ToDictionary(static assembly => assembly.GetName().Name!,
				static assembly => assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "(none)"),
			StringComparer.Ordinal);

	static OpenIddictTestHost.TokenRow RefreshTokenOf(OpenIddictTestHost.GrantRow grant) =>
		grant.Tokens.Single(static token => token.Type == TokenTypeIdentifiers.RefreshToken);

	/// <summary>An authorization in <paramref name="authorizationStatus" /> holding one refresh token in <paramref name="tokenStatus" />.</summary>
	async Task<(Guid Authorization, Guid Token)> SeedAsync(string authorizationStatus, string tokenStatus)
	{
		using var scope = fixture.CreateOwnedScope();
		var authorizations = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
		var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
		var subject = $"premise-{Guid.NewGuid():N}";
		var authorization = await authorizations.CreateAsync(new OpenIddictAuthorizationDescriptor
		{
			CreationDate = DateTimeOffset.UtcNow,
			Status = authorizationStatus,
			Subject = subject,
			Type = AuthorizationTypes.AdHoc
		}, Cancellation);
		var authorizationId = await authorizations.GetIdAsync(authorization, Cancellation) ??
			throw new InvalidOperationException("The seeded authorization carries no id.");
		var token = await tokens.CreateAsync(new OpenIddictTokenDescriptor
		{
			AuthorizationId = authorizationId,
			CreationDate = DateTimeOffset.UtcNow,
			ExpirationDate = DateTimeOffset.UtcNow.AddDays(14),
			Status = tokenStatus,
			Subject = subject,
			Type = TokenTypeIdentifiers.RefreshToken
		}, Cancellation);
		var tokenId = await tokens.GetIdAsync(token, Cancellation) ??
			throw new InvalidOperationException("The seeded token carries no id.");
		return (Guid.Parse(authorizationId), Guid.Parse(tokenId));
	}

	static Task<StoredToken> ReadTokenAsync(NorseIdentityDbContext context, Guid id) =>
		context.Set<NorseOpenIddictToken>()
			.Where(token => token.Id == id)
			.Select(static token => new StoredToken(token.Status, token.RedemptionDate, token.ConcurrencyToken))
			.SingleAsync(Cancellation);

	static Task<StoredAuthorization> ReadAuthorizationAsync(NorseIdentityDbContext context, Guid id) =>
		context.Set<NorseOpenIddictAuthorization>()
			.Where(authorization => authorization.Id == id)
			.Select(static authorization => new StoredAuthorization(authorization.Status, authorization.ConcurrencyToken))
			.SingleAsync(Cancellation);

	sealed record StoredToken(string? Status, DateTime? RedemptionDate, string? ConcurrencyToken);

	sealed record StoredAuthorization(string? Status, string? ConcurrencyToken);
}
