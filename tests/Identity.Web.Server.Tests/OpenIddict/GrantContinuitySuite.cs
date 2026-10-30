using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     Grant continuity and its security consequence (2026-10-29 OpenIddict spec §4.5 facts 3 and 4; plan gate H7), once
///     per provider, through <see cref="OpenIddictTestHost" />: a refresh chain stays on the one authorization its code
///     was issued under, so replaying a rotated refresh token ends that grant, and only that grant.
/// </summary>
/// <remarks>
///     Asserted on the <c>tokens</c> and <c>authorizations</c> rows, never only on principal claims: a refresh that lost
///     its authorization id would otherwise be handed a fresh ad-hoc authorization by <c>AttachAuthorization</c>,
///     splitting the grant.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class GrantContinuitySuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	// §4.5 fact 3: code → R0 → R1 → R2 keeps one non-null authorization, and refresh creates no other.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Refresh_chain_keeps_one_authorization()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await OpenIddictTestHost.StartAsync(fixture);
		var r0 = await host.SignInAsync(Cancellation);
		var r1 = await RefreshAsync(host, r0.RefreshToken);
		await RefreshAsync(host, r1.RefreshToken);

		var (context, _) = await fixture.CreateScopeAsync();
		var authorization = (await context.Set<NorseOpenIddictAuthorization>()
				.Where(entity => entity.Subject == host.Subject)
				.Select(static entity => entity.Id)
				.ToListAsync(Cancellation))
			.ShouldHaveSingleItem();
		var tokens = await context.Set<NorseOpenIddictToken>()
			.Where(entity => entity.Subject == host.Subject)
			.Select(static entity => new ChainToken(entity.Type, entity.AuthorizationId))
			.ToListAsync(Cancellation);
		foreach (var token in tokens)
			TestContext.Current.TestOutputHelper?.WriteLine($"{token.Type} {token.AuthorizationId?.ToString() ?? "(null)"}");

		tokens.Count(static token => token.Type == TokenTypeIdentifiers.RefreshToken).ShouldBe(3);
		tokens.ShouldAllBe(token => token.AuthorizationId == authorization);
	}

	// §4.5 fact 4: replaying R0 after two rotations ends the original authorization, R2 can no longer refresh, and an
	// independent grant for the same user and client is untouched.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Replaying_r0_after_two_rotations_ends_the_grant()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await OpenIddictTestHost.StartAsync(fixture, revokeOnEnd: true);
		var r0 = await host.SignInAsync(Cancellation);
		var r1 = await RefreshAsync(host, r0.RefreshToken);
		var r2 = await RefreshAsync(host, r1.RefreshToken);
		var original = (await host.ReadGrantsAsync(Cancellation)).ShouldHaveSingleItem().Id;

		using (var replay = await host.RefreshAsync(r0.RefreshToken, Cancellation))
			await ShouldBeInvalidGrantAsync(replay);
		host.Termination.Ended.ShouldContain(original);
		(await host.ReadGrantsAsync(Cancellation)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Revoked);

		using (var successor = await host.RefreshAsync(r2.RefreshToken, Cancellation))
			await ShouldBeInvalidGrantAsync(successor);

		var independent = await host.SignInAsync(Cancellation);
		await RefreshAsync(host, independent.RefreshToken);
		var grants = await host.ReadGrantsAsync(Cancellation);
		grants.Count.ShouldBe(2);
		grants.Single(grant => grant.Id == original).Status.ShouldBe(Statuses.Revoked);
		grants.Single(grant => grant.Id != original).Status.ShouldBe(Statuses.Valid);
		host.Termination.Ended.ShouldAllBe(ended => ended == original);
	}

	static async Task<OpenIddictTestHost.TokenSet> RefreshAsync(OpenIddictTestHost host, string refreshToken)
	{
		using var response = await host.RefreshAsync(refreshToken, Cancellation);
		return await OpenIddictTestHost.ReadTokensAsync(response, Cancellation);
	}

	static async Task ShouldBeInvalidGrantAsync(HttpResponseMessage response)
	{
		response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
		var body = await response.Content.ReadFromJsonAsync<JsonElement>(Cancellation);
		body.GetProperty(Parameters.Error).GetString().ShouldBe(Errors.InvalidGrant);
	}

	sealed record ChainToken(string? Type, Guid? AuthorizationId);
}
