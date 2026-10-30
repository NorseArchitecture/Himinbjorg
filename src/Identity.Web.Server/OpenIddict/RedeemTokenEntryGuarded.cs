using Norse.Identity.EntityFramework;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     The guarded redemption (2026-10-29 OpenIddict spec §5.5), in place of OpenIddict's <c>RedeemTokenEntry</c> and
///     at its order: a presented authorization code or refresh token is redeemed by one conditional statement
///     (<see cref="GrantStatements.RedeemAsync" />) that also requires its authorization to be <c>valid</c>. One row
///     proceeds; zero rows is reuse, so the grant ends and the request answers <c>invalid_grant</c>. A database exception
///     propagates: it is never retried and never classified as reuse.
/// </summary>
/// <remarks>
///     The built-in also redeems request tokens (request caching, pushed authorization), device codes and user codes.
///     None of those is enabled on this server, so meeting one fails closed instead of passing it unredeemed: enabling
///     any of them needs its own guarded redemption.
/// </remarks>
/// <param name="database">
///     The request's identity context, which the statement runs on: the handler is scoped, so it is the one the request's
///     stores share.
/// </param>
/// <param name="termination">Ends the grant on reuse (<see cref="GrantTermination" /> in production).</param>
sealed class RedeemTokenEntryGuarded(NorseIdentityDbContext database, IGrantTermination termination)
	: IOpenIddictServerHandler<ProcessSignInContext>
{
	/// <summary>The built-in's filters and order, with this handler in its place.</summary>
	public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
		OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
			.AddFilter<RequireDegradedModeDisabled>()
			.AddFilter<RequireTokenStorageEnabled>()
			.UseScopedHandler<RedeemTokenEntryGuarded>()
			.SetOrder(RedeemTokenEntry.Descriptor.Order)
			.SetType(OpenIddictServerHandlerType.Custom)
			.Build();

	/// <inheritdoc />
	public async ValueTask HandleAsync(ProcessSignInContext context)
	{
		ArgumentNullException.ThrowIfNull(context);
		var request = context.Request;
		var redeemsGrant = context.EndpointType is OpenIddictServerEndpointType.Token
			&& (request.IsAuthorizationCodeGrantType()
				|| (request.IsRefreshTokenGrantType() && !context.Options.DisableRollingRefreshTokens));
		var unguarded = context.EndpointType is OpenIddictServerEndpointType.Authorization
				or OpenIddictServerEndpointType.EndUserVerification
			|| (context.EndpointType is OpenIddictServerEndpointType.Token && request.IsDeviceCodeGrantType());
		if (!redeemsGrant && !unguarded)
			return;

		var authentication = context.Transaction.GetProperty<ProcessAuthenticationContext>(
				typeof(ProcessAuthenticationContext).FullName!) ??
			throw new InvalidOperationException("The sign-in carries no authentication context to redeem from.");
		if (unguarded)
		{
			if ((authentication.RequestTokenPrincipal ?? authentication.DeviceCodePrincipal ?? authentication.UserCodePrincipal)
				is not null)
				throw new NotSupportedException(
					"Only authorization codes and refresh tokens have a guarded redemption; request caching, pushed authorization and the device flow are not enabled.");
			return;
		}

		var principal = request.IsAuthorizationCodeGrantType() ?
			authentication.AuthorizationCodePrincipal :
			authentication.RefreshTokenPrincipal;
		// Fail-closed: every code and refresh token this server issues has its row and its ad-hoc authorization (§5.2,
		// §4.5), and validation already refuses one without both ids (EndGrantOnReuse). One arriving here without them
		// anyway is never redeemed unguarded nor passed through to mint: it is refused, after the grant that can still be
		// named ends.
		if (!Guid.TryParse(principal?.GetTokenId(), out var token)
			|| !Guid.TryParse(principal?.GetAuthorizationId(), out var authorization))
		{
			await UnanchoredGrant.EndAsync(database, termination, principal?.GetTokenId(), principal?.GetAuthorizationId(),
				context.CancellationToken).ConfigureAwait(false);
			context.Reject(error: Errors.InvalidGrant);
			return;
		}

		// A database exception propagates (§5.5): the request fails as a 500 with nothing minted, the statement is never
		// retried, and the grant is never ended, since the token's state may be redeemed (indeterminate) or not.
		var redeemed = await GrantStatements
			.RedeemAsync(database, token, authorization, context.Options.TimeProvider.GetUtcNow(), context.CancellationToken)
			.ConfigureAwait(false);
		if (redeemed is 1)
			return;

		await termination.EndAsync(authorization, context.CancellationToken).ConfigureAwait(false);
		context.Reject(error: Errors.InvalidGrant);
	}
}
