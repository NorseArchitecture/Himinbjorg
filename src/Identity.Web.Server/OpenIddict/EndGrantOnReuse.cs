using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     Reuse caught at validation (2026-10-29 OpenIddict spec §5.5, r5): presenting an authorization code or a refresh
///     token whose entry is not <c>valid</c> (<c>redeemed</c>, <c>revoked</c>, <c>inactive</c>), at the token endpoint or
///     the revocation endpoint, ends its grant and is refused: <c>invalid_grant</c> at the token endpoint,
///     <c>invalid_token</c> at the revocation endpoint, which OpenIddict normalizes to HTTP 200 there. It runs
///     immediately before OpenIddict's <c>ValidateTokenEntry</c>, so the built-in sweep never runs for these cases, and
///     every other token validation (access tokens, id-token hints, client assertions) passes through untouched.
/// </summary>
/// <remarks>
///     Fail-closed: a code or refresh token reaching it without a token id or an authorization id (every one this server
///     issues has both, §4.5) is refused the same way, after the grant that can still be named ends, never passed on to
///     OpenIddict's entry checks, which the same missing id would filter out.
/// </remarks>
/// <param name="database">The request's identity context: the handler is scoped, so it is the one the request's stores share.</param>
/// <param name="termination">Ends the grant (<see cref="GrantTermination" /> in production).</param>
sealed class EndGrantOnReuse(NorseIdentityDbContext database, IGrantTermination termination)
	: IOpenIddictServerHandler<ValidateTokenContext>
{
	/// <summary>
	///     Immediately before <c>ValidateTokenEntry</c>, with its storage filters but never an id filter, and only for a
	///     code or refresh token presented at the token endpoint (its own grant) or the revocation endpoint.
	/// </summary>
	public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
		OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
			.AddFilter<RequireDegradedModeDisabled>()
			.AddFilter<RequireTokenStorageEnabled>()
			.AddFilter<RequireGrantTokenAtTokenOrRevocation>()
			.UseScopedHandler<EndGrantOnReuse>()
			.SetOrder(ValidateTokenEntry.Descriptor.Order - 1)
			.SetType(OpenIddictServerHandlerType.Custom)
			.Build();

	/// <inheritdoc />
	public async ValueTask HandleAsync(ValidateTokenContext context)
	{
		ArgumentNullException.ThrowIfNull(context);
		if (!Guid.TryParse(context.TokenId, out var token) || !Guid.TryParse(context.AuthorizationId, out var authorization))
		{
			await UnanchoredGrant.EndAsync(database, termination, context.TokenId, context.AuthorizationId,
				context.CancellationToken).ConfigureAwait(false);
			Refuse(context);
			return;
		}

		// The read decides whether the grant ends, so it ignores the request's cancellation, as EndGrant's first step does
		// (M2): a client presenting a reused token and hanging up at once must not keep the grant alive.
		var status = await database
			.Set<NorseOpenIddictToken>()
			.Where(entry => entry.Id == token)
			.Select(static entry => entry.Status)
			.SingleOrDefaultAsync(CancellationToken.None)
			.ConfigureAwait(false);
		// A missing entry is ValidateTokenEntry's to refuse; a valid one is no reuse.
		if (status is null or Statuses.Valid)
			return;

		await termination.EndAsync(authorization, context.CancellationToken).ConfigureAwait(false);
		Refuse(context);
	}

	/// <summary><c>invalid_token</c> at the revocation endpoint, <c>invalid_grant</c> at the token endpoint.</summary>
	static void Refuse(ValidateTokenContext context) =>
		context.Reject(error: context.EndpointType is OpenIddictServerEndpointType.Revocation ?
			Errors.InvalidToken :
			Errors.InvalidGrant);

	/// <summary>
	///     The endpoint and token-type filter: a code or refresh token, at the token endpoint under the
	///     <c>authorization_code</c> or <c>refresh_token</c> grant, or at the revocation endpoint.
	/// </summary>
	internal sealed class RequireGrantTokenAtTokenOrRevocation : IOpenIddictServerHandlerFilter<ValidateTokenContext>
	{
		/// <inheritdoc />
		public ValueTask<bool> IsActiveAsync(ValidateTokenContext context)
		{
			ArgumentNullException.ThrowIfNull(context);
			var grantToken = context.Principal is { } principal
				&& (principal.HasTokenType(TokenTypeIdentifiers.Private.AuthorizationCode)
					|| principal.HasTokenType(TokenTypeIdentifiers.RefreshToken));
			var endpoint = context.EndpointType switch
			{
				OpenIddictServerEndpointType.Revocation => true,
				OpenIddictServerEndpointType.Token => context.Request is { } request
					&& (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType()),
				_ => false
			};
			return new(grantToken && endpoint);
		}
	}
}
