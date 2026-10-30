using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     <c>Norse.Bearer</c> (spec §7.1): the one bearer source Midgard's lanes authenticate by name, forwarding authenticate,
///     challenge and forbid to the OpenIddict validation scheme, with the authenticate-before-challenge behavior
///     Himinbjorg#49 found and Midgard no longer carries.
/// </summary>
/// <remarks>
///     OpenIddict's validation handler reads the reason for a challenge from the state its own authenticate pass left in
///     the request. A challenge that reaches it with no authenticate pass in the same request finds nothing and answers
///     403 <c>insufficient_access</c> (ID2095) instead of a bare 401: decompiled 7.6.0 (#49), and re-verified on
///     8.0.0-preview.4, where the gRPC lane's credential-less and invalid-cookie calls, which challenge through
///     <c>Norse.Machine</c> without ever authenticating the bearer, answered exactly that. So the challenge authenticates
///     first. A request that already authenticated reuses the handler's cached result, so the façade path does no second
///     validation. Forbid needs nothing: 403 is already its answer.
///     <para>
///         A challenge after the bearer itself <i>succeeded</i> means a Midgard lane refused the validated token (the lane
///         ruling: a <c>Norse.Machine</c> token needs exactly <c>Norse.Facade</c>, a <c>Norse.User</c> one exactly
///         <c>Norse.User</c>), which is an authentication failure. OpenIddict would answer it as the authenticated
///         request it saw, 403 <c>insufficient_access</c>, so the challenge names <c>invalid_token</c> (RFC 6750: invalid
///         for this resource), unless the caller named an error itself: a bare 401, its details suppressed (§5.7).
///     </para>
/// </remarks>
sealed class BearerChallengeHandler(
	IOptionsMonitor<AuthenticationSchemeOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder)
	: AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
	const string Validation = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;

	protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
		Context.AuthenticateAsync(Validation);

	protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
	{
		var authentication = await Context.AuthenticateAsync(Validation).ConfigureAwait(false);
		if (authentication.Succeeded && !properties.Items.ContainsKey(OpenIddictValidationAspNetCoreConstants.Properties.Error))
		{
			properties = properties.Clone();
			properties.Items[OpenIddictValidationAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidToken;
		}

		await Context.ChallengeAsync(Validation, properties).ConfigureAwait(false);
	}

	protected override Task HandleForbiddenAsync(AuthenticationProperties properties) =>
		Context.ForbidAsync(Validation, properties);
}
