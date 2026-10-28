using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.TwoFactor;

/// <summary>
///     Answers what the enable-authenticator page renders in place: the caller's key, its URI under the configured
///     issuer, and that URI as a QR code. A missing key is provisioned losslessly without rotating the stamp (T3-13):
///     an unverified key is not a factor, so no session needs to die. Provisioning is a conditional write, so two
///     setups racing on a first load both answer the one key stored. Failures pass through unchanged.
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Provisions the key and reads the email it is filed under.</param>
/// <param name="options">The configured issuer.</param>
sealed class GetAuthenticatorSetupHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	IOptions<AuthenticatorOptions> options)
	: IRequestHandler<GetAuthenticatorSetupCommand, AuthenticatorSetupResponse>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<AuthenticatorSetupResponse>> Handle(GetAuthenticatorSetupCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> user);

		var provisioned = await userManager.Outcome.ProvisionAuthenticatorKeyAsync(user.Value, cancellationToken).ConfigureAwait(false);
		if (provisioned.TryGetValue(out Failed failed))
			return new(failed);
		provisioned.TryGetValue(out Success<string> key);

		var email = await userManager.GetEmailAsync(user.Value).ConfigureAwait(false) ?? string.Empty;
		var uri = AuthenticatorSetup.Uri(options.Value.Issuer, email, key.Value);
		return Outcome<AuthenticatorSetupResponse>.Ok(new AuthenticatorSetupResponse
		{
			SharedKey = AuthenticatorSetup.FormatKey(key.Value),
			AuthenticatorUri = uri,
			QrCodeSvg = AuthenticatorSetup.QrSvg(uri)
		});
	}
}
