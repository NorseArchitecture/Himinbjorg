using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     Answers the caller's external logins: the linked ones, the configured providers not yet linked, and whether the
///     page should offer a remove button (a password exists, or more than one login does) -- presentation only, the
///     store refuses removing the last sign-in method regardless. Every call is a read-only manager call (raw by law,
///     §5.2). The fold's failures pass through unchanged.
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Reads the linked logins.</param>
/// <param name="signInManager">Reads the configured external authentication schemes.</param>
sealed class GetExternalLoginsHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	SignInManager<NorseUser> signInManager)
	: IRequestHandler<GetExternalLoginsCommand, ExternalLoginsResponse>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<ExternalLoginsResponse>> Handle(GetExternalLoginsCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed failed))
			return new(failed);
		found.TryGetValue(out Success<NorseUser> success);
		var user = success.Value;

		var logins = await userManager.GetLoginsAsync(user).ConfigureAwait(false);
		var schemes = await signInManager.GetExternalAuthenticationSchemesAsync().ConfigureAwait(false);
		return Outcome<ExternalLoginsResponse>.Ok(new ExternalLoginsResponse
		{
			Logins =
			[
				.. logins.Select(l => new ExternalLoginEntry
				{
					LoginProvider = l.LoginProvider,
					ProviderKey = l.ProviderKey,
					DisplayName = l.ProviderDisplayName ?? l.LoginProvider
				})
			],
			AvailableProviders =
			[
				.. schemes
					.Where(s => logins.All(l => l.LoginProvider != s.Name))
					.Select(s => new ExternalProviderEntry { Name = s.Name, DisplayName = s.DisplayName ?? s.Name })
			],
			CanRemove = await userManager.HasPasswordAsync(user).ConfigureAwait(false) || logins.Count > 1
		});
	}
}
