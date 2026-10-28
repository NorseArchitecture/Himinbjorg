using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Passkeys;

/// <summary>
///     Lists the caller's passkeys in place, each with its base64url id, its name (<c>""</c> when unnamed) and its
///     server-authored rename URL (T3-10).
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Reads the caller's passkeys.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class GetPasskeysHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<GetPasskeysCommand, PasskeysResponse>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<PasskeysResponse>> Handle(GetPasskeysCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> user);

		var pathBase = httpContextAccessor.HttpContext!.Request.PathBase;
		var passkeys = await userManager.GetPasskeysAsync(user.Value).ConfigureAwait(false);
		return Outcome<PasskeysResponse>.Ok(new PasskeysResponse
		{
			Passkeys = [.. passkeys.Select(passkey => CredentialIds.Entry(pathBase, passkey))]
		});
	}
}
