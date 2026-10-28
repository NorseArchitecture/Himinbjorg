using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Passkeys;

/// <summary>
///     T3-16: the cap of 100 passkeys per account, a resource bound enforced here on the server, where the client
///     only hides Add. Both halves of the registration ceremony check it, so a caller at the cap starts no ceremony
///     and completes none. Two concurrent adds at 99 can both pass.
/// </summary>
static class PasskeyCap
{
	/// <summary>The most passkeys one account may register (template parity).</summary>
	public const int Limit = 100;

	/// <summary>What a caller at the cap answers.</summary>
	public static readonly Failed Reached = new(Problem.ModelError(ErrorCategory.Conflict,
		"You have reached the maximum number of allowed passkeys."));

	/// <summary>Whether <paramref name="user" /> already holds <see cref="Limit" /> passkeys.</summary>
	/// <param name="userManager">Reads the user's passkeys.</param>
	/// <param name="user">The caller.</param>
	/// <returns><see langword="true" /> at or past the cap.</returns>
	public static async ValueTask<bool> IsReachedAsync(UserManager<NorseUser> userManager, NorseUser user) =>
		(await userManager.GetPasskeysAsync(user).ConfigureAwait(false)).Count >= Limit;
}
