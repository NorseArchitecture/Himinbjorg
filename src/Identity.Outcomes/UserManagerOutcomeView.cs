using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Outcomes;

/// <summary>
///     <c>userManager.Outcome</c> (2026-10-24 explicit-writes spec §4.12): the stock <see cref="UserManager{TUser}" />,
///     answering <see cref="Outcome{T}" /> through <see cref="IdentityOutcomeMap" />. Each method keeps the name of the
///     manager method it wraps.
/// </summary>
/// <param name="userManager">The manager this view wraps.</param>
public sealed class UserManagerOutcomeView(UserManager<NorseUser> userManager)
{
	/// <summary>Wraps <see cref="UserManager{TUser}.CreateAsync(TUser, string)" />.</summary>
	/// <param name="user">The user to create.</param>
	/// <param name="password">The user's password.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes its own <c>CancellationToken</c>.
	/// </param>
	public ValueTask<Outcome<Unit>> CreateAsync(NorseUser user, string password,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return IdentityOutcomeMap.GuardAsync(async () =>
			IdentityOutcomeMap.ToOutcome(await userManager.CreateAsync(user, password).ConfigureAwait(false),
				Unit.Value));
	}

	/// <summary>
	///     Wraps <see cref="UserManager{TUser}.FindByEmailAsync" />: <see cref="ErrorCategory.NotFound" /> for no such
	///     user, and <see cref="ErrorCategory.Erased" /> with the receipt for a user whose key is destroyed.
	/// </summary>
	/// <param name="email">The email to look up.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes its own <c>CancellationToken</c>.
	/// </param>
	public ValueTask<Outcome<NorseUser>> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return IdentityOutcomeMap.GuardAsync(async () =>
			await userManager.FindByEmailAsync(email).ConfigureAwait(false) is { } user ?
				Outcome<NorseUser>.Ok(user) :
				Outcome<NorseUser>.Err(ErrorCategory.NotFound));
	}
}
