using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;

namespace Norse.Identity.Web.Server;

/// <summary>
///     <c>signInManager.Outcome</c> (2026-10-24 explicit-writes spec §4.12): the stock <see cref="SignInManager{TUser}" />,
///     answering <see cref="Outcome{T}" /> through <see cref="IdentityOutcomeMap" />. It lives here, not in
///     <c>Identity.Outcomes</c>, because <c>SignInManager</c> lives in the ASP.NET Core shared framework, which the
///     migrations service must never take.
/// </summary>
/// <param name="signInManager">The manager this view wraps.</param>
sealed class SignInManagerOutcomeView(SignInManager<NorseUser> signInManager)
{
	/// <summary>
	///     Wraps <see cref="SignInManager{TUser}.PasswordSignInAsync(string, string, bool, bool)" />. An indeterminate
	///     access-failed increment (spec §4.5) answers <see cref="ErrorCategory.Indeterminate" />, and a destroyed key
	///     <see cref="ErrorCategory.Erased" />: outcomes, never exceptions.
	/// </summary>
	/// <param name="userName">The user name.</param>
	/// <param name="password">The password to check.</param>
	/// <param name="isPersistent">Whether the sign-in cookie persists.</param>
	/// <param name="lockoutOnFailure">Whether a failure counts toward lockout.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes the request's own cancellation.
	/// </param>
	public async ValueTask<Outcome<SignInCompletion>> PasswordSignInAsync(string userName, string password,
		bool isPersistent, bool lockoutOnFailure, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		try
		{
			return IdentityOutcomeMap.ToOutcome(await signInManager
				.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure)
				.ConfigureAwait(false));
		}
		catch (Exception exception) when (IdentityOutcomeMap.TryClassify(exception, out var problem))
		{
			return new(new Failed(problem));
		}
	}
}
