using Microsoft.AspNetCore.Identity;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Outcomes;

/// <summary>
///     A lossless recovery-code replacement: the update's own <see cref="IdentityResult" /> beside the codes it
///     wrote, where <see cref="UserManager{TUser}.GenerateNewTwoFactorRecoveryCodesAsync" /> answers
///     <see langword="null" /> for every failure and so loses an indeterminate commit. Implemented by
///     <c>NorseUserManager</c>; Norse callers reach it through <see cref="UserManagerOutcomeView.ReplaceRecoveryCodesAsync" />.
/// </summary>
public interface IRecoveryCodeReplacement
{
	/// <summary>Replaces <paramref name="user" />'s recovery codes with <paramref name="number" /> new ones.</summary>
	/// <param name="user">The user whose codes to replace.</param>
	/// <param name="number">How many codes to generate.</param>
	/// <returns>The update's result, untouched, and the codes generated.</returns>
	Task<(IdentityResult Result, string[] Codes)> ReplaceRecoveryCodesAsync(NorseUser user, int number);
}
