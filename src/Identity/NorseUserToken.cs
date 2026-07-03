using Microsoft.AspNetCore.Identity;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity user-token entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseUserToken : IdentityUserToken<Guid>
{
	/// <summary>
	/// The user this token belongs to.
	/// </summary>
	public NorseUser User { get; init; } = null!;
}
