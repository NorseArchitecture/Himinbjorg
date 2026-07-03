using Microsoft.AspNetCore.Identity;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity role-claim entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseRoleClaim : IdentityRoleClaim<Guid>
{
	/// <summary>
	/// The role this claim belongs to.
	/// </summary>
	public NorseRole? Role { get; init; }
}
