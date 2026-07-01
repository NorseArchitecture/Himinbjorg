using Microsoft.AspNetCore.Identity;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity user-claim entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseUserClaim : IdentityUserClaim<Guid>;
