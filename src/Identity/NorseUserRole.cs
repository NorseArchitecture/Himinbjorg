using Microsoft.AspNetCore.Identity;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity user-role join entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseUserRole : IdentityUserRole<Guid>;
