using Microsoft.AspNetCore.Identity;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity role entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseRole : IdentityRole<Guid>;
