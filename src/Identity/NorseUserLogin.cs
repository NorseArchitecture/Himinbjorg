using Microsoft.AspNetCore.Identity;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity external-login entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseUserLogin : IdentityUserLogin<Guid>;
