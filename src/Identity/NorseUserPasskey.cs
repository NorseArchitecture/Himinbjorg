using Microsoft.AspNetCore.Identity;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity passkey entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseUserPasskey : IdentityUserPasskey<Guid>;
