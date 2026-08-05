using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Backend.Keys;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

/// <summary>
/// The one chokepoint every identity write traverses, establishing the ambient crypto subject
/// around the base call so the protector always knows whose DEK to use -- Heimdall and every future
/// caller inherit the scope for free. Create assigns the id first when the caller didn't: the
/// subject must exist before the store encrypts.
/// </summary>
public sealed class NorseUserManager(
	IUserStore<NorseUser> store, IOptions<IdentityOptions> optionsAccessor,
	IPasswordHasher<NorseUser> passwordHasher, IEnumerable<IUserValidator<NorseUser>> userValidators,
	IEnumerable<IPasswordValidator<NorseUser>> passwordValidators, ILookupNormalizer keyNormalizer,
	IdentityErrorDescriber errors, IServiceProvider services, ILogger<UserManager<NorseUser>> logger) :
	UserManager<NorseUser>(store, optionsAccessor, passwordHasher, userValidators, passwordValidators,
		keyNormalizer, errors, services, logger)
{
	/// <inheritdoc />
	public override async Task<IdentityResult> CreateAsync(NorseUser user)
	{
		ArgumentNullException.ThrowIfNull(user);
		if (user.Id == Guid.Empty)
			user.Id = Guid.CreateVersion7();
		using (SubjectCryptoScope.Begin(user.Id))
			return await base.CreateAsync(user).ConfigureAwait(false);
	}

	/// <inheritdoc />
	protected override async Task<IdentityResult> UpdateUserAsync(NorseUser user)
	{
		using (SubjectCryptoScope.Begin(user.Id))
			return await base.UpdateUserAsync(user).ConfigureAwait(false);
	}
}
