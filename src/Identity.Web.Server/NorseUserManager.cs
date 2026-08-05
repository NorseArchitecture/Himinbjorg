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
	/// <exception cref="InvalidOperationException">
	/// <paramref name="user"/> has no id yet (<see cref="Guid.Empty"/>). Establishing the ambient scope
	/// on an empty id would mint a DEK for nobody -- the exact silent fallback
	/// <see cref="SubjectCryptoScope"/> exists to forbid -- so this fails loudly before the store is
	/// ever called instead of quietly encrypting under an all-zeros subject.
	/// </exception>
	protected override async Task<IdentityResult> UpdateUserAsync(NorseUser user)
	{
		ArgumentNullException.ThrowIfNull(user);
		if (user.Id == Guid.Empty)
			throw new InvalidOperationException(
				"NorseUserManager.UpdateUserAsync was called with an empty user id -- the subject must exist (see CreateAsync) before the store can establish an ambient crypto scope and encrypt.");
		using (SubjectCryptoScope.Begin(user.Id))
			return await base.UpdateUserAsync(user).ConfigureAwait(false);
	}
}
