using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Norse.Identity;

/// <summary>
/// Norse platform <see cref="UserStore{TUser,TRole,TContext,TKey,TUserClaim,TUserRole,TUserLogin,TUserToken,TRoleClaim,TUserPasskey}"/>
/// backed by <see cref="NorseIdentityDbContext"/>, with projection overrides for read paths that do not
/// need the full navigation graph.
/// </summary>
/// <param name="context">The Identity database context.</param>
/// <param name="describer">Describes errors raised by the store.</param>
public sealed class NorseUserStore(NorseIdentityDbContext context, IdentityErrorDescriber describer)
	: UserStore<NorseUser, NorseRole, NorseIdentityDbContext, Guid,
		NorseUserClaim, NorseUserRole, NorseUserLogin,
		NorseUserToken, NorseRoleClaim, NorseUserPasskey>(context, describer)
{
	/// <summary>
	/// Finds a user by id, projecting only the fields required by callers instead of materializing the
	/// full <see cref="NorseUser"/> navigation graph.
	/// </summary>
	/// <param name="userId">The user id, as a <see cref="Guid"/> string.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>The projected user, or <see langword="null"/> if no user with the given id exists.</returns>
	public override Task<NorseUser?> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
	{
		var id = Guid.Parse(userId);
		return Users
			.Where(u => u.Id == id)
			.Select(u => new NorseUser
			{
				Id = u.Id,
				UserName = u.UserName,
				NormalizedUserName = u.NormalizedUserName,
				Email = u.Email,
				NormalizedEmail = u.NormalizedEmail,
				SecurityStamp = u.SecurityStamp,
				ConcurrencyStamp = u.ConcurrencyStamp
			})
			.SingleOrDefaultAsync(cancellationToken);
	}
}
