using System.Globalization;
using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     The store link contract (2026-10-29 OpenIddict spec §4.5), shared by <see cref="NorseOpenIddictTokenStore" />,
///     <see cref="NorseOpenIddictAuthorizationStore" /> and <see cref="NorseOpenIddictSessionStore" />. A link is the
///     entity's explicit FK scalar: the getter answers it and nothing else, and the setter writes it together with the
///     navigation, so the two never disagree, tracked or detached, before or after persistence.
/// </summary>
/// <remarks>
///     OpenIddict's stock accessors read the navigation, loading it through the change tracker when it is unloaded and
///     answering null when the entity is detached, which is what the platform's NoTracking default hands them from
///     <c>FindByIdAsync</c>. A missing link is never recovered from anywhere else (no claim, no query) and never
///     manufactured: it is the database's, or it is absent.
/// </remarks>
static class OpenIddictLinks
{
	/// <summary>The link's string form, or <see langword="null" /> when there is none. Issues no query.</summary>
	/// <param name="entity">The dependent entity.</param>
	/// <param name="scalar">Reads the dependent's explicit FK scalar.</param>
	public static ValueTask<string?> Get<TEntity>(TEntity entity, Func<TEntity, Guid?> scalar) where TEntity : class
	{
		ArgumentNullException.ThrowIfNull(entity);
		return ValueTask.FromResult(scalar(entity)?.ToString());
	}

	/// <summary>
	///     Points <paramref name="entity" />'s link at <paramref name="identifier" />, or clears it when that is null or
	///     empty: the scalar always, and the navigation to the principal when the context already tracks it, to
	///     <see langword="null" /> otherwise. Never a stub, never a principal read for the occasion, so nothing the
	///     context later attaches can shadow the real row; the FK constraint refuses a principal that does not exist.
	/// </summary>
	/// <param name="contexts">The store's context accessor.</param>
	/// <param name="entity">The dependent entity.</param>
	/// <param name="identifier">The principal's id, or null/empty to clear the link.</param>
	/// <param name="navigation">The dependent's reference navigation.</param>
	/// <param name="scalar">The dependent's explicit FK scalar.</param>
	/// <param name="assign">Writes the navigation, then the scalar, on a detached entity.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	public static async ValueTask SetAsync<TEntity, TPrincipal>(IOpenIddictEntityFrameworkCoreContext contexts, TEntity entity,
		string? identifier, Expression<Func<TEntity, TPrincipal?>> navigation, Expression<Func<TEntity, Guid?>> scalar,
		Action<TEntity, TPrincipal?, Guid?> assign, CancellationToken cancellationToken = default)
		where TEntity : class
		where TPrincipal : class
	{
		ArgumentNullException.ThrowIfNull(entity);
		var context = await contexts.GetDbContextAsync(cancellationToken).ConfigureAwait(false);
		Guid? key = string.IsNullOrEmpty(identifier) ? null : Guid.Parse(identifier, CultureInfo.InvariantCulture);
		var principal = key.HasValue ? context.Set<TPrincipal>().Local.FindEntry(key.Value)?.Entity : null;
		var entry = context.Entry(entity);
		if (entry.State is EntityState.Detached)
		{
			assign(entity, principal, key);
			return;
		}

		// Through the change tracker, navigation first: clearing a loaded navigation nulls the scalar only while the
		// scalar still names the old principal, so writing the scalar second always leaves it the last word.
		entry.Reference(navigation).CurrentValue = principal;
		entry.Property(scalar).CurrentValue = key;
	}
}
