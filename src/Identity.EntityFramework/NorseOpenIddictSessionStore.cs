using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     OpenIddict's EF Core session store with the store link contract (2026-10-29 OpenIddict spec §4.5): the application
///     and authorization links answer from <see cref="NorseOpenIddictSession" />'s explicit FK scalars, tracked or not.
///     Everything else is stock.
/// </summary>
/// <param name="context">The store's context accessor.</param>
/// <param name="options">The EF Core integration's options.</param>
sealed class NorseOpenIddictSessionStore(
	IOpenIddictEntityFrameworkCoreContext context,
	IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
	: OpenIddictEntityFrameworkCoreSessionStore<NorseOpenIddictSession, NorseOpenIddictApplication,
		NorseOpenIddictAuthorization, NorseOpenIddictToken, Guid>(context, options)
{
	/// <inheritdoc />
	public override ValueTask<string?> GetApplicationIdAsync(NorseOpenIddictSession session,
		CancellationToken cancellationToken) =>
		OpenIddictLinks.Get(session, static s => s.ApplicationId);

	/// <inheritdoc />
	public override ValueTask<string?> GetAuthorizationIdAsync(NorseOpenIddictSession session,
		CancellationToken cancellationToken) =>
		OpenIddictLinks.Get(session, static s => s.AuthorizationId);

	/// <inheritdoc />
	public override ValueTask SetApplicationIdAsync(NorseOpenIddictSession session, string? identifier,
		CancellationToken cancellationToken) =>
		OpenIddictLinks.SetAsync(Context, session, identifier, static s => s.Application, static s => s.ApplicationId,
			static (s, application, id) =>
			{
				s.Application = application;
				s.ApplicationId = id;
			}, cancellationToken);

	/// <inheritdoc />
	public override ValueTask SetAuthorizationIdAsync(NorseOpenIddictSession session, string? identifier,
		CancellationToken cancellationToken) =>
		OpenIddictLinks.SetAsync(Context, session, identifier, static s => s.Authorization, static s => s.AuthorizationId,
			static (s, authorization, id) =>
			{
				s.Authorization = authorization;
				s.AuthorizationId = id;
			}, cancellationToken);
}
