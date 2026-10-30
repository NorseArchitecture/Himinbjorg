using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     OpenIddict's EF Core token store with the store link contract (2026-10-29 OpenIddict spec §4.5): the application,
///     authorization and session links answer from <see cref="NorseOpenIddictToken" />'s explicit FK scalars, so a token
///     read by id, detached under the platform's NoTracking default, still carries its grant. Everything else is stock.
/// </summary>
/// <param name="context">The store's context accessor.</param>
/// <param name="options">The EF Core integration's options.</param>
sealed class NorseOpenIddictTokenStore(
	IOpenIddictEntityFrameworkCoreContext context,
	IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
	: OpenIddictEntityFrameworkCoreTokenStore<NorseOpenIddictToken, NorseOpenIddictApplication, NorseOpenIddictAuthorization,
		NorseOpenIddictSession, Guid>(context, options)
{
	/// <inheritdoc />
	public override ValueTask<string?> GetApplicationIdAsync(NorseOpenIddictToken token, CancellationToken cancellationToken) =>
		OpenIddictLinks.Get(token, static t => t.ApplicationId);

	/// <inheritdoc />
	public override ValueTask<string?> GetAuthorizationIdAsync(NorseOpenIddictToken token, CancellationToken cancellationToken) =>
		OpenIddictLinks.Get(token, static t => t.AuthorizationId);

	/// <inheritdoc />
	public override ValueTask<string?> GetSessionIdAsync(NorseOpenIddictToken token, CancellationToken cancellationToken) =>
		OpenIddictLinks.Get(token, static t => t.SessionId);

	/// <inheritdoc />
	public override ValueTask SetApplicationIdAsync(NorseOpenIddictToken token, string? identifier,
		CancellationToken cancellationToken) =>
		OpenIddictLinks.SetAsync(Context, token, identifier, static t => t.Application, static t => t.ApplicationId,
			static (t, application, id) =>
			{
				t.Application = application;
				t.ApplicationId = id;
			}, cancellationToken);

	/// <inheritdoc />
	public override ValueTask SetAuthorizationIdAsync(NorseOpenIddictToken token, string? identifier,
		CancellationToken cancellationToken) =>
		OpenIddictLinks.SetAsync(Context, token, identifier, static t => t.Authorization, static t => t.AuthorizationId,
			static (t, authorization, id) =>
			{
				t.Authorization = authorization;
				t.AuthorizationId = id;
			}, cancellationToken);

	/// <inheritdoc />
	public override ValueTask SetSessionIdAsync(NorseOpenIddictToken token, string? identifier,
		CancellationToken cancellationToken) =>
		OpenIddictLinks.SetAsync(Context, token, identifier, static t => t.Session, static t => t.SessionId,
			static (t, session, id) =>
			{
				t.Session = session;
				t.SessionId = id;
			}, cancellationToken);
}
