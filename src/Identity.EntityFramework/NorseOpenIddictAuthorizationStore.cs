using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     OpenIddict's EF Core authorization store with the store link contract (2026-10-29 OpenIddict spec §4.5): the
///     application link answers from <see cref="NorseOpenIddictAuthorization.ApplicationId" />, tracked or not.
///     Everything else is stock; this store never creates an authorization of its own accord.
/// </summary>
/// <param name="context">The store's context accessor.</param>
/// <param name="options">The EF Core integration's options.</param>
sealed class NorseOpenIddictAuthorizationStore(
	IOpenIddictEntityFrameworkCoreContext context,
	IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
	: OpenIddictEntityFrameworkCoreAuthorizationStore<NorseOpenIddictAuthorization, NorseOpenIddictApplication,
		NorseOpenIddictSession, NorseOpenIddictToken, Guid>(context, options)
{
	/// <inheritdoc />
	public override ValueTask<string?> GetApplicationIdAsync(NorseOpenIddictAuthorization authorization,
		CancellationToken cancellationToken) =>
		OpenIddictLinks.Get(authorization, static a => a.ApplicationId);

	/// <inheritdoc />
	public override ValueTask SetApplicationIdAsync(NorseOpenIddictAuthorization authorization, string? identifier,
		CancellationToken cancellationToken) =>
		OpenIddictLinks.SetAsync(Context, authorization, identifier, static a => a.Application, static a => a.ApplicationId,
			static (a, application, id) =>
			{
				a.Application = application;
				a.ApplicationId = id;
			}, cancellationToken);
}
