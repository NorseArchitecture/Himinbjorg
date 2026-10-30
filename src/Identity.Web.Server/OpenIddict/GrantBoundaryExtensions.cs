using Microsoft.Extensions.DependencyInjection.Extensions;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>The grant boundary's registration (2026-10-29 OpenIddict spec §5.5; Train 4 ruling PF1).</summary>
static class GrantBoundaryExtensions
{
	/// <param name="builder">The server builder.</param>
	extension(OpenIddictServerBuilder builder)
	{
		/// <summary>
		///     Removes OpenIddict's <c>RedeemTokenEntry</c> and registers <see cref="RedeemTokenEntryGuarded" /> at its
		///     order and <see cref="EndGrantOnReuse" /> immediately before <c>ValidateTokenEntry</c>, and registers the
		///     <see cref="IGrantTermination" /> both take, <see cref="GrantTermination" />, one per request scope; a host (or a
		///     test) registering its own afterward wins.
		/// </summary>
		/// <returns>The same <paramref name="builder" /> for chaining.</returns>
		public OpenIddictServerBuilder AddNorseGrantBoundary()
		{
			// A handler filter is resolved from the request's services, like the built-in filters OpenIddict registers.
			builder.Services.TryAddSingleton<EndGrantOnReuse.RequireGrantTokenAtTokenOrRevocation>();
			builder.Services.TryAddScoped<IGrantTermination, GrantTermination>();
			return builder
				.RemoveEventHandler(RedeemTokenEntry.Descriptor)
				.AddEventHandler(RedeemTokenEntryGuarded.Descriptor)
				.AddEventHandler(EndGrantOnReuse.Descriptor);
		}
	}
}
