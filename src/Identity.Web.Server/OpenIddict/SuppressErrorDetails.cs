using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     Protocol errors carry the required <c>error</c> and nothing optional (2026-10-29 OpenIddict spec §5.7): OpenIddict
///     fills <c>error_description</c> and <c>error_uri</c> with its own diagnostics, which this clears from the response
///     before it is applied, whether it is redirected to the client or rendered as a page.
/// </summary>
/// <typeparam name="TContext">The endpoint's apply-response event.</typeparam>
sealed class SuppressErrorDetails<TContext> : IOpenIddictServerHandler<TContext>
	where TContext : BaseRequestContext
{
	/// <summary>First among the endpoint's response handlers, before any of them writes the response.</summary>
	public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
		OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
			.UseSingletonHandler<SuppressErrorDetails<TContext>>()
			.SetOrder(int.MinValue + 50_000)
			.SetType(OpenIddictServerHandlerType.Custom)
			.Build();

	/// <inheritdoc />
	public ValueTask HandleAsync(TContext context)
	{
		ArgumentNullException.ThrowIfNull(context);
		if (context.Transaction.Response is { } response)
		{
			response.ErrorDescription = null;
			response.ErrorUri = null;
		}

		return ValueTask.CompletedTask;
	}
}
