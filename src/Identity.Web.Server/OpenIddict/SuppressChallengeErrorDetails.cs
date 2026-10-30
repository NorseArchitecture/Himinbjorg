using OpenIddict.Validation;
using static OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreHandlers;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     The validation side of <see cref="SuppressErrorDetails{TContext}" /> (2026-10-29 OpenIddict spec §5.7): a
///     <c>Norse.Bearer</c> challenge or forbid answers <c>WWW-Authenticate: Bearer error="..."</c> and nothing optional.
///     OpenIddict otherwise fills <c>error_description</c> with its own diagnostics and <c>error_uri</c> with a link to its
///     documentation (a forbid's default is ID2095), which fingerprints the stack and explains a refusal to the caller.
/// </summary>
/// <typeparam name="TContext">The challenge or error event whose response becomes the header.</typeparam>
sealed class SuppressChallengeErrorDetails<TContext> : IOpenIddictValidationHandler<TContext>
	where TContext : OpenIddictValidationEvents.BaseRequestContext
{
	/// <summary>
	///     After every handler that fills the response (the default challenge error, the host's properties, custom
	///     parameters), immediately before the ASP.NET Core integration writes the header from it.
	/// </summary>
	public static OpenIddictValidationHandlerDescriptor Descriptor { get; } =
		OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
			.UseSingletonHandler<SuppressChallengeErrorDetails<TContext>>()
			.SetOrder(AttachWwwAuthenticateHeader<TContext>.Descriptor.Order - 500)
			.SetType(OpenIddictValidationHandlerType.Custom)
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
