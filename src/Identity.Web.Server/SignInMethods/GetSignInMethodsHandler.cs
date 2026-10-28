using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.SignInMethods;

/// <summary>
///     Authors every link between the sign-in pages (T3-38): the password and passkey pages, and one start URL per
///     displayed external scheme, ordered by display name. Each carries only the landing <see cref="ReturnUrls.Resolve" />
///     decided, PathBase-qualified. They are links, not continuations, so none is deferral-wrapped; a provider start is a
///     full page load onto the external-login GET start.
/// </summary>
/// <param name="signInManager">Reads the displayed external authentication schemes.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class GetSignInMethodsHandler(
	SignInManager<NorseUser> signInManager,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<GetSignInMethodsCommand, SignInMethodsResponse>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<SignInMethodsResponse>> Handle(GetSignInMethodsCommand request,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(request);
		var pathBase = httpContextAccessor.HttpContext!.Request.PathBase;
		var landing = ReturnUrls.Resolve(request.Request.ReturnUrl, pathBase);
		var returnUrl = QueryString.Create("returnUrl", landing);

		var schemes = await signInManager.GetExternalAuthenticationSchemesAsync().ConfigureAwait(false);
		return Outcome<SignInMethodsResponse>.Ok(new SignInMethodsResponse
		{
			PasswordSignInUrl = UriHelper.BuildRelative(pathBase, "/Account/Login", returnUrl),
			PasskeySignInUrl = UriHelper.BuildRelative(pathBase, "/Account/LoginWithPasskey", returnUrl),
			Providers =
			[
				.. schemes
					.Where(static scheme => !string.IsNullOrEmpty(scheme.DisplayName))
					.OrderBy(static scheme => scheme.DisplayName, StringComparer.OrdinalIgnoreCase)
					.Select(scheme => new ExternalProviderLink
					{
						DisplayName = scheme.DisplayName!,
						StartUrl = UriHelper.BuildRelative(pathBase, ExternalLoginRoutes.Start,
							QueryString.Create([
								new KeyValuePair<string, string?>("provider", scheme.Name),
								new KeyValuePair<string, string?>("returnUrl", landing)
							]))
					})
			]
		});
	}
}
