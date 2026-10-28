using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Components.Shared;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.ExternalLogin;
using Norse.Primitives;

#pragma warning disable IDE0130
namespace Microsoft.AspNetCore.Routing;
#pragma warning restore IDE0130

/// <summary>Extension methods that map the external-login HTTP endpoints onto an app.</summary>
public static partial class ExternalLoginEndpointRouteBuilderExtensions
{
	const string ExternalLoginsRoute = "/Account/Manage/ExternalLogins";

	/// <param name="endpoints">The endpoint route builder to add the external-login endpoints to.</param>
	extension(IEndpointRouteBuilder endpoints)
	{
		/// <summary>
		///     Maps the external-login starts and the link callback, the only HTTP surface a provider round trip needs:
		///     <c>GET /Account/PerformExternalLogin</c>, <c>GET /Account/Manage/LinkExternalLogin</c> and
		///     <c>GET /Account/Manage/LinkExternalLoginCallback</c>. Both starts are antiforgery-free GETs that proceed
		///     only for a same-origin or user-initiated navigation (T3-34); everything else challenges nothing.
		/// </summary>
		/// <returns>A convention builder for the mapped external-login endpoint group.</returns>
		public IEndpointConventionBuilder MapNorseExternalLoginEndpoints()
		{
			ArgumentNullException.ThrowIfNull(endpoints);

			var accountGroup = endpoints.MapGroup(string.Empty);

			// A GET, so a server-authored link starts it (GetSignInMethods' provider StartUrl). Only ReturnUrls.Resolve
			// decides the landing, and every refusal returns to login carrying it, with no challenge.
			accountGroup.MapGet(ExternalLoginRoutes.Start, async Task<Results<ChallengeHttpResult, RedirectHttpResult>> (
				HttpContext context,
				[FromServices] SignInManager<NorseUser> signInManager,
				[FromQuery] string? provider,
				[FromQuery] string? returnUrl) =>
			{
				var pathBase = context.Request.PathBase;
				var landing = ReturnUrls.Resolve(returnUrl, pathBase);
				if (!FetchMetadata.IsSameOriginOrUserInitiated(context.Request)
					|| !await IsDisplayedSchemeAsync(signInManager, provider).ConfigureAwait(false))
					return TypedResults.LocalRedirect(UriHelper.BuildRelative(pathBase, "/Account/Login",
						QueryString.Create("ReturnUrl", landing)));

				KeyValuePair<string, string?>[] query =
				[
					new("Action", ExternalLoginCallback.LoginCallbackAction),
					new("ReturnUrl", landing)
				];
				var callbackUrl = UriHelper.BuildRelative(pathBase, "/Account/ExternalLogin", QueryString.Create(query));

				var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, callbackUrl);
				return TypedResults.Challenge(properties, [provider!]);
			});

			var manageGroup = accountGroup.MapGroup(string.Empty).RequireAuthorization(AuthNPolicies.Account);

			// A GET, so a plain link starts it (Heimdall's external-logins page), under the same fail-closed check as
			// the sign-in start; a refused start, or a name that is no displayed external scheme, challenges nothing.
			manageGroup.MapGet(ExternalLoginRoutes.LinkStart, async Task<Results<ChallengeHttpResult, RedirectHttpResult>> (
				HttpContext context,
				[FromServices] SignInManager<NorseUser> signInManager,
				[FromQuery] string? provider) =>
			{
				if (!FetchMetadata.IsSameOriginOrUserInitiated(context.Request)
					|| !await IsDisplayedSchemeAsync(signInManager, provider).ConfigureAwait(false))
					return TypedResults.LocalRedirect(ExternalLoginsUrl(context, ManageStatus.ExternalLoginFailed));

				// Clear the existing external cookie to ensure a clean login process
				await context.SignOutAsync(IdentityConstants.ExternalScheme).ConfigureAwait(false);

				var redirectUrl = UriHelper.BuildRelative(context.Request.PathBase, ExternalLoginRoutes.LinkCallback);

				var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl,
					signInManager.UserManager.GetUserId(context.User));
				return TypedResults.Challenge(properties, [provider!]);
			});

			// The provider's return leg: no gRPC answer exists here, so the outcome rides the status key on the redirect.
			// The external cookie is cleared on every exit, so a leftover one can never be consumed by the login flow.
			manageGroup.MapGet(ExternalLoginRoutes.LinkCallback, async (
				HttpContext context,
				[FromServices] UserManager<NorseUser> userManager,
				[FromServices] SignInManager<NorseUser> signInManager,
				[FromServices] ILoggerFactory loggerFactory,
				CancellationToken cancellationToken) =>
			{
				try
				{
					return await LinkExternalLoginAsync(context, userManager, signInManager,
						loggerFactory.CreateLogger(typeof(ExternalLoginEndpointRouteBuilderExtensions)),
						cancellationToken).ConfigureAwait(false);
				}
				finally
				{
					await context.SignOutAsync(IdentityConstants.ExternalScheme).ConfigureAwait(false);
				}
			});

			return accountGroup.ExcludeFromDescription();
		}
	}

	/// <summary>
	///     Whether <paramref name="provider" /> names a displayed external scheme: the manager answers only schemes with a
	///     display name (Ruling 41), so the platform's own policy and cookie schemes are never challengeable from here.
	/// </summary>
	static async Task<bool> IsDisplayedSchemeAsync(SignInManager<NorseUser> signInManager, string? provider)
	{
		if (string.IsNullOrEmpty(provider))
			return false;
		var schemes = await signInManager.GetExternalAuthenticationSchemesAsync().ConfigureAwait(false);
		return schemes.Any(scheme => scheme.Name == provider);
	}

	/// <summary>
	///     Links the external login the provider returned to the caller (T3-6). A login already associated with another
	///     account answers <see cref="ManageStatus.ExternalLoginNotAdded" />; an indeterminate commit answers the page with
	///     no status key, so it lists the truth on load instead of reporting a definite failure; every other failure (an
	///     unloadable caller, a missing external cookie, any other definite refusal) answers
	///     <see cref="ManageStatus.ExternalLoginFailed" />. Discarded problems are logged by category and correlation id
	///     only.
	/// </summary>
	static async Task<RedirectHttpResult> LinkExternalLoginAsync(HttpContext context, UserManager<NorseUser> userManager,
		SignInManager<NorseUser> signInManager, ILogger logger, CancellationToken cancellationToken = default)
	{
		var found = await userManager.Outcome.GetUserAsync(context.User, cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
		{
			LogLinkLookupFailed(logger, lookupFailed.Problem.Category, lookupFailed.Problem.CorrelationId);
			return TypedResults.LocalRedirect(ExternalLoginsUrl(context, ManageStatus.ExternalLoginFailed));
		}

		found.TryGetValue(out Success<NorseUser> user);

		var info = await signInManager.GetExternalLoginInfoAsync(user.Value.Id.ToString()).ConfigureAwait(false);
		if (info is null)
			return TypedResults.LocalRedirect(ExternalLoginsUrl(context, ManageStatus.ExternalLoginFailed));

		var added = await userManager.Outcome.AddLoginAsync(user.Value, info, cancellationToken).ConfigureAwait(false);
		if (!added.TryGetValue(out Failed failed))
			return TypedResults.LocalRedirect(ExternalLoginsUrl(context, ManageStatus.ExternalLoginAdded));

		LogLinkAddFailed(logger, failed.Problem.Category, failed.Problem.CorrelationId);
		return TypedResults.LocalRedirect(failed.Problem switch
		{
			{ Category: ErrorCategory.Indeterminate } => ExternalLoginsUrl(context, null),
			_ when failed.Problem.Errors.ContainsKey(nameof(IdentityErrorDescriber.LoginAlreadyAssociated)) =>
				ExternalLoginsUrl(context, ManageStatus.ExternalLoginNotAdded),
			_ => ExternalLoginsUrl(context, ManageStatus.ExternalLoginFailed)
		});
	}

	static string ExternalLoginsUrl(HttpContext context, string? status) =>
		status is null ?
			UriHelper.BuildRelative(context.Request.PathBase, ExternalLoginsRoute) :
			ManageUrls.Status(context.Request.PathBase, ExternalLoginsRoute, status);

	[LoggerMessage(Level = LogLevel.Warning,
		Message = "Linking an external login could not load the caller: {Category} (correlation {CorrelationId}).")]
	static partial void LogLinkLookupFailed(ILogger logger, ErrorCategory category, Guid? correlationId);

	[LoggerMessage(Level = LogLevel.Warning,
		Message = "Linking an external login was not added: {Category} (correlation {CorrelationId}).")]
	static partial void LogLinkAddFailed(ILogger logger, ErrorCategory category, Guid? correlationId);
}
