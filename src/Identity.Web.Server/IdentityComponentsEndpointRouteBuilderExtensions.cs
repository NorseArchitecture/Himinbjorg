using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Components.Shared;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Components.Pages;
using Norse.Primitives;

#pragma warning disable IDE0130
namespace Microsoft.AspNetCore.Routing;
#pragma warning restore IDE0130

/// <summary>Extension methods that map the Identity Razor components' supporting endpoints onto an app.</summary>
public static partial class IdentityComponentsEndpointRouteBuilderExtensions
{
	/// <param name="endpoints">The endpoint route builder to add the Identity endpoints to.</param>
	extension(IEndpointRouteBuilder endpoints)
	{
		// These endpoints are required by the Identity Razor components defined in the /Components/Pages directory of this project.
		/// <summary>
		///     Maps the external login, logout, passkey, and account-management endpoints required by the
		///     Identity Razor components under <c>/Components/Pages</c>.
		/// </summary>
		/// <returns>A convention builder for the mapped <c>/Account</c> endpoint group.</returns>
		public IEndpointConventionBuilder MapAdditionalIdentityEndpoints()
		{
			ArgumentNullException.ThrowIfNull(endpoints);

			var accountGroup = endpoints.MapGroup("/Account");

			accountGroup.MapPost("/PerformExternalLogin", (
				HttpContext context,
				[FromServices] SignInManager<NorseUser> signInManager,
				[FromForm] string provider,
				[FromForm] string returnUrl) =>
			{
				IEnumerable<KeyValuePair<string, StringValues>> query =
				[
					new("ReturnUrl", returnUrl),
					new("Action", ExternalLogin.LoginCallbackAction)
				];

				var redirectUrl = UriHelper.BuildRelative(
					context.Request.PathBase,
					"/Account/ExternalLogin",
					QueryString.Create(query));

				provider = TemporaryFluentButtonFix(provider);

				var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
				return TypedResults.Challenge(properties, [provider]);
			});

			accountGroup.MapPost("/Logout", async (
				[FromServices] SignInManager<NorseUser> signInManager,
				[FromForm] string returnUrl) =>
			{
				await signInManager.SignOutAsync().ConfigureAwait(false);
				return TypedResults.LocalRedirect($"~/{returnUrl}");
			});

			accountGroup.MapPost("/PasskeyCreationOptions", async (
				HttpContext context,
				[FromServices] UserManager<NorseUser> userManager,
				[FromServices] SignInManager<NorseUser> signInManager,
				[FromServices] IAntiforgery antiforgery) =>
			{
				await antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);

				var user = await userManager.GetUserAsync(context.User).ConfigureAwait(false);
				if (user is null)
				{
					return Results.NotFound($"Unable to load user with ID '{userManager.GetUserId(context.User)}'.");
				}

				var userId = await userManager.GetUserIdAsync(user).ConfigureAwait(false);
				var userName = await userManager.GetUserNameAsync(user).ConfigureAwait(false) ?? "User";
				var optionsJson = await signInManager.MakePasskeyCreationOptionsAsync(new()
				{
					Id = userId,
					Name = userName,
					DisplayName = userName
				}).ConfigureAwait(false);
				return TypedResults.Content(optionsJson, contentType: "application/json");
			});

			accountGroup.MapPost("/PasskeyRequestOptions", async (
				HttpContext context,
				[FromServices] UserManager<NorseUser> userManager,
				[FromServices] SignInManager<NorseUser> signInManager,
				[FromServices] IAntiforgery antiforgery,
				[FromQuery] string? username) =>
			{
				await antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);

				var user = string.IsNullOrEmpty(username) ?
					null :
					await userManager.FindByNameAsync(username).ConfigureAwait(false);
				var optionsJson = await signInManager.MakePasskeyRequestOptionsAsync(user).ConfigureAwait(false);
				return TypedResults.Content(optionsJson, contentType: "application/json");
			});

			var manageGroup = accountGroup.MapGroup("/Manage").RequireAuthorization(AuthNPolicies.Account);

			// A GET, so a plain link starts it (Heimdall's external-logins page). The provider arrives as a query value,
			// never a FluentButton form value, so it needs no TemporaryFluentButtonFix; a name that is no configured
			// external scheme challenges nothing.
			manageGroup.MapGet("/LinkExternalLogin", async Task<Results<ChallengeHttpResult, RedirectHttpResult>> (
				HttpContext context,
				[FromServices] SignInManager<NorseUser> signInManager,
				[FromQuery] string provider) =>
			{
				var schemes = await signInManager.GetExternalAuthenticationSchemesAsync().ConfigureAwait(false);
				if (!schemes.Any(scheme => scheme.Name == provider))
					return TypedResults.LocalRedirect(ExternalLoginsUrl(ManageStatus.ExternalLoginNotAdded));

				// Clear the existing external cookie to ensure a clean login process
				await context.SignOutAsync(IdentityConstants.ExternalScheme).ConfigureAwait(false);

				var redirectUrl = UriHelper.BuildRelative(
					context.Request.PathBase,
					"/Account/Manage/LinkExternalLoginCallback");

				var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl,
					signInManager.UserManager.GetUserId(context.User));
				return TypedResults.Challenge(properties, [provider]);
			});

			// The provider's return leg: no gRPC answer exists here, so the outcome rides the status key on the redirect.
			// The external cookie is cleared on every exit, so a leftover one can never be consumed by the login flow.
			manageGroup.MapGet("/LinkExternalLoginCallback", async (
				HttpContext context,
				[FromServices] UserManager<NorseUser> userManager,
				[FromServices] SignInManager<NorseUser> signInManager,
				[FromServices] ILoggerFactory loggerFactory,
				CancellationToken cancellationToken) =>
			{
				try
				{
					return await LinkExternalLoginAsync(context, userManager, signInManager,
						loggerFactory.CreateLogger(typeof(IdentityComponentsEndpointRouteBuilderExtensions)),
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
	///     Links the external login the provider returned to the caller. An indeterminate commit answers the page with no
	///     status key, so it lists the truth on load instead of reporting a definite failure; every other failure answers
	///     <see cref="ManageStatus.ExternalLoginNotAdded" />. Discarded problems are logged by category and correlation id
	///     only.
	/// </summary>
	static async Task<RedirectHttpResult> LinkExternalLoginAsync(HttpContext context, UserManager<NorseUser> userManager,
		SignInManager<NorseUser> signInManager, ILogger logger, CancellationToken cancellationToken = default)
	{
		var found = await userManager.Outcome.GetUserAsync(context.User, cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
		{
			LogLinkLookupFailed(logger, lookupFailed.Problem.Category, lookupFailed.Problem.CorrelationId);
			return TypedResults.LocalRedirect(ExternalLoginsUrl(ManageStatus.ExternalLoginNotAdded));
		}

		found.TryGetValue(out Success<NorseUser> user);

		var info = await signInManager.GetExternalLoginInfoAsync(user.Value.Id.ToString()).ConfigureAwait(false);
		if (info is null)
			return TypedResults.LocalRedirect(ExternalLoginsUrl(ManageStatus.ExternalLoginNotAdded));

		var added = await userManager.Outcome.AddLoginAsync(user.Value, info, cancellationToken).ConfigureAwait(false);
		if (!added.TryGetValue(out Failed failed))
			return TypedResults.LocalRedirect(ExternalLoginsUrl(ManageStatus.ExternalLoginAdded));

		LogLinkAddFailed(logger, failed.Problem.Category, failed.Problem.CorrelationId);
		return TypedResults.LocalRedirect(failed.Problem.Category is ErrorCategory.Indeterminate ?
			ExternalLoginsUrl(null) :
			ExternalLoginsUrl(ManageStatus.ExternalLoginNotAdded));
	}

	static string ExternalLoginsUrl(string? status) =>
		status is null ?
			"~/Account/Manage/ExternalLogins" :
			$"~/Account/Manage/ExternalLogins?status={status}";

	[LoggerMessage(Level = LogLevel.Warning,
		Message = "Linking an external login could not load the caller: {Category} (correlation {CorrelationId}).")]
	static partial void LogLinkLookupFailed(ILogger logger, ErrorCategory category, Guid? correlationId);

	[LoggerMessage(Level = LogLevel.Warning,
		Message = "Linking an external login was not added: {Category} (correlation {CorrelationId}).")]
	static partial void LogLinkAddFailed(ILogger logger, ErrorCategory category, Guid? correlationId);

	static string TemporaryFluentButtonFix(string provider)
	{
		// Temporary workaround for FluentButton returning a provider value twice
		// Split the comma-separated list of strings
		var providers = provider.Split(',');

		// Find the value that appears twice in the list
		provider = providers.GroupBy(p => p)
			.Where(g => g.Count() == 2)
			.Select(g => g.Key)
			.First();
		return provider;
	}
}
