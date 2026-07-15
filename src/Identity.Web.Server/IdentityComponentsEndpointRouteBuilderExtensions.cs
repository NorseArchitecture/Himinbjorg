using Norse.Identity.Web.Server.Components.Pages;
using Norse.Identity.Web.Server.Components.Pages.Manage;
using Norse.Identity;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using System.Text.Json;

#pragma warning disable IDE0130
namespace Microsoft.AspNetCore.Routing;
#pragma warning restore IDE0130

/// <summary>Extension methods that map the Identity Razor components' supporting endpoints onto an app.</summary>
public static partial class IdentityComponentsEndpointRouteBuilderExtensions
{
	// These endpoints are required by the Identity Razor components defined in the /Components/Pages directory of this project.
	/// <summary>
	/// Maps the external login, logout, passkey, and account-management endpoints required by the
	/// Identity Razor components under <c>/Components/Pages</c>.
	/// </summary>
	/// <param name="endpoints">The endpoint route builder to add the Identity endpoints to.</param>
	/// <returns>A convention builder for the mapped <c>/Account</c> endpoint group.</returns>
	public static IEndpointConventionBuilder MapAdditionalIdentityEndpoints(this IEndpointRouteBuilder endpoints)
	{
		ArgumentNullException.ThrowIfNull(endpoints);

		var accountGroup = endpoints.MapGroup("/Account");

		accountGroup.MapPost("/PerformExternalLogin", (
			HttpContext context,
			[FromServices] SignInManager<NorseUser> signInManager,
			[FromForm] string provider,
			[FromForm] string returnUrl) =>
		{
			IEnumerable<KeyValuePair<string, StringValues>> query = [
				new("ReturnUrl", returnUrl),
					new("Action", ExternalLogin.LoginCallbackAction)];

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

			var user = string.IsNullOrEmpty(username) ? null : await userManager.FindByNameAsync(username).ConfigureAwait(false);
			var optionsJson = await signInManager.MakePasskeyRequestOptionsAsync(user).ConfigureAwait(false);
			return TypedResults.Content(optionsJson, contentType: "application/json");
		});

		var manageGroup = accountGroup.MapGroup("/Manage").RequireAuthorization();

		manageGroup.MapPost("/LinkExternalLogin", async (
			HttpContext context,
			[FromServices] SignInManager<NorseUser> signInManager,
			[FromForm] string provider) =>
		{
			// Clear the existing external cookie to ensure a clean login process
			await context.SignOutAsync(IdentityConstants.ExternalScheme).ConfigureAwait(false);

			var redirectUrl = UriHelper.BuildRelative(
				context.Request.PathBase,
				"/Account/Manage/ExternalLogins",
				QueryString.Create("Action", ExternalLogins.LinkLoginCallbackAction));

			provider = TemporaryFluentButtonFix(provider);

			var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, signInManager.UserManager.GetUserId(context.User));
			return TypedResults.Challenge(properties, [provider]);
		});

		var loggerFactory = endpoints.ServiceProvider.GetRequiredService<ILoggerFactory>();
		var downloadLogger = loggerFactory.CreateLogger("DownloadPersonalData");

		manageGroup.MapPost("/DownloadPersonalData", async (
			HttpContext context,
			[FromServices] UserManager<NorseUser> userManager,
			[FromServices] AuthenticationStateProvider authenticationStateProvider) =>
		{
			var user = await userManager.GetUserAsync(context.User).ConfigureAwait(false);
			if (user is null)
			{
				return Results.NotFound($"Unable to load user with ID '{userManager.GetUserId(context.User)}'.");
			}

			var userId = await userManager.GetUserIdAsync(user).ConfigureAwait(false);
			downloadLogger.LogUserPersonalDataRequested(userId);

			// Only include personal data for download
			var personalData = new Dictionary<string, string>();
			var personalDataProps = typeof(NorseUser).GetProperties().Where(
				prop => Attribute.IsDefined(prop, typeof(PersonalDataAttribute)));
			foreach (var p in personalDataProps)
			{
				personalData.Add(p.Name, p.GetValue(user)?.ToString() ?? "null");
			}

			var logins = await userManager.GetLoginsAsync(user).ConfigureAwait(false);
			foreach (var l in logins)
			{
				personalData.Add($"{l.LoginProvider} external login provider key", l.ProviderKey);
			}

			personalData.Add("Authenticator Key", (await userManager.GetAuthenticatorKeyAsync(user).ConfigureAwait(false))!);
			var fileBytes = JsonSerializer.SerializeToUtf8Bytes(personalData);

			context.Response.Headers.TryAdd("Content-Disposition", "attachment; filename=PersonalData.json");
			return TypedResults.File(fileBytes, contentType: "application/json", fileDownloadName: "PersonalData.json");
		});

		return accountGroup;
	}

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

	[LoggerMessage(LogLevel.Information, "User with ID '{UserId}' asked for their personal data.")]
	static partial void LogUserPersonalDataRequested(this ILogger logger, string userId);
}
