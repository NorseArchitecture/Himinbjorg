using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FluentUI.AspNetCore.Components;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Components;
using Norse.AuthN.Components.FluentUI;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     Heimdall's login page on an <see cref="AuthorizeHost" /> (spec §6.4), statically rendered as Yggdrasil serves it,
///     with the real <see cref="LoginHandler" /> behind a test endpoint standing in for the gRPC hop its submit makes.
/// </summary>
static class LoginPage
{
	/// <summary>The test-only endpoint that runs <see cref="LoginHandler" /> for a user and a return URL.</summary>
	public const string LoginPath = "/test/login";

	/// <summary>The page's services: Razor components, Fluent UI and the page's three injected contracts.</summary>
	public static void Compose(WebApplicationBuilder builder)
	{
		builder.Services.AddRazorComponents();
		builder.Services.AddFluentUIComponents();
		builder.Services.AddAntiforgery();
		var signInMethods = Substitute.For<ISignInMethodsService>();
		signInMethods.GetSignInMethods(Arg.Any<GetSignInMethodsRequest>(), Arg.Any<CancellationToken>())
			.Returns(Outcome<SignInMethodsResponse>.Ok(new()));
		builder.Services
			.AddSingleton(signInMethods)
			.AddSingleton(Substitute.For<IAuthenticationService>())
			.AddSingleton(Substitute.For<ISessionTransition>());
	}

	/// <summary>Maps the page and the login endpoint.</summary>
	public static void Map(WebApplication app)
	{
		app.UseAntiforgery();
		app.MapRazorComponents<LoginTestRoot>().AddAdditionalAssemblies(typeof(Login).Assembly);
		app.MapGet(LoginPath, LoginEndpointAsync);
	}

	// The submit's server side: LoginHandler itself, on this request, answering its NextUrl.
	static async Task<IResult> LoginEndpointAsync(HttpContext context, Guid user, string returnUrl)
	{
		var userManager = context.RequestServices.GetRequiredService<UserManager<NorseUser>>();
		var found = (await userManager.FindByIdAsync(user.ToString())).ShouldNotBeNull();
		var email = (await userManager.GetEmailAsync(found)).ShouldNotBeNull();
		var handler = ActivatorUtilities.CreateInstance<LoginHandler>(context.RequestServices);
		var outcome = await handler.Handle(new(new()
		{
			EmailInput = email,
			Password = AuthorizeHost.Password,
			ReturnUrl = returnUrl
		}), context.RequestAborted);
		return outcome.Match(static next => Results.Text(next.NextUrl), static problem => Results.Problem(problem.Category.ToString()));
	}
}
