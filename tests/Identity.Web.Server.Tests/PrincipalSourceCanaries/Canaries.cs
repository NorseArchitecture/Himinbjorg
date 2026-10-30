using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;

// Never run: the IL scan's canaries (OutcomeSurfaceEnforcementTests.Every_ambient_principal_source_is_caught). Top-level
// types, because the scan judges by the outermost type. Each signs a principal in from one source.
namespace Norse.Identity.Web.Server.Tests.PrincipalSourceCanaries;

sealed class ReadsHttpContextUser
{
	internal static Task SignInAsync(HttpContext context) =>
		context.SignInAsync(IdentityConstants.ApplicationScheme, context.User);
}

sealed class ReadsAuthenticationState
{
	internal static async Task SignInAsync(HttpContext context, AuthenticationStateProvider state) =>
		await context.SignInAsync((await state.GetAuthenticationStateAsync()).User);
}

sealed class AuthenticatesTheDefaultScheme
{
	internal static async Task SignInAsync(HttpContext context) =>
		await context.SignInAsync((await context.AuthenticateAsync()).Principal!);
}

sealed class AuthenticatesAnotherScheme
{
	internal static async Task SignInAsync(HttpContext context) =>
		await context.SignInAsync((await context.AuthenticateAsync("Norse.User")).Principal!);
}

// The constant loaded elsewhere in the same method allows nothing: only the call's own scheme argument counts.
sealed class AuthenticatesAnotherSchemeBesideTheConstant
{
	internal static async Task SignInAsync(HttpContext context)
	{
		var scheme = IdentityConstants.ApplicationScheme;
		var result = await context.AuthenticateAsync("Norse.Bearer");
		await context.SignInAsync(scheme, result.Principal!);
	}
}

sealed class BindsAMinimalApiPrincipal
{
	internal static void Map(IEndpointRouteBuilder endpoints) =>
		endpoints.MapGet("/canary", Handle);

	static IResult Handle(ClaimsPrincipal user) =>
		Results.SignIn(user);
}

sealed class AuthenticatesTheIdentityCookie
{
	internal static async Task<IResult> Handle(HttpContext context) =>
		Results.SignIn((await context.AuthenticateAsync(IdentityConstants.ApplicationScheme)).Principal!);
}
