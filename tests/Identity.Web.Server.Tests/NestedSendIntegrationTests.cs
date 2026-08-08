using Norse.Abstractions.Contracts;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Infrastructure.Web.Server.Mediator;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
/// The server-side half of "run twice" (Heimdall's Task 10 async validator rule): dispatching a
/// <see cref="RegisterCommand"/> through the real pipeline runs <c>RegisterRequestValidator</c>,
/// whose email rule sends a nested <see cref="EmailExistsCommand"/> through the very same
/// <see cref="ISender"/> mid-validation. A real DI container -- Midgard's <c>AddNorsePipeline()</c>
/// plus the generated <c>AddNorseIdentityWebServerHandlers()</c> -- proves the two commands compose
/// end to end, with no lifetime/scope error, and that <see cref="EmailExistsHandler"/> genuinely
/// executed, not just that validation happened to pass.
/// </summary>
public sealed class NestedSendIntegrationTests
{
	// Satisfies AuthorizationBehavior's IPrincipalAccessor -> AuthenticationStateProvider fallback
	// (PrincipalAccessor is internal to Midgard, so it can't be seeded directly from here). Anonymous
	// is fine: AuthNPolicies.Public accepts any principal, including this one.
	sealed class AnonymousAuthenticationStateProvider : AuthenticationStateProvider
	{
		public override Task<AuthenticationState> GetAuthenticationStateAsync() =>
			Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));
	}

	[Fact]
	async Task RegisterCommand_dispatch_runs_EmailExistsHandler_mid_validation_with_no_lifetime_errors()
	{
		using var userManager = MockUserManager.Create();
		userManager.FindByEmailAsync(Arg.Any<string>()).Returns((NorseUser?)null);
		userManager.CreateAsync(Arg.Any<NorseUser>(), Arg.Any<string>()).Returns(IdentityResult.Success);

		var builder = Host.CreateApplicationBuilder();
		builder.Services
			.AddNorsePipeline()
			.AddNorseIdentityWebServerHandlers()
			.AddAuthorization(options => options.AddPolicy(AuthNPolicies.Public, policy => policy.RequireAssertion(_ => true)))
			.AddSingleton<AuthenticationStateProvider, AnonymousAuthenticationStateProvider>()
			.AddScoped<IAuthenticationService, AuthenticationService>()
			.AddScoped(_ => userManager);

		using var host = builder.Build();
		using var scope = host.Services.CreateScope();
		var sender = scope.ServiceProvider.GetRequiredService<ISender>();
		RegisterCommand command = new(new RegisterRequest { EmailInput = "nested-send@example.com", Password = "correct-horse-battery-1A!" });

		var outcome = await sender.Send(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/Account/Login");
		await userManager.Received(1).FindByEmailAsync("nested-send@example.com");
	}
}
