using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Norse.Identity.Web.Server.Tests;

public sealed class ServiceCollectionExtensionsTests
{
	[Fact]
	void AddNorseAuthenticationService_registers_NorseSignInManager_as_SignInManager()
	{
		ServiceCollection services = new();

		services.AddNorseAuthenticationService("Host=localhost;Database=norse_identity_test");

		var descriptor = services.LastOrDefault(d => d.ServiceType == typeof(SignInManager<NorseUser>));
		descriptor.ShouldNotBeNull();
		descriptor.ImplementationType.ShouldBe(typeof(NorseSignInManager));
	}
}
