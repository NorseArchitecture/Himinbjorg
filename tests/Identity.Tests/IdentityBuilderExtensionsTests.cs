using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Norse.Identity.Tests;

public sealed class IdentityBuilderExtensionsTests
{
	[Fact]
	public void AddNorseIdentity_registers_NorseUserStore_as_IUserStore()
	{
		ServiceCollection services = new();

		services.AddNorseIdentity();

		var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IUserStore<NorseUser>));
		descriptor.ShouldNotBeNull();
		descriptor.ImplementationType.ShouldBe(typeof(NorseUserStore));
	}

	[Fact]
	public void AddNorseIdentity_returns_same_services_for_chaining()
	{
		ServiceCollection services = new();

		var result = services.AddNorseIdentity();

		result.ShouldBeSameAs(services);
	}
}
