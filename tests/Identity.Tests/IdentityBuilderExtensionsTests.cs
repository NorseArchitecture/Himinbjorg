using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Norse.Identity.Tests;

public sealed class IdentityBuilderExtensionsTests
{
	[Fact]
	void AddNorseIdentity_registers_NorseUserStore_as_IUserStore()
	{
		ServiceCollection services = new();

		services.AddNorseIdentity();

		var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IUserStore<NorseUser>));
		descriptor.ShouldNotBeNull();
		descriptor.ImplementationType.ShouldBe(typeof(NorseUserStore));
	}

	[Fact]
	void AddNorseIdentity_returns_same_services_for_chaining()
	{
		ServiceCollection services = new();

		var result = services.AddNorseIdentity();

		result.ShouldBeSameAs(services);
	}

	[Fact]
	void AddNorseIdentity_configures_SchemaVersion_to_Version3()
	{
		ServiceCollection services = new();
		services.AddDbContext<NorseIdentityDbContext>(o => o.UseSqlite("Data Source=:memory:"));

		services.AddNorseIdentity();

		using var provider = services.BuildServiceProvider();
		var options = provider.GetRequiredService<IOptions<IdentityOptions>>();

		options.Value.Stores.SchemaVersion.ShouldBe(IdentitySchemaVersions.Version3);
	}
}
