using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Norse.Identity.Web.Server.Tests;

public sealed class NorseIdentityDbContextTests
{
	[Fact]
	void NorseIdentityDbContext_builds_Version3_schema_without_any_external_Identity_configuration()
	{
		ServiceCollection services = new();
		services.AddDbContext<NorseIdentityDbContext>(o => o.UseSqlite("Data Source=:memory:"));
		// Deliberately NOT calling AddNorseIdentity() or configuring IdentityOptions here -- this is
		// exactly the migrations service's registration shape, and the whole point of this test.

		using var provider = services.BuildServiceProvider();
		using var ctx = provider.GetRequiredService<NorseIdentityDbContext>();

		ctx.Model.FindEntityType(typeof(NorseUserPasskey)).ShouldNotBeNull();
	}
}
