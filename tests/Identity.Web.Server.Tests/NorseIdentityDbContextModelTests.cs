using Microsoft.EntityFrameworkCore;

namespace Norse.Identity.Web.Server.Tests;

public sealed class NorseIdentityDbContextModelTests
{
	[Fact]
	void Model_builds_without_throwing()
	{
		var options = new DbContextOptionsBuilder<NorseIdentityDbContext>()
			.UseNpgsql("Host=localhost;Database=norse_identity_model_test")
			.Options;
		using NorseIdentityDbContext ctx = new(options);

		Should.NotThrow(() => ctx.Model);
	}

	[Fact]
	void Every_entity_in_the_model_implements_INorseEntity_including_OpenIddict_wrappers()
	{
		var options = new DbContextOptionsBuilder<NorseIdentityDbContext>()
			.UseNpgsql("Host=localhost;Database=norse_identity_model_test")
			.Options;
		using NorseIdentityDbContext ctx = new(options);

		var openIddictTypes = new[]
		{
			typeof(NorseOpenIddictApplication), typeof(NorseOpenIddictAuthorization),
			typeof(NorseOpenIddictScope), typeof(NorseOpenIddictToken),
		};

		foreach (var type in openIddictTypes)
			ctx.Model.FindEntityType(type).ShouldNotBeNull();
	}
}
