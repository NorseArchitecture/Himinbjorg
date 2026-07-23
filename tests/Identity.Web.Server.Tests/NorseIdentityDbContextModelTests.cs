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

	[Fact]
	void Passkey_CredentialId_is_the_primary_key()
	{
		var options = new DbContextOptionsBuilder<NorseIdentityDbContext>()
			.UseNpgsql("Host=localhost;Database=norse_identity_model_test")
			.Options;
		using NorseIdentityDbContext ctx = new(options);

		var entityType = ctx.Model.FindEntityType(typeof(NorseUserPasskey))!;
		entityType.FindPrimaryKey()!.Properties.Single().Name.ShouldBe(nameof(NorseUserPasskey.CredentialId));
	}

	[Fact]
	void Passkey_Data_is_mapped_as_a_complex_JSON_property()
	{
		// Data is an EF Core complex type (ComplexProperty<T>().ToJson()), not an owned entity type
		// (OwnsOne(...).ToJson()) -- the two are distinct model constructs, and registering both for the
		// same property name is exactly the bug this test guards against (NorseUserPasskey.Configure
		// used to redeclare it via OwnsOne, colliding with this base-class registration).
		var options = new DbContextOptionsBuilder<NorseIdentityDbContext>()
			.UseNpgsql("Host=localhost;Database=norse_identity_model_test")
			.Options;
		using NorseIdentityDbContext ctx = new(options);

		var entityType = ctx.Model.FindEntityType(typeof(NorseUserPasskey))!;
		var complexProperty = entityType.FindComplexProperty(nameof(NorseUserPasskey.Data))!;

		complexProperty.ComplexType.ClrType.ShouldBe(typeof(Microsoft.AspNetCore.Identity.IdentityPasskeyData));
		complexProperty.ComplexType.GetContainerColumnName().ShouldNotBeNullOrEmpty();
	}
}
