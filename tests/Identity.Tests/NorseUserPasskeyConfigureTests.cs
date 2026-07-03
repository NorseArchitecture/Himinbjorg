using Microsoft.EntityFrameworkCore;

namespace Norse.Identity.Tests;

public sealed class NorseUserPasskeyConfigureTests
{
	[Fact]
	public void Configure_sets_CredentialId_as_the_primary_key()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseUserPasskey>(NorseUserPasskey.Configure);

		var entityType = builder.Model.FindEntityType(typeof(NorseUserPasskey))!;
		entityType.FindPrimaryKey()!.Properties.Single().Name.ShouldBe(nameof(NorseUserPasskey.CredentialId));
	}

	[Fact]
	public void Configure_maps_Data_as_an_owned_JSON_column()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseUserPasskey>(NorseUserPasskey.Configure);

		var ownedType = builder.Model.GetEntityTypes()
			.Single(t => t.ClrType == typeof(Microsoft.AspNetCore.Identity.IdentityPasskeyData));

		ownedType.IsOwned().ShouldBeTrue();
		ownedType.IsMappedToJson().ShouldBeTrue();
	}
}
