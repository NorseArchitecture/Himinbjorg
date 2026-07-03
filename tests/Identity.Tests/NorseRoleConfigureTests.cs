using Microsoft.EntityFrameworkCore;

namespace Norse.Identity.Tests;

public sealed class NorseRoleConfigureTests
{
	[Fact]
	public void Configure_sets_table_name()
	{
		BuildEntityType().GetTableName().ShouldBe("roles");
	}

	[Fact]
	public void Configure_converts_ConcurrencyStamp()
	{
		BuildEntityType().FindProperty(nameof(NorseRole.ConcurrencyStamp))!.GetValueConverter().ShouldNotBeNull();
	}

	[Fact]
	public void Configure_sets_unique_index_on_NormalizedName()
	{
		var index = BuildEntityType().GetIndexes()
			.Single(i => i.GetDatabaseName() == "ix_roles_normalized_name");

		index.IsUnique.ShouldBeTrue();
	}

	[Fact]
	public void Configure_wires_Claims_relationship_through_the_Role_navigation()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseRole>(NorseRole.Configure);
		builder.Entity<NorseRoleClaim>();

		var claimType = builder.Model.FinalizeModel().FindEntityType(typeof(NorseRoleClaim))!;
		var fk = claimType.GetForeignKeys().Single();

		fk.DependentToPrincipal!.Name.ShouldBe(nameof(NorseRoleClaim.Role));
		fk.IsRequired.ShouldBeTrue();
	}

	static Microsoft.EntityFrameworkCore.Metadata.IEntityType BuildEntityType()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseRole>(NorseRole.Configure);
		builder.Entity<NorseRoleClaim>();
		return builder.Model.FinalizeModel().FindEntityType(typeof(NorseRole))!;
	}
}
