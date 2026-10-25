using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Norse.Identity.EntityFramework.Tests;

public sealed class NorseRoleConfigureTests
{
	[Fact]
	void Configure_sets_table_name() =>
		BuildEntityType().GetTableName().ShouldBe("Roles");

	[Fact]
	void Configure_converts_ConcurrencyStamp() =>
		BuildEntityType().FindProperty(nameof(NorseRole.ConcurrencyStamp))!.GetValueConverter().ShouldNotBeNull();

	[Fact]
	void Configure_sets_unique_index_on_NormalizedName()
	{
		var index = BuildEntityType().GetIndexes()
			.Single(i => i.GetDatabaseName() == "IX_Roles_NormalizedName");

		index.IsUnique.ShouldBeTrue();
	}

	// The relationship fact (Role_claims_are_required_through_the_Role_navigation) moved to NorseIdentityModelTests (Task 4.2 triage, 2026-10-24):
	// requiredness is now inferred by EF convention from the non-nullable FK, and a bare
	// new ModelBuilder() runs no conventions, so only the provider-built model can observe it.

	static IEntityType BuildEntityType()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseRole>(NorseRole.Configure);
		builder.Entity<NorseRoleClaim>();
		return builder.Model.FinalizeModel().FindEntityType(typeof(NorseRole))!;
	}
}
