using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Norse.Identity.EntityFramework.Tests;

public sealed class NorseUserRoleConfigureTests
{
	[Fact]
	void Configure_sets_table_name() => BuildEntityType().GetTableName().ShouldBe("UserRoles");

	// The relationship fact (User_roles_are_required_through_explicit_User_and_Role_navigations) moved to NorseIdentityModelTests (Task 4.2 triage, 2026-10-24):
	// requiredness is now inferred by EF convention from the non-nullable FK, and a bare
	// new ModelBuilder() runs no conventions, so only the provider-built model can observe it.

	static IEntityType BuildEntityType()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseUserRole>(NorseUserRole.Configure);
		return builder.Model.FinalizeModel().FindEntityType(typeof(NorseUserRole))!;
	}
}
