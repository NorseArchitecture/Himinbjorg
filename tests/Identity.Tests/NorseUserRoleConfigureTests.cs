using Microsoft.EntityFrameworkCore;

namespace Norse.Identity.Tests;

public sealed class NorseUserRoleConfigureTests
{
	[Fact]
	void Configure_sets_table_name()
	{
		BuildEntityType().GetTableName().ShouldBe("user_roles");
	}

	[Fact]
	void Configure_wires_explicit_User_and_Role_navigations()
	{
		var entityType = BuildEntityType();
		var foreignKeys = entityType.GetForeignKeys().ToList();

		foreignKeys.ShouldContain(fk =>
			fk.DependentToPrincipal!.Name == nameof(NorseUserRole.User) && fk.IsRequired);
		foreignKeys.ShouldContain(fk =>
			fk.DependentToPrincipal!.Name == nameof(NorseUserRole.Role) && fk.IsRequired);
	}

	static Microsoft.EntityFrameworkCore.Metadata.IEntityType BuildEntityType()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseUserRole>(NorseUserRole.Configure);
		return builder.Model.FinalizeModel().FindEntityType(typeof(NorseUserRole))!;
	}
}
