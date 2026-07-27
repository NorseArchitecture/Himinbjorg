using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Norse.Identity.Web.Server.Tests;

public sealed class NorseUserRoleConfigureTests
{
	[Fact]
	void Configure_sets_table_name() => BuildEntityType().GetTableName().ShouldBe("UserRoles");

	[Fact]
	void Configure_wires_explicit_User_and_Role_navigations()
	{
		var entityType = BuildEntityType();
		List<IForeignKey> foreignKeys = [.. entityType.GetForeignKeys()];

		foreignKeys.ShouldContain(fk =>
			fk.DependentToPrincipal!.Name == nameof(NorseUserRole.User) && fk.IsRequired);
		foreignKeys.ShouldContain(fk =>
			fk.DependentToPrincipal!.Name == nameof(NorseUserRole.Role) && fk.IsRequired);
	}

	static IEntityType BuildEntityType()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseUserRole>(NorseUserRole.Configure);
		return builder.Model.FinalizeModel().FindEntityType(typeof(NorseUserRole))!;
	}
}
