using Microsoft.EntityFrameworkCore;

namespace Norse.Identity.Web.Server.Tests;

public sealed class NorseUserPasskeyConfigureTests
{
	[Fact]
	void Configure_sets_table_name()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseUserPasskey>(NorseUserPasskey.Configure);

		var entityType = builder.Model.FindEntityType(typeof(NorseUserPasskey))!;
		entityType.GetTableName().ShouldBe("UserPasskeys");
	}
}
