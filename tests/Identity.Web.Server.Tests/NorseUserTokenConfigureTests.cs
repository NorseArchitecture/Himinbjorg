using Microsoft.EntityFrameworkCore;

namespace Norse.Identity.Web.Server.Tests;

public sealed class NorseUserTokenConfigureTests
{
	[Fact]
	void Configure_bounds_LoginProvider_and_Name()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseUserToken>(NorseUserToken.Configure);

		var entityType = builder.Model.FindEntityType(typeof(NorseUserToken))!;
		entityType.FindProperty(nameof(NorseUserToken.LoginProvider))!.GetMaxLength().ShouldBe(128);
		entityType.FindProperty(nameof(NorseUserToken.Name))!.GetMaxLength().ShouldBe(128);
	}

	[Fact]
	void Configure_declares_Value_explicitly_unbounded()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseUserToken>(NorseUserToken.Configure);

		builder.Model.FindEntityType(typeof(NorseUserToken))!
			.FindProperty(nameof(NorseUserToken.Value))!.GetMaxLength().ShouldBe(-1);
	}
}
