using Microsoft.EntityFrameworkCore;

namespace Norse.Identity.Web.Server.Tests;

public sealed class NorseUserLoginConfigureTests
{
	[Fact]
	void Configure_bounds_LoginProvider_ProviderKey_and_ProviderDisplayName()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseUserLogin>(NorseUserLogin.Configure);

		var entityType = builder.Model.FindEntityType(typeof(NorseUserLogin))!;
		entityType.FindProperty(nameof(NorseUserLogin.LoginProvider))!.GetMaxLength().ShouldBe(128);
		entityType.FindProperty(nameof(NorseUserLogin.ProviderKey))!.GetMaxLength().ShouldBe(256);
		entityType.FindProperty(nameof(NorseUserLogin.ProviderDisplayName))!.GetMaxLength().ShouldBe(256);
	}
}
