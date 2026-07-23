using Microsoft.EntityFrameworkCore;

namespace Norse.Identity.Web.Server.Tests;

public sealed class NorseOpenIddictEntitiesConfigureTests
{
	[Fact]
	void Application_Configure_bounds_ClientSecret_and_DisplayName()
	{
		var entityType = BuildApplicationModel().FindEntityType(typeof(NorseOpenIddictApplication))!;

		entityType.FindProperty(nameof(NorseOpenIddictApplication.ClientSecret))!.GetMaxLength().ShouldBe(-1);
		entityType.FindProperty(nameof(NorseOpenIddictApplication.DisplayName))!.GetMaxLength().ShouldBe(200);
	}

	[Fact]
	void Authorization_Configure_bounds_Scopes_and_declares_explicit_ApplicationId()
	{
		var model = BuildAuthorizationModel();
		var entityType = model.FindEntityType(typeof(NorseOpenIddictAuthorization))!;
		entityType.FindProperty(nameof(NorseOpenIddictAuthorization.Scopes))!.GetMaxLength().ShouldBe(-1);

		var fk = entityType.GetForeignKeys().Single();
		fk.Properties.Single().Name.ShouldBe(nameof(NorseOpenIddictAuthorization.ApplicationId));
		fk.DependentToPrincipal!.Name.ShouldBe(nameof(NorseOpenIddictAuthorization.Application));
	}

	[Fact]
	void Scope_Configure_bounds_Description_and_DisplayName()
	{
		var entityType = BuildScopeModel().FindEntityType(typeof(NorseOpenIddictScope))!;

		entityType.FindProperty(nameof(NorseOpenIddictScope.Description))!.GetMaxLength().ShouldBe(1000);
		entityType.FindProperty(nameof(NorseOpenIddictScope.DisplayName))!.GetMaxLength().ShouldBe(200);
	}

	[Fact]
	void Token_Configure_bounds_Payload_and_declares_explicit_FKs()
	{
		var model = BuildTokenModel();
		var entityType = model.FindEntityType(typeof(NorseOpenIddictToken))!;
		entityType.FindProperty(nameof(NorseOpenIddictToken.Payload))!.GetMaxLength().ShouldBe(-1);

		var foreignKeys = entityType.GetForeignKeys().ToList();
		foreignKeys.ShouldContain(fk => fk.Properties.Single().Name == nameof(NorseOpenIddictToken.ApplicationId));
		foreignKeys.ShouldContain(fk => fk.Properties.Single().Name == nameof(NorseOpenIddictToken.AuthorizationId));
	}

	static Microsoft.EntityFrameworkCore.Metadata.IModel BuildApplicationModel()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseOpenIddictApplication>(NorseOpenIddictApplication.Configure);
		return builder.Model.FinalizeModel();
	}

	static Microsoft.EntityFrameworkCore.Metadata.IModel BuildAuthorizationModel()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseOpenIddictAuthorization>(NorseOpenIddictAuthorization.Configure);
		builder.Entity<NorseOpenIddictApplication>();
		return builder.Model.FinalizeModel();
	}

	static Microsoft.EntityFrameworkCore.Metadata.IModel BuildScopeModel()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseOpenIddictScope>(NorseOpenIddictScope.Configure);
		return builder.Model.FinalizeModel();
	}

	static Microsoft.EntityFrameworkCore.Metadata.IModel BuildTokenModel()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseOpenIddictToken>(NorseOpenIddictToken.Configure);
		builder.Entity<NorseOpenIddictApplication>();
		builder.Entity<NorseOpenIddictAuthorization>(NorseOpenIddictAuthorization.Configure);
		return builder.Model.FinalizeModel();
	}
}
