using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Norse.Identity.EntityFramework.Tests;

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
	void Authorization_Configure_bounds_Properties_and_declares_explicit_ApplicationId()
	{
		var model = BuildAuthorizationModel();
		var entityType = model.FindEntityType(typeof(NorseOpenIddictAuthorization))!;
		// OpenIddict 8 maps Properties through a JSON-string converter; Scopes is a string[] primitive collection.
		entityType.FindProperty(nameof(NorseOpenIddictAuthorization.Properties))!.GetMaxLength().ShouldBe(-1);

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

		List<IForeignKey> foreignKeys = [.. entityType.GetForeignKeys()];
		foreignKeys.ShouldContain(fk => fk.Properties.Single().Name == nameof(NorseOpenIddictToken.ApplicationId));
		foreignKeys.ShouldContain(fk => fk.Properties.Single().Name == nameof(NorseOpenIddictToken.AuthorizationId));
		foreignKeys.ShouldContain(fk => fk.Properties.Single().Name == nameof(NorseOpenIddictToken.SessionId)
			&& fk.DependentToPrincipal!.Name == nameof(NorseOpenIddictToken.Session));
	}

	[Fact]
	void Session_Configure_bounds_Properties_and_declares_explicit_FKs()
	{
		var entityType = BuildSessionModel().FindEntityType(typeof(NorseOpenIddictSession))!;
		entityType.FindProperty(nameof(NorseOpenIddictSession.Properties))!.GetMaxLength().ShouldBe(-1);

		entityType.GetForeignKeys()
			.Select(static fk => $"{fk.DependentToPrincipal!.Name}:{fk.Properties.Single().Name}")
			.Order(StringComparer.Ordinal)
			.ShouldBe([
				$"{nameof(NorseOpenIddictSession.Application)}:{nameof(NorseOpenIddictSession.ApplicationId)}",
				$"{nameof(NorseOpenIddictSession.Authorization)}:{nameof(NorseOpenIddictSession.AuthorizationId)}"
			]);
	}

	[Fact]
	void Resource_Configure_bounds_Description_and_DisplayName()
	{
		var entityType = BuildResourceModel().FindEntityType(typeof(NorseOpenIddictResource))!;

		entityType.FindProperty(nameof(NorseOpenIddictResource.Description))!.GetMaxLength().ShouldBe(1000);
		entityType.FindProperty(nameof(NorseOpenIddictResource.DisplayName))!.GetMaxLength().ShouldBe(200);
	}

	static IModel BuildApplicationModel()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseOpenIddictApplication>(NorseOpenIddictApplication.Configure);
		return builder.Model.FinalizeModel();
	}

	static IModel BuildAuthorizationModel()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseOpenIddictAuthorization>(NorseOpenIddictAuthorization.Configure);
		builder.Entity<NorseOpenIddictApplication>();
		return builder.Model.FinalizeModel();
	}

	static IModel BuildScopeModel()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseOpenIddictScope>(NorseOpenIddictScope.Configure);
		return builder.Model.FinalizeModel();
	}

	static IModel BuildTokenModel()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseOpenIddictToken>(NorseOpenIddictToken.Configure);
		builder.Entity<NorseOpenIddictApplication>();
		builder.Entity<NorseOpenIddictAuthorization>(NorseOpenIddictAuthorization.Configure);
		builder.Entity<NorseOpenIddictSession>(NorseOpenIddictSession.Configure);
		return builder.Model.FinalizeModel();
	}

	static IModel BuildSessionModel()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseOpenIddictSession>(NorseOpenIddictSession.Configure);
		builder.Entity<NorseOpenIddictApplication>();
		builder.Entity<NorseOpenIddictAuthorization>(NorseOpenIddictAuthorization.Configure);
		builder.Entity<NorseOpenIddictToken>(NorseOpenIddictToken.Configure);
		return builder.Model.FinalizeModel();
	}

	static IModel BuildResourceModel()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseOpenIddictResource>(NorseOpenIddictResource.Configure);
		return builder.Model.FinalizeModel();
	}
}
