using Microsoft.EntityFrameworkCore;

namespace Norse.Identity.Tests;

public sealed class NorseUserConfigureTests
{
	[Fact]
	void Configure_sets_table_name()
	{
		var entityType = BuildEntityType();

		entityType.GetTableName().ShouldBe("users");
	}

	[Fact]
	void Configure_bounds_PasswordHash_and_converts_it()
	{
		var entityType = BuildEntityType();
		var property = entityType.FindProperty(nameof(NorseUser.PasswordHash))!;

		property.GetMaxLength().ShouldBe(128);
		property.GetValueConverter().ShouldNotBeNull();
	}

	[Fact]
	void Configure_bounds_PhoneNumber()
	{
		var entityType = BuildEntityType();

		entityType.FindProperty(nameof(NorseUser.PhoneNumber))!.GetMaxLength().ShouldBe(20);
	}

	[Fact]
	void Configure_converts_ConcurrencyStamp()
	{
		var entityType = BuildEntityType();

		entityType.FindProperty(nameof(NorseUser.ConcurrencyStamp))!.GetValueConverter().ShouldNotBeNull();
	}

	[Fact]
	void Configure_bounds_SecurityStamp_as_fixed_length_without_converting_it()
	{
		var entityType = BuildEntityType();
		var property = entityType.FindProperty(nameof(NorseUser.SecurityStamp))!;

		// UserManager.NewSecurityStamp() is Base32.GenerateBase32() -- always exactly 32 base32
		// characters, never Guid-shaped -- so this must NOT go through IdentityValueConverters.Stamp
		// (Guid.Parse), unlike ConcurrencyStamp, which Identity always sets to a real Guid string.
		// Fixed-length, not "up to 32" -- the output length never varies.
		property.GetMaxLength().ShouldBe(32);
		property.IsFixedLength().ShouldBe(true);
		property.GetValueConverter().ShouldBeNull();
	}

	[Fact]
	void Configure_wires_Claims_relationship_through_the_User_navigation()
	{
		var model = BuildModel();
		var claimType = model.FindEntityType(typeof(NorseUserClaim))!;
		var fk = claimType.GetForeignKeys().Single();

		fk.DependentToPrincipal!.Name.ShouldBe(nameof(NorseUserClaim.User));
		fk.IsRequired.ShouldBeTrue();
	}

	[Fact]
	void Configure_sets_unique_index_on_NormalizedUserName()
	{
		var entityType = BuildEntityType();
		var index = entityType.GetIndexes().Single(i => i.GetDatabaseName() == "ix_users_normalized_user_name");

		index.IsUnique.ShouldBeTrue();
	}

	static Microsoft.EntityFrameworkCore.Metadata.IEntityType FindType<T>(
		Microsoft.EntityFrameworkCore.Metadata.IModel model) => model.FindEntityType(typeof(T))!;

	static Microsoft.EntityFrameworkCore.Metadata.IEntityType BuildEntityType() => FindType<NorseUser>(BuildModel());

	static Microsoft.EntityFrameworkCore.Metadata.IModel BuildModel()
	{
		ModelBuilder builder = new();
		builder.Entity<NorseUser>(NorseUser.Configure);
		builder.Entity<NorseUserClaim>();
		builder.Entity<NorseUserLogin>();
		builder.Entity<NorseUserToken>();
		builder.Entity<NorseUserPasskey>(eb => eb.HasKey(p => p.CredentialId));
		return builder.Model.FinalizeModel();
	}
}
