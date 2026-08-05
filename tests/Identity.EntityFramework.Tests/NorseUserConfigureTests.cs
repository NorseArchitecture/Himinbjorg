using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Norse.Identity.EntityFramework.Tests;

public sealed class NorseUserConfigureTests
{
	[Fact]
	void Configure_sets_table_name()
	{
		var entityType = BuildEntityType();

		entityType.GetTableName().ShouldBe("Users");
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

		// 256, not a raw E.164 bound: this column now carries the NorsePersonalDataProtector envelope
		// ("v1:{subjectId:D}:{base64}"), not a bare phone number -- mirrors Email's own ASP.NET Core
		// Identity convention bound, which fits the same envelope shape comfortably.
		entityType.FindProperty(nameof(NorseUser.PhoneNumber))!.GetMaxLength().ShouldBe(256);
	}

	[Fact]
	void Configure_converts_ConcurrencyStamp()
	{
		var entityType = BuildEntityType();

		entityType.FindProperty(nameof(NorseUser.ConcurrencyStamp))!.GetValueConverter().ShouldNotBeNull();
	}

	[Fact]
	void Configure_bounds_SecurityStamp_without_converting_it()
	{
		var entityType = BuildEntityType();
		var property = entityType.FindProperty(nameof(NorseUser.SecurityStamp))!;

		// UserManager.NewSecurityStamp() is Base32.GenerateBase32() -- always exactly 32 base32
		// characters, never Guid-shaped -- so this must NOT go through IdentityValueConverters.Stamp
		// (Guid.Parse), unlike ConcurrencyStamp, which Identity always sets to a real Guid string.
		// Deliberately not .IsFixedLength(): Postgres's character(n) has no storage/perf advantage
		// over character varying(n) on this engine, unlike SQL Server/MySQL.
		property.GetMaxLength().ShouldBe(32);
		property.IsFixedLength().ShouldNotBe(true);
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

	// The NormalizedUserName unique index moved to NorseIdentityDbContext.OnModelCreating (2026-08-03
	// PII spec §4.2): the filter differs by provider ([NormalizedUserName] IS NOT NULL on SQL Server,
	// unfiltered on Postgres), a decision only the context can make since NorseUser.Configure never
	// sees the provider. Covered by NorseIdentityModelTests now.

	static IEntityType FindType<T>(IModel model) =>
		model.FindEntityType(typeof(T))!;

	static IEntityType BuildEntityType() => FindType<NorseUser>(BuildModel());

	static IModel BuildModel()
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
