using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Norse.Identity.EntityFramework;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.Design;
using Norse.Persistence.EntityFramework.SqlServer;

namespace Norse.Identity.Migrations.SqlServer;

/// <summary>
/// Design-time factory for <see cref="NorseIdentityDbContext"/>, used only by <c>dotnet ef</c> tooling
/// (e.g. <c>dotnet ef migrations add</c>) to construct a context instance outside of DI at design time.
/// </summary>
/// <remarks>
/// Same ASP.NET Core Identity <c>SchemaVersion</c> gotcha as the PostgreSQL factory — see that type's
/// doc comment for the full explanation. Provider-independent: the fallback to
/// <see cref="IdentitySchemaVersions.Version1"/> happens in Identity's own model-building code, not
/// anything provider-specific.
/// </remarks>
public sealed class NorseIdentityDbContextFactory : NorseDesignTimeDbContextFactory<NorseIdentityDbContext>
{
	/// <inheritdoc />
	protected override INorseEfProvider ProviderBinding => NorseSqlServerEfProvider.Instance;

	/// <inheritdoc />
	protected override string DatabaseName => "norse_identity";

	/// <inheritdoc />
	protected override void ConfigureOptions(DbContextOptionsBuilder<NorseIdentityDbContext> builder)
	{
		base.ConfigureOptions(builder);

		// ProtectPersonalData must mirror the runtime flag: with it on, ASP.NET Core Identity's own
		// OnModelCreatingVersion3 resolves IPersonalDataProtector from this application service provider
		// while building the model (it converts every [ProtectedPersonalData] property, e.g. UserName
		// and Email), throwing InvalidOperationException if the service can't be found -- design time
		// never decrypts, but the no-op registrations below let model build succeed anyway.
		var applicationServices = new ServiceCollection()
			.Configure<IdentityOptions>(o =>
			{
				o.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
				o.Stores.ProtectPersonalData = true;
			})
			.AddSingleton<IPersonalDataProtector, DesignTimePersonalDataProtector>()
			.AddSingleton<ILookupProtector, DesignTimeLookupProtector>()
			.AddSingleton<ILookupProtectorKeyRing, DesignTimeLookupProtectorKeyRing>()
			.BuildServiceProvider();

		builder.UseApplicationServiceProvider(applicationServices);
	}

	/// <inheritdoc />
	protected override NorseIdentityDbContext CreateContext(DbContextOptions<NorseIdentityDbContext> options) =>
		new(options);
}

/// <summary>
/// Design-time-only <see cref="IPersonalDataProtector"/>: model build needs the service to exist so
/// ASP.NET Core Identity's <c>OnModelCreatingVersion3</c> can resolve it, but migrations never touch
/// plaintext, so both members throw if ever actually invoked.
/// </summary>
file sealed class DesignTimePersonalDataProtector : IPersonalDataProtector
{
	public string? Protect(string? data) =>
		throw new NotSupportedException("Design time never touches plaintext.");

	public string? Unprotect(string? data) =>
		throw new NotSupportedException("Design time never touches plaintext.");
}

/// <summary>Design-time-only <see cref="ILookupProtector"/> -- see <see cref="DesignTimePersonalDataProtector"/>.</summary>
file sealed class DesignTimeLookupProtector : ILookupProtector
{
	public string? Protect(string keyId, string? data) =>
		throw new NotSupportedException("Design time never touches plaintext.");

	public string? Unprotect(string keyId, string? data) =>
		throw new NotSupportedException("Design time never touches plaintext.");
}

/// <summary>Design-time-only <see cref="ILookupProtectorKeyRing"/> -- see <see cref="DesignTimePersonalDataProtector"/>.</summary>
file sealed class DesignTimeLookupProtectorKeyRing : ILookupProtectorKeyRing
{
	public string CurrentKeyId =>
		throw new NotSupportedException("Design time never touches plaintext.");

	public string this[string keyId] =>
		throw new NotSupportedException("Design time never touches plaintext.");

	public IEnumerable<string> GetAllKeyIds() =>
		throw new NotSupportedException("Design time never touches plaintext.");
}
