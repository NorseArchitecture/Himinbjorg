using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Norse.Identity.EntityFramework;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.Design;
using Norse.Persistence.EntityFramework.PostgreSQL;

namespace Norse.Identity.Migrations.PostgreSQL;

/// <summary>
/// Design-time factory for <see cref="NorseIdentityDbContext"/>, used only by <c>dotnet ef</c> tooling
/// (e.g. <c>dotnet ef migrations add</c>) to construct a context instance outside of DI at design time.
/// </summary>
/// <remarks>
/// ASP.NET Core Identity's base <c>OnModelCreating</c> reads
/// <c>IOptions&lt;IdentityOptions&gt;.Value.Stores.SchemaVersion</c> off the context's
/// <c>ApplicationServiceProvider</c> — not the (dead, never-consulted) protected <c>SchemaVersion</c>
/// property — to decide which passkey/OpenIddict schema shape to emit. Without an application service
/// provider supplying <see cref="IdentitySchemaVersions.Version3"/>, ASP.NET Core Identity silently
/// falls back to <see cref="IdentitySchemaVersions.Version1"/> and omits the passkey table entirely.
/// </remarks>
public sealed class NorseIdentityDbContextFactory : NorseDesignTimeDbContextFactory<NorseIdentityDbContext>
{
	/// <inheritdoc />
	protected override INorseEfProvider ProviderBinding => NorsePostgresEfProvider.Instance;

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
