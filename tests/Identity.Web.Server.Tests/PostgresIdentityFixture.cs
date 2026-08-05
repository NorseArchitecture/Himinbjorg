using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Identity.EntityFramework;
using Norse.Identity.Migrations;
using Norse.Identity.Migrations.PostgreSQL;
using Norse.Infrastructure.Backend.Keys;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.PostgreSQL;
using Testcontainers.PostgreSql;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
/// Real-Postgres, real-DI fixture for the shred ceremony's integration tests. Migrates
/// <c>norse_identity</c> via the checked-in Postgres <c>InitialCreate</c> migration, then wires the
/// full production graph -- <see cref="ServiceCollectionExtensions.AddNorseAuthenticationService"/>,
/// which itself calls <c>IdentityBuilderExtensions.AddNorseIdentity()</c> -- over Midgard's
/// file-backed development key store. This is also the composition-level proof (flagged during
/// Task 17's review) that the protectors' <see cref="ISubjectKeyStore"/>/<see cref="ILookupKeyRing"/>
/// dependencies actually resolve end to end, not merely in isolation: the fixture-level smoke
/// assertion below fails loudly the moment that graph doesn't wire up.
/// </summary>
public sealed class PostgresIdentityFixture : IAsyncLifetime
{
	readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:19beta2")
		.WithDatabase("norse_identity")
		.Build();
	readonly List<IServiceScope> _scopes = [];

	string _keysRoot = null!;
	IHost _host = null!;

	/// <inheritdoc />
	public async ValueTask InitializeAsync()
	{
		await _container.StartAsync();
		var connectionString = _container.GetConnectionString();

		DbContextOptionsBuilder<NorseIdentityDbContext> migrationOptions = new();
		migrationOptions.ApplyNorseProviderOptions(NorsePostgresEfProvider.Instance, connectionString,
			typeof(NorseIdentityDbContextFactory).Assembly.GetName().Name);
		await using (NorseIdentityDbContext migrationContext = new(migrationOptions.Options))
		{
			NorseIdentityMigrationContributor contributor = new(migrationContext);
			await contributor.MigrateAsync(CancellationToken.None);
		}

		_keysRoot = Path.Combine(Path.GetTempPath(), $"norse-identity-keys-{Guid.NewGuid():N}");

		var builder = Host.CreateApplicationBuilder();
		builder.Configuration["ConnectionStrings:identity"] = connectionString;
		builder.AddNorseAuthenticationService("identity");
		builder.Services
			.AddNorseDevelopmentKeys(_keysRoot)
			.AddSingleton<IDeferredSignIn>(Substitute.For<IDeferredSignIn>())
			.AddSingleton<IHttpContextAccessor>(new HttpContextAccessor { HttpContext = new DefaultHttpContext() });

		_host = builder.Build();

		// Fixture-level smoke assertion (load-bearing, per Task 18's review): seeding through the
		// real NorseUserManager must actually encrypt Email and HMAC NormalizedEmail, proving the
		// full AddNorseIdentity() graph -- not just IdentityBuilderExtensions in isolation --
		// resolves against a real Postgres database. Read via raw SQL, deliberately bypassing
		// NorseUser.Email/NormalizedEmail's own EF value converters -- going through the mapped
		// entity property would transparently decrypt/round-trip the column and this assertion would
		// pass against plaintext even if the seam were never wired at all.
		var smokeUser = await SeedUserAsync("smoke-test@example.com");
		var (smokeContext, _) = await CreateScopeAsync();
		var rawEmail = await smokeContext.Database
			.SqlQuery<string>($"""SELECT email AS "Value" FROM users WHERE id = {smokeUser.Id}""")
			.SingleAsync(CancellationToken.None);
		rawEmail.ShouldStartWith("v1:");
		var rawNormalizedEmail = await smokeContext.Database
			.SqlQuery<string>($"""SELECT normalized_email AS "Value" FROM users WHERE id = {smokeUser.Id}""")
			.SingleAsync(CancellationToken.None);
		Convert.FromBase64String(rawNormalizedEmail).Length.ShouldBe(32); // HMAC-SHA256 -- exactly 32 bytes decoded, not just "some base64".
	}

	/// <inheritdoc />
	public async ValueTask DisposeAsync()
	{
		foreach (var scope in _scopes)
			scope.Dispose();
		// IHost itself only declares IDisposable; the concrete Host the builder returns also
		// implements IAsyncDisposable, so dispose asynchronously when it's there rather than block.
		switch (_host)
		{
			case IAsyncDisposable asyncDisposable:
				await asyncDisposable.DisposeAsync();
				break;
			case not null:
				_host.Dispose();
				break;
		}
		await _container.DisposeAsync();
		if (Directory.Exists(_keysRoot))
			Directory.Delete(_keysRoot, recursive: true);
	}

	/// <summary>Resolves a fresh <see cref="NorseIdentityDbContext"/> and <see cref="ISubjectKeyStore"/> from a new DI scope.</summary>
	public Task<(NorseIdentityDbContext Context, ISubjectKeyStore KeyStore)> CreateScopeAsync()
	{
		var scope = _host.Services.CreateScope();
		_scopes.Add(scope);
		return Task.FromResult((
			scope.ServiceProvider.GetRequiredService<NorseIdentityDbContext>(),
			scope.ServiceProvider.GetRequiredService<ISubjectKeyStore>()));
	}

	/// <summary>Seeds a user through the real <c>NorseUserManager</c> chokepoint -- no manual <c>SubjectCryptoScope</c>.</summary>
	public async Task<NorseUser> SeedUserAsync(string email)
	{
		var scope = _host.Services.CreateScope();
		_scopes.Add(scope);
		var userManager = scope.ServiceProvider.GetRequiredService<UserManager<NorseUser>>();
		NorseUser user = new() { UserName = email, Email = email };
		var result = await userManager.CreateAsync(user);
		return result.Succeeded ?
			user :
			throw new InvalidOperationException(
				$"Seeding user '{email}' failed: {string.Join(", ", result.Errors.Select(e => e.Description))}");
	}

	/// <summary>Resolves a real <see cref="SignInManager{TUser}"/> from a new DI scope, over a bare <see cref="DefaultHttpContext"/>.</summary>
	public SignInManager<NorseUser> CreateSignInManager()
	{
		var scope = _host.Services.CreateScope();
		_scopes.Add(scope);
		return scope.ServiceProvider.GetRequiredService<SignInManager<NorseUser>>();
	}
}
