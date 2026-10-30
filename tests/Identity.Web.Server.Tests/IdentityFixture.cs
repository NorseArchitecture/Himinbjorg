using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Identity.EntityFramework;
using Norse.Identity.Migrations;
using Norse.Infrastructure.Backend.Keys;
using Norse.Persistence.EntityFramework;
using OpenIddict.Abstractions;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     Real-database, real-DI fixture shared by both providers. Migrates <c>norse_identity</c> via the
///     provider's checked-in <c>InitialCreate</c> migration, then wires the full production graph --
///     <c>AddNorseAuthenticationService</c> over the provider binding,
///     which itself calls <c>IdentityBuilderExtensions.AddNorseIdentity()</c> -- over Midgard's
///     file-backed development key store. This is also the composition-level proof (flagged during
///     Task 17's review) that the protectors' <see cref="ISubjectKeyStore" />/<see cref="ILookupKeyRing" />
///     dependencies actually resolve end to end, not merely in isolation: the fixture-level smoke
///     assertion below fails loudly the moment that graph doesn't wire up.
/// </summary>
/// <remarks>
///     <b>Exactly one instance may ever exist per provider per process.</b> Every test class that needs one
///     consumes it as a shared <c>ICollectionFixture</c> (<see cref="PostgresTestGroup" />,
///     <see cref="SqlServerTestGroup" />), never as its own <c>IClassFixture</c> -- found the hard way,
///     root-caused after the fact: ASP.NET Core Identity's <c>OnModelCreating</c> resolves
///     <see cref="IPersonalDataProtector" /> from the context's <c>ApplicationServiceProvider</c> once, at
///     model-build time, and closes over that exact instance inside the compiled model's
///     <c>PersonalDataConverter</c> value converters. EF Core's own <c>ServiceProviderCache</c>/<c>ModelSource</c>
///     then caches that compiled model keyed by an options fingerprint that does <em>not</em> include the
///     connection string -- so a second <see cref="NorseIdentityDbContext" /> built from a second host in the
///     same process, on the same provider, silently reuses the first host's cached model, and therefore the
///     first host's <see cref="IPersonalDataProtector" /> and key store, even though it is talking to its own,
///     different database and its own, different <c>norse-identity-keys-*</c> directory on disk. That mismatch
///     is exactly what produced the spurious <c>KeyMissingException</c>/<c>DirectoryNotFoundException</c>
///     flake discovered while writing the disclosure-surface tests (Task 19b). A different provider is a
///     different options fingerprint, hence a different internal service provider and a different compiled
///     model, which is why one Postgres and one SQL Server fixture coexist safely. One
///     <see cref="IPersonalDataProtector" /> per process-wide EF model is production-safe by construction
///     (exactly one host per process there); a second in-process fixture instance on one provider is a bug,
///     not a tolerance to design around.
/// </remarks>
public abstract class IdentityFixture : IAsyncLifetime
{
	readonly List<IServiceScope> _scopes = [];
	WebApplication? _app;
	X509Certificate2? _certificate;
	string? _connectionString;
	string? _keysRoot;

	/// <summary>
	///     True once a real, usable database is up. Always true for Postgres once initialized; SQL Server's
	///     emulated container can die on start, and a collection fixture's <c>InitializeAsync</c> throwing would
	///     fail every test before its body runs -- so every provider-parameterized test calls
	///     <see cref="SkipUnlessAvailable" /> first.
	/// </summary>
	public bool Available { get; private set; }

	/// <summary>Why <see cref="Available" /> is false, surfaced by <see cref="SkipUnlessAvailable" />.</summary>
	public string? UnavailableReason { get; private set; }

	/// <summary>The provider binding the production composition registers the context against.</summary>
	protected abstract INorseEfProvider Provider { get; }

	/// <summary>The assembly carrying the provider's checked-in <c>InitialCreate</c>.</summary>
	protected abstract string MigrationsAssemblyName { get; }

	/// <inheritdoc />
	public async ValueTask InitializeAsync()
	{
		var connectionString = await StartDatabaseAsync();
		if (connectionString is null)
			return;
		_connectionString = connectionString;

		DbContextOptionsBuilder<NorseIdentityDbContext> migrationOptions = new();
		migrationOptions.ApplyNorseProviderOptions(Provider, connectionString, MigrationsAssemblyName);
		await using (NorseIdentityDbContext migrationContext = new(migrationOptions.Options))
		{
			NorseIdentityMigrationContributor contributor = new(migrationContext);
			await contributor.MigrateAsync(CancellationToken.None);
			await VerifySchemaAsync(migrationContext);
		}

		_keysRoot = Path.Combine(Path.GetTempPath(), $"norse-identity-keys-{Guid.NewGuid():N}");
		_certificate = IdentityTestCertificate.CreateFresh();

		var builder = Compose(_certificate);
		_app = builder.Build();
		_app.UseAuthentication();
		_app.UseAuthorization();
		_app.MapNorseOpenIddictEndpoints();
		await _app.StartAsync(CancellationToken.None);

		// Fixture-level smoke assertion (load-bearing, per Task 18's review): seeding through the
		// real NorseUserManager must actually encrypt Email and HMAC NormalizedEmail, proving the
		// full AddNorseIdentity() graph -- not just IdentityBuilderExtensions in isolation --
		// resolves against a real database. Read via raw SQL, deliberately bypassing
		// NorseUser.Email/NormalizedEmail's own EF value converters -- going through the mapped
		// entity property would transparently decrypt/round-trip the column and this assertion would
		// pass against plaintext even if the seam were never wired at all.
		var smokeUser = await SeedUserAsync("smoke-test@example.com");
		var (smokeContext, _) = await CreateScopeAsync();
		(await ReadRawEmailAsync(smokeContext, smokeUser.Id)).ShouldStartWith("v1:");
		Convert.FromBase64String(await ReadRawNormalizedEmailAsync(smokeContext, smokeUser.Id)).Length
			.ShouldBe(32); // HMAC-SHA256 -- exactly 32 bytes decoded, not just "some base64".
		Available = true;
	}

	/// <inheritdoc />
	public async ValueTask DisposeAsync()
	{
		foreach (var scope in _scopes)
			scope.Dispose();
		if (_app is not null)
		{
			// Stopped first, so the hosted services (the OpenIddict pruner) end as a host stop ends them, not faulted by
			// disposal.
			await _app.StopAsync(CancellationToken.None);
			await _app.DisposeAsync(); // WebApplication implements IAsyncDisposable directly -- no switch needed.
		}
		_certificate?.Dispose();

		await DisposeDatabaseAsync();
		if (_keysRoot is not null && Directory.Exists(_keysRoot))
			Directory.Delete(_keysRoot, recursive: true);
		GC.SuppressFinalize(this);
	}

	/// <summary>
	///     A <see cref="TestServer" />-backed builder carrying the fixture's own production composition, over its
	///     database and its key store, signing with <paramref name="certificate" />. The fixture builds its host from it,
	///     and so does any fact that needs a second host on the same database with more configured on top, such as
	///     <c>OpenIddictTestHost</c>. The second host shares the fixture's compiled EF model (see the class remark), which
	///     is safe here because its key store is the fixture's own.
	/// </summary>
	/// <param name="certificate">The OpenIddict signing/encryption certificate; the caller owns it.</param>
	public WebApplicationBuilder Compose(X509Certificate2 certificate)
	{
		var builder = WebApplication.CreateBuilder();
		builder.WebHost.UseTestServer();
		builder.Configuration["ConnectionStrings:identity"] = _connectionString ??
			throw new InvalidOperationException(UnavailableReason ?? "The fixture never started.");
		// Required configuration (T3-27): the host is Production, where nothing supplies an issuer by default.
		builder.Configuration["Identity:Authenticator:Issuer"] = "Norse";
		// The production pruner stays off over the collection's shared database: a fact seeding old prunable rows must not
		// lose them to a host's startup run. PruningSuite proves the pruner with instances of its own.
		builder.Configuration["Identity:OpenIddict:Pruning:Enabled"] = "false";
		builder.AddNorseAuthenticationService(Provider, "identity", certificate);
		builder.Services
			// Neither AddNorseAuthenticationService nor AddNorseIdentity registers authorization
			// services -- that's host-composition-root responsibility in production (Yggdrasil), and
			// this fixture stands in for that root by also calling UseAuthorization() below, so it
			// must supply the matching AddAuthorization() the middleware requires at startup.
			.AddAuthorization()
			.AddNorseDevelopmentKeys(KeysRoot)
			.AddSingleton<IDeferredSignIn>(Substitute.For<IDeferredSignIn>())
			.AddSingleton<IHttpContextAccessor>(new HttpContextAccessor { HttpContext = new DefaultHttpContext() });
		return builder;
	}

	/// <summary>Skips the calling test, by name, when the database never came up.</summary>
	public void SkipUnlessAvailable() =>
		Assert.SkipUnless(Available, UnavailableReason ?? "The identity database is unavailable.");

	/// <summary>A real <see cref="TestServer" />-backed <see cref="HttpClient" /> against <c>/connect/token</c>.</summary>
	public HttpClient CreateTestClient()
	{
		var client = App.GetTestServer().CreateClient();
		// TestServer's default client addresses http://localhost/, but OpenIddict's token endpoint
		// rejects non-HTTPS requests by default (spec §2.3 -- deliberately not relaxed via
		// DisableTransportSecurityRequirement()). TestServer never opens a real socket, so pointing the
		// client at an https:// base address is enough to make Request.IsHttps true -- no certificate
		// needed on this side of the fake transport.
		client.BaseAddress = new Uri("https://localhost/");
		return client;
	}

	/// <summary>Resolves a real <see cref="IOpenIddictApplicationManager" /> from a new DI scope, for seeding test clients.</summary>
	public IOpenIddictApplicationManager CreateApplicationManager() =>
		Resolve<IOpenIddictApplicationManager>(NewScope());

	/// <summary>
	///     Resolves a fresh <see cref="NorseIdentityDbContext" /> and <see cref="ISubjectKeyStore" /> from a new DI
	///     scope.
	/// </summary>
	public Task<(NorseIdentityDbContext Context, ISubjectKeyStore KeyStore)> CreateScopeAsync()
	{
		var scope = NewScope();
		return Task.FromResult((Resolve<NorseIdentityDbContext>(scope), Resolve<ISubjectKeyStore>(scope)));
	}

	/// <summary>
	///     The development key store's root, for tests that stage a state no public call reaches -- a pending
	///     receipt, a key gone with no receipt -- in the store's documented on-disk shape.
	/// </summary>
	public string KeysRoot =>
		_keysRoot ?? throw new InvalidOperationException(UnavailableReason ?? "The fixture never started.");

	/// <summary>
	///     A <see cref="NorseIdentityDbContext" /> on the fixture's own registered options plus
	///     <paramref name="interceptors" />, for failure injection. The options are frozen, exactly as the pooled
	///     registration's are, so <c>OnConfiguring</c> leaves the application service provider alone and the
	///     context shares the fixture's compiled model. The caller disposes it.
	/// </summary>
	/// <param name="interceptors">The interceptors that inject the failure.</param>
	public NorseIdentityDbContext CreateContext(params IInterceptor[] interceptors)
	{
		var options = new DbContextOptionsBuilder<NorseIdentityDbContext>(
				Resolve<DbContextOptions<NorseIdentityDbContext>>(NewScope()))
			.AddInterceptors(interceptors)
			.Options;
		options.Freeze();
		return new(options);
	}

	/// <summary>
	///     A new, empty database on the fixture's own container, migrated through the same checked-in
	///     <c>InitialCreate</c> (<c>CREATE DATABASE</c>, then <c>Database.MigrateAsync()</c>), for a fact that must know
	///     exactly what the database holds. Disposing the handle drops it; a failed migration drops it before throwing.
	/// </summary>
	public async Task<FreshDatabase> CreateFreshDatabaseAsync()
	{
		var name = $"norse_fresh_{Guid.NewGuid():N}";
		var (context, _) = await CreateScopeAsync();
		var create = $"CREATE DATABASE {name}";
		await context.Database.ExecuteSqlRawAsync(create);

		DbContextOptionsBuilder<NorseIdentityDbContext> options = new();
		options.ApplyNorseProviderOptions(Provider,
			ConnectionStringFor(_connectionString ?? throw new InvalidOperationException(UnavailableReason), name),
			MigrationsAssemblyName);
		var drop = DropDatabaseSql(name);
		FreshDatabase fresh = new(options.Options, () => context.Database.ExecuteSqlRawAsync(drop));
		try
		{
			await using var migration = fresh.CreateContext();
			await migration.Database.MigrateAsync();
		}
		// A database that never finished migrating is dropped too: no fact holds a handle to it.
		catch
		{
			await fresh.DisposeAsync();
			throw;
		}

		return fresh;
	}

	/// <summary>Seeds a user through the real <c>NorseUserManager</c> chokepoint -- no manual <c>SubjectCryptoScope</c>.</summary>
	/// <param name="email">The user's email -- also stands in as the username.</param>
	/// <param name="phone">
	///     The user's phone number, E.164. Omitted leaves the column null, same as a user who never supplied
	///     one.
	/// </param>
	public async Task<NorseUser> SeedUserAsync(string email, string? phone = null)
	{
		var userManager = CreateUserManager();
		NorseUser user = new() { UserName = email, Email = email, PhoneNumber = phone };
		var result = await userManager.CreateAsync(user);
		return result.Succeeded ?
			user :
			throw new InvalidOperationException(
				$"Seeding user '{email}' failed: {string.Join(", ", result.Errors.Select(e => e.Description))}");
	}

	/// <summary>
	///     Resolves a real <see cref="SignInManager{TUser}" /> from a new DI scope, over a bare
	///     <see cref="DefaultHttpContext" />.
	/// </summary>
	public SignInManager<NorseUser> CreateSignInManager() =>
		Resolve<SignInManager<NorseUser>>(NewScope());

	/// <summary>
	///     A real <see cref="NorseSignInManager" /> from a new DI scope over <paramref name="userManager" /> instead of
	///     the scope's own, for tests that observe the store's statements through a context of their own.
	/// </summary>
	/// <param name="userManager">The manager the sign-in manager drives.</param>
	public NorseSignInManager CreateSignInManager(UserManager<NorseUser> userManager) =>
		ActivatorUtilities.CreateInstance<NorseSignInManager>(NewScope().ServiceProvider, userManager);

	/// <summary>
	///     Resolves a real <see cref="UserManager{TUser}" /> from a new DI scope -- for tests that need a
	///     shape <see cref="SeedUserAsync" /> can't produce, e.g. a user with no email at all
	///     (<c>SeedUserAsync</c> always sets one, standing in for the username).
	/// </summary>
	public UserManager<NorseUser> CreateUserManager() =>
		Resolve<UserManager<NorseUser>>(NewScope());

	/// <summary>
	///     A real <see cref="NorseUserManager" /> from a new DI scope over <paramref name="store" /> instead of the
	///     registered store, for tests that observe the store's statements through a context of their own.
	/// </summary>
	/// <param name="store">The store the manager drives.</param>
	public NorseUserManager CreateUserManager(IUserStore<NorseUser> store) =>
		ActivatorUtilities.CreateInstance<NorseUserManager>(NewScope().ServiceProvider, store);

	/// <summary>
	///     Resolves the real <see cref="IUserStore{TUser}" /> from a new DI scope, for flows that set properties
	///     through the store before <c>CreateAsync</c>, as the retired <c>ExternalLogin.razor</c> scaffold did.
	/// </summary>
	public IUserStore<NorseUser> CreateUserStore() =>
		Resolve<IUserStore<NorseUser>>(NewScope());

	/// <summary>
	///     A DI scope the caller owns and disposes, unlike every other scope the fixture hands out, for tests that
	///     prove state outlives the scope it was created in.
	/// </summary>
	public IServiceScope CreateOwnedScope() =>
		App.Services.CreateScope();

	/// <summary>Resolves a real <see cref="RoleManager{TRole}" /> from a new DI scope, for tests that grant and revoke roles.</summary>
	public RoleManager<NorseRole> CreateRoleManager() =>
		Resolve<RoleManager<NorseRole>>(NewScope());

	/// <summary>
	///     Starts the database and returns its connection string, or <see langword="null" /> after calling
	///     <see cref="MarkUnavailable" /> when the host cannot run it.
	/// </summary>
	protected abstract Task<string?> StartDatabaseAsync();

	/// <summary>The fixture's connection string, pointed at <paramref name="database" /> instead.</summary>
	/// <param name="connectionString">The fixture's connection string.</param>
	/// <param name="database">The database to connect to.</param>
	protected abstract string ConnectionStringFor(string connectionString, string database);

	/// <summary>The statement that drops <paramref name="database" />, closing any connection still open to it.</summary>
	/// <param name="database">The database to drop.</param>
	protected abstract string DropDatabaseSql(string database);

	/// <summary>Provider-specific catalog checks run straight after the migration applies.</summary>
	/// <param name="context">The migration context, still open.</param>
	protected virtual Task VerifySchemaAsync(NorseIdentityDbContext context) =>
		Task.CompletedTask;

	/// <summary>The raw, undecrypted <c>Email</c> column of one user row.</summary>
	protected abstract Task<string> ReadRawEmailAsync(NorseIdentityDbContext context, Guid userId);

	/// <summary>The raw <c>NormalizedEmail</c> blind-index column of one user row.</summary>
	protected abstract Task<string> ReadRawNormalizedEmailAsync(NorseIdentityDbContext context, Guid userId);

	/// <summary>Disposes the database container. Called whether or not it ever started.</summary>
	protected abstract ValueTask DisposeDatabaseAsync();

	/// <summary>Records why the database is unavailable; every gated test then skips with it.</summary>
	/// <param name="reason">The skip reason.</param>
	protected void MarkUnavailable(string reason) =>
		UnavailableReason = reason;

	WebApplication App =>
		_app ?? throw new InvalidOperationException(UnavailableReason ?? "The fixture never started.");

	IServiceScope NewScope()
	{
		var scope = App.Services.CreateScope();
		_scopes.Add(scope);
		return scope;
	}

	static T Resolve<T>(IServiceScope scope) where T : notnull =>
		scope.ServiceProvider.GetRequiredService<T>();

	/// <summary>A database of the fact's own, from <see cref="CreateFreshDatabaseAsync" />; disposing it drops it.</summary>
	/// <param name="options">Options on the fresh database.</param>
	/// <param name="drop">Drops the database.</param>
	public sealed class FreshDatabase(DbContextOptions<NorseIdentityDbContext> options, Func<Task<int>> drop) : IAsyncDisposable
	{
		/// <summary>A new context on the fresh database, plus <paramref name="interceptors" />. The caller disposes it.</summary>
		/// <param name="interceptors">The interceptors to attach.</param>
		public NorseIdentityDbContext CreateContext(params IInterceptor[] interceptors) =>
			new(new DbContextOptionsBuilder<NorseIdentityDbContext>(options).AddInterceptors(interceptors).Options);

		/// <inheritdoc />
		public async ValueTask DisposeAsync() =>
			await drop();
	}
}
