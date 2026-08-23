using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Norse.Identity.EntityFramework;
using Norse.Identity.Migrations.PostgreSQL;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.PostgreSQL;
using OpenIddict.Abstractions;

namespace Norse.Identity.Migrations.Tests;

[Collection("Postgres")]
public sealed class MachineClientSeedContributorTests(PostgresContainerFixture fixture)
{
	[Fact]
	async Task First_run_creates_the_application_with_both_required_permissions()
	{
		await using var context = await CreateMigratedContextAsync();
		var manager = BuildApplicationManager(context);
		await ResetMachineClientAsync(manager);
		var contributor = new MachineClientSeedContributor(BuildConfiguration("first-secret"), manager);

		await contributor.SeedAsync(TestContext.Current.CancellationToken);

		var application = await manager.FindByClientIdAsync(MachineClientSeedContributor.ClientId,
			TestContext.Current.CancellationToken);
		application.ShouldNotBeNull();
		var permissions = await manager.GetPermissionsAsync(application, TestContext.Current.CancellationToken);
		permissions.ShouldContain(OpenIddictConstants.Permissions.Endpoints.Token);
		permissions.ShouldContain(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
	}

	[Fact]
	async Task Reseeding_with_the_same_secret_writes_nothing_new()
	{
		await using var context = await CreateMigratedContextAsync();
		var manager = BuildApplicationManager(context);
		await ResetMachineClientAsync(manager);
		var configuration = BuildConfiguration("stable-secret");
		var contributor = new MachineClientSeedContributor(configuration, manager);
		await contributor.SeedAsync(TestContext.Current.CancellationToken);
		var afterFirstRun = await manager.FindByClientIdAsync(MachineClientSeedContributor.ClientId,
			TestContext.Current.CancellationToken);
		var tokenAfterFirstRun = await manager.GetIdAsync(afterFirstRun!, TestContext.Current.CancellationToken);
		var concurrencyTokenAfterFirstRun = await GetConcurrencyTokenAsync(context, tokenAfterFirstRun!);

		await contributor.SeedAsync(TestContext.Current.CancellationToken); // identical config, second run

		var concurrencyTokenAfterSecondRun = await GetConcurrencyTokenAsync(context, tokenAfterFirstRun!);
		// The real, observable proof no write happened: OpenIddict's own optimistic-concurrency column is
		// untouched. A validate-then-skip check alone (the prior draft's mistake) only proves the secret is
		// still valid -- it cannot tell "nothing was written" from "something was written back to the same
		// value," and this table has no audit log to check instead.
		concurrencyTokenAfterSecondRun.ShouldBe(concurrencyTokenAfterFirstRun);
		(await manager.ValidateClientSecretAsync(afterFirstRun!, "stable-secret", TestContext.Current.CancellationToken))
			.ShouldBeTrue();
	}

	[Fact]
	async Task Reseeding_with_a_changed_secret_invalidates_the_old_one_and_writes_a_new_one()
	{
		await using var context = await CreateMigratedContextAsync();
		var manager = BuildApplicationManager(context);
		await ResetMachineClientAsync(manager);
		var contributor = new MachineClientSeedContributor(BuildConfiguration("old-secret"), manager);
		await contributor.SeedAsync(TestContext.Current.CancellationToken);
		var application = await manager.FindByClientIdAsync(MachineClientSeedContributor.ClientId,
			TestContext.Current.CancellationToken);
		var id = await manager.GetIdAsync(application!, TestContext.Current.CancellationToken);
		var concurrencyTokenBeforeRotation = await GetConcurrencyTokenAsync(context, id!);

		var rotatedContributor = new MachineClientSeedContributor(BuildConfiguration("new-secret"), manager);
		await rotatedContributor.SeedAsync(TestContext.Current.CancellationToken);

		var concurrencyTokenAfterRotation = await GetConcurrencyTokenAsync(context, id!);
		concurrencyTokenAfterRotation.ShouldNotBe(concurrencyTokenBeforeRotation); // a write did happen this time.
		var rotated = await manager.FindByClientIdAsync(MachineClientSeedContributor.ClientId,
			TestContext.Current.CancellationToken);
		(await manager.ValidateClientSecretAsync(rotated!, "old-secret", TestContext.Current.CancellationToken))
			.ShouldBeFalse();
		(await manager.ValidateClientSecretAsync(rotated!, "new-secret", TestContext.Current.CancellationToken))
			.ShouldBeTrue();
	}

	[Fact]
	async Task Reseeding_with_a_changed_display_name_does_not_disturb_the_still_valid_secret()
	{
		await using var context = await CreateMigratedContextAsync();
		var manager = BuildApplicationManager(context);
		await ResetMachineClientAsync(manager);
		var contributor = new MachineClientSeedContributor(BuildConfiguration("stable-secret"), manager);
		await contributor.SeedAsync(TestContext.Current.CancellationToken);
		var application = await manager.FindByClientIdAsync(MachineClientSeedContributor.ClientId,
			TestContext.Current.CancellationToken);

		// MachineClientSeedContributor.DisplayName is a compile-time constant, so the only way to make the
		// stored DisplayName differ from it -- the reconcile trigger this test needs -- is to mutate it
		// directly here, through the manager's own descriptor-based UpdateAsync (which correctly round-trips
		// the existing secret hash via PopulateAsync, unlike the bug under test). This reproduces exactly the
		// drift the contributor's own doc comment anticipates future issues (#51/#53) will exercise: an
		// existing norse_identity database whose DisplayName no longer matches what the contributor wants.
		OpenIddictApplicationDescriptor mutation = new();
		await manager.PopulateAsync(mutation, application!, TestContext.Current.CancellationToken);
		mutation.DisplayName = "Some Other Display Name";
		await manager.UpdateAsync(application!, mutation, TestContext.Current.CancellationToken);

		// The bug: the reconcile path used to pass ClientSecret = null whenever the secret still validated
		// but some OTHER field (here, DisplayName) differed -- PopulateAsync writes that null straight to
		// the store, and UpdateAsync's own secret-changed check then throws
		// OpenIddictExceptions.ValidationException (ID2113: a confidential client can't have a null secret).
		await contributor.SeedAsync(TestContext.Current.CancellationToken);

		var reconciled = await manager.FindByClientIdAsync(MachineClientSeedContributor.ClientId,
			TestContext.Current.CancellationToken);
		(await manager.GetDisplayNameAsync(reconciled!, TestContext.Current.CancellationToken))
			.ShouldBe(MachineClientSeedContributor.DisplayName); // reconciled back to the contributor's own name.

		// The real proof the secret's hash survived unchanged -- not just that no exception was thrown.
		(await manager.ValidateClientSecretAsync(reconciled!, "stable-secret", TestContext.Current.CancellationToken))
			.ShouldBeTrue();
	}

	async Task<NorseIdentityDbContext> CreateMigratedContextAsync()
	{
		DbContextOptionsBuilder<NorseIdentityDbContext> optionsBuilder = new();
		optionsBuilder.ApplyNorseProviderOptions(NorsePostgresEfProvider.Instance,
			fixture.ConnectionString, typeof(NorseIdentityDbContextFactory).Assembly.GetName().Name);
		NorseIdentityDbContext context = new(optionsBuilder.Options);
		await new NorseIdentityMigrationContributor(context).MigrateAsync(TestContext.Current.CancellationToken);
		return context;
	}

	static IOpenIddictApplicationManager BuildApplicationManager(NorseIdentityDbContext context)
	{
		ServiceCollection services = new();
		services.AddSingleton(context);
		MachineClientSeedContributor.ConfigureServices(services);
		return services.BuildServiceProvider().GetRequiredService<IOpenIddictApplicationManager>();
	}

	static IConfiguration BuildConfiguration(string secret) =>
		new ConfigurationBuilder()
			.AddInMemoryCollection([new("OIDC_MACHINE_CLIENT_SECRET", secret)])
			.Build();

	static async Task ResetMachineClientAsync(IOpenIddictApplicationManager manager)
	{
		var existing = await manager.FindByClientIdAsync(MachineClientSeedContributor.ClientId,
			TestContext.Current.CancellationToken);
		if (existing is not null)
			await manager.DeleteAsync(existing, TestContext.Current.CancellationToken);
	}

	static async Task<string> GetConcurrencyTokenAsync(NorseIdentityDbContext context, string id) =>
		(await context.Set<Norse.Identity.EntityFramework.NorseOpenIddictApplication>()
			.AsNoTracking()
			.SingleAsync(a => a.Id == Guid.Parse(id), TestContext.Current.CancellationToken))
		.ConcurrencyToken!;
}
