using System.Data.Common;
using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Norse.Identity.EntityFramework;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     The store link contract (2026-10-29 OpenIddict spec §4.5, amendment r6.1; plan gate H7), once per provider: the
///     token, authorization and session stores answer every relationship from the entity's explicit FK scalar, whether
///     or not the entity is tracked or its navigation loaded, and their setters keep the scalar and the navigation in
///     step for setting, replacing and clearing each link. Facts 1, 2 and 5 of §4.5; <see cref="GrantContinuitySuite" />
///     carries 3 and 4.
/// </summary>
/// <remarks>
///     The stores are reached only through OpenIddict's own interfaces, resolved from the production composition, so
///     every fact runs unchanged against whatever store that composition registers.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class StoreLinkContractSuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	/// <summary>One relationship a store owns (§4.5's table).</summary>
	public enum StoreLink
	{
		/// <summary>Not a link.</summary>
		None = 0,

		/// <summary>A token's application.</summary>
		TokenApplication = 1,

		/// <summary>A token's authorization.</summary>
		TokenAuthorization = 2,

		/// <summary>A token's session.</summary>
		TokenSession = 3,

		/// <summary>An authorization's application.</summary>
		AuthorizationApplication = 4,

		/// <summary>A session's application.</summary>
		SessionApplication = 5,

		/// <summary>A session's authorization.</summary>
		SessionAuthorization = 6
	}

	/// <summary>What a setter call does to a link.</summary>
	public enum LinkWrite
	{
		/// <summary>Not a write.</summary>
		None = 0,

		/// <summary>An absent link becomes one.</summary>
		Set = 1,

		/// <summary>A link moves to another principal.</summary>
		Replace = 2,

		/// <summary>A link becomes absent.</summary>
		Clear = 3
	}

	/// <summary>How the entity the setter is handed was read.</summary>
	public enum EntityTracking
	{
		/// <summary>Not a mode.</summary>
		None = 0,

		/// <summary>By the store's <c>FindByIdAsync</c>: detached under the platform's NoTracking default.</summary>
		Detached = 1,

		/// <summary>Tracked by the store's context, its navigation not loaded.</summary>
		Tracked = 2,

		/// <summary>Tracked by the store's context, its navigation loaded to the principal it points at.</summary>
		TrackedWithNavigationLoaded = 3
	}

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>Every link, every write, every way of reading the entity.</summary>
	public static TheoryData<StoreLink, LinkWrite, EntityTracking> RoundTrips
	{
		get
		{
			TheoryData<StoreLink, LinkWrite, EntityTracking> data = [];
			foreach (var link in Enum.GetValues<StoreLink>().Where(static link => link is not StoreLink.None))
				foreach (var write in Enum.GetValues<LinkWrite>().Where(static write => write is not LinkWrite.None))
					foreach (var tracking in Enum.GetValues<EntityTracking>().Where(static tracking => tracking is not EntityTracking.None))
						data.Add(link, write, tracking);
			return data;
		}
	}

	/// <summary>Every link of §4.5's table.</summary>
	public static TheoryData<StoreLink> EveryLink =>
		[.. Enum.GetValues<StoreLink>().Where(static link => link is not StoreLink.None)];

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	// §4.5 fact 1: a fresh scope's entities come back detached with their navigations unloaded, and still answer every
	// persisted link.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Detached_entities_return_persisted_links()
	{
		fixture.SkipUnlessAvailable();
		var graph = await SeedGraphAsync();
		var token = await SeedAsync(new NorseOpenIddictToken
		{
			Id = Guid.CreateVersion7(),
			ApplicationId = graph.Applications[0],
			AuthorizationId = graph.Authorizations[0],
			SessionId = graph.Sessions[0]
		});

		using var scope = fixture.CreateOwnedScope();
		var services = scope.ServiceProvider;
		var context = services.GetRequiredService<NorseIdentityDbContext>();
		var tokens = services.GetRequiredService<IOpenIddictTokenStore<NorseOpenIddictToken>>();
		var authorizations = services.GetRequiredService<IOpenIddictAuthorizationStore<NorseOpenIddictAuthorization>>();
		var sessions = services.GetRequiredService<IOpenIddictSessionStore<NorseOpenIddictSession>>();

		var readToken = (await tokens.FindByIdAsync(token.ToString(), Cancellation)).ShouldNotBeNull();
		var readAuthorization = (await authorizations.FindByIdAsync(graph.Authorizations[0].ToString(), Cancellation)).ShouldNotBeNull();
		var readSession = (await sessions.FindByIdAsync(graph.Sessions[0].ToString(), Cancellation)).ShouldNotBeNull();
		// The premise the contract exists for: detached, nothing loaded.
		context.Entry(readToken).State.ShouldBe(EntityState.Detached);
		context.Entry(readAuthorization).State.ShouldBe(EntityState.Detached);
		context.Entry(readSession).State.ShouldBe(EntityState.Detached);
		readToken.Application.ShouldBeNull();
		readToken.Authorization.ShouldBeNull();
		readToken.Session.ShouldBeNull();
		readAuthorization.Application.ShouldBeNull();
		readSession.Application.ShouldBeNull();
		readSession.Authorization.ShouldBeNull();

		(await tokens.GetApplicationIdAsync(readToken, Cancellation)).ShouldBe(graph.Applications[0].ToString());
		(await tokens.GetAuthorizationIdAsync(readToken, Cancellation)).ShouldBe(graph.Authorizations[0].ToString());
		(await tokens.GetSessionIdAsync(readToken, Cancellation)).ShouldBe(graph.Sessions[0].ToString());
		(await authorizations.GetApplicationIdAsync(readAuthorization, Cancellation)).ShouldBe(graph.Applications[0].ToString());
		(await sessions.GetApplicationIdAsync(readSession, Cancellation)).ShouldBe(graph.Applications[0].ToString());
		(await sessions.GetAuthorizationIdAsync(readSession, Cancellation)).ShouldBe(graph.Authorizations[0].ToString());
	}

	// §4.5 fact 1: an absent link stays absent.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Null_links_return_null()
	{
		fixture.SkipUnlessAvailable();
		var token = await SeedAsync(new NorseOpenIddictToken { Id = Guid.CreateVersion7() });
		var authorization = await SeedAsync(new NorseOpenIddictAuthorization { Id = Guid.CreateVersion7() });
		var session = await SeedAsync(new NorseOpenIddictSession { Id = Guid.CreateVersion7() });

		using var scope = fixture.CreateOwnedScope();
		var services = scope.ServiceProvider;
		var tokens = services.GetRequiredService<IOpenIddictTokenStore<NorseOpenIddictToken>>();
		var authorizations = services.GetRequiredService<IOpenIddictAuthorizationStore<NorseOpenIddictAuthorization>>();
		var sessions = services.GetRequiredService<IOpenIddictSessionStore<NorseOpenIddictSession>>();
		var readToken = (await tokens.FindByIdAsync(token.ToString(), Cancellation)).ShouldNotBeNull();
		var readAuthorization = (await authorizations.FindByIdAsync(authorization.ToString(), Cancellation)).ShouldNotBeNull();
		var readSession = (await sessions.FindByIdAsync(session.ToString(), Cancellation)).ShouldNotBeNull();

		(await tokens.GetApplicationIdAsync(readToken, Cancellation)).ShouldBeNull();
		(await tokens.GetAuthorizationIdAsync(readToken, Cancellation)).ShouldBeNull();
		(await tokens.GetSessionIdAsync(readToken, Cancellation)).ShouldBeNull();
		(await authorizations.GetApplicationIdAsync(readAuthorization, Cancellation)).ShouldBeNull();
		(await sessions.GetApplicationIdAsync(readSession, Cancellation)).ShouldBeNull();
		(await sessions.GetAuthorizationIdAsync(readSession, Cancellation)).ShouldBeNull();
	}

	// §4.5 fact 1: a getter never loads the relationship, tracked or not; the command interceptor sees nothing.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Getters_issue_no_query()
	{
		fixture.SkipUnlessAvailable();
		var graph = await SeedGraphAsync();
		var token = await SeedAsync(new NorseOpenIddictToken
		{
			Id = Guid.CreateVersion7(),
			ApplicationId = graph.Applications[0],
			AuthorizationId = graph.Authorizations[0],
			SessionId = graph.Sessions[0]
		});

		using var scope = fixture.CreateOwnedScope();
		CommandCounter counter = new();
		await using var context = fixture.CreateContext(counter);
		var tokens = StoreOn<IOpenIddictTokenStore<NorseOpenIddictToken>>(scope.ServiceProvider, context);
		var authorizations = StoreOn<IOpenIddictAuthorizationStore<NorseOpenIddictAuthorization>>(scope.ServiceProvider, context);
		var sessions = StoreOn<IOpenIddictSessionStore<NorseOpenIddictSession>>(scope.ServiceProvider, context);
		var detachedToken = (await tokens.FindByIdAsync(token.ToString(), Cancellation)).ShouldNotBeNull();
		var detachedAuthorization = (await authorizations.FindByIdAsync(graph.Authorizations[0].ToString(), Cancellation)).ShouldNotBeNull();
		var detachedSession = (await sessions.FindByIdAsync(graph.Sessions[0].ToString(), Cancellation)).ShouldNotBeNull();
		// The tracked token's principals are never tracked, so its navigations stay unloaded.
		var trackedToken = await context.Set<NorseOpenIddictToken>().AsTracking().SingleAsync(entity => entity.Id == token, Cancellation);
		var trackedAuthorization = await context.Set<NorseOpenIddictAuthorization>().AsTracking()
			.SingleAsync(entity => entity.Id == graph.Authorizations[1], Cancellation);
		var trackedSession = await context.Set<NorseOpenIddictSession>().AsTracking()
			.SingleAsync(entity => entity.Id == graph.Sessions[1], Cancellation);
		counter.Reset();

		string?[] answers =
		[
			await tokens.GetApplicationIdAsync(detachedToken, Cancellation),
			await tokens.GetAuthorizationIdAsync(detachedToken, Cancellation),
			await tokens.GetSessionIdAsync(detachedToken, Cancellation),
			await tokens.GetApplicationIdAsync(trackedToken, Cancellation),
			await tokens.GetAuthorizationIdAsync(trackedToken, Cancellation),
			await tokens.GetSessionIdAsync(trackedToken, Cancellation),
			await authorizations.GetApplicationIdAsync(detachedAuthorization, Cancellation),
			await authorizations.GetApplicationIdAsync(trackedAuthorization, Cancellation),
			await sessions.GetApplicationIdAsync(detachedSession, Cancellation),
			await sessions.GetAuthorizationIdAsync(detachedSession, Cancellation),
			await sessions.GetApplicationIdAsync(trackedSession, Cancellation),
			await sessions.GetAuthorizationIdAsync(trackedSession, Cancellation)
		];

		counter.Commands.ShouldBe(0);
		string[] a = [.. graph.Applications.Select(static id => id.ToString())],
			z = [.. graph.Authorizations.Select(static id => id.ToString())],
			s = [.. graph.Sessions.Select(static id => id.ToString())];
		answers.ShouldBe([a[0], z[0], s[0], a[0], z[0], s[0], a[0], a[1], a[0], z[0], a[1], z[1]]);
	}

	// §4.5 fact 2: the getter agrees with the setter immediately, after UpdateAsync and after a fresh-scope reload, and
	// the navigation never disagrees with the scalar on the way.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(RoundTrips))]
	protected Task Set_replace_and_clear_round_trip(StoreLink link, LinkWrite write, EntityTracking tracking)
	{
		fixture.SkipUnlessAvailable();
		return link switch
		{
			StoreLink.TokenApplication => RoundTripAsync(Links.TokenApplication, write, tracking),
			StoreLink.TokenAuthorization => RoundTripAsync(Links.TokenAuthorization, write, tracking),
			StoreLink.TokenSession => RoundTripAsync(Links.TokenSession, write, tracking),
			StoreLink.AuthorizationApplication => RoundTripAsync(Links.AuthorizationApplication, write, tracking),
			StoreLink.SessionApplication => RoundTripAsync(Links.SessionApplication, write, tracking),
			StoreLink.SessionAuthorization => RoundTripAsync(Links.SessionAuthorization, write, tracking),
			_ => throw new ArgumentOutOfRangeException(nameof(link), link, null)
		};
	}

	// §4.5 fact 2: creation through the real OpenIddict managers, each in a scope of its own, persists every link.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Managers_create_with_links()
	{
		fixture.SkipUnlessAvailable();
		var application = await SeedAsync(new NorseOpenIddictApplication
		{
			Id = Guid.CreateVersion7(),
			ClientId = $"links-{Guid.NewGuid():N}"
		});
		var subject = $"links-{Guid.NewGuid():N}";
		var now = DateTimeOffset.UtcNow;

		string authorization, session, token;
		using (var scope = fixture.CreateOwnedScope())
		{
			var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();
			authorization = (await manager.GetIdAsync(await manager.CreateAsync(new OpenIddictAuthorizationDescriptor
			{
				ApplicationId = application.ToString(),
				CreationDate = now,
				Status = Statuses.Valid,
				Subject = subject,
				Type = AuthorizationTypes.AdHoc
			}, Cancellation), Cancellation)).ShouldNotBeNull();
		}

		using (var scope = fixture.CreateOwnedScope())
		{
			var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictSessionManager>();
			session = (await manager.GetIdAsync(await manager.CreateAsync(new OpenIddictSessionDescriptor
			{
				ApplicationId = application.ToString(),
				AuthorizationId = authorization,
				CreationDate = now,
				LoginId = Guid.NewGuid().ToString("N"),
				Status = Statuses.Valid,
				Subject = subject
			}, Cancellation), Cancellation)).ShouldNotBeNull();
		}

		using (var scope = fixture.CreateOwnedScope())
		{
			var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
			token = (await manager.GetIdAsync(await manager.CreateAsync(new OpenIddictTokenDescriptor
			{
				ApplicationId = application.ToString(),
				AuthorizationId = authorization,
				SessionId = session,
				CreationDate = now,
				ExpirationDate = now.AddDays(14),
				Status = Statuses.Valid,
				Subject = subject,
				Type = TokenTypeIdentifiers.RefreshToken
			}, Cancellation), Cancellation)).ShouldNotBeNull();
		}

		var (context, _) = await fixture.CreateScopeAsync();
		var storedToken = await context.Set<NorseOpenIddictToken>()
			.Where(entity => entity.Id == Guid.Parse(token))
			.Select(static entity => new TokenLinks(entity.ApplicationId, entity.AuthorizationId, entity.SessionId))
			.SingleAsync(Cancellation);
		storedToken.ShouldBe(new(application, Guid.Parse(authorization), Guid.Parse(session)));
		(await context.Set<NorseOpenIddictAuthorization>()
				.Where(entity => entity.Id == Guid.Parse(authorization))
				.Select(static entity => entity.ApplicationId)
				.SingleAsync(Cancellation))
			.ShouldBe(application);
		(await context.Set<NorseOpenIddictSession>()
				.Where(entity => entity.Id == Guid.Parse(session))
				.Select(static entity => new SessionLinks(entity.ApplicationId, entity.AuthorizationId))
				.SingleAsync(Cancellation))
			.ShouldBe(new(application, Guid.Parse(authorization)));

		// And the managers read them back from a fresh scope, through their entity caches.
		using var reader = fixture.CreateOwnedScope();
		var tokens = reader.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
		var read = (await tokens.FindByIdAsync(token, Cancellation)).ShouldNotBeNull();
		(await tokens.GetApplicationIdAsync(read, Cancellation)).ShouldBe(application.ToString());
		(await tokens.GetAuthorizationIdAsync(read, Cancellation)).ShouldBe(authorization);
		(await tokens.GetSessionIdAsync(read, Cancellation)).ShouldBe(session);
	}

	// §4.5 fact 5: the production composition registers the Norse stores, scoped, under OpenIddict's default entity
	// cache, and they answer the persisted link in each of two request scopes, a cached re-read included.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Production_di_resolves_the_norse_stores()
	{
		fixture.SkipUnlessAvailable();
		var graph = await SeedGraphAsync();
		var token = await SeedAsync(new NorseOpenIddictToken
		{
			Id = Guid.CreateVersion7(),
			ApplicationId = graph.Applications[0],
			AuthorizationId = graph.Authorizations[0],
			SessionId = graph.Sessions[0]
		});

		using var certificate = IdentityTestCertificate.CreateFresh();
		await using var app = fixture.Compose(certificate).Build();
		var cache = app.Services.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;
		cache.DisableEntityCaching.ShouldBeFalse();
		cache.EntityCacheLimit.ShouldBe(new OpenIddictCoreOptions().EntityCacheLimit);

		List<object> seen = [];
		foreach (var _ in Enumerable.Range(0, 2))
		{
			await using var scope = app.Services.CreateAsyncScope();
			var services = scope.ServiceProvider;
			object[] stores =
			[
				services.GetRequiredService<IOpenIddictTokenStore<NorseOpenIddictToken>>(),
				services.GetRequiredService<IOpenIddictAuthorizationStore<NorseOpenIddictAuthorization>>(),
				services.GetRequiredService<IOpenIddictSessionStore<NorseOpenIddictSession>>()
			];
			stores.Select(static store => store.GetType().FullName).ShouldBe([
				"Norse.Identity.EntityFramework.NorseOpenIddictTokenStore",
				"Norse.Identity.EntityFramework.NorseOpenIddictAuthorizationStore",
				"Norse.Identity.EntityFramework.NorseOpenIddictSessionStore"
			]);
			// Scoped: the same instance within a scope, a new one in the next.
			services.GetRequiredService<IOpenIddictTokenStore<NorseOpenIddictToken>>().ShouldBeSameAs(stores[0]);
			stores.ShouldAllBe(store => !seen.Contains(store));
			seen.AddRange(stores);

			var manager = services.GetRequiredService<IOpenIddictTokenManager>();
			var first = (await manager.FindByIdAsync(token.ToString(), Cancellation)).ShouldNotBeNull();
			var cached = (await manager.FindByIdAsync(token.ToString(), Cancellation)).ShouldNotBeNull();
			(await manager.GetAuthorizationIdAsync(first, Cancellation)).ShouldBe(graph.Authorizations[0].ToString());
			(await manager.GetAuthorizationIdAsync(cached, Cancellation)).ShouldBe(graph.Authorizations[0].ToString());
			(await manager.GetSessionIdAsync(cached, Cancellation)).ShouldBe(graph.Sessions[0].ToString());
		}
	}

	// The setter never manufactures a principal (§4.5), so a write naming one that does not exist is the database's to
	// refuse: the foreign key does, at save, on every link (Tasks 0.2 and 0.3 review, carried to Task 4.8).
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(EveryLink))]
	protected Task A_write_naming_an_unknown_link_is_refused_at_save(StoreLink link)
	{
		fixture.SkipUnlessAvailable();
		return link switch
		{
			StoreLink.TokenApplication => UnknownLinkAsync(Links.TokenApplication),
			StoreLink.TokenAuthorization => UnknownLinkAsync(Links.TokenAuthorization),
			StoreLink.TokenSession => UnknownLinkAsync(Links.TokenSession),
			StoreLink.AuthorizationApplication => UnknownLinkAsync(Links.AuthorizationApplication),
			StoreLink.SessionApplication => UnknownLinkAsync(Links.SessionApplication),
			StoreLink.SessionAuthorization => UnknownLinkAsync(Links.SessionAuthorization),
			_ => throw new ArgumentOutOfRangeException(nameof(link), link, null)
		};
	}

	async Task UnknownLinkAsync<TEntity>(LinkProbe<TEntity> probe)
		where TEntity : class
	{
		var id = Guid.CreateVersion7();
		await SeedAsync(probe.Create(id, null));

		using (var scope = fixture.CreateOwnedScope())
		{
			var services = scope.ServiceProvider;
			var entity = (await probe.FindAsync(services, id, Cancellation)).ShouldNotBeNull();
			await probe.SetAsync(services, entity, Guid.CreateVersion7().ToString(), Cancellation);

			var refused = await Should.ThrowAsync<DbUpdateException>(async () =>
				await probe.UpdateAsync(services, entity, Cancellation));
			refused.InnerException.ShouldBeAssignableTo<DbException>();
		}

		var (context, _) = await fixture.CreateScopeAsync();
		(await context.Set<TEntity>()
				.Where(entity => EF.Property<Guid>(entity, "Id") == id)
				.Select(probe.Scalar)
				.SingleAsync(Cancellation))
			.ShouldBeNull("the refused write left the row as it was");
	}

	async Task RoundTripAsync<TEntity>(LinkProbe<TEntity> probe, LinkWrite write, EntityTracking tracking)
		where TEntity : class
	{
		var graph = await SeedGraphAsync();
		var pool = probe.Principals(graph);
		var (initial, expected) = write switch
		{
			LinkWrite.Set => ((Guid?)null, (Guid?)pool[0]),
			LinkWrite.Replace => (pool[0], pool[1]),
			LinkWrite.Clear => (pool[0], null),
			_ => throw new ArgumentOutOfRangeException(nameof(write), write, null)
		};
		var id = Guid.CreateVersion7();
		await SeedAsync(probe.Create(id, initial));

		using (var scope = fixture.CreateOwnedScope())
		{
			var services = scope.ServiceProvider;
			var context = services.GetRequiredService<NorseIdentityDbContext>();
			var entity = tracking switch
			{
				EntityTracking.Detached => (await probe.FindAsync(services, id, Cancellation)).ShouldNotBeNull(),
				EntityTracking.Tracked => await context.Set<TEntity>().AsTracking()
					.SingleAsync(entity => EF.Property<Guid>(entity, "Id") == id, Cancellation),
				EntityTracking.TrackedWithNavigationLoaded => await context.Set<TEntity>().AsTracking()
					.Include(probe.Navigation)
					.SingleAsync(entity => EF.Property<Guid>(entity, "Id") == id, Cancellation),
				_ => throw new ArgumentOutOfRangeException(nameof(tracking), tracking, null)
			};
			(context.Entry(entity).State is EntityState.Detached).ShouldBe(tracking is EntityTracking.Detached);
			if (tracking is EntityTracking.TrackedWithNavigationLoaded && initial.HasValue)
				probe.NavigationId(entity).ShouldBe(initial);

			await probe.SetAsync(services, entity, expected?.ToString(), Cancellation);
			AssertInStep(probe, entity, expected, "after the setter");
			(await probe.GetAsync(services, entity, Cancellation)).ShouldBe(expected?.ToString(), "after the setter");

			await probe.UpdateAsync(services, entity, Cancellation);
			AssertInStep(probe, entity, expected, "after UpdateAsync");
			(await probe.GetAsync(services, entity, Cancellation)).ShouldBe(expected?.ToString(), "after UpdateAsync");
		}

		using (var scope = fixture.CreateOwnedScope())
		{
			var services = scope.ServiceProvider;
			var reloaded = (await probe.FindAsync(services, id, Cancellation)).ShouldNotBeNull();
			(await probe.GetAsync(services, reloaded, Cancellation)).ShouldBe(expected?.ToString(), "after a fresh-scope reload");
			(await services.GetRequiredService<NorseIdentityDbContext>()
					.Set<TEntity>()
					.Where(entity => EF.Property<Guid>(entity, "Id") == id)
					.Select(probe.Scalar)
					.SingleAsync(Cancellation))
				.ShouldBe(expected, "in the row");
		}
	}

	/// <summary>The scalar reads the expected link, and the navigation, when present, points at the same principal.</summary>
	static void AssertInStep<TEntity>(LinkProbe<TEntity> probe, TEntity entity, Guid? expected, string when)
		where TEntity : class
	{
		probe.ScalarOf(entity).ShouldBe(expected, $"the scalar {when}");
		if (probe.NavigationId(entity) is { } navigation)
			navigation.ShouldBe(expected.ShouldNotBeNull($"a navigation is loaded {when}, but the link is clear"),
				$"the navigation {when}");
	}

	/// <summary>Two applications, an authorization under each, and a session under each authorization.</summary>
	async Task<Graph> SeedGraphAsync()
	{
		Guid[] applications = [Guid.CreateVersion7(), Guid.CreateVersion7()],
			authorizations = [Guid.CreateVersion7(), Guid.CreateVersion7()],
			sessions = [Guid.CreateVersion7(), Guid.CreateVersion7()];
		var (context, _) = await fixture.CreateScopeAsync();
		foreach (var index in Enumerable.Range(0, 2))
		{
			context.Add(new NorseOpenIddictApplication { Id = applications[index], ClientId = $"links-{Guid.NewGuid():N}" });
			context.Add(new NorseOpenIddictAuthorization
			{
				Id = authorizations[index],
				ApplicationId = applications[index],
				Status = Statuses.Valid,
				Subject = $"links-{Guid.NewGuid():N}",
				Type = AuthorizationTypes.AdHoc
			});
			context.Add(new NorseOpenIddictSession
			{
				Id = sessions[index],
				ApplicationId = applications[index],
				AuthorizationId = authorizations[index],
				Status = Statuses.Valid
			});
		}

		await context.SaveChangesAsync(Cancellation);
		return new(applications, authorizations, sessions);
	}

	/// <summary>Inserts <paramref name="entity" /> on a context of its own and answers its id.</summary>
	async Task<Guid> SeedAsync<TEntity>(TEntity entity) where TEntity : class
	{
		var (context, _) = await fixture.CreateScopeAsync();
		context.Add(entity);
		await context.SaveChangesAsync(Cancellation);
		return context.Entry(entity).Property<Guid>("Id").CurrentValue;
	}

	/// <summary>The store the scope's composition registers as <typeparamref name="TStore" />, rebuilt over <paramref name="context" />.</summary>
	static TStore StoreOn<TStore>(IServiceProvider services, NorseIdentityDbContext context) where TStore : notnull =>
		(TStore)ActivatorUtilities.CreateInstance(services, services.GetRequiredService<TStore>().GetType(),
			new OpenIddictEntityFrameworkCoreContext<NorseIdentityDbContext>(context));

	/// <summary>The principals a round trip draws on.</summary>
	/// <param name="Applications">Two applications.</param>
	/// <param name="Authorizations">An authorization under each application.</param>
	/// <param name="Sessions">A session under each authorization.</param>
	sealed record Graph(Guid[] Applications, Guid[] Authorizations, Guid[] Sessions);

	sealed record TokenLinks(Guid? Application, Guid? Authorization, Guid? Session);

	sealed record SessionLinks(Guid? Application, Guid? Authorization);

	/// <summary>One link, as the round trip drives it: the entity it lives on, its store's accessors, its scalar and its navigation.</summary>
	sealed record LinkProbe<TEntity>(
		Func<Guid, Guid?, TEntity> Create,
		Func<Graph, Guid[]> Principals,
		Func<IServiceProvider, Guid, CancellationToken, ValueTask<TEntity?>> FindAsync,
		Func<IServiceProvider, TEntity, CancellationToken, ValueTask<string?>> GetAsync,
		Func<IServiceProvider, TEntity, string?, CancellationToken, ValueTask> SetAsync,
		Func<IServiceProvider, TEntity, CancellationToken, ValueTask> UpdateAsync,
		Expression<Func<TEntity, Guid?>> Scalar,
		Func<TEntity, Guid?> NavigationId,
		string Navigation)
		where TEntity : class
	{
		readonly Func<TEntity, Guid?> _scalar = Scalar.Compile();

		public Guid? ScalarOf(TEntity entity) =>
			_scalar(entity);
	}

	/// <summary>The six links of §4.5's table.</summary>
	static class Links
	{
		public static LinkProbe<NorseOpenIddictToken> TokenApplication { get; } = Token(
			static (id, link) => new() { Id = id, ApplicationId = link },
			static graph => graph.Applications,
			static (store, token, cancellationToken) => store.GetApplicationIdAsync(token, cancellationToken),
			static (store, token, link, cancellationToken) => store.SetApplicationIdAsync(token, link, cancellationToken),
			static token => token.ApplicationId,
			static token => token.Application?.Id,
			nameof(NorseOpenIddictToken.Application));

		public static LinkProbe<NorseOpenIddictToken> TokenAuthorization { get; } = Token(
			static (id, link) => new() { Id = id, AuthorizationId = link },
			static graph => graph.Authorizations,
			static (store, token, cancellationToken) => store.GetAuthorizationIdAsync(token, cancellationToken),
			static (store, token, link, cancellationToken) => store.SetAuthorizationIdAsync(token, link, cancellationToken),
			static token => token.AuthorizationId,
			static token => token.Authorization?.Id,
			nameof(NorseOpenIddictToken.Authorization));

		public static LinkProbe<NorseOpenIddictToken> TokenSession { get; } = Token(
			static (id, link) => new() { Id = id, SessionId = link },
			static graph => graph.Sessions,
			static (store, token, cancellationToken) => store.GetSessionIdAsync(token, cancellationToken),
			static (store, token, link, cancellationToken) => store.SetSessionIdAsync(token, link, cancellationToken),
			static token => token.SessionId,
			static token => token.Session?.Id,
			nameof(NorseOpenIddictToken.Session));

		public static LinkProbe<NorseOpenIddictAuthorization> AuthorizationApplication { get; } = new(
			static (id, link) => new() { Id = id, ApplicationId = link },
			static graph => graph.Applications,
			static (services, id, cancellationToken) => Authorizations(services).FindByIdAsync(id.ToString(), cancellationToken),
			static (services, authorization, cancellationToken) =>
				Authorizations(services).GetApplicationIdAsync(authorization, cancellationToken),
			static (services, authorization, link, cancellationToken) =>
				Authorizations(services).SetApplicationIdAsync(authorization, link, cancellationToken),
			static (services, authorization, cancellationToken) => Authorizations(services).UpdateAsync(authorization, cancellationToken),
			static authorization => authorization.ApplicationId,
			static authorization => authorization.Application?.Id,
			nameof(NorseOpenIddictAuthorization.Application));

		public static LinkProbe<NorseOpenIddictSession> SessionApplication { get; } = Session(
			static (id, link) => new() { Id = id, ApplicationId = link },
			static graph => graph.Applications,
			static (store, session, cancellationToken) => store.GetApplicationIdAsync(session, cancellationToken),
			static (store, session, link, cancellationToken) => store.SetApplicationIdAsync(session, link, cancellationToken),
			static session => session.ApplicationId,
			static session => session.Application?.Id,
			nameof(NorseOpenIddictSession.Application));

		public static LinkProbe<NorseOpenIddictSession> SessionAuthorization { get; } = Session(
			static (id, link) => new() { Id = id, AuthorizationId = link },
			static graph => graph.Authorizations,
			static (store, session, cancellationToken) => store.GetAuthorizationIdAsync(session, cancellationToken),
			static (store, session, link, cancellationToken) => store.SetAuthorizationIdAsync(session, link, cancellationToken),
			static session => session.AuthorizationId,
			static session => session.Authorization?.Id,
			nameof(NorseOpenIddictSession.Authorization));

		static IOpenIddictAuthorizationStore<NorseOpenIddictAuthorization> Authorizations(IServiceProvider services) =>
			services.GetRequiredService<IOpenIddictAuthorizationStore<NorseOpenIddictAuthorization>>();

		static LinkProbe<NorseOpenIddictToken> Token(
			Func<Guid, Guid?, NorseOpenIddictToken> create,
			Func<Graph, Guid[]> principals,
			Func<IOpenIddictTokenStore<NorseOpenIddictToken>, NorseOpenIddictToken, CancellationToken, ValueTask<string?>> get,
			Func<IOpenIddictTokenStore<NorseOpenIddictToken>, NorseOpenIddictToken, string?, CancellationToken, ValueTask> set,
			Expression<Func<NorseOpenIddictToken, Guid?>> scalar,
			Func<NorseOpenIddictToken, Guid?> navigationId,
			string navigation) =>
			new(create, principals,
				(services, id, cancellationToken) => Tokens(services).FindByIdAsync(id.ToString(), cancellationToken),
				(services, token, cancellationToken) => get(Tokens(services), token, cancellationToken),
				(services, token, link, cancellationToken) => set(Tokens(services), token, link, cancellationToken),
				static (services, token, cancellationToken) => Tokens(services).UpdateAsync(token, cancellationToken),
				scalar, navigationId, navigation);

		static LinkProbe<NorseOpenIddictSession> Session(
			Func<Guid, Guid?, NorseOpenIddictSession> create,
			Func<Graph, Guid[]> principals,
			Func<IOpenIddictSessionStore<NorseOpenIddictSession>, NorseOpenIddictSession, CancellationToken, ValueTask<string?>> get,
			Func<IOpenIddictSessionStore<NorseOpenIddictSession>, NorseOpenIddictSession, string?, CancellationToken, ValueTask> set,
			Expression<Func<NorseOpenIddictSession, Guid?>> scalar,
			Func<NorseOpenIddictSession, Guid?> navigationId,
			string navigation) =>
			new(create, principals,
				(services, id, cancellationToken) => Sessions(services).FindByIdAsync(id.ToString(), cancellationToken),
				(services, session, cancellationToken) => get(Sessions(services), session, cancellationToken),
				(services, session, link, cancellationToken) => set(Sessions(services), session, link, cancellationToken),
				static (services, session, cancellationToken) => Sessions(services).UpdateAsync(session, cancellationToken),
				scalar, navigationId, navigation);

		static IOpenIddictTokenStore<NorseOpenIddictToken> Tokens(IServiceProvider services) =>
			services.GetRequiredService<IOpenIddictTokenStore<NorseOpenIddictToken>>();

		static IOpenIddictSessionStore<NorseOpenIddictSession> Sessions(IServiceProvider services) =>
			services.GetRequiredService<IOpenIddictSessionStore<NorseOpenIddictSession>>();
	}

	/// <summary>Counts every command a context sends, so a fact can prove a call sent none.</summary>
	sealed class CommandCounter : DbCommandInterceptor
	{
		int _commands;

		/// <summary>How many commands were sent since the last <see cref="Reset" />.</summary>
		public int Commands => Volatile.Read(ref _commands);

		/// <summary>Starts the count again.</summary>
		public void Reset() =>
			Volatile.Write(ref _commands, 0);

		public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command, CommandEventData eventData,
			InterceptionResult<DbDataReader> result)
		{
			Interlocked.Increment(ref _commands);
			return result;
		}

		public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
			CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
		{
			Interlocked.Increment(ref _commands);
			return ValueTask.FromResult(result);
		}

		public override InterceptionResult<object> ScalarExecuting(DbCommand command, CommandEventData eventData,
			InterceptionResult<object> result)
		{
			Interlocked.Increment(ref _commands);
			return result;
		}

		public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(DbCommand command,
			CommandEventData eventData, InterceptionResult<object> result, CancellationToken cancellationToken = default)
		{
			Interlocked.Increment(ref _commands);
			return ValueTask.FromResult(result);
		}

		public override InterceptionResult<int> NonQueryExecuting(DbCommand command, CommandEventData eventData,
			InterceptionResult<int> result)
		{
			Interlocked.Increment(ref _commands);
			return result;
		}

		public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
			CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
		{
			Interlocked.Increment(ref _commands);
			return ValueTask.FromResult(result);
		}
	}
}
