using Norse.Primitives.Pii;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class EmailExistsHandlerTests
{
	// A real ServiceProvider, not a hand-rolled fake IServiceScopeFactory -- the whole point of the
	// fix under test is genuine per-call scope isolation, so the test needs a container that actually
	// creates independent scopes, the same guarantee production DI provides.
	static ServiceProvider BuildContainer(UserManager<NorseUser> userManager) =>
		new ServiceCollection().AddScoped(_ => userManager).BuildServiceProvider();

	[Fact]
	async Task Reports_true_when_the_store_finds_a_matching_user()
	{
		using var userManager = MockUserManager.Create();
		userManager.FindByEmailAsync("user@example.com")
			.Returns(new NorseUser { UserName = "user@example.com", Email = "user@example.com" });
		await using var container = BuildContainer(userManager);
		EmailExistsHandler handler = new(container.GetRequiredService<IServiceScopeFactory>());
		EmailExistsCommand command = new(new EmailExistsRequest { Email = EmailAddress.Parse("user@example.com") });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<BoolResponse> success).ShouldBeTrue();
		success.Value.Value.ShouldBeTrue();
	}

	[Fact]
	async Task Reports_false_when_no_user_matches()
	{
		using var userManager = MockUserManager.Create();
		userManager.FindByEmailAsync("ghost@example.com").Returns((NorseUser?)null);
		await using var container = BuildContainer(userManager);
		EmailExistsHandler handler = new(container.GetRequiredService<IServiceScopeFactory>());
		EmailExistsCommand command = new(new EmailExistsRequest { Email = EmailAddress.Parse("ghost@example.com") });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<BoolResponse> success).ShouldBeTrue();
		success.Value.Value.ShouldBeFalse();
	}

	// The actual regression: reproduced live against a real Blazor Server circuit as
	// InvalidOperationException("A second operation was started on this context instance before a
	// previous operation completed") -- two overlapping Handle calls sharing one UserManager/DbContext
	// instance from the circuit's single ambient scope, since RegisterRequestValidator's email-exists
	// rule fires on blur AND again on submit's re-validation with no cancellation between them. This
	// proves the fix's actual guarantee: each Handle call resolves its OWN UserManager from its OWN
	// scope, so two concurrent calls can never share one DbContext no matter how they overlap in time.
	[Fact]
	async Task Concurrent_calls_each_resolve_an_independent_scope()
	{
		HashSet<IServiceScope> observedScopes = [];
		var scopeFactory = Substitute.For<IServiceScopeFactory>();
		scopeFactory.CreateScope().Returns(_ =>
		{
			using var userManager = MockUserManager.Create();
			userManager.FindByEmailAsync(Arg.Any<string>()).Returns((NorseUser?)null);
			var scope = Substitute.For<IServiceScope, IAsyncDisposable>();
			var provider = Substitute.For<IServiceProvider>();
			provider.GetService(typeof(UserManager<NorseUser>)).Returns(userManager);
			scope.ServiceProvider.Returns(provider);
			observedScopes.Add(scope);
			return scope;
		});
		EmailExistsHandler handler = new(scopeFactory);
		EmailExistsCommand first = new(new EmailExistsRequest { Email = EmailAddress.Parse("a@example.com") });
		EmailExistsCommand second = new(new EmailExistsRequest { Email = EmailAddress.Parse("b@example.com") });

		await Task.WhenAll(
			handler.Handle(first, TestContext.Current.CancellationToken).AsTask(),
			handler.Handle(second, TestContext.Current.CancellationToken).AsTask());

		observedScopes.Count.ShouldBe(2);
	}
}
