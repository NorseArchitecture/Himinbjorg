using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class EmailExistsHandlerTests
{
	[Fact]
	async Task Reports_true_when_the_store_finds_a_matching_user()
	{
		using var userManager = MockUserManager.Create();
		userManager.FindByEmailAsync("user@example.com")
			.Returns(new NorseUser { UserName = "user@example.com", Email = "user@example.com" });
		EmailExistsHandler handler = new(userManager);
		EmailExistsCommand command = new(new EmailExistsRequest { Email = "user@example.com" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<BoolResponse> success).ShouldBeTrue();
		success.Value.Value.ShouldBeTrue();
	}

	[Fact]
	async Task Reports_false_when_no_user_matches()
	{
		using var userManager = MockUserManager.Create();
		userManager.FindByEmailAsync("ghost@example.com").Returns((NorseUser?)null);
		EmailExistsHandler handler = new(userManager);
		EmailExistsCommand command = new(new EmailExistsRequest { Email = "ghost@example.com" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<BoolResponse> success).ShouldBeTrue();
		success.Value.Value.ShouldBeFalse();
	}
}
