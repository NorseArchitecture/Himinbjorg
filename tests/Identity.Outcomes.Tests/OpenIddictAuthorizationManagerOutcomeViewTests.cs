using Norse.Abstractions.Contracts;
using Norse.Primitives;
using OpenIddict.Abstractions;

namespace Norse.Identity.Outcomes.Tests;

/// <summary><c>authorizationManager.Outcome</c>, one fact per view method, against a substituted manager.</summary>
public sealed class OpenIddictAuthorizationManagerOutcomeViewTests
{
	readonly IOpenIddictAuthorizationManager _manager = Substitute.For<IOpenIddictAuthorizationManager>();
	readonly object _authorization = new();

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task CreateAsync_answers_the_created_authorization_or_a_Fault()
	{
		OpenIddictAuthorizationDescriptor valid = new() { Subject = "valid" }, invalid = new() { Subject = "invalid" };
		_manager.CreateAsync(valid, Arg.Any<CancellationToken>()).Returns(_authorization);
		_manager.CreateAsync(invalid, Arg.Any<CancellationToken>())
			.ThrowsAsync(new OpenIddictExceptions.ValidationException("ID2000"));

		Value(await _manager.Outcome.CreateAsync(valid, Cancellation)).ShouldBeSameAs(_authorization);
		Category(await _manager.Outcome.CreateAsync(invalid, Cancellation)).ShouldBe(ErrorCategory.Fault);
	}

	[Fact]
	async Task GetIdAsync_answers_the_id_or_NotFound()
	{
		object anonymous = new();
		_manager.GetIdAsync(_authorization, Arg.Any<CancellationToken>()).Returns("the-id");
		_manager.GetIdAsync(anonymous, Arg.Any<CancellationToken>()).Returns((string?)null);

		Value(await _manager.Outcome.GetIdAsync(_authorization, Cancellation)).ShouldBe("the-id");
		Category(await _manager.Outcome.GetIdAsync(anonymous, Cancellation)).ShouldBe(ErrorCategory.NotFound);
	}

	[Fact]
	async Task PruneAsync_answers_the_pruned_count_or_a_Fault()
	{
		DateTimeOffset threshold = new(2026, 10, 16, 0, 0, 0, TimeSpan.Zero), refused = threshold.AddDays(1);
		_manager.PruneAsync(threshold, Arg.Any<CancellationToken>()).Returns(5L);
		_manager.PruneAsync(refused, Arg.Any<CancellationToken>())
			.ThrowsAsync(new OpenIddictExceptions.ValidationException("ID2000"));

		Value(await _manager.Outcome.PruneAsync(threshold, Cancellation)).ShouldBe(5);
		Category(await _manager.Outcome.PruneAsync(refused, Cancellation)).ShouldBe(ErrorCategory.Fault);
	}

	static T Value<T>(Outcome<T> outcome)
		where T : notnull
	{
		outcome.TryGetValue(out Success<T> success).ShouldBeTrue();
		return success.Value;
	}

	static ErrorCategory Category<T>(Outcome<T> outcome)
		where T : notnull
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem.Category;
	}
}
