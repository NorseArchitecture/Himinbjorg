using Norse.Abstractions.Contracts;
using Norse.Primitives;
using OpenIddict.Abstractions;

namespace Norse.Identity.Outcomes.Tests;

/// <summary><c>tokenManager.Outcome</c>, one fact per view method, against a substituted manager.</summary>
public sealed class OpenIddictTokenManagerOutcomeViewTests
{
	readonly IOpenIddictTokenManager _manager = Substitute.For<IOpenIddictTokenManager>();

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task RevokeByAuthorizationIdAsync_answers_the_revoked_count_or_a_Fault()
	{
		_manager.RevokeByAuthorizationIdAsync("valid", Arg.Any<CancellationToken>()).Returns(3L);
		_manager.RevokeByAuthorizationIdAsync("invalid", Arg.Any<CancellationToken>())
			.Returns(static _ => ValueTask.FromException<long>(new OpenIddictExceptions.ValidationException("ID2000")));

		var revoked = await _manager.Outcome.RevokeByAuthorizationIdAsync("valid", Cancellation);
		revoked.TryGetValue(out Success<long> success).ShouldBeTrue();
		success.Value.ShouldBe(3);
		var failed = await _manager.Outcome.RevokeByAuthorizationIdAsync("invalid", Cancellation);
		failed.TryGetValue(out Failed failure).ShouldBeTrue();
		failure.Problem.Category.ShouldBe(ErrorCategory.Fault);
	}

	[Fact]
	async Task PruneAsync_answers_the_pruned_count_or_a_Fault()
	{
		DateTimeOffset threshold = new(2026, 10, 16, 0, 0, 0, TimeSpan.Zero), refused = threshold.AddDays(1);
		_manager.PruneAsync(threshold, Arg.Any<CancellationToken>()).Returns(7L);
		_manager.PruneAsync(refused, Arg.Any<CancellationToken>())
			.Returns(static _ => ValueTask.FromException<long>(new OpenIddictExceptions.ValidationException("ID2000")));

		var pruned = await _manager.Outcome.PruneAsync(threshold, Cancellation);
		pruned.TryGetValue(out Success<long> success).ShouldBeTrue();
		success.Value.ShouldBe(7);
		var failed = await _manager.Outcome.PruneAsync(refused, Cancellation);
		failed.TryGetValue(out Failed failure).ShouldBeTrue();
		failure.Problem.Category.ShouldBe(ErrorCategory.Fault);
	}
}
