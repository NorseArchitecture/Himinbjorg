using Norse.Abstractions.Contracts;
using Norse.Primitives;
using OpenIddict.Abstractions;

namespace Norse.Identity.Outcomes.Tests;

/// <summary><c>sessionManager.Outcome</c>, one fact per view method, against a substituted manager.</summary>
public sealed class OpenIddictSessionManagerOutcomeViewTests
{
	readonly IOpenIddictSessionManager _manager = Substitute.For<IOpenIddictSessionManager>();

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task PruneAsync_answers_the_pruned_count_or_a_Fault()
	{
		DateTimeOffset threshold = new(2026, 10, 16, 0, 0, 0, TimeSpan.Zero), refused = threshold.AddDays(1);
		_manager.PruneAsync(threshold, Arg.Any<CancellationToken>()).Returns(2L);
		_manager.PruneAsync(refused, Arg.Any<CancellationToken>())
			.Returns(static _ => ValueTask.FromException<long>(new OpenIddictExceptions.ValidationException("ID2000")));

		var pruned = await _manager.Outcome.PruneAsync(threshold, Cancellation);
		pruned.TryGetValue(out Success<long> success).ShouldBeTrue();
		success.Value.ShouldBe(2);
		var failed = await _manager.Outcome.PruneAsync(refused, Cancellation);
		failed.TryGetValue(out Failed failure).ShouldBeTrue();
		failure.Problem.Category.ShouldBe(ErrorCategory.Fault);
	}
}
