using System.Collections.Immutable;
using Norse.Abstractions.Contracts;
using Norse.Primitives;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Norse.Identity.Outcomes.Tests;

/// <summary><c>applicationManager.Outcome</c>, one fact per view method, against a substituted manager.</summary>
public sealed class OpenIddictApplicationManagerOutcomeViewTests
{
	readonly IOpenIddictApplicationManager _manager = Substitute.For<IOpenIddictApplicationManager>();
	readonly object _application = new();

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task FindByClientIdAsync_answers_the_application_or_NotFound()
	{
		_manager.FindByClientIdAsync("known", Arg.Any<CancellationToken>()).Returns(_application);
		_manager.FindByClientIdAsync("unknown", Arg.Any<CancellationToken>()).Returns((object?)null);

		Value(await _manager.Outcome.FindByClientIdAsync("known", Cancellation)).ShouldBeSameAs(_application);
		Category(await _manager.Outcome.FindByClientIdAsync("unknown", Cancellation)).ShouldBe(ErrorCategory.NotFound);
	}

	[Fact]
	async Task GetIdAsync_answers_the_id_or_NotFound()
	{
		object anonymous = new();
		_manager.GetIdAsync(_application, Arg.Any<CancellationToken>()).Returns("the-id");
		_manager.GetIdAsync(anonymous, Arg.Any<CancellationToken>()).Returns((string?)null);

		Value(await _manager.Outcome.GetIdAsync(_application, Cancellation)).ShouldBe("the-id");
		Category(await _manager.Outcome.GetIdAsync(anonymous, Cancellation)).ShouldBe(ErrorCategory.NotFound);
	}

	[Fact]
	async Task CreateAsync_answers_the_created_application_or_a_Fault()
	{
		OpenIddictApplicationDescriptor valid = new() { ClientId = "valid" }, invalid = new() { ClientId = "invalid" };
		_manager.CreateAsync(valid, Arg.Any<CancellationToken>()).Returns(_application);
		_manager.CreateAsync(invalid, Arg.Any<CancellationToken>())
			.ThrowsAsync(new OpenIddictExceptions.ValidationException("ID2113"));

		Value(await _manager.Outcome.CreateAsync(valid, Cancellation)).ShouldBeSameAs(_application);
		Category(await _manager.Outcome.CreateAsync(invalid, Cancellation)).ShouldBe(ErrorCategory.Fault);
	}

	[Fact]
	async Task ValidateClientSecretAsync_answers_the_verdict()
	{
		_manager.ValidateClientSecretAsync(_application, "right", Arg.Any<CancellationToken>()).Returns(true);
		_manager.ValidateClientSecretAsync(_application, "wrong", Arg.Any<CancellationToken>()).Returns(false);

		Value(await _manager.Outcome.ValidateClientSecretAsync(_application, "right", Cancellation)).ShouldBeTrue();
		Value(await _manager.Outcome.ValidateClientSecretAsync(_application, "wrong", Cancellation)).ShouldBeFalse();
	}

	[Fact]
	async Task GetPermissionsAsync_answers_the_permissions()
	{
		ImmutableArray<string> permissions = ["ept:token"];
		_manager.GetPermissionsAsync(_application, Arg.Any<CancellationToken>()).Returns(permissions);

		Value(await _manager.Outcome.GetPermissionsAsync(_application, Cancellation)).ShouldBe(["ept:token"]);
	}

	[Fact]
	async Task GetClientTypeAsync_answers_the_type_or_NotFound()
	{
		object untyped = new();
		_manager.GetClientTypeAsync(_application, Arg.Any<CancellationToken>()).Returns("confidential");
		_manager.GetClientTypeAsync(untyped, Arg.Any<CancellationToken>()).Returns((string?)null);

		Value(await _manager.Outcome.GetClientTypeAsync(_application, Cancellation)).ShouldBe("confidential");
		Category(await _manager.Outcome.GetClientTypeAsync(untyped, Cancellation)).ShouldBe(ErrorCategory.NotFound);
	}

	[Fact]
	async Task GetConsentTypeAsync_answers_the_type_or_NotFound()
	{
		object untyped = new();
		_manager.GetConsentTypeAsync(_application, Arg.Any<CancellationToken>()).Returns(ConsentTypes.Implicit);
		_manager.GetConsentTypeAsync(untyped, Arg.Any<CancellationToken>()).Returns((string?)null);

		Value(await _manager.Outcome.GetConsentTypeAsync(_application, Cancellation)).ShouldBe(ConsentTypes.Implicit);
		Category(await _manager.Outcome.GetConsentTypeAsync(untyped, Cancellation)).ShouldBe(ErrorCategory.NotFound);
	}

	[Fact]
	async Task GetDisplayNameAsync_answers_the_name_or_NotFound()
	{
		object unnamed = new();
		_manager.GetDisplayNameAsync(_application, Arg.Any<CancellationToken>()).Returns("Machine");
		_manager.GetDisplayNameAsync(unnamed, Arg.Any<CancellationToken>()).Returns((string?)null);

		Value(await _manager.Outcome.GetDisplayNameAsync(_application, Cancellation)).ShouldBe("Machine");
		Category(await _manager.Outcome.GetDisplayNameAsync(unnamed, Cancellation)).ShouldBe(ErrorCategory.NotFound);
	}

	[Fact]
	async Task PopulateAsync_fills_the_descriptor()
	{
		OpenIddictApplicationDescriptor descriptor = new();

		(await _manager.Outcome.PopulateAsync(descriptor, _application, Cancellation)).TryGetValue(out Success<Unit> _)
			.ShouldBeTrue();
		await _manager.Received(1).PopulateAsync(descriptor, _application, Arg.Any<CancellationToken>());
	}

	[Fact]
	async Task UpdateAsync_maps_concurrency_to_Conflict()
	{
		OpenIddictApplicationDescriptor current = new(), stale = new();
		_manager.UpdateAsync(_application, stale, Arg.Any<CancellationToken>())
			.ThrowsAsync(new OpenIddictExceptions.ConcurrencyException("stale"));

		(await _manager.Outcome.UpdateAsync(_application, current, Cancellation)).TryGetValue(out Success<Unit> _)
			.ShouldBeTrue();
		await _manager.Received(1).UpdateAsync(_application, current, Arg.Any<CancellationToken>());
		Category(await _manager.Outcome.UpdateAsync(_application, stale, Cancellation)).ShouldBe(ErrorCategory.Conflict);
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
