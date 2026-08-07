using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
/// <see cref="AuthenticationService"/> is pure hydrate-and-send now — every method wraps the wire
/// request in its command and forwards to <see cref="ISender"/> unchanged. These tests prove exactly
/// that: field-for-field hydration of the command from the wire request, and the sender's outcome
/// passed straight through with no mapping in between.
/// </summary>
public sealed class AuthenticationServiceTests
{
	[Fact]
	async Task Login_hydrates_a_LoginCommand_from_the_request_and_sends_it()
	{
		LoginCommand? captured = null;
		var sender = Substitute.For<ISender>();
		sender.Send(Arg.Do<LoginCommand>(c => captured = c), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<LoginResult>.Ok(new LoginResult())));
		AuthenticationService service = new(sender);
		LoginRequest request = new() { Email = "a@b.com", Password = "x", RememberMe = true };

		await service.Login(request, TestContext.Current.CancellationToken);

		captured.ShouldNotBeNull();
		captured.Request.ShouldBe(request);
	}

	[Fact]
	async Task Login_returns_the_senders_outcome_unchanged()
	{
		var sender = Substitute.For<ISender>();
		var expected = Outcome<LoginResult>.Ok(new LoginResult { DeferredCompletionUrl = "/x" });
		sender.Send(Arg.Any<LoginCommand>(), Arg.Any<CancellationToken>()).Returns(_ => ValueTask.FromResult(expected));
		AuthenticationService service = new(sender);

		var outcome = await service.Login(new LoginRequest { Email = "a@b.com", Password = "x" }, TestContext.Current.CancellationToken);

		outcome.ShouldBeSameAs(expected);
	}

	[Fact]
	async Task Login_passes_through_a_failed_outcome_unchanged()
	{
		var sender = Substitute.For<ISender>();
		var expected = Outcome<LoginResult>.Err(ErrorCategory.LockedOut);
		sender.Send(Arg.Any<LoginCommand>(), Arg.Any<CancellationToken>()).Returns(_ => ValueTask.FromResult(expected));
		AuthenticationService service = new(sender);

		var outcome = await service.Login(new LoginRequest { Email = "a@b.com", Password = "x" }, TestContext.Current.CancellationToken);

		outcome.ShouldBeSameAs(expected);
	}

	[Fact]
	async Task Register_hydrates_a_RegisterCommand_from_the_request_and_sends_it()
	{
		RegisterCommand? captured = null;
		var sender = Substitute.For<ISender>();
		sender.Send(Arg.Do<RegisterCommand>(c => captured = c), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<RegisterResult>.Ok(new RegisterResult { Succeeded = true })));
		AuthenticationService service = new(sender);
		RegisterRequest request = new() { Email = "a@b.com", Password = "x" };

		await service.Register(request, TestContext.Current.CancellationToken);

		captured.ShouldNotBeNull();
		captured.Request.ShouldBe(request);
	}

	[Fact]
	async Task Register_returns_the_senders_outcome_unchanged()
	{
		var sender = Substitute.For<ISender>();
		var expected = Outcome<RegisterResult>.Err(ErrorCategory.Conflict);
		sender.Send(Arg.Any<RegisterCommand>(), Arg.Any<CancellationToken>()).Returns(_ => ValueTask.FromResult(expected));
		AuthenticationService service = new(sender);

		var outcome = await service.Register(new RegisterRequest { Email = "a@b.com", Password = "x" }, TestContext.Current.CancellationToken);

		outcome.ShouldBeSameAs(expected);
	}

	[Fact]
	async Task Logout_hydrates_a_LogoutCommand_wrapping_Unit_and_sends_it()
	{
		LogoutCommand? captured = null;
		var sender = Substitute.For<ISender>();
		sender.Send(Arg.Do<LogoutCommand>(c => captured = c), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<LogoutResult>.Ok(new LogoutResult())));
		AuthenticationService service = new(sender);

		await service.Logout(TestContext.Current.CancellationToken);

		captured.ShouldNotBeNull();
		captured.Request.ShouldBe(Unit.Value);
	}

	[Fact]
	async Task Logout_returns_the_senders_outcome_unchanged()
	{
		var sender = Substitute.For<ISender>();
		var expected = Outcome<LogoutResult>.Ok(new LogoutResult { DeferredCompletionUrl = "/x" });
		sender.Send(Arg.Any<LogoutCommand>(), Arg.Any<CancellationToken>()).Returns(_ => ValueTask.FromResult(expected));
		AuthenticationService service = new(sender);

		var outcome = await service.Logout(TestContext.Current.CancellationToken);

		outcome.ShouldBeSameAs(expected);
	}

	[Fact]
	async Task Logout_passes_through_a_failed_outcome_unchanged()
	{
		var sender = Substitute.For<ISender>();
		var expected = Outcome<LogoutResult>.Err(ErrorCategory.Fault);
		sender.Send(Arg.Any<LogoutCommand>(), Arg.Any<CancellationToken>()).Returns(_ => ValueTask.FromResult(expected));
		AuthenticationService service = new(sender);

		var outcome = await service.Logout(TestContext.Current.CancellationToken);

		outcome.ShouldBeSameAs(expected);
	}
}
