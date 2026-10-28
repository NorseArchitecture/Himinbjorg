using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests.Account;

public sealed class GetAccountStatusHandlerTests
{
	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly NorseUser _user = new() { UserName = "user@example.com", Email = "user@example.com" };

	public GetAccountStatusHandlerTests() =>
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>())
			.Returns(call => call.Arg<ClaimsPrincipal>().FindFirstValue(ClaimTypes.NameIdentifier) == _user.Id.ToString()
				? _user
				: null);

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Answers_every_status_field_from_the_managers()
	{
		_userManager.HasPasswordAsync(_user).Returns(true);
		_userManager.IsEmailConfirmedAsync(_user).Returns(true);
		_userManager.GetTwoFactorEnabledAsync(_user).Returns(true);
		_userManager.GetAuthenticatorKeyAsync(_user).Returns("AUTHENTICATORKEY");
		_userManager.CountRecoveryCodesAsync(_user).Returns(7);
		_signInManager.IsTwoFactorClientRememberedAsync(_user).Returns(true);
		_userManager.GetPasskeysAsync(_user).Returns([NewPasskey([1]), NewPasskey([2])]);
		_userManager.GetLoginsAsync(_user)
			.Returns([new("Google", "g-key", "Google"), new("GitHub", "h-key", "GitHub"), new("Microsoft", "m-key", "Microsoft")]);

		var outcome = await HandleAsync(FakePrincipal.For(_user.Id));

		outcome.TryGetValue(out Success<AccountStatusResponse> success).ShouldBeTrue();
		success.Value.ShouldBe(new AccountStatusResponse
		{
			HasPassword = true,
			EmailConfirmed = true,
			TwoFactorEnabled = true,
			HasAuthenticator = true,
			RecoveryCodesLeft = 7,
			IsMachineRemembered = true,
			PasskeyCount = 2,
			ExternalLoginCount = 3
		});
	}

	[Fact]
	async Task An_anonymous_caller_answers_NotFound() =>
		ProblemOf(await HandleAsync(FakePrincipal.Empty())).Category.ShouldBe(ErrorCategory.NotFound);

	[Fact]
	async Task An_erased_subject_answers_Erased()
	{
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>())
			.ThrowsAsync(new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch)));

		ProblemOf(await HandleAsync(FakePrincipal.For(_user.Id))).Category.ShouldBe(ErrorCategory.Erased);
		await _userManager.DidNotReceiveWithAnyArgs().HasPasswordAsync(default!);
	}

	ValueTask<Outcome<AccountStatusResponse>> HandleAsync(IPrincipalAccessor principal)
	{
		GetAccountStatusHandler handler = new(new AccountCaller(principal, _userManager), _userManager, _signInManager);
		return handler.Handle(new(Unit.Value), Cancellation);
	}

	static UserPasskeyInfo NewPasskey(byte[] credentialId) =>
		new(credentialId, [1, 2, 3], DateTimeOffset.UtcNow, 0, ["internal"], true, false, false, [4], [5]);

	static Problem ProblemOf(Outcome<AccountStatusResponse> outcome)
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem;
	}
}
