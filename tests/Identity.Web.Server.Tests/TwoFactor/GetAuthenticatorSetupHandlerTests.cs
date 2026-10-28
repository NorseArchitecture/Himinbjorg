using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.TwoFactor;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary>
///     <see cref="GetAuthenticatorSetupHandler" /> over a real <see cref="NorseUserManager" /> and a substituted store,
///     so what is written is observable: a missing key is provisioned without rotating the stamp (T3-13), a stored key
///     is read without a write, and the answer is the stored key formatted, its URI under the configured issuer, and
///     that URI as a QR code.
/// </summary>
public sealed class GetAuthenticatorSetupHandlerTests
{
	const string Email = "user@example.com";

	readonly IUserStore<NorseUser> _store = (IUserStore<NorseUser>)Substitute.For([typeof(IUserStore<NorseUser>),
		typeof(IUserAuthenticatorKeyStore<NorseUser>), typeof(IUserEmailStore<NorseUser>),
		typeof(IUserSecurityStampStore<NorseUser>)], []);

	readonly NorseUser _user = new() { Id = Guid.CreateVersion7(), UserName = Email, Email = Email };
	readonly NorseUserManager _userManager;

	public GetAuthenticatorSetupHandlerTests()
	{
		_store.FindByIdAsync(_user.Id.ToString(), Arg.Any<CancellationToken>()).Returns(_user);
		_store.UpdateAsync(_user, Arg.Any<CancellationToken>()).Returns(IdentityResult.Success);
		Emails.GetEmailAsync(_user, Arg.Any<CancellationToken>()).Returns(Email);
		_userManager = TestUserManager.Create(_store);
	}

	IUserAuthenticatorKeyStore<NorseUser> Keys => (IUserAuthenticatorKeyStore<NorseUser>)_store;

	IUserEmailStore<NorseUser> Emails => (IUserEmailStore<NorseUser>)_store;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task A_missing_key_is_provisioned_without_rotating_the_stamp()
	{
		string? stored = null;
		Keys.GetAuthenticatorKeyAsync(_user, Arg.Any<CancellationToken>()).Returns(_ => stored);
		Keys.SetAuthenticatorKeyAsync(_user, Arg.Any<string>(), Arg.Any<CancellationToken>())
			.Returns(call =>
			{
				stored = call.ArgAt<string>(1);
				return Task.CompletedTask;
			});

		var setup = SetupOf(await HandleAsync());

		stored.ShouldNotBeNullOrEmpty();
		ShouldAnswer(setup, stored);
		await Keys.ReceivedWithAnyArgs(1).SetAuthenticatorKeyAsync(default!, default!, Cancellation);
		await _store.Received(1).UpdateAsync(_user, Arg.Any<CancellationToken>());
		await ((IUserSecurityStampStore<NorseUser>)_store).DidNotReceiveWithAnyArgs()
			.SetSecurityStampAsync(default!, default!, Cancellation);
	}

	[Fact]
	async Task An_existing_key_is_read_without_a_write()
	{
		Keys.GetAuthenticatorKeyAsync(_user, Arg.Any<CancellationToken>()).Returns("ABCDEFGHIJKLMNOP");

		ShouldAnswer(SetupOf(await HandleAsync()), "ABCDEFGHIJKLMNOP");

		await Keys.DidNotReceiveWithAnyArgs().SetAuthenticatorKeyAsync(default!, default!, Cancellation);
		await _store.DidNotReceiveWithAnyArgs().UpdateAsync(default!, Cancellation);
	}

	[Fact]
	async Task An_indeterminate_provisioning_passes_through()
	{
		Keys.GetAuthenticatorKeyAsync(_user, Arg.Any<CancellationToken>()).Returns((string?)null);
		_store.UpdateAsync(_user, Arg.Any<CancellationToken>())
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));

		ProblemOf(await HandleAsync()).Category.ShouldBe(ErrorCategory.Indeterminate);
	}

	[Fact]
	async Task An_erased_subject_answers_Erased()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_store.FindByIdAsync(_user.Id.ToString(), Arg.Any<CancellationToken>()).ThrowsAsync(new KeyDestroyedException(receipt));

		var problem = ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBeSameAs(receipt);
		await Keys.DidNotReceiveWithAnyArgs().GetAuthenticatorKeyAsync(default!, Cancellation);
	}

	static void ShouldAnswer(AuthenticatorSetupResponse setup, string key)
	{
		var uri = AuthenticatorSetup.Uri("Norse", Email, key);
		setup.SharedKey.ShouldBe(AuthenticatorSetup.FormatKey(key));
		setup.AuthenticatorUri.ShouldBe(uri);
		setup.QrCodeSvg.ShouldBe(AuthenticatorSetup.QrSvg(uri));
	}

	ValueTask<Outcome<AuthenticatorSetupResponse>> HandleAsync()
	{
		GetAuthenticatorSetupHandler handler = new(new AccountCaller(FakePrincipal.For(_user.Id), _userManager), _userManager,
			Options.Create(new AuthenticatorOptions { Issuer = "Norse" }));
		return handler.Handle(new(Unit.Value), Cancellation);
	}

	static AuthenticatorSetupResponse SetupOf(Outcome<AuthenticatorSetupResponse> outcome)
	{
		outcome.TryGetValue(out Success<AuthenticatorSetupResponse> success).ShouldBeTrue();
		return success.Value;
	}

	static Problem ProblemOf(Outcome<AuthenticatorSetupResponse> outcome)
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem;
	}
}
