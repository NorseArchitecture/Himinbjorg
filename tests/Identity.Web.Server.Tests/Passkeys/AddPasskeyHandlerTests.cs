using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.Passkeys;

namespace Norse.Identity.Web.Server.Tests.Passkeys;

/// <summary>
///     <see cref="AddPasskeyHandler" />, over a real <see cref="NorseSignInManager" /> on <see cref="TwoFactorHarness" />:
///     the cap first (T3-16), then the attestation, then the binding to the account completing it -- a ceremony
///     started for another account is <see cref="ErrorCategory.Forbidden" /> with nothing persisted -- and only then the
///     save, answering the new passkey's rename URL (Review Focus 2).
/// </summary>
public sealed class AddPasskeyHandlerTests
{
	static readonly byte[] _credentialId = [0xFB, 0xFF, 0xBF];

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task A_ceremony_started_for_another_account_is_forbidden_and_persists_nothing()
	{
		using var harness = await StartAsync(passkeys: 0);
		Attests(harness, PasskeyAttestationResult.Success(TestPasskeys.Info(_credentialId),
			new() { Id = Guid.CreateVersion7().ToString(), Name = "other@example.com", DisplayName = "other@example.com" }));

		var problem = BaseRequest.ProblemOf(await HandleAsync(harness));

		problem.Category.ShouldBe(ErrorCategory.Forbidden);
		problem.Errors.Values.SelectMany(static messages => messages)
			.ShouldBe(["This passkey was created for a different account."]);
		await harness.UserManager.DidNotReceiveWithAnyArgs().AddOrUpdatePasskeyAsync(default!, default!);
	}

	[Fact]
	async Task A_failed_attestation_persists_nothing()
	{
		using var harness = await StartAsync(passkeys: 0);
		Attests(harness, PasskeyAttestationResult.Fail(new PasskeyException("The credential is already registered.")));

		var problem = BaseRequest.ProblemOf(await HandleAsync(harness));

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors.Values.SelectMany(static messages => messages)
			.ShouldBe(["The passkey could not be verified. Try again."]);
		await harness.UserManager.DidNotReceiveWithAnyArgs().AddOrUpdatePasskeyAsync(default!, default!);
	}

	[Fact]
	async Task Success_persists_and_answers_the_rename_url()
	{
		using var harness = await StartAsync(passkeys: 99);
		var passkey = TestPasskeys.Info(_credentialId);
		Attests(harness, PasskeyAttestationResult.Success(passkey,
			new() { Id = harness.UserId, Name = "user@example.com", DisplayName = "user@example.com" }));
		harness.UserManager.AddOrUpdatePasskeyAsync(harness.User, passkey).Returns(IdentityResult.Success);

		BaseRequest.ValueOf(await HandleAsync(harness)).NextUrl.ShouldBe("/base/Account/Manage/RenamePasskey/-_-_");
		await harness.UserManager.Received(1).AddOrUpdatePasskeyAsync(harness.User, passkey);
	}

	[Fact]
	async Task A_failed_save_passes_through()
	{
		using var harness = await StartAsync(passkeys: 0);
		var passkey = TestPasskeys.Info(_credentialId);
		Attests(harness, PasskeyAttestationResult.Success(passkey,
			new() { Id = harness.UserId, Name = "user@example.com", DisplayName = "user@example.com" }));
		harness.UserManager.AddOrUpdatePasskeyAsync(harness.User, passkey)
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));

		BaseRequest.ProblemOf(await HandleAsync(harness)).Category.ShouldBe(ErrorCategory.Indeterminate);
	}

	[Fact]
	async Task At_the_cap_answers_Conflict_before_attestation()
	{
		using var harness = await StartAsync(passkeys: 100);

		var problem = BaseRequest.ProblemOf(await HandleAsync(harness));

		problem.Category.ShouldBe(ErrorCategory.Conflict);
		problem.Errors.Values.SelectMany(static messages => messages)
			.ShouldBe(["You have reached the maximum number of allowed passkeys."]);
		await harness.PasskeyHandler.DidNotReceiveWithAnyArgs().PerformAttestationAsync(default!);
		await harness.UserManager.DidNotReceiveWithAnyArgs().AddOrUpdatePasskeyAsync(default!, default!);
	}

	static async Task<TwoFactorHarness> StartAsync(int passkeys)
	{
		var harness = await TwoFactorHarness.StartAsync();
		harness.UserManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(harness.User);
		harness.UserManager.GetPasskeysAsync(harness.User).Returns(TestPasskeys.Many(passkeys));
		return harness;
	}

	static void Attests(TwoFactorHarness harness, PasskeyAttestationResult result) =>
		harness.PasskeyHandler.PerformAttestationAsync(Arg.Any<PasskeyAttestationContext>()).Returns(result);

	static async Task<Outcome<NavigationResult>> HandleAsync(TwoFactorHarness harness)
	{
		var state = harness.AttestationProtector.Protect("state", TimeSpan.FromMinutes(5));
		return (await harness.RunAsync(manager =>
		{
			AddPasskeyHandler handler = new(new AccountCaller(FakePrincipal.For(harness.User.Id), harness.UserManager),
				harness.UserManager, manager, BaseRequest.Accessor());
			return handler.Handle(new(new AddPasskeyRequest { CredentialJson = "{}", AttestationState = state }),
				Cancellation).AsTask();
		})).Value.ShouldNotBeNull();
	}
}
