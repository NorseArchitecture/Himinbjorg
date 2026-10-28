using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.Passkeys;

namespace Norse.Identity.Web.Server.Tests.Passkeys;

/// <summary>
///     <see cref="GetPasskeyCreationOptionsHandler" />, over a real <see cref="NorseSignInManager" /> on
///     <see cref="TwoFactorHarness" />: the creation options and the protected attestation state, or, at the cap of 100
///     passkeys (T3-16), <see cref="ErrorCategory.Conflict" /> before any ceremony starts.
/// </summary>
public sealed class GetPasskeyCreationOptionsHandlerTests
{
	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Below_the_cap_answers_the_options_and_the_protected_state()
	{
		using var harness = await StartAsync(passkeys: 99);
		harness.PasskeyHandler.MakeCreationOptionsAsync(Arg.Any<PasskeyUserEntity>(), Arg.Any<HttpContext>())
			.Returns(new PasskeyCreationOptionsResult { CreationOptionsJson = "{}", AttestationState = "state" });

		var response = BaseRequest.ValueOf(await HandleAsync(harness));

		response.OptionsJson.ShouldBe("{}");
		harness.AttestationProtector.Unprotect(response.AttestationState).ShouldBe("state");
	}

	[Fact]
	async Task At_the_cap_answers_Conflict_and_starts_no_ceremony()
	{
		using var harness = await StartAsync(passkeys: 100);

		var problem = BaseRequest.ProblemOf(await HandleAsync(harness));

		problem.Category.ShouldBe(ErrorCategory.Conflict);
		problem.Errors.Values.SelectMany(static messages => messages)
			.ShouldBe(["You have reached the maximum number of allowed passkeys."]);
		await harness.PasskeyHandler.DidNotReceiveWithAnyArgs().MakeCreationOptionsAsync(default!, default!);
	}

	static async Task<TwoFactorHarness> StartAsync(int passkeys)
	{
		var harness = await TwoFactorHarness.StartAsync();
		harness.UserManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(harness.User);
		harness.UserManager.GetPasskeysAsync(harness.User).Returns(TestPasskeys.Many(passkeys));
		return harness;
	}

	static async Task<Outcome<PasskeyCreationOptionsResponse>> HandleAsync(TwoFactorHarness harness) =>
		(await harness.RunAsync(manager =>
		{
			GetPasskeyCreationOptionsHandler handler = new(
				new AccountCaller(FakePrincipal.For(harness.User.Id), harness.UserManager), harness.UserManager, manager);
			return handler.Handle(new(Unit.Value), Cancellation).AsTask();
		})).Value.ShouldNotBeNull();
}
