using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;
using Norse.Primitives.Pii;

namespace Norse.Identity.Web.Server.Tests.Account;

public sealed class SetPhoneNumberHandlerTests
{
	const string Normalized = "+15551234567";
	const string Stored = "+15557654321";
	const string StashedSignInKey = "stashed-refresh";

	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly NorseUser _user = new() { UserName = "user@example.com", Email = "user@example.com" };

	public SetPhoneNumberHandlerTests()
	{
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);
		_userManager.SetPhoneNumberAsync(_user, Arg.Any<string?>()).Returns(IdentityResult.Success);
		_userManager.GetPhoneNumberAsync(_user).Returns(Stored);
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task A_parsed_phone_is_stored_normalized_and_the_sign_in_refreshed()
	{
		var outcome = await HandleAsync(new() { PhoneInput = "+1 (555) 123-4567" });

		NextUrlOf(outcome).ShouldBe("/base/Account/Manage?status=phone-updated");
		await _userManager.Received(1).SetPhoneNumberAsync(_user, Normalized);
		await _signInManager.Received(1).RefreshSignInAsync(_user);
	}

	[Fact]
	async Task An_empty_phone_clears_it()
	{
		SetPhoneNumberRequest request = new() { PhoneInput = "" };
		request.Phone.ShouldBeNull();

		NextUrlOf(await HandleAsync(request)).ShouldBe("/base/Account/Manage?status=phone-updated");
		await _userManager.Received(1).SetPhoneNumberAsync(_user, null);
		await _signInManager.Received(1).RefreshSignInAsync(_user);
	}

	[Fact]
	async Task A_phone_set_over_an_empty_stored_value_is_written_and_the_sign_in_refreshed()
	{
		_userManager.GetPhoneNumberAsync(_user).Returns("");

		var outcome = await HandleAsync(new() { PhoneInput = Normalized });

		NextUrlOf(outcome).ShouldBe("/base/Account/Manage?status=phone-updated");
		await _userManager.Received(1).SetPhoneNumberAsync(_user, Normalized);
		await _signInManager.Received(1).RefreshSignInAsync(_user);
	}

	[Theory]
	[InlineData(Stored)]
	[InlineData("+1 (555) 765-4321")] // the stored number, formatted: it parses to the same E.164 string
	async Task An_unchanged_phone_answers_success_and_writes_and_refreshes_nothing(string input)
	{
		var outcome = await HandleAsync(new() { PhoneInput = input });

		NextUrlOf(outcome).ShouldBe("/base/Account/Manage?status=phone-updated");
		await _userManager.DidNotReceiveWithAnyArgs().SetPhoneNumberAsync(default!, default);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	async Task Clearing_an_absent_phone_answers_success_and_writes_and_refreshes_nothing(string? stored)
	{
		_userManager.GetPhoneNumberAsync(_user).Returns(stored);

		var outcome = await HandleAsync(new() { PhoneInput = "" });

		NextUrlOf(outcome).ShouldBe("/base/Account/Manage?status=phone-updated");
		await _userManager.DidNotReceiveWithAnyArgs().SetPhoneNumberAsync(default!, default);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task An_erased_subject_answers_Erased_before_the_stored_phone_is_read()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).ThrowsAsync(new KeyDestroyedException(receipt));

		var problem = ProblemOf(await HandleAsync(new() { PhoneInput = Stored }));

		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBeSameAs(receipt);
		await _userManager.DidNotReceiveWithAnyArgs().GetPhoneNumberAsync(default!);
		await _userManager.DidNotReceiveWithAnyArgs().SetPhoneNumberAsync(default!, default);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task A_malformed_phone_trips_the_wire_with_Validation_on_the_phone_field()
	{
		var problem = ProblemOf(await HandleAsync(new() { PhoneInput = "not a phone" }));

		AssertTripwire(problem);
		await _userManager.DidNotReceiveWithAnyArgs().SetPhoneNumberAsync(default!, default);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task A_present_empty_phone_failure_trips_the_wire()
	{
		SetPhoneNumberRequest request = new()
		{
			PhoneInput = "",
			Phone = new Result<PhoneNumber>(new Failure(ParseFailure.Empty, "", nameof(PhoneNumber)))
		};

		AssertTripwire(ProblemOf(await HandleAsync(request)));
		await _userManager.DidNotReceiveWithAnyArgs().SetPhoneNumberAsync(default!, default);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task A_store_failure_passes_through_and_refreshes_nothing()
	{
		_userManager.SetPhoneNumberAsync(_user, Normalized)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().ConcurrencyFailure()));

		var problem = ProblemOf(await HandleAsync(new() { PhoneInput = Normalized }));

		problem.Category.ShouldBe(ErrorCategory.Conflict);
		problem.Errors.Keys.ShouldBe([""]);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task An_indeterminate_store_write_is_reported_on_the_summary()
	{
		_userManager.SetPhoneNumberAsync(_user, Normalized)
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));

		var problem = ProblemOf(await HandleAsync(new() { PhoneInput = Normalized }));

		problem.Category.ShouldBe(ErrorCategory.Indeterminate);
		problem.Errors.Keys.ShouldBe([""]);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task A_refresh_on_a_started_response_answers_the_completion_url()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.UserManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(harness.User);
		harness.UserManager.SetPhoneNumberAsync(harness.User, Normalized).Returns(IdentityResult.Success);
		harness.DeferredSignIn
			.StashSignIn(Arg.Any<string>(), Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>())
			.Returns(StashedSignInKey);
		harness.DeferredSignIn.BuildCompletionUrl(Arg.Any<string>(), Arg.Any<string>())
			.Returns(call =>
				$"/_auth/complete?key={call.ArgAt<string>(0)}&returnUrl={Uri.EscapeDataString(call.ArgAt<string>(1))}");
		var signedIn = await harness.RunAsync(manager =>
			manager.SignInWithClaimsAsync(harness.User, isPersistent: false, additionalClaims: []));
		var cookie = TwoFactorHarness.CookieOf(signedIn.SetCookieFor(".AspNetCore.Identity.Application")!);

		var probe = await harness.RunAsync(manager =>
		{
			var accessor = harness.Services.GetRequiredService<IHttpContextAccessor>();
			SetPhoneNumberHandler handler = new(harness.UserManager, manager, FakePrincipal.For(harness.User.Id),
				new(harness.DeferredSignIn, accessor), accessor);
			return handler.Handle(new(new() { PhoneInput = Normalized }), Cancellation).AsTask();
		}, responseAlreadyStarted: true, cookie);

		probe.Exception.ShouldBeNull();
		probe.IdentityKey.ShouldBe(StashedSignInKey);
		NextUrlOf(probe.Value.ShouldNotBeNull())
			.ShouldBe(harness.DeferredSignIn.BuildCompletionUrl(StashedSignInKey, "/Account/Manage?status=phone-updated"));
	}

	static void AssertTripwire(Problem problem)
	{
		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors.Keys.ShouldBe([nameof(SetPhoneNumberRequest.Phone)]);
		problem.Errors[nameof(SetPhoneNumberRequest.Phone)].ShouldBe(["Enter a valid phone number (+15551234567)."]);
	}

	ValueTask<Outcome<NavigationResult>> HandleAsync(SetPhoneNumberRequest request, IPrincipalAccessor? principal = null)
	{
		DefaultHttpContext context = new();
		context.Request.PathBase = "/base";
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(context);
		SetPhoneNumberHandler handler = new(_userManager, _signInManager, principal ?? FakePrincipal.For(_user.Id),
			new(Substitute.For<IDeferredSignIn>(), accessor), accessor);
		return handler.Handle(new(request), Cancellation);
	}

	static string NextUrlOf(Outcome<NavigationResult> outcome)
	{
		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		return success.Value.NextUrl;
	}

	static Problem ProblemOf(Outcome<NavigationResult> outcome)
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem;
	}
}
