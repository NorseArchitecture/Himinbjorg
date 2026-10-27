using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     V6 (2026-10-24 explicit-writes spec §12, plan Task 4.10), once per provider: every write the surviving scaffold
///     (<c>ExternalLogin</c> and the <c>/Account/Manage</c> tree) and the account handlers make, driven the way the
///     page or handler drives it -- the instance obtained by the same read it makes (<c>GetUserAsync</c> on the principal,
///     <c>FindByIdAsync</c>, <c>FindByEmailAsync</c>, or the sign-in manager's own lookup), then the same manager and
///     sign-in-manager calls. None may meet the store's no-baseline refusal: every <see cref="NorseUser" /> a write sees came from a store read or a create.
/// </summary>
/// <remarks>
///     <para>
///         Not driven here: the passkey assertion sign-in (<c>PasskeySignInAsync</c>), which needs a WebAuthn
///         assertion. V7 confirmed on RC2 that it reads the passkey through the store before
///         <c>AddOrUpdatePasskeyAsync</c>, and <see cref="NorseUserStoreSuite" />'s passkey facts make exactly that
///         read. <c>RefreshSignInAsync</c>, <c>SignOutAsync</c>, <c>ForgetTwoFactorClientAsync</c> and the token
///         generators write no user state; <c>DeletePersonalData</c>'s erasure goes through
///         <see cref="ErasureService" />, never the store.
///     </para>
///     <para>
///         Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///         records: xUnit discovers them on each <see langword="sealed" /> provider class.
///     </para>
/// </remarks>
public abstract class ScaffoldWritePathSuite : IDisposable
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	/// <summary>The password every user with one starts with.</summary>
	const string Password = "Correct-Horse-1!";

	readonly IdentityFixture _fixture;
	readonly List<IServiceScope> _scopes = [];

	/// <summary>Binds the suite to the provider's shared fixture.</summary>
	/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
	protected ScaffoldWritePathSuite(IdentityFixture fixture) =>
		_fixture = fixture;

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>Every scaffold-reachable write path, named for the page or handler that makes it and its calls.</summary>
	public static TheoryData<string> WritePaths =>
	[
		"Login: PasswordSignInAsync, a wrong password then the right one",
		"Register: CreateAsync with a password",
		"ExternalLogin: store setters, CreateAsync, AddLoginAsync",
		"ExternalLogin: ExternalLoginSignInAsync",
		"ConfirmEmail: ConfirmEmailAsync",
		"ConfirmEmailChange: ChangeEmailAsync",
		"ResetPassword: ResetPasswordAsync",
		"LoginWith2fa: TwoFactorAuthenticatorSignInAsync with a wrong code",
		"LoginWithRecoveryCode: TwoFactorRecoveryCodeSignInAsync after a failed attempt",
		"Manage/ChangePassword: ChangePasswordAsync",
		"Manage/SetPassword: AddPasswordAsync",
		"Manage/Index: SetPhoneNumberAsync",
		"Manage/EnableAuthenticator: ResetAuthenticatorKeyAsync, SetTwoFactorEnabledAsync, GenerateNewTwoFactorRecoveryCodesAsync",
		"Manage/Disable2fa: SetTwoFactorEnabledAsync",
		"Manage/ResetAuthenticator: SetTwoFactorEnabledAsync, ResetAuthenticatorKeyAsync",
		"Manage/GenerateRecoveryCodes: GenerateNewTwoFactorRecoveryCodesAsync",
		"Manage/ExternalLogins: AddLoginAsync, RemoveLoginAsync",
		"Manage/Passkeys: AddOrUpdatePasskeyAsync, RemovePasskeyAsync",
		"Manage/RenamePasskey: GetPasskeyAsync, AddOrUpdatePasskeyAsync",
		"Manage/DeletePersonalData: CheckPasswordAsync"
	];

	/// <summary>The current test's cancellation token.</summary>
	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	/// <inheritdoc />
	public void Dispose()
	{
		foreach (var scope in _scopes)
			scope.Dispose();
		GC.SuppressFinalize(this);
	}

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(WritePaths))]
	protected async Task Scaffold_write_path_never_meets_the_no_baseline_refusal(string path)
	{
		_fixture.SkipUnlessAvailable();

		await (path switch
		{
			"Login: PasswordSignInAsync, a wrong password then the right one" => LoginAsync(),
			"Register: CreateAsync with a password" => RegisterAsync(),
			"ExternalLogin: store setters, CreateAsync, AddLoginAsync" => ExternalLoginRegistrationAsync(),
			"ExternalLogin: ExternalLoginSignInAsync" => ExternalLoginSignInAsync(),
			"ConfirmEmail: ConfirmEmailAsync" => ConfirmEmailAsync(),
			"ConfirmEmailChange: ChangeEmailAsync" => ConfirmEmailChangeAsync(),
			"ResetPassword: ResetPasswordAsync" => ResetPasswordAsync(),
			"LoginWith2fa: TwoFactorAuthenticatorSignInAsync with a wrong code" => LoginWith2faAsync(),
			"LoginWithRecoveryCode: TwoFactorRecoveryCodeSignInAsync after a failed attempt" => LoginWithRecoveryCodeAsync(),
			"Manage/ChangePassword: ChangePasswordAsync" => ChangePasswordAsync(),
			"Manage/SetPassword: AddPasswordAsync" => SetPasswordAsync(),
			"Manage/Index: SetPhoneNumberAsync" => SetPhoneNumberAsync(),
			"Manage/EnableAuthenticator: ResetAuthenticatorKeyAsync, SetTwoFactorEnabledAsync, GenerateNewTwoFactorRecoveryCodesAsync" =>
				EnableAuthenticatorAsync(),
			"Manage/Disable2fa: SetTwoFactorEnabledAsync" => Disable2faAsync(),
			"Manage/ResetAuthenticator: SetTwoFactorEnabledAsync, ResetAuthenticatorKeyAsync" => ResetAuthenticatorAsync(),
			"Manage/GenerateRecoveryCodes: GenerateNewTwoFactorRecoveryCodesAsync" => GenerateRecoveryCodesAsync(),
			"Manage/ExternalLogins: AddLoginAsync, RemoveLoginAsync" => ExternalLoginsAsync(),
			"Manage/Passkeys: AddOrUpdatePasskeyAsync, RemovePasskeyAsync" => PasskeysAsync(),
			"Manage/RenamePasskey: GetPasskeyAsync, AddOrUpdatePasskeyAsync" => RenamePasskeyAsync(),
			"Manage/DeletePersonalData: CheckPasswordAsync" => CheckPasswordAsync(),
			_ => throw new ArgumentOutOfRangeException(nameof(path), path, "Not a scaffold write path this suite drives.")
		});
	}

	/// <summary><c>LoginHandler</c>: the sign-in manager reads the user by name, then counts the failure and resets it.</summary>
	async Task LoginAsync()
	{
		var user = await SeedAsync(withPassword: true);
		var signIn = SignIn(_fixture.CreateUserManager());

		(await signIn.PasswordSignInAsync(user.Email!, "wrong-password", false, lockoutOnFailure: true)).Succeeded.ShouldBeFalse();
		(await RereadAsync(user.Id)).AccessFailedCount.ShouldBe(1);
		(await signIn.PasswordSignInAsync(user.Email!, Password, false, lockoutOnFailure: true)).Succeeded.ShouldBeTrue();

		(await RereadAsync(user.Id)).AccessFailedCount.ShouldBe(0);
	}

	/// <summary><c>RegisterHandler</c>: a new instance is legal as the argument to create, and leaves it writable.</summary>
	async Task RegisterAsync()
	{
		var email = NewEmail();
		NorseUser user = new() { UserName = email, Email = email };

		(await _fixture.CreateUserManager().CreateAsync(user, Password)).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(user);
	}

	/// <summary><c>ExternalLogin.razor</c>'s registration: store setters on a new instance, create, then the login.</summary>
	async Task ExternalLoginRegistrationAsync()
	{
		var email = NewEmail();
		var store = _fixture.CreateUserStore();
		NorseUser user = new();
		await store.SetUserNameAsync(user, email, Cancellation);
		await ((IUserEmailStore<NorseUser>)store).SetEmailAsync(user, email, Cancellation);
		var userManager = _fixture.CreateUserManager();

		(await userManager.CreateAsync(user)).Succeeded.ShouldBeTrue();
		(await userManager.AddLoginAsync(user, new("TestProvider", $"register-{user.Id:N}", "Test"))).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(user);
	}

	/// <summary><c>ExternalLogin.razor</c>'s sign-in: the sign-in manager reads the user by login.</summary>
	async Task ExternalLoginSignInAsync()
	{
		var seeded = await SeedAsync();
		var providerKey = $"sign-in-{seeded.Id:N}";
		var linking = _fixture.CreateUserManager();
		(await linking.AddLoginAsync(await PageUserAsync(linking, seeded.Id), new("TestProvider", providerKey, "Test")))
			.Succeeded.ShouldBeTrue();

		var result = await SignIn(_fixture.CreateUserManager())
			.ExternalLoginSignInAsync("TestProvider", providerKey, isPersistent: false, bypassTwoFactor: true);

		result.Succeeded.ShouldBeTrue();
	}

	/// <summary><c>ResendEmailConfirmationHandler</c> mints the token; <c>ConfirmEmailHandler</c> reads by id and confirms.</summary>
	async Task ConfirmEmailAsync()
	{
		var seeded = await SeedAsync();
		var minting = _fixture.CreateUserManager();
		var token = await minting.GenerateEmailConfirmationTokenAsync(
			(await minting.FindByEmailAsync(seeded.Email!)).ShouldNotBeNull());
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		(await userManager.ConfirmEmailAsync(user, token)).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(user);
		(await RereadAsync(seeded.Id)).EmailConfirmed.ShouldBeTrue();
	}

	/// <summary><c>Manage/Email.razor</c> mints the token; <c>ConfirmEmailChangeHandler</c> reads by id and changes.</summary>
	async Task ConfirmEmailChangeAsync()
	{
		var seeded = await SeedAsync();
		var newEmail = NewEmail();
		var minting = _fixture.CreateUserManager();
		var token = await minting.GenerateChangeEmailTokenAsync(await PageUserAsync(minting, seeded.Id), newEmail);
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		(await userManager.ChangeEmailAsync(user, newEmail, token)).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(user);
		(await RereadAsync(seeded.Id)).UserName.ShouldBe(newEmail);
	}

	/// <summary><c>ForgotPasswordHandler</c> and <c>ResetPasswordHandler</c> each read the user by email.</summary>
	async Task ResetPasswordAsync()
	{
		var seeded = await SeedAsync(withPassword: true);
		var minting = _fixture.CreateUserManager();
		var token = await minting.GeneratePasswordResetTokenAsync((await minting.FindByEmailAsync(seeded.Email!)).ShouldNotBeNull());
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByEmailAsync(seeded.Email!)).ShouldNotBeNull();

		(await userManager.ResetPasswordAsync(user, token, "Reset-Horse-2!")).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(user);
		(await userManager.CheckPasswordAsync(await RereadAsync(seeded.Id), "Reset-Horse-2!")).ShouldBeTrue();
	}

	/// <summary>
	///     <c>TwoFactorSignInHandler</c>'s write over the challenge token: the user the token names, read afresh by the
	///     second-factor step, takes the failed second factor's increment.
	/// </summary>
	async Task LoginWith2faAsync()
	{
		var (email, _) = await SeedTwoFactorAsync();
		var signIn = SignIn(_fixture.CreateUserManager());
		(await signIn.PasswordSignInAsync(email, Password, false, lockoutOnFailure: true)).RequiresTwoFactor.ShouldBeTrue();

		var result = await signIn.TwoFactorChallengeSignInAsync(ChallengeToken(signIn), "not-a-code", rememberClient: false);

		result.Succeeded.ShouldBeFalse();
		(await RereadAsync((await _fixture.CreateUserManager().FindByEmailAsync(email)).ShouldNotBeNull().Id))
			.AccessFailedCount.ShouldBe(1);
	}

	/// <summary>
	///     <c>RecoveryCodeSignInHandler</c>'s write over the challenge token: the user the token names redeems a
	///     code, then the sign-in resets the failure the wrong code counted.
	/// </summary>
	async Task LoginWithRecoveryCodeAsync()
	{
		var (email, codes) = await SeedTwoFactorAsync();
		var signIn = SignIn(_fixture.CreateUserManager());
		(await signIn.PasswordSignInAsync(email, Password, false, lockoutOnFailure: true)).RequiresTwoFactor.ShouldBeTrue();
		var token = ChallengeToken(signIn);
		(await signIn.TwoFactorChallengeSignInAsync(token, "not-a-code", rememberClient: false)).Succeeded.ShouldBeFalse();

		(await signIn.RecoveryCodeChallengeSignInAsync(token, codes[0])).Succeeded.ShouldBeTrue();

		var userManager = _fixture.CreateUserManager();
		var reread = (await userManager.FindByEmailAsync(email)).ShouldNotBeNull();
		reread.AccessFailedCount.ShouldBe(0);
		(await userManager.CountRecoveryCodesAsync(reread)).ShouldBe(codes.Length - 1);
	}

	async Task ChangePasswordAsync()
	{
		var seeded = await SeedAsync(withPassword: true);
		var userManager = _fixture.CreateUserManager();
		var user = await PageUserAsync(userManager, seeded.Id);

		(await userManager.ChangePasswordAsync(user, Password, "Changed-Horse-3!")).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(user);
	}

	async Task SetPasswordAsync()
	{
		var seeded = await SeedAsync();
		var userManager = _fixture.CreateUserManager();
		var user = await PageUserAsync(userManager, seeded.Id);
		(await userManager.HasPasswordAsync(user)).ShouldBeFalse();

		(await userManager.AddPasswordAsync(user, Password)).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(user);
	}

	async Task SetPhoneNumberAsync()
	{
		var seeded = await SeedAsync();
		var userManager = _fixture.CreateUserManager();
		var user = await PageUserAsync(userManager, seeded.Id);

		(await userManager.SetPhoneNumberAsync(user, "+15550300")).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(user);
	}

	/// <summary>
	///     Loading the page resets a missing key on one request's instance; the verified submit, a second request,
	///     enables two-factor and generates the codes on its own. The TOTP check itself only reads.
	/// </summary>
	async Task EnableAuthenticatorAsync()
	{
		var seeded = await SeedAsync(withPassword: true);
		var loading = _fixture.CreateUserManager();
		var loaded = await PageUserAsync(loading, seeded.Id);
		(await loading.GetAuthenticatorKeyAsync(loaded)).ShouldBeNull();
		(await loading.ResetAuthenticatorKeyAsync(loaded)).Succeeded.ShouldBeTrue();
		var submitting = _fixture.CreateUserManager();
		var user = await PageUserAsync(submitting, seeded.Id);

		(await submitting.SetTwoFactorEnabledAsync(user, true)).Succeeded.ShouldBeTrue();
		(await submitting.CountRecoveryCodesAsync(user)).ShouldBe(0);
		(await submitting.GenerateNewTwoFactorRecoveryCodesAsync(user, 10)).ShouldNotBeNull().Count().ShouldBe(10);

		ShouldStillBeWritable(loaded);
		ShouldStillBeWritable(user);
	}

	async Task Disable2faAsync()
	{
		var (email, _) = await SeedTwoFactorAsync();
		var userManager = _fixture.CreateUserManager();
		var user = await PageUserAsync(userManager, (await userManager.FindByEmailAsync(email)).ShouldNotBeNull().Id);
		(await userManager.GetTwoFactorEnabledAsync(user)).ShouldBeTrue();

		(await userManager.SetTwoFactorEnabledAsync(user, false)).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(user);
	}

	async Task ResetAuthenticatorAsync()
	{
		var (email, _) = await SeedTwoFactorAsync();
		var userManager = _fixture.CreateUserManager();
		var user = await PageUserAsync(userManager, (await userManager.FindByEmailAsync(email)).ShouldNotBeNull().Id);
		var oldKey = await userManager.GetAuthenticatorKeyAsync(user);

		(await userManager.SetTwoFactorEnabledAsync(user, false)).Succeeded.ShouldBeTrue();
		(await userManager.ResetAuthenticatorKeyAsync(user)).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(user);
		(await userManager.GetAuthenticatorKeyAsync(user)).ShouldNotBe(oldKey);
	}

	async Task GenerateRecoveryCodesAsync()
	{
		var (email, codes) = await SeedTwoFactorAsync();
		var userManager = _fixture.CreateUserManager();
		var user = await PageUserAsync(userManager, (await userManager.FindByEmailAsync(email)).ShouldNotBeNull().Id);

		var fresh = (await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10)).ShouldNotBeNull().ToArray();

		ShouldStillBeWritable(user);
		fresh.ShouldNotContain(codes[0]);
	}

	/// <summary>Linking and unlinking are separate submits, so separate requests and instances.</summary>
	async Task ExternalLoginsAsync()
	{
		var seeded = await SeedAsync();
		UserLoginInfo login = new("TestProvider", $"manage-{seeded.Id:N}", "Test");
		var linking = _fixture.CreateUserManager();
		var linked = await PageUserAsync(linking, seeded.Id);
		(await linking.AddLoginAsync(linked, login)).Succeeded.ShouldBeTrue();
		var removing = _fixture.CreateUserManager();
		var user = await PageUserAsync(removing, seeded.Id);

		(await removing.RemoveLoginAsync(user, login.LoginProvider, login.ProviderKey)).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(linked);
		ShouldStillBeWritable(user);
		(await removing.GetLoginsAsync(user)).ShouldBeEmpty();
	}

	/// <summary>The attestation's result is enrolled on one request's instance and removed on another's.</summary>
	async Task PasskeysAsync()
	{
		var seeded = await SeedAsync();
		byte[] credentialId = [.. seeded.Id.ToByteArray(), 31];
		var enrolling = _fixture.CreateUserManager();
		var enrolled = await PageUserAsync(enrolling, seeded.Id);
		(await enrolling.GetPasskeysAsync(enrolled)).ShouldBeEmpty();
		(await enrolling.AddOrUpdatePasskeyAsync(enrolled, NewPasskey(credentialId))).Succeeded.ShouldBeTrue();
		var removing = _fixture.CreateUserManager();
		var user = await PageUserAsync(removing, seeded.Id);

		(await removing.RemovePasskeyAsync(user, credentialId)).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(enrolled);
		ShouldStillBeWritable(user);
		(await removing.GetPasskeysAsync(user)).ShouldBeEmpty();
	}

	async Task RenamePasskeyAsync()
	{
		var seeded = await SeedAsync();
		byte[] credentialId = [.. seeded.Id.ToByteArray(), 32];
		var enrolling = _fixture.CreateUserManager();
		(await enrolling.AddOrUpdatePasskeyAsync(await PageUserAsync(enrolling, seeded.Id), NewPasskey(credentialId))).Succeeded
			.ShouldBeTrue();
		var userManager = _fixture.CreateUserManager();
		var user = await PageUserAsync(userManager, seeded.Id);
		var passkey = (await userManager.GetPasskeyAsync(user, credentialId)).ShouldNotBeNull();
		passkey.Name = "renamed";

		(await userManager.AddOrUpdatePasskeyAsync(user, passkey)).Succeeded.ShouldBeTrue();

		ShouldStillBeWritable(user);
		(await _fixture.CreateUserManager().GetPasskeyAsync(user, credentialId)).ShouldNotBeNull().Name.ShouldBe("renamed");
	}

	/// <summary>The password check can rehash and write; the erasure that follows never touches the store.</summary>
	async Task CheckPasswordAsync()
	{
		var seeded = await SeedAsync(withPassword: true);
		var userManager = _fixture.CreateUserManager();
		var user = await PageUserAsync(userManager, seeded.Id);

		(await userManager.CheckPasswordAsync(user, Password)).ShouldBeTrue();

		ShouldStillBeWritable(user);
	}

	/// <summary>A new user, created through the real manager, with or without <see cref="Password" />.</summary>
	async Task<NorseUser> SeedAsync(bool withPassword = false)
	{
		var email = NewEmail();
		NorseUser user = new() { UserName = email, Email = email };
		var userManager = _fixture.CreateUserManager();
		(await (withPassword ?
			userManager.CreateAsync(user, Password) :
			userManager.CreateAsync(user))).Succeeded.ShouldBeTrue();
		return user;
	}

	/// <summary>A user with a password, an authenticator key, two-factor on and ten recovery codes, set up as the pages do.</summary>
	async Task<(string Email, string[] Codes)> SeedTwoFactorAsync()
	{
		var seeded = await SeedAsync(withPassword: true);
		var userManager = _fixture.CreateUserManager();
		var user = await PageUserAsync(userManager, seeded.Id);
		(await userManager.ResetAuthenticatorKeyAsync(user)).Succeeded.ShouldBeTrue();
		(await userManager.SetTwoFactorEnabledAsync(user, true)).Succeeded.ShouldBeTrue();
		var codes = (await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10)).ShouldNotBeNull().ToArray();
		return (seeded.Email!, codes);
	}

	/// <summary>The instance a <c>/Account/Manage</c> page works on: <c>GetUserAsync</c> on the signed-in principal.</summary>
	static async Task<NorseUser> PageUserAsync(UserManager<NorseUser> userManager, Guid userId)
	{
		ClaimsPrincipal principal = new(new ClaimsIdentity(
			[new(userManager.Options.ClaimsIdentity.UserIdClaimType, userId.ToString())], "Test"));
		return (await userManager.GetUserAsync(principal)).ShouldNotBeNull();
	}

	/// <summary>
	///     A real sign-in manager over <paramref name="userManager" />, on a request context whose services can sign
	///     in, as a page's request has.
	/// </summary>
	NorseSignInManager SignIn(UserManager<NorseUser> userManager)
	{
		var scope = _fixture.CreateOwnedScope();
		_scopes.Add(scope);
		var signIn = _fixture.CreateSignInManager(userManager);
		signIn.Context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
		return signIn;
	}

	/// <summary>The challenge token the password step parked, as the handler carries it to the second-factor step.</summary>
	static string ChallengeToken(NorseSignInManager signIn) =>
		signIn.Context.Items[NorseSignInManager.TwoFactorChallengeItemName].ShouldBeOfType<string>();

	/// <summary>A fresh read of the user through a new scope's store.</summary>
	async Task<NorseUser> RereadAsync(Guid userId) =>
		(await _fixture.CreateUserStore().FindByIdAsync(userId.ToString(), Cancellation)).ShouldNotBeNull();

	/// <summary>The instance still carries its baseline: the store read or created it, and nothing poisoned it.</summary>
	static void ShouldStillBeWritable(NorseUser user) =>
		NorseUserStore.TryGetBaseline(user, out _).ShouldBeTrue("every instance a write path sees comes from a store read");

	static string NewEmail() =>
		$"scaffold-{Guid.NewGuid():N}@example.com";

	/// <summary>A newly attested passkey, as <c>PasskeyHandler</c> builds one.</summary>
	static UserPasskeyInfo NewPasskey(byte[] credentialId) =>
		new(credentialId, [1, 2, 3], DateTimeOffset.UtcNow, 0, ["internal"], true, false, false, [4], [5]);
}
