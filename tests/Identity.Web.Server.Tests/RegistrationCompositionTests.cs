using System.Security.Claims;
using Norse.Abstractions.Contracts;
using FluentValidation;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Infrastructure.Web.Server.Mediator;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.Disclosure;
using Norse.Identity.Web.Server.Passkeys;
using Norse.Identity.Web.Server.SignInMethods;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests;

public sealed class RegistrationCompositionTests
{
	[Fact]
	void AddNorseAuthenticationService_registers_handlers_dispatch_entries_and_validators()
	{
		var builder = Host.CreateApplicationBuilder();
		builder.Configuration["ConnectionStrings:test"] = "Host=localhost;Database=test";
		using var certificate = IdentityTestCertificate.CreateFresh();

		builder.AddNorseAuthenticationService("test", certificate);
		var services = builder.Services;

		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<LoginCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<RegisterCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<LogoutCommand, NavigationResult>));
		services.ShouldContain(d =>
			d.ServiceType == typeof(IRequestHandler<EmailExistsCommand, Norse.Abstractions.Contracts.BoolResponse>));
		services.ShouldContain(d =>
			d.ServiceType == typeof(IRequestHandler<GetMyPersonalDataCommand, PersonalDataResponse>));
		services.ShouldContain(d =>
			d.ServiceType == typeof(IRequestHandler<MaskedPersonalDataCommand, MaskedPersonalDataResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<TwoFactorSignInCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<RecoveryCodeSignInCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<ForgotPasswordCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<ResetPasswordCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<ConfirmEmailCommand, Norse.Abstractions.Contracts.BoolResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<ConfirmEmailChangeCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<ResendEmailConfirmationCommand, Norse.Abstractions.Contracts.BoolResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<GetAccountStatusCommand, AccountStatusResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<SetPhoneNumberCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<ChangePasswordCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<SetPasswordCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<ChangeEmailCommand, Norse.Abstractions.Contracts.BoolResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<GetExternalLoginsCommand, ExternalLoginsResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<RemoveExternalLoginCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<DeletePersonalDataCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<GetAuthenticatorSetupCommand, AuthenticatorSetupResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<EnableAuthenticatorCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<RevealRecoveryCodesCommand, RecoveryCodesResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<ResetAuthenticatorCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<DisableTwoFactorCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<GenerateRecoveryCodesCommand, RecoveryCodesResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<ForgetTwoFactorClientCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<GetPasskeysCommand, PasskeysResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<GetPasskeyCommand, PasskeyEntry>));
		services.ShouldContain(d =>
			d.ServiceType == typeof(IRequestHandler<GetPasskeyCreationOptionsCommand, PasskeyCreationOptionsResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<AddPasskeyCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<RenamePasskeyCommand, NavigationResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<RemovePasskeyCommand, BoolResponse>));
		services.ShouldContain(d =>
			d.ServiceType == typeof(IRequestHandler<GetPasskeyRequestOptionsCommand, PasskeyRequestOptionsResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<PasskeySignInCommand, NavigationResult>));
		services.Count(d => d.ServiceType == typeof(ISenderDispatch)).ShouldBe(37);

		// The generated CommandRequestValidator<TCommand,TWire,TResponse> adapters — emitted
		// uniformly for every wrapper command, LogoutCommand/GetMyPersonalDataCommand/
		// EmailExistsCommand included even though no IValidator<Unit>/
		// IValidator<GetMyPersonalDataRequest>/IValidator<EmailExistsRequest> exists anywhere (an
		// empty child collection validates clean; absence is a pass).
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<LoginCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RegisterCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<LogoutCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<EmailExistsCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<GetMyPersonalDataCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<MaskedPersonalDataCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<TwoFactorSignInCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RecoveryCodeSignInCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<ForgotPasswordCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<ResetPasswordCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<ConfirmEmailCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<ConfirmEmailChangeCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<ResendEmailConfirmationCommand>));

		// Heimdall's real wire validators — registered under IValidator<TWire> so the adapters above
		// have something to resolve and run.
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<LoginRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RegisterRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<GetMaskedPersonalDataRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<TwoFactorSignInRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RecoveryCodeSignInRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<ForgotPasswordRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<ResetPasswordRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<ConfirmEmailRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<ConfirmEmailChangeRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<ResendEmailConfirmationRequest>));

		// Train 3 (the 4.10 carry): server-side validation on the wire path is the train's premise, so every Train 3
		// command that carries a wire request has its adapter, and each of the seven Heimdall wire validators is there
		// for it to run. GetSignInMethodsRequest has no validator: its one member is a returnUrl ReturnUrls.Resolve judges.
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<EnableAuthenticatorCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RevealRecoveryCodesCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<GetPasskeyCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<AddPasskeyCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RenamePasskeyCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RemovePasskeyCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<GetSignInMethodsCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<PasskeySignInCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<EnableAuthenticatorRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RevealRecoveryCodesRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<GetPasskeyRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<AddPasskeyRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RenamePasskeyRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RemovePasskeyRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<PasskeySignInRequest>));
	}

	// The registrations above prove the validators are there; this proves the real pipeline runs one before the handler:
	// an empty passkey name is refused as Validation, and the handler never reads the caller.
	[Fact]
	async Task A_rename_with_an_invalid_name_answers_Validation_without_reaching_the_handler()
	{
		using var userManager = MockUserManager.Create();
		var builder = Host.CreateApplicationBuilder();
		builder.Services
			.AddNorsePipeline()
			.AddNorseIdentityWebServerHandlers()
			.AddAuthorization(options =>
				options.AddPolicy(AuthNPolicies.Account, policy => policy.RequireAssertion(_ => true)))
			.AddSingleton<AuthenticationStateProvider, AnonymousAuthenticationStateProvider>()
			.AddHttpContextAccessor()
			.AddScoped<AccountCaller>()
			.AddScoped(_ => userManager);
		using var host = builder.Build();
		using var scope = host.Services.CreateScope();
		var sender = scope.ServiceProvider.GetRequiredService<ISender>();

		var outcome = await sender.Send(new RenamePasskeyCommand(new RenamePasskeyRequest
		{
			CredentialId = "AQID",
			Name = ""
		}), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Validation);
		failed.Problem.Errors.Keys.ShouldContain(nameof(RenamePasskeyRequest.Name));
		await userManager.DidNotReceiveWithAnyArgs().GetUserAsync(default!);
		await userManager.DidNotReceiveWithAnyArgs().AddOrUpdatePasskeyAsync(default!, default!);
	}

	// Satisfies the pipeline's principal accessor; the Account policy above accepts any principal.
	sealed class AnonymousAuthenticationStateProvider : AuthenticationStateProvider
	{
		public override Task<AuthenticationState> GetAuthenticationStateAsync() =>
			Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));
	}
}
