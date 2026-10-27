using Norse.Abstractions.Contracts;
using FluentValidation;
using Microsoft.Extensions.Hosting;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.Web.Server.Disclosure;

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
		services.Count(d => d.ServiceType == typeof(ISenderDispatch)).ShouldBe(13);

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
	}
}
