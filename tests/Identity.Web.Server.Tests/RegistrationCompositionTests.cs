using FluentValidation;
using Microsoft.Extensions.DependencyInjection;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.Tests;

public sealed class RegistrationCompositionTests
{
	[Fact]
	void AddNorseAuthenticationService_registers_handlers_dispatch_entries_and_validators()
	{
		var services = new ServiceCollection();
		services.AddNorseAuthenticationService("Host=localhost;Database=test");

		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<LoginCommand, LoginResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<RegisterCommand, RegisterResult>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<LogoutCommand, LogoutResult>));
		services.Count(d => d.ServiceType == typeof(ISenderDispatch)).ShouldBe(3);

		// The generated CommandRequestValidator<TCommand,TWire,TResponse> adapters — emitted
		// uniformly for every wrapper command, LogoutCommand included even though no IValidator<Unit>
		// exists anywhere (an empty child collection validates clean; absence is a pass).
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<LoginCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RegisterCommand>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<LogoutCommand>));

		// Heimdall's real wire validators — registered under IValidator<TWire> so the adapters above
		// have something to resolve and run.
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<LoginRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RegisterRequest>));
	}
}
