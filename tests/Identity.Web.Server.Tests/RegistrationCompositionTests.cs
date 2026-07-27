using FluentValidation;
using Microsoft.Extensions.DependencyInjection;
using Norse.Abstractions.Contracts;
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

		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<LoginRequest, BoolResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<RegisterRequest, BoolResponse>));
		services.ShouldContain(d => d.ServiceType == typeof(IRequestHandler<LogoutRequest, Unit>));
		services.Count(d => d.ServiceType == typeof(ISenderDispatch)).ShouldBe(3);
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<LoginRequest>));
		services.ShouldContain(d => d.ServiceType == typeof(IValidator<RegisterRequest>));
	}
}
