using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry.Metrics;
using System.Diagnostics.Metrics;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

public sealed class ServiceCollectionExtensionsTests
{
	[Fact]
	void AddNorseAuthenticationService_registers_NorseSignInManager_as_SignInManager()
	{
		ServiceCollection services = new();

		services.AddNorseAuthenticationService("Host=localhost;Database=norse_identity_test");

		var descriptor = services.LastOrDefault(d => d.ServiceType == typeof(SignInManager<NorseUser>));
		descriptor.ShouldNotBeNull();
		descriptor.ImplementationType.ShouldBe(typeof(NorseSignInManager));
	}

	[Fact]
	void AddNorseAuthenticationService_registers_the_no_op_email_sender()
	{
		// IEmailSender<NorseUser> is closed over an entity the host has no business naming -- this
		// registration is what lets Yggdrasil's composition root stay clear of Identity.EntityFramework.
		ServiceCollection services = new();

		services.AddNorseAuthenticationService("Host=localhost;Database=norse_identity_test");

		var descriptor = services.LastOrDefault(d => d.ServiceType == typeof(IEmailSender<NorseUser>));
		descriptor.ShouldNotBeNull();
		descriptor.ImplementationType.ShouldBe(typeof(IdentityNoOpEmailSender));
	}

	[Fact]
	void AddNorseAuthenticationService_subscribes_the_aspnet_identity_meter()
	{
		List<Metric> exported = [];
		ServiceCollection services = new();
		services.AddLogging();
		services.AddNorseAuthenticationService("Host=localhost;Database=norse_identity_test");
		services.AddOpenTelemetry().WithMetrics(metrics => metrics.AddInMemoryExporter(exported));

		using var provider = services.BuildServiceProvider();
		var meterProvider = provider.GetRequiredService<MeterProvider>();
		using Meter meter = new("Microsoft.AspNetCore.Identity");
		meter.CreateCounter<long>("identity_probe").Add(1);
		meterProvider.ForceFlush();

		exported.ShouldContain(m => m.Name == "identity_probe");
	}
}
