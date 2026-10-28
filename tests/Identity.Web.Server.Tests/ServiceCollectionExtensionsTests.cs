using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Metrics;
using System.Diagnostics.Metrics;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;

namespace Norse.Identity.Web.Server.Tests;

public sealed class ServiceCollectionExtensionsTests
{
	const string Email = "u@example.test";
	const string ResetLink = "https://example.test/reset?code=SECRET-LINK";
	const string ConfirmationLink = "https://example.test/confirm?code=SECRET-CONFIRM";
	const string ResetCode = "SECRET-CODE";

	static HostApplicationBuilder CreateBuilder(string connectionString = "Host=localhost;Database=norse_identity_test")
	{
		var builder = Host.CreateApplicationBuilder();
		builder.Configuration["ConnectionStrings:test"] = connectionString;
		return builder;
	}

	/// <summary>The services of a host in <paramref name="environment" />, every record they log collected.</summary>
	static ServiceProvider BuildServices(string environment)
	{
		var builder = Host.CreateEmptyApplicationBuilder(new() { EnvironmentName = environment });
		builder.Configuration["ConnectionStrings:test"] = "Host=localhost;Database=norse_identity_test";
		using var certificate = IdentityTestCertificate.CreateFresh();

		builder.AddNorseAuthenticationService("test", certificate);
		builder.Services.AddLogging(logging => logging.AddFakeLogging());

		return builder.Services.BuildServiceProvider();
	}

	static async Task SendAllAsync(IEmailSender<NorseUser> sender)
	{
		NorseUser user = new();
		await sender.SendPasswordResetLinkAsync(user, Email, ResetLink);
		await sender.SendConfirmationLinkAsync(user, Email, ConfirmationLink);
		await sender.SendPasswordResetCodeAsync(user, Email, ResetCode);
	}

	[Fact]
	void AddNorseAuthenticationService_registers_NorseSignInManager_as_SignInManager()
	{
		var builder = CreateBuilder();
		using var certificate = IdentityTestCertificate.CreateFresh();

		builder.AddNorseAuthenticationService("test", certificate);

		var descriptor = builder.Services.LastOrDefault(d => d.ServiceType == typeof(SignInManager<NorseUser>));
		descriptor.ShouldNotBeNull();
		descriptor.ImplementationType.ShouldBe(typeof(NorseSignInManager));
	}

	[Fact]
	void Registers_the_account_service_as_scoped()
	{
		var builder = CreateBuilder();
		using var certificate = IdentityTestCertificate.CreateFresh();

		builder.AddNorseAuthenticationService("test", certificate);

		var descriptor = builder.Services.LastOrDefault(static d => d.ServiceType == typeof(IAccountService));
		descriptor.ShouldNotBeNull();
		descriptor.ImplementationType.ShouldBe(typeof(AccountService));
		descriptor.Lifetime.ShouldBe(ServiceLifetime.Scoped);
	}

	[Fact]
	async Task Under_Development_the_sender_logs_every_link_and_code()
	{
		using var services = BuildServices(Environments.Development);
		var sender = services.GetRequiredService<IEmailSender<NorseUser>>();

		await SendAllAsync(sender);

		sender.ShouldBeOfType<DevelopmentEmailSender>();
		var messages = services.GetFakeLogCollector().GetSnapshot().Select(static r => r.Message).ToList();
		messages.Count.ShouldBe(3);
		messages.ShouldContain(static m => m.Contains(ResetLink, StringComparison.Ordinal));
		messages.ShouldContain(static m => m.Contains(ConfirmationLink, StringComparison.Ordinal));
		messages.ShouldContain(static m => m.Contains(ResetCode, StringComparison.Ordinal));
	}

	[Theory]
	[InlineData("Production")]
	[InlineData("Staging")]
	async Task Outside_Development_nothing_token_bearing_is_logged(string environment)
	{
		// The sender is registered for every host, and Midgard's service defaults export formatted logs through
		// OpenTelemetry: a reset link, a reset code or a confirmation link logged here would leave the process.
		using var services = BuildServices(environment);
		var sender = services.GetRequiredService<IEmailSender<NorseUser>>();

		await SendAllAsync(sender);

		sender.ShouldBeOfType<IdentityNoOpEmailSender>();
		var logged = string.Join("\n", services.GetFakeLogCollector().GetSnapshot().Select(static r => r.Message));
		logged.ShouldNotContain("SECRET-LINK");
		logged.ShouldNotContain("SECRET-CONFIRM");
		logged.ShouldNotContain("SECRET-CODE");
		logged.ShouldNotContain(Email);
	}

	[Fact]
	void AddNorseAuthenticationService_subscribes_the_aspnet_identity_meter()
	{
		List<Metric> exported = [];
		var builder = CreateBuilder();
		using var certificate = IdentityTestCertificate.CreateFresh();

		builder.AddNorseAuthenticationService("test", certificate);
		builder.Services.AddOpenTelemetry().WithMetrics(metrics => metrics.AddInMemoryExporter(exported));

		using var host = builder.Build();
		var meterProvider = host.Services.GetRequiredService<MeterProvider>();
		using Meter meter = new("Microsoft.AspNetCore.Identity");
		meter.CreateCounter<long>("identity_probe").Add(1);
		meterProvider.ForceFlush();

		exported.ShouldContain(m => m.Name == "identity_probe");
	}
}
