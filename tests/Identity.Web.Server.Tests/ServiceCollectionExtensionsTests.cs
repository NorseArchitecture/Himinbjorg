using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Metrics;
using System.Diagnostics.Metrics;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.OpenIddict;
using Norse.Identity.Web.Server.Passkeys;
using Norse.Identity.Web.Server.SignInMethods;
using Norse.Identity.Web.Server.TwoFactor;

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

	[Theory]
	[InlineData(typeof(ITwoFactorService), typeof(TwoFactorService))]
	[InlineData(typeof(IPasskeyService), typeof(PasskeyService))]
	[InlineData(typeof(ISignInMethodsService), typeof(SignInMethodsService))]
	[InlineData(typeof(AccountCaller), typeof(AccountCaller))]
	void Registers_the_train_3_services_and_the_account_caller_as_scoped(Type service, Type implementation)
	{
		var builder = CreateBuilder();
		using var certificate = IdentityTestCertificate.CreateFresh();

		builder.AddNorseAuthenticationService("test", certificate);

		var descriptor = builder.Services.LastOrDefault(d => d.ServiceType == service);
		descriptor.ShouldNotBeNull();
		descriptor.ImplementationType.ShouldBe(implementation);
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

	// One marker protector serves the stamp point and the authorize endpoint (spec §5.2), so NorseSignInManager takes it
	// from DI rather than building its own.
	[Fact]
	void Registers_one_reauth_marker_protector_the_sign_in_manager_takes()
	{
		var builder = CreateBuilder();
		using var certificate = IdentityTestCertificate.CreateFresh();

		builder.AddNorseAuthenticationService("test", certificate);

		builder.Services.Where(static d => d.ServiceType == typeof(ReauthMarkers)).ShouldHaveSingleItem()
			.Lifetime.ShouldBe(ServiceLifetime.Singleton);
		typeof(NorseSignInManager).GetConstructors().ShouldHaveSingleItem().GetParameters()
			.Select(static parameter => parameter.ParameterType).ShouldContain(typeof(ReauthMarkers));
	}

	// PF1, closed by Task 4.5: production DI registers the one GrantTermination per scope, and both grant-boundary handlers take
	// it by constructor, never from a locator.
	[Fact]
	void The_grant_boundary_handlers_take_the_production_grant_termination()
	{
		using var provider = BuildServices(Environments.Production);
		using var scope = provider.CreateScope();

		scope.ServiceProvider.GetRequiredService<IGrantTermination>().ShouldBeOfType<GrantTermination>();
		scope.ServiceProvider.GetRequiredService<EndGrantOnReuse>().ShouldNotBeNull();
		scope.ServiceProvider.GetRequiredService<RedeemTokenEntryGuarded>().ShouldNotBeNull();
		foreach (var handler in (Type[])[typeof(EndGrantOnReuse), typeof(RedeemTokenEntryGuarded)])
			handler.GetConstructors().ShouldHaveSingleItem().GetParameters()
				.Select(static parameter => parameter.ParameterType).ShouldContain(typeof(IGrantTermination));
	}
}
