using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

public sealed class IdentityBuilderExtensionsTests
{
	[Fact]
	void AddNorseIdentity_registers_NorseUserStore_as_IUserStore()
	{
		ServiceCollection services = new();
		using var certificate = IdentityTestCertificate.CreateFresh();

		services.AddNorseIdentity(certificate);

		var descriptor = services.FirstOrDefault(d => d.ServiceType == typeof(IUserStore<NorseUser>));
		descriptor.ShouldNotBeNull();
		descriptor.ImplementationType.ShouldBe(typeof(NorseUserStore));
	}

	[Fact]
	void AddNorseIdentity_returns_the_identity_builder_wrapping_the_same_services()
	{
		ServiceCollection services = new();
		using var certificate = IdentityTestCertificate.CreateFresh();

		var result = services.AddNorseIdentity(certificate);

		result.Services.ShouldBeSameAs(services);
	}

	[Fact]
	void AddNorseIdentity_configures_SchemaVersion_to_Version3()
	{
		ServiceCollection services = new();
		services.AddDbContext<NorseIdentityDbContext>(o => o.UseSqlite("Data Source=:memory:"));
		using var certificate = IdentityTestCertificate.CreateFresh();

		services.AddNorseIdentity(certificate);

		using var provider = services.BuildServiceProvider();
		var options = provider.GetRequiredService<IOptions<IdentityOptions>>();

		options.Value.Stores.SchemaVersion.ShouldBe(IdentitySchemaVersions.Version3);
	}

	/// <summary>
	///     T3-33: without user verification a PIN-less key is possession only. The option is pinned explicitly (RC3's
	///     default happens to agree), and the real handler's creation and request options carry it to the browser.
	/// </summary>
	[Fact]
	async Task User_verification_is_required_for_passkeys()
	{
		ServiceCollection services = new();
		using var certificate = IdentityTestCertificate.CreateFresh();
		services.AddNorseIdentity(certificate);
		using var provider = services.BuildServiceProvider();
		var options = provider.GetRequiredService<IOptions<IdentityPasskeyOptions>>();
		using var userManager = MockUserManager.Create();
		PasskeyHandler<NorseUser> handler = new(userManager, options);
		DefaultHttpContext context = new();
		context.Request.Host = new HostString("example.test");

		var creation = await handler.MakeCreationOptionsAsync(
			new() { Id = Guid.CreateVersion7().ToString(), Name = "user@example.com", DisplayName = "user@example.com" },
			context);
		var request = await handler.MakeRequestOptionsAsync(null, context);

		options.Value.UserVerificationRequirement.ShouldBe("required");
		creation.CreationOptionsJson.ShouldContain("\"userVerification\":\"required\"");
		request.RequestOptionsJson.ShouldContain("\"userVerification\":\"required\"");
	}

	// Enforced through PostConfigure, so a host's own later Configure cannot relax it.
	[Fact]
	void A_host_configure_cannot_relax_user_verification()
	{
		ServiceCollection services = new();
		using var certificate = IdentityTestCertificate.CreateFresh();
		services.AddNorseIdentity(certificate);
		services.Configure<IdentityPasskeyOptions>(o => o.UserVerificationRequirement = "preferred");
		using var provider = services.BuildServiceProvider();

		provider.GetRequiredService<IOptions<IdentityPasskeyOptions>>().Value.UserVerificationRequirement.ShouldBe("required");
	}
}
