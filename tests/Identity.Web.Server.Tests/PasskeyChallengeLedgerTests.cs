using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The database ledger's own facts that need no database: the key it stores is the state's SHA-256, so distinct
///     states never share a row, and it is registered scoped, on the request's context. Consumption itself is pinned
///     on both providers by <see cref="ConsumedPasskeyChallengeSuite" />.
/// </summary>
public sealed class PasskeyChallengeLedgerTests
{
	[Fact]
	void Different_states_never_share_a_hash()
	{
		byte[] state = [1, 2, 3];

		var hash = PasskeyChallengeLedger.Hash(state);

		hash.ShouldBe(SHA256.HashData(state));
		hash.Length.ShouldBe(32);
		PasskeyChallengeLedger.Hash(new byte[] { 1, 2, 4 }).ShouldNotBe(hash);
		PasskeyChallengeLedger.Hash(new byte[] { 1, 2, 3, 0 }).ShouldNotBe(hash);
		PasskeyChallengeLedger.Hash(state).ShouldBe(hash);
	}

	[Fact]
	void Registered_scoped()
	{
		var builder = Host.CreateApplicationBuilder();
		builder.Configuration["ConnectionStrings:test"] = "Host=localhost;Database=norse_identity_test";
		using var certificate = IdentityTestCertificate.CreateFresh();

		builder.AddNorseAuthenticationService("test", certificate);

		var descriptor = builder.Services.Where(static d => d.ServiceType == typeof(IPasskeyChallengeLedger))
			.ShouldHaveSingleItem();
		descriptor.ImplementationType.ShouldBe(typeof(PasskeyChallengeLedger));
		descriptor.Lifetime.ShouldBe(ServiceLifetime.Scoped);
		builder.Services.ShouldContain(static d => d.ServiceType == typeof(TimeProvider));
	}
}
