using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The one throwaway self-signed certificate every test in this project needs to satisfy
///     <c>AddNorseIdentity</c>/<c>AddNorseAuthenticationService</c>'s OpenIddict server/validation
///     wiring, which requires a real signing/encryption certificate with a private key even when a test
///     only asserts on DI registration shape. Found duplicated four times (<see cref="PostgresIdentityFixture" />,
///     <c>IdentityBuilderExtensionsTests</c>, <c>ServiceCollectionExtensionsTests</c>,
///     <c>RegistrationCompositionTests</c>) by the same review that fixed Himinbjörg#49's reconcile bug;
///     this is that one helper. Mirrors Yggdrasil's <c>MachineAuthTestCertificate</c>
///     (<c>Hosting.Web.Server.Tests/Authentication</c>) in shape -- this realm's own copy, not a NorseRef
///     to another realm's test project.
/// </summary>
static class IdentityTestCertificate
{
	/// <summary>A freshly generated, throwaway self-signed certificate with a private key.</summary>
	internal static X509Certificate2 CreateFresh()
	{
		using var rsa = RSA.Create(2048);
		var request = new CertificateRequest("CN=Norse Identity Tests", rsa, HashAlgorithmName.SHA256,
			RSASignaturePadding.Pkcs1);
		return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
	}
}
