namespace Norse.Identity.Migrations.Tests;

/// <summary>
///     The dependency graph (2026-10-24 explicit-writes spec §4.12): the migrations service takes the OpenIddict
///     <c>.Outcome</c> view from the non-web <c>Identity.Outcomes</c>, so it never acquires <c>Identity.Web.Server</c> or
///     the ASP.NET Core framework.
/// </summary>
public sealed class MigrationsAssemblyGraphTests
{
	[Fact]
	void Migration_assembly_does_not_reference_Identity_Web_Server_or_AspNetCore()
	{
		string[] references =
		[
			.. typeof(MachineClientSeedContributor).Assembly
				.GetReferencedAssemblies()
				.Select(static reference => reference.Name!)
		];

		references.ShouldContain("Norse.Identity.Outcomes");
		references.ShouldNotContain("Norse.Identity.Web.Server");
		references.ShouldNotContain(static name => name.StartsWith("Microsoft.AspNetCore.", StringComparison.Ordinal));
	}
}
