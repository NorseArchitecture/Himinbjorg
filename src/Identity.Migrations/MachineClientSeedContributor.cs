using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Migrations.Seeding;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using OpenIddict.Abstractions;

namespace Norse.Identity.Migrations;

/// <summary>
///     Seeds the platform's one machine client (Himinbjorg#49) — the seeded application every
///     client_credentials caller authenticates as until #51/#53 add more. Idempotent by reconciliation,
///     not by skip-if-exists: an unconditional re-hash on every run would rewrite the stored secret hash
///     even when the configured secret has not changed (<see cref="IOpenIddictApplicationManager" />
///     salts on write), so the secret is validated before it is ever replaced.
/// </summary>
/// <param name="configuration">Configuration — reads <c>OIDC_MACHINE_CLIENT_SECRET</c>.</param>
/// <param name="applicationManager">Resolved via <see cref="ConfigureServices" />.</param>
public sealed class MachineClientSeedContributor(
	IConfiguration configuration,
	IOpenIddictApplicationManager applicationManager) : ISeedContributor
{
	internal const string ClientId = "norse-machine";
	internal const string DisplayName = "Norse Machine Client";

	static readonly HashSet<string> _requiredPermissions =
	[
		OpenIddictConstants.Permissions.Endpoints.Token,
		OpenIddictConstants.Permissions.GrantTypes.ClientCredentials
	];

	/// <inheritdoc />
	public string Name => "Norse.Identity.MachineClient";

	/// <inheritdoc />
	public static void ConfigureServices(IServiceCollection services) =>
		services.AddNorseOpenIddictCore();

	/// <inheritdoc />
	public async Task SeedAsync(CancellationToken cancellationToken)
	{
		var secret = configuration["OIDC_MACHINE_CLIENT_SECRET"] ??
			throw new InvalidOperationException("Configuration value 'OIDC_MACHINE_CLIENT_SECRET' is not configured.");

		var view = applicationManager.Outcome;
		var found = await view.FindByClientIdAsync(ClientId, cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed missing))
		{
			if (missing.Problem.Category is not ErrorCategory.NotFound)
				throw SeedingFailed(missing.Problem);
			Required(await view.CreateAsync(BuildDescriptor(secret), cancellationToken).ConfigureAwait(false));
			return;
		}

		var application = Required(found);
		var secretStillValid = Required(await view.ValidateClientSecretAsync(application, secret, cancellationToken)
			.ConfigureAwait(false));
		var permissions = Required(await view.GetPermissionsAsync(application, cancellationToken).ConfigureAwait(false));
		var clientTypeMatches = Matches(await view.GetClientTypeAsync(application, cancellationToken)
			.ConfigureAwait(false), OpenIddictConstants.ClientTypes.Confidential);
		var displayNameMatches = Matches(await view.GetDisplayNameAsync(application, cancellationToken)
			.ConfigureAwait(false), DisplayName);

		var permissionsMatch = permissions.ToHashSet().SetEquals(_requiredPermissions);

		if (secretStillValid && permissionsMatch && clientTypeMatches && displayNameMatches)
			return; // Nothing differs -- no write.

		var descriptor = await BuildUpdateDescriptorAsync(application, secretStillValid ? null : secret,
			cancellationToken).ConfigureAwait(false);
		Required(await view.UpdateAsync(application, descriptor, cancellationToken).ConfigureAwait(false));
	}

	/// <summary>
	///     The success value; a failure fails the seed, which runs in the migrations job (startup, where a failure
	///     is an exception by law), never in a request.
	/// </summary>
	static T Required<T>(Outcome<T> outcome)
		where T : notnull =>
		outcome.Match(static value => value, static problem => throw SeedingFailed(problem));

	/// <summary>Whether a stored value equals <paramref name="expected" />; an absent one never does.</summary>
	static bool Matches(Outcome<string> stored, string expected) =>
		stored.Match(
			value => string.Equals(value, expected, StringComparison.Ordinal),
			static problem => problem.Category is ErrorCategory.NotFound ?
				false :
				throw SeedingFailed(problem));

	static InvalidOperationException SeedingFailed(Problem problem) =>
		new($"Seeding the machine client '{ClientId}' failed ({problem.Category}): {string.Join("; ", problem.Errors.Values.SelectMany(static messages => messages))}");

	static OpenIddictApplicationDescriptor BuildDescriptor(string secret)
	{
		OpenIddictApplicationDescriptor descriptor = new()
		{
			ClientId = ClientId,
			ClientSecret = secret,
			ClientType = OpenIddictConstants.ClientTypes.Confidential,
			DisplayName = DisplayName
		};
		foreach (var permission in _requiredPermissions)
			descriptor.Permissions.Add(permission);
		return descriptor;
	}

	/// <summary>
	///     Builds the descriptor for the reconcile-update path. <see cref="IOpenIddictApplicationManager" />
	///     exposes no <c>GetClientSecretAsync</c> -- the only way to tell <c>UpdateAsync</c> "the secret is
	///     unchanged" is to hand back the value it already has, and the only way to read that value back is
	///     <see cref="IOpenIddictApplicationManager.PopulateAsync(OpenIddictApplicationDescriptor,object,CancellationToken)" />,
	///     which fills <c>descriptor.ClientSecret</c> from the application's own stored hash (among every
	///     other current field). Passing <see langword="null" /> instead -- the prior bug -- reads to
	///     <c>PopulateAsync</c>/<c>UpdateAsync</c> as "clear the secret," which
	///     <c>OpenIddictExceptions.ValidationException</c> (<c>ID2113</c>) then rejects for a confidential
	///     client. <paramref name="rotatedSecret" /> overrides the populated (unchanged) value only when the
	///     secret genuinely needs replacing.
	/// </summary>
	async Task<OpenIddictApplicationDescriptor> BuildUpdateDescriptorAsync(object application,
		string? rotatedSecret, CancellationToken cancellationToken)
	{
		OpenIddictApplicationDescriptor descriptor = new();
		Required(await applicationManager.Outcome.PopulateAsync(descriptor, application, cancellationToken)
			.ConfigureAwait(false));

		descriptor.ClientType = OpenIddictConstants.ClientTypes.Confidential;
		descriptor.DisplayName = DisplayName;
		descriptor.Permissions.Clear();
		foreach (var permission in _requiredPermissions)
			descriptor.Permissions.Add(permission);

		if (rotatedSecret is not null)
			descriptor.ClientSecret = rotatedSecret;

		return descriptor;
	}
}
