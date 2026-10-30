using System.Collections.Immutable;
using Norse.Abstractions.Contracts;
using OpenIddict.Abstractions;

namespace Norse.Identity.Outcomes;

/// <summary>
///     <c>applicationManager.Outcome</c> (2026-10-24 explicit-writes spec §4.12): the stock
///     <see cref="IOpenIddictApplicationManager" />, answering <see cref="Outcome{T}" /> through
///     <see cref="IdentityOutcomeMap" />. A <see langword="null" /> answer is <see cref="ErrorCategory.NotFound" />;
///     concurrency is <see cref="ErrorCategory.Conflict" />; OpenIddict's other failures are
///     <see cref="ErrorCategory.Fault" />. Each method keeps the name of the manager method it wraps.
/// </summary>
/// <param name="manager">The manager this view wraps.</param>
public sealed class OpenIddictApplicationManagerOutcomeView(IOpenIddictApplicationManager manager)
{
	/// <summary>Wraps <see cref="IOpenIddictApplicationManager.FindByClientIdAsync" />.</summary>
	/// <param name="identifier">The client id.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	public ValueTask<Outcome<object>> FindByClientIdAsync(string identifier,
		CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
			Found(await manager.FindByClientIdAsync(identifier, cancellationToken).ConfigureAwait(false)));

	/// <summary>Wraps <see cref="IOpenIddictApplicationManager.GetIdAsync" />.</summary>
	/// <param name="application">The application.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	public ValueTask<Outcome<string>> GetIdAsync(object application, CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
			Found(await manager.GetIdAsync(application, cancellationToken).ConfigureAwait(false)));

	/// <summary>Wraps <see cref="IOpenIddictApplicationManager.CreateAsync(OpenIddictApplicationDescriptor, CancellationToken)" />.</summary>
	/// <param name="descriptor">The application to create.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	public ValueTask<Outcome<object>> CreateAsync(OpenIddictApplicationDescriptor descriptor,
		CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
			Outcome<object>.Ok(await manager.CreateAsync(descriptor, cancellationToken).ConfigureAwait(false)));

	/// <summary>Wraps <see cref="IOpenIddictApplicationManager.ValidateClientSecretAsync" />.</summary>
	/// <param name="application">The application.</param>
	/// <param name="secret">The secret to validate.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	public ValueTask<Outcome<bool>> ValidateClientSecretAsync(object application, string secret,
		CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () => Outcome<bool>.Ok(
			await manager.ValidateClientSecretAsync(application, secret, cancellationToken).ConfigureAwait(false)));

	/// <summary>Wraps <see cref="IOpenIddictApplicationManager.GetPermissionsAsync" />.</summary>
	/// <param name="application">The application.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	public ValueTask<Outcome<ImmutableArray<string>>> GetPermissionsAsync(object application,
		CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () => Outcome<ImmutableArray<string>>.Ok(
			await manager.GetPermissionsAsync(application, cancellationToken).ConfigureAwait(false)));

	/// <summary>Wraps <see cref="IOpenIddictApplicationManager.GetClientTypeAsync" />.</summary>
	/// <param name="application">The application.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	public ValueTask<Outcome<string>> GetClientTypeAsync(object application,
		CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
			Found(await manager.GetClientTypeAsync(application, cancellationToken).ConfigureAwait(false)));

	/// <summary>Wraps <see cref="IOpenIddictApplicationManager.GetConsentTypeAsync" />.</summary>
	/// <param name="application">The application.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	public ValueTask<Outcome<string>> GetConsentTypeAsync(object application,
		CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
			Found(await manager.GetConsentTypeAsync(application, cancellationToken).ConfigureAwait(false)));

	/// <summary>Wraps <see cref="IOpenIddictApplicationManager.GetDisplayNameAsync" />.</summary>
	/// <param name="application">The application.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	public ValueTask<Outcome<string>> GetDisplayNameAsync(object application,
		CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
			Found(await manager.GetDisplayNameAsync(application, cancellationToken).ConfigureAwait(false)));

	/// <summary>
	///     Wraps <see cref="IOpenIddictApplicationManager.PopulateAsync(OpenIddictApplicationDescriptor, object, CancellationToken)" />.
	/// </summary>
	/// <param name="descriptor">The descriptor to fill.</param>
	/// <param name="application">The application to read.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	public ValueTask<Outcome<Unit>> PopulateAsync(OpenIddictApplicationDescriptor descriptor, object application,
		CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
		{
			await manager.PopulateAsync(descriptor, application, cancellationToken).ConfigureAwait(false);
			return Outcome<Unit>.Ok(Unit.Value);
		});

	/// <summary>
	///     Wraps <see cref="IOpenIddictApplicationManager.UpdateAsync(object, OpenIddictApplicationDescriptor, CancellationToken)" />.
	/// </summary>
	/// <param name="application">The application to update.</param>
	/// <param name="descriptor">Its new state.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	public ValueTask<Outcome<Unit>> UpdateAsync(object application, OpenIddictApplicationDescriptor descriptor,
		CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
		{
			await manager.UpdateAsync(application, descriptor, cancellationToken).ConfigureAwait(false);
			return Outcome<Unit>.Ok(Unit.Value);
		});

	static Outcome<T> Found<T>(T? value)
		where T : class =>
		value is null ?
			Outcome<T>.Err(ErrorCategory.NotFound) :
			Outcome<T>.Ok(value);
}
