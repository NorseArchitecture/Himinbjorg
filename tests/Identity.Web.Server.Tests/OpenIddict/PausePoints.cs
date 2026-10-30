using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Norse.Identity.Web.Server.OpenIddict;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     The named points a token or revocation request can be held at (2026-10-29 OpenIddict spec §10.7: deterministic
///     interleavings, never two requests released at one barrier).
/// </summary>
enum PausePoint
{
	/// <summary>Not a pause point.</summary>
	None = 0,

	/// <summary>On the token endpoint's sign-in, immediately before the redemption handler.</summary>
	BeforeRedemption = 1,

	/// <summary>On the token endpoint's sign-in, immediately after the redemption handler, before <c>GenerateRefreshToken</c>.</summary>
	AfterRedemption = 2,

	/// <summary>
	///     On a token or revocation request's token validation, before <c>ValidateTokenEntry</c> and before
	///     <see cref="EndGrantOnReuse" />, which sits at the one order between the two.
	/// </summary>
	BeforeValidateTokenEntry = 3
}

/// <summary>A request held at a pause point.</summary>
sealed class Pause
{
	readonly TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
	readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);

	/// <summary>Completes when a request reaches the point.</summary>
	public Task Reached => _reached.Task;

	/// <summary>Lets the held request continue.</summary>
	public void Release() =>
		_released.TrySetResult();

	internal Task HoldAsync(CancellationToken cancellationToken)
	{
		_reached.TrySetResult();
		return _released.Task.WaitAsync(cancellationToken);
	}
}

/// <summary>
///     The armed pauses of one host: each holds exactly one request, the first token or revocation request to reach its
///     point after it was armed. Every token or revocation request that passes a point, held or not, is journaled.
/// </summary>
sealed class PausePoints
{
	readonly ConcurrentDictionary<PausePoint, Pause> _armed = new();
	readonly ConcurrentQueue<Pause> _all = new();
	readonly ConcurrentQueue<PausePoint> _passed = new();

	/// <summary>Every point a token or revocation request reached, in order.</summary>
	public IReadOnlyList<PausePoint> Passed => [.. _passed];

	/// <summary>Registers the three points' handlers on <paramref name="server" />, at their orders.</summary>
	/// <param name="server">The server builder.</param>
	public void Register(OpenIddictServerBuilder server) =>
		server
			.AddEventHandler<ProcessSignInContext>(handler => handler
				.UseInlineHandler(context => HoldAsync(PausePoint.BeforeRedemption, context))
				.SetOrder(RedeemTokenEntryGuarded.Descriptor.Order - 1))
			.AddEventHandler<ProcessSignInContext>(handler => handler
				.UseInlineHandler(context => HoldAsync(PausePoint.AfterRedemption, context))
				.SetOrder(RedeemTokenEntryGuarded.Descriptor.Order + 1))
			.AddEventHandler<ValidateTokenContext>(handler => handler
				.UseInlineHandler(context => HoldAsync(PausePoint.BeforeValidateTokenEntry, context))
				.SetOrder(EndGrantOnReuse.Descriptor.Order - 1));

	/// <summary>Holds the next request that reaches <paramref name="point" /> until the returned pause is released.</summary>
	/// <param name="point">The point.</param>
	public Pause Arm(PausePoint point)
	{
		Pause pause = new();
		_armed[point] = pause;
		_all.Enqueue(pause);
		return pause;
	}

	/// <summary>Releases every pause ever armed, so no request outlives its host.</summary>
	public void ReleaseAll()
	{
		foreach (var pause in _all)
			pause.Release();
	}

	ValueTask HoldAsync(PausePoint point, BaseContext context)
	{
		if (context.EndpointType is not (OpenIddictServerEndpointType.Token or OpenIddictServerEndpointType.Revocation))
			return ValueTask.CompletedTask;

		_passed.Enqueue(point);
		return _armed.TryRemove(point, out var pause) ?
			new(pause.HoldAsync(context.CancellationToken)) :
			ValueTask.CompletedTask;
	}
}
