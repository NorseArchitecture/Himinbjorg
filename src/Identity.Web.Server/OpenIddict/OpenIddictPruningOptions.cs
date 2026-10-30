namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     The OpenIddict pruner's configuration (2026-10-29 OpenIddict spec §5.6), bound from <see cref="Section" /> and
///     validated at startup by <c>AddNorseIdentity</c>.
/// </summary>
sealed class OpenIddictPruningOptions
{
	/// <summary>The configuration section the options bind from.</summary>
	public const string Section = "Identity:OpenIddict:Pruning";

	/// <summary>
	///     The longest <see cref="Interval" /> accepted: one day. <see cref="PeriodicTimer" /> refuses about 49.7 days with an
	///     exception that names no setting, and the stranded-account verification holds the same bound.
	/// </summary>
	internal static readonly TimeSpan MaxInterval = TimeSpan.FromDays(1);

	/// <summary>Whether the pruner runs at all. A disabled pruner logs once and returns.</summary>
	public bool Enabled { get; set; } = true;

	/// <summary>
	///     How long a replica waits between runs. Must be positive and at most <see cref="MaxInterval" />; a host that sets
	///     otherwise fails at startup.
	/// </summary>
	public TimeSpan Interval { get; set; } = TimeSpan.FromHours(1);

	/// <summary>
	///     How old a row must be, by its creation date, before a run may remove it. Must be at least the OpenIddict server's
	///     refresh token lifetime (14 days, spec §5.1), read from the server's own options: a redeemed refresh token removed
	///     while it could still be replayed would turn reuse, which ends the grant, into an unknown token, which does not.
	/// </summary>
	public TimeSpan MinimumAge { get; set; } = TimeSpan.FromDays(14);
}
