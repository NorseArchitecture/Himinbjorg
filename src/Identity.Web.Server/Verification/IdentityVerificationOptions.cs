using System.ComponentModel.DataAnnotations;

namespace Norse.Identity.Web.Server.Verification;

/// <summary>
///     The stranded-account verification's configuration (T3-28), bound from <see cref="Section" /> and validated at
///     startup.
/// </summary>
sealed class IdentityVerificationOptions
{
	/// <summary>The configuration section the options bind from.</summary>
	public const string Section = "Identity:Verification";

	/// <summary>Whether the verification runs at all. A disabled service logs once and returns.</summary>
	public bool Enabled { get; set; } = true;

	/// <summary>
	///     The longest <see cref="Interval" /> accepted: one day. A verification that rarely runs is no verification, and
	///     <see cref="PeriodicTimer" /> refuses about 49.7 days with an exception that names no setting.
	/// </summary>
	internal static readonly TimeSpan MaxInterval = TimeSpan.FromDays(1);

	/// <summary>
	///     How long a replica waits between runs. Must be positive and at most <see cref="MaxInterval" />; a host that sets
	///     otherwise fails at startup.
	/// </summary>
	public TimeSpan Interval { get; set; } = TimeSpan.FromHours(1);

	/// <summary>
	///     The page size: how many accounts one run visits. Every account is visited in turn, never sampled; the name
	///     is the plan's.
	/// </summary>
	[Range(1, 10_000)]
	public int SampleSize { get; set; } = 100;
}
