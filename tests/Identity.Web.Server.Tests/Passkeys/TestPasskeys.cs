using Microsoft.AspNetCore.Identity;

namespace Norse.Identity.Web.Server.Tests.Passkeys;

/// <summary>Stored passkeys for the passkey handler and view tests: only the id and name matter to them.</summary>
static class TestPasskeys
{
	/// <summary>A passkey with <paramref name="credentialId" />, named <paramref name="name" />.</summary>
	public static UserPasskeyInfo Info(byte[] credentialId, string? name = null) =>
		new(credentialId, [0x01], DateTimeOffset.UnixEpoch, 0, null, isUserVerified: true, isBackupEligible: false,
			isBackedUp: false, [0x02], [0x03])
		{
			Name = name
		};

	/// <summary><paramref name="count" /> distinct passkeys.</summary>
	public static IList<UserPasskeyInfo> Many(int count) =>
		[.. Enumerable.Range(0, count).Select(static index => Info(BitConverter.GetBytes(index)))];
}
