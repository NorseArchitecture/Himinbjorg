using System.ComponentModel;
using System.Diagnostics;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     Whether a Docker daemon answers at all -- the pre-flight half of the SQL Server gate, copied from
///     Urðarbrunnr's <c>Persistence.EntityFramework.SqlServer.IntegrationTests</c> (itself Midgard's). A
///     <c>docker info</c> probe, so a host with no daemon skips by name instead of failing every test in the
///     collection inside the fixture's start.
/// </summary>
static class DockerAvailability
{
	public static bool IsAvailable { get; } = Probe();

	static bool Probe()
	{
		try
		{
			using Process process = new()
			{
				StartInfo = new ProcessStartInfo("docker", "info")
				{
					RedirectStandardOutput = true,
					RedirectStandardError = true,
					UseShellExecute = false
				}
			};
			process.Start();
			return process.WaitForExit(TimeSpan.FromSeconds(5)) && process.ExitCode == 0;
		}
		catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
		{
			// docker CLI not on PATH at all -- the same "not available" outcome as a daemon that won't answer.
			return false;
		}
	}
}
