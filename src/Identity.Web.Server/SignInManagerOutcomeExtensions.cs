using Microsoft.AspNetCore.Identity;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

/// <summary>The <c>SignInManager</c> <c>.Outcome</c> view (2026-10-24 explicit-writes spec §4.12).</summary>
static class SignInManagerOutcomeExtensions
{
	/// <param name="signInManager">The manager to view.</param>
	extension(SignInManager<NorseUser> signInManager)
	{
		/// <summary>The manager, answering <c>Outcome</c>.</summary>
		public SignInManagerOutcomeView Outcome =>
			new(signInManager);
	}
}
