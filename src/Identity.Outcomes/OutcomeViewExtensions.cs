using Microsoft.AspNetCore.Identity;
using Norse.Identity.EntityFramework;
using OpenIddict.Abstractions;

namespace Norse.Identity.Outcomes;

/// <summary>
///     The <c>.Outcome</c> views (2026-10-24 explicit-writes spec §4.12): how every Norse caller reaches Identity and
///     OpenIddict. <c>SignInManager</c>'s view lives in <c>Identity.Web.Server</c>, beside the ASP.NET Core framework it
///     belongs to.
/// </summary>
public static class OutcomeViewExtensions
{
	/// <param name="userManager">The manager to view.</param>
	extension(UserManager<NorseUser> userManager)
	{
		/// <summary>The manager, answering <c>Outcome</c>.</summary>
		public UserManagerOutcomeView Outcome =>
			new(userManager);
	}

	/// <param name="manager">The manager to view.</param>
	extension(IOpenIddictApplicationManager manager)
	{
		/// <summary>The manager, answering <c>Outcome</c>.</summary>
		public OpenIddictApplicationManagerOutcomeView Outcome =>
			new(manager);
	}

	/// <param name="manager">The manager to view.</param>
	extension(IOpenIddictAuthorizationManager manager)
	{
		/// <summary>The manager, answering <c>Outcome</c>.</summary>
		public OpenIddictAuthorizationManagerOutcomeView Outcome =>
			new(manager);
	}

	/// <param name="manager">The manager to view.</param>
	extension(IOpenIddictTokenManager manager)
	{
		/// <summary>The manager, answering <c>Outcome</c>.</summary>
		public OpenIddictTokenManagerOutcomeView Outcome =>
			new(manager);
	}

	/// <param name="manager">The manager to view.</param>
	extension(IOpenIddictSessionManager manager)
	{
		/// <summary>The manager, answering <c>Outcome</c>.</summary>
		public OpenIddictSessionManagerOutcomeView Outcome =>
			new(manager);
	}
}
