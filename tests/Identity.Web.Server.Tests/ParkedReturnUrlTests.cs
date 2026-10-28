using Microsoft.AspNetCore.Http;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The one home of the landing's park on <see cref="NorseSignInManager.ReturnUrlItemName" />: the landing is on
///     <c>HttpContext.Items</c> only while the scope is open, and gone after it on every exit, a throw included.
/// </summary>
public sealed class ParkedReturnUrlTests
{
	[Fact]
	void The_landing_is_parked_while_the_scope_is_open()
	{
		DefaultHttpContext context = new();

		using (ParkedReturnUrl.Park(context, "/app/Account"))
			context.Items[NorseSignInManager.ReturnUrlItemName].ShouldBe("/app/Account");

		context.Items.ContainsKey(NorseSignInManager.ReturnUrlItemName).ShouldBeFalse();
	}

	[Fact]
	void The_landing_is_removed_when_the_scope_throws()
	{
		DefaultHttpContext context = new();

		Should.Throw<InvalidOperationException>(() =>
		{
			using (ParkedReturnUrl.Park(context, "/app/Account"))
				throw new InvalidOperationException("the sign-in failed");
		});

		context.Items.ContainsKey(NorseSignInManager.ReturnUrlItemName).ShouldBeFalse();
	}

	// The challenge mint takes the item and removes it; the scope's removal is then a no-op.
	[Fact]
	void A_landing_the_mint_already_took_closes_cleanly()
	{
		DefaultHttpContext context = new();

		using (ParkedReturnUrl.Park(context, "/app/Account"))
			context.Items.Remove(NorseSignInManager.ReturnUrlItemName);

		context.Items.ContainsKey(NorseSignInManager.ReturnUrlItemName).ShouldBeFalse();
	}
}
