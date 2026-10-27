using Microsoft.AspNetCore.Http;
using Norse.Abstractions.Web.Server.DeferredSignIn;

namespace Norse.Identity.Web.Server.Tests;

public sealed class DeferredCompletionTests
{
	static DeferredCompletion CreateCompletion(string? identityKey, string? rememberKey)
	{
		var deferredSignIn = Substitute.For<IDeferredSignIn>();
		deferredSignIn.BuildCompletionUrl(Arg.Any<string>(), Arg.Any<string>())
			.Returns(call =>
				$"/_auth/complete?key={call.ArgAt<string>(0)}&returnUrl={Uri.EscapeDataString(call.ArgAt<string>(1))}");
		DefaultHttpContext httpContext = new();
		if (identityKey is not null)
			httpContext.Items[NorseSignInManager.DeferredSignInKeyItemName] = identityKey;
		if (rememberKey is not null)
			httpContext.Items[NorseSignInManager.DeferredRememberClientKeyItemName] = rememberKey;
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(httpContext);
		return new(deferredSignIn, accessor);
	}

	[Fact]
	void No_stash_answers_null() =>
		CreateCompletion(null, null).TryBuildUrl("/").ShouldBeNull();

	[Fact]
	void An_identity_stash_alone_wraps_the_return_url_once() =>
		CreateCompletion("id", null).TryBuildUrl("/").ShouldBe("/_auth/complete?key=id&returnUrl=%2F");

	[Fact]
	void A_remember_stash_alone_wraps_the_return_url_once() =>
		CreateCompletion(null, "rem").TryBuildUrl("/").ShouldBe("/_auth/complete?key=rem&returnUrl=%2F");

	// Outer completes the identity cookie, inner the remember cookie (spec §5.4). The inner URL's own
	// escaped "%2F" is escaped again by the outer wrap, hence "%252F".
	[Fact]
	void Both_stashes_chain_identity_outside_remember_inside() =>
		CreateCompletion("id", "rem").TryBuildUrl("/")
			.ShouldBe("/_auth/complete?key=id&returnUrl=%2F_auth%2Fcomplete%3Fkey%3Drem%26returnUrl%3D%252F");
}
