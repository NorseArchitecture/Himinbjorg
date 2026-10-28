using Microsoft.AspNetCore.Http;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The account handler tests' live request, hosted under <c>/base</c> so every server-authored URL proves it
///     carries the <c>PathBase</c>, with nothing stashed for a deferred completion; and their outcome readers.
/// </summary>
static class BaseRequest
{
	/// <summary>An accessor whose request runs under <c>/base</c>.</summary>
	public static IHttpContextAccessor Accessor()
	{
		DefaultHttpContext context = new();
		context.Request.PathBase = "/base";
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(context);
		return accessor;
	}

	/// <summary>The deferred completion over <paramref name="accessor" />'s request, with a substituted builder.</summary>
	public static DeferredCompletion Completion(IHttpContextAccessor accessor) =>
		new(Substitute.For<IDeferredSignIn>(), accessor);

	/// <summary>The success's value, asserting there was one.</summary>
	public static T ValueOf<T>(Outcome<T> outcome)
		where T : notnull
	{
		outcome.TryGetValue(out Success<T> success).ShouldBeTrue();
		return success.Value;
	}

	/// <summary>The failure's problem, asserting there was one.</summary>
	public static Problem ProblemOf<T>(Outcome<T> outcome)
		where T : notnull
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem;
	}
}
