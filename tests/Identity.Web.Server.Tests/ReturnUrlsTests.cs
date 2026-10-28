using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The open-redirect defense (T3-2, Buvy r6): the candidate is split at its first literal <c>?</c> or <c>#</c> before
///     any decoding, the separator, encoding, dot-segment and <c>PathBase</c> checks judge the path alone, an accepted
///     candidate comes back verbatim with its query and fragment, and length and control characters are judged over the
///     whole candidate. Anything ambiguous lands on the app root; nothing is normalized and accepted.
/// </summary>
public sealed class ReturnUrlsTests
{
	const string AppBase = "/app";

	/// <summary>Candidate, <c>PathBase</c>, expected landing.</summary>
	static readonly (string? Candidate, string PathBase, string Expected)[] _rows =
	[
		("/Account/Manage?x=1", "", "/Account/Manage?x=1"),
		(null, "", "/"),
		("", "", "/"),
		("https://evil.example/", "", "/"),
		("//evil.example", "", "/"),
		("/\\evil.example", "", "/"),
		("javascript:alert(1)", "", "/"),
		("/%2F%2Fevil.example", "", "/"),
		("/a\u0001b", "", "/"),
		("/" + new string('a', 2048), "", "/"),
		("/app/Account/Manage", AppBase, "/app/Account/Manage"),
		("/Account/Manage", AppBase, "/app/"),
		// The repro.
		("/app/../outside", AppBase, "/app/"),
		// The repro, encoded.
		("/app/%2e%2e/outside", AppBase, "/app/"),
		("/app/a/../../outside", AppBase, "/app/"),
		// Mixed case.
		("/app/%2E%2e/outside", AppBase, "/app/"),
		// Double encoding.
		("/app/%252e%252e/outside", AppBase, "/app/"),
		("/app/./Account", AppBase, "/app/"),
		("/app/x%2Fy", AppBase, "/app/"),
		("/app/x%5cy", AppBase, "/app/"),
		("/app/x\\y", AppBase, "/app/"),
		("/app//Account", AppBase, "/app/"),
		// The query is verbatim: Resolve vouches only for the landing's path.
		("/app/Account?next=//evil.example", AppBase, "/app/Account?next=//evil.example"),
		("/app/Account?next=https://evil.example/", AppBase, "/app/Account?next=https://evil.example/"),
		(
			"/app/Account?returnUrl=%2Fapp%2F..%2Foutside", AppBase,
			"/app/Account?returnUrl=%2Fapp%2F..%2Foutside"
		),
		("/app/Account#https://evil.example/x/../y", AppBase, "/app/Account#https://evil.example/x/../y"),
		("/app/../outside?next=https://evil.example/", AppBase, "/app/"),
		// A decoded ? or # is never a new boundary: it stays inside its segment.
		("/app/x%3F/../../outside", AppBase, "/app/"),
		("/app/x%3f/..%2F..%2Foutside", AppBase, "/app/"),
		// A double-encoded ?.
		("/app/x%253F/../../outside", AppBase, "/app/"),
		("/app/x%23/../../outside", AppBase, "/app/"),
		// A double-encoded #.
		("/app/x%2523/../../outside", AppBase, "/app/"),
		// Control characters, in the path, the query and the fragment, and encoded in the query.
		("/app/a\u0001b", AppBase, "/app/"),
		("/app/Account?x=a\u0001b", AppBase, "/app/"),
		("/app/Account#a\u0001b", AppBase, "/app/"),
		("/app/Account?x=%01", AppBase, "/app/"),
		("/app/Account/Manage?x=1", AppBase, "/app/Account/Manage?x=1"),
		// Containment is by whole segments: a sibling sharing the PathBase's characters is outside.
		("/application/x", AppBase, "/app/"),
		// The PathBase itself is one whole segment, so containment admits it as-is (the app root without its slash).
		(AppBase, AppBase, AppBase),
		// A literal tab is a control character: rejected, never stripped into //evil.example.
		("/\t/evil.example", "", "/"),
		// T3-34: an external-login route is never a landing -- plain, mixed case, a trailing slash, under PathBase, with a
		// query, and encoded (routing matches the decoded path).
		("/Account/PerformExternalLogin", "", "/"),
		("/account/performexternallogin", "", "/"),
		("/Account/PerformExternalLogin/", "", "/"),
		("/app/Account/PerformExternalLogin", AppBase, "/app/"),
		("/app/Account/PerformExternalLogin/?provider=X", AppBase, "/app/"),
		("/Account/PerformExternalLogin?provider=X&returnUrl=%2F", "", "/"),
		("/Account/Manage/LinkExternalLogin", "", "/"),
		("/account/manage/linkexternallogin", "", "/"),
		("/Account/Manage/LinkExternalLogin/", "", "/"),
		("/app/Account/Manage/LinkExternalLogin", AppBase, "/app/"),
		("/app/Account/Manage/LinkExternalLogin/?provider=X", AppBase, "/app/"),
		("/Account/Manage/LinkExternalLogin?provider=X&returnUrl=%2F", "", "/"),
		("/Account/Manage/LinkExternalLoginCallback", "", "/"),
		("/ACCOUNT/MANAGE/LINKEXTERNALLOGINCALLBACK", "", "/"),
		("/Account/Manage/LinkExternalLoginCallback/", "", "/"),
		("/app/Account/Manage/LinkExternalLoginCallback", AppBase, "/app/"),
		("/app/Account/Manage/LinkExternalLoginCallback/?provider=X", AppBase, "/app/"),
		("/Account/Manage/LinkExternalLoginCallback?provider=X&returnUrl=%2F", "", "/"),
		("/Account/%50erformExternalLogin?provider=X", "", "/"),
		("/app/Account/Manage/LinkExternalLogi%6E", AppBase, "/app/"),
		// A sibling that only shares a prefix is still a landing.
		("/Account/PerformExternalLoginHelp", "", "/Account/PerformExternalLoginHelp")
	];

	public static TheoryData<string?, string, string> Rows { get; } = [.. _rows];

	/// <summary>
	///     The <see cref="Rows" /> hosted under <see cref="AppBase" />, but the bare <see cref="AppBase" /> landing, whose
	///     resolved path is <c>/app</c> itself rather than one under <c>/app/</c>.
	/// </summary>
	public static TheoryData<string?, string> AppBaseRows { get; } =
	[
		.. _rows
			.Where(static row => row.PathBase == AppBase && row.Expected != AppBase)
			.Select(static row => (row.Candidate, row.Expected))
	];

	/// <summary>
	///     Self-enforcing: every GET route <c>MapNorseExternalLoginEndpoints</c> maps, read off a built host, lands on the
	///     root, so a new external start cannot be added without the landing refusal covering it.
	/// </summary>
	[Fact]
	async Task Every_mapped_external_login_GET_route_lands_on_the_root()
	{
		var builder = WebApplication.CreateSlimBuilder();
		builder.WebHost.UseTestServer();
		builder.Services.AddRouting().AddAuthorization();
		await using var app = builder.Build();
		app.MapNorseExternalLoginEndpoints();
		await app.StartAsync(TestContext.Current.CancellationToken);

		string[] routes =
		[
			.. app.Services.GetRequiredService<EndpointDataSource>().Endpoints
				.OfType<RouteEndpoint>()
				.Where(static endpoint =>
					endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods.Contains("GET") is true)
				.Select(static endpoint => endpoint.RoutePattern.RawText!)
		];

		routes.Length.ShouldBe(3);
		routes.ShouldAllBe(static route => ReturnUrls.Resolve(route, new PathString()) == "/");
		routes.ShouldAllBe(static route => ReturnUrls.Resolve(AppBase + route, new PathString(AppBase)) == AppBase + "/");
	}

	[Fact]
	void The_maximum_length_is_2048() =>
		ReturnUrls.MaxLength.ShouldBe(2048);

	[Theory]
	[MemberData(nameof(Rows))]
	void Resolve_answers_the_candidate_only_when_it_is_local(string? candidate, string pathBase, string expected) =>
		ReturnUrls.Resolve(candidate, new PathString(pathBase.Length == 0 ? null : pathBase)).ShouldBe(expected);

	// System.Uri is not the browser's resolver; Task 6.2 Step 3 corroborates the same matrix with WHATWG URL in the browser.
	[Theory]
	[MemberData(nameof(AppBaseRows))]
	void Every_landing_resolves_inside_the_path_base(string? candidate, string expected)
	{
		Uri origin = new("https://example.test/app/");

		var landing = ReturnUrls.Resolve(candidate, new PathString(AppBase));
		Uri resolved = new(origin, landing);

		landing.ShouldBe(expected);
		resolved.GetLeftPart(UriPartial.Authority).ShouldBe("https://example.test");
		resolved.AbsolutePath.ShouldStartWith("/app/");
	}
}
