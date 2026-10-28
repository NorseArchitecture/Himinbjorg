using Microsoft.AspNetCore.Identity;

namespace Norse.Identity.Web.Server;

/// <summary>
///     What a two-factor challenge completion answers: the sign-in result, and the landing the challenge carried
///     (<see cref="TwoFactorChallenge.ReturnUrl" />). Raw, like <see cref="SignInResult" />: Norse callers reach it only
///     through the <c>.Outcome</c> view, which answers the landing.
/// </summary>
/// <param name="Result">The sign-in result.</param>
/// <param name="ReturnUrl">
///     The challenge's landing when <paramref name="Result" /> succeeded; <see cref="string.Empty" /> otherwise.
/// </param>
public sealed record ChallengeSignInResult(SignInResult Result, string ReturnUrl);
