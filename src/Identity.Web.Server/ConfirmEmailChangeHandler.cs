using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;
using Norse.Primitives.Pii;

namespace Norse.Identity.Web.Server;

/// <summary>
///     Confirms a pending email change with the emailed change code; <see cref="NorseUserManager" /> sets the email and
///     the username together (law). The change rotates the security stamp, so when the caller <em>is</em> that user the
///     sign-in is refreshed and the answer is the app root, through the deferred-completion detour on a circuit;
///     anyone else — another user, or nobody — is sent to sign in, and their own session is never touched. Failures
///     pass through unchanged.
/// </summary>
/// <param name="userManager">Finds the account and changes its email.</param>
/// <param name="signInManager">Refreshes the caller's sign-in after the stamp rotation.</param>
/// <param name="principalAccessor">Reaches the caller's principal.</param>
/// <param name="deferredCompletion">Builds the completion detour for whatever the refresh stashed.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class ConfirmEmailChangeHandler(
	UserManager<NorseUser> userManager,
	SignInManager<NorseUser> signInManager,
	IPrincipalAccessor principalAccessor,
	DeferredCompletion deferredCompletion,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<ConfirmEmailChangeCommand, NavigationResult>
{
	static readonly Failed _malformedCode =
		new(Problem.ModelError(ErrorCategory.InvalidCredentials, "The confirmation link is invalid or has expired."));

	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(ConfirmEmailChangeCommand request,
		CancellationToken cancellationToken = default)
	{
		var wire = request.Request;

		// The server-side validator run guarantees a proven stamp before this handler executes — this guard is the
		// tripwire for a hostile caller or a misregistered validator, keyed to the same wire field the client renders.
		if (!wire.Email.TryGetValue(out Success<EmailAddress> email))
			return Outcome<NavigationResult>.Err(ErrorCategory.Validation,
				new Dictionary<string, string[]>
				{
					[nameof(ConfirmEmailChangeRequest.Email)] = ["Enter a valid email address (local@domain.tld)."]
				});

		var found = await userManager.Outcome.FindByIdAsync(wire.UserId, cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> user);

		if (!IdentityTokens.TryDecode(wire.Code, out var token))
			return new(_malformedCode);

		// WireValue is the deliberate plaintext egress — Identity's store speaks canonical strings.
		var changed = await userManager.Outcome.ChangeEmailAsync(user.Value, email.Value.WireValue, token,
			cancellationToken).ConfigureAwait(false);
		if (changed.TryGetValue(out Failed failed))
			return new(failed);

		var pathBase = httpContextAccessor.HttpContext!.Request.PathBase;
		var principal = await principalAccessor.GetPrincipalAsync(cancellationToken).ConfigureAwait(false);
		if (userManager.GetUserId(principal) != user.Value.Id.ToString())
			return Outcome<NavigationResult>.Ok(new NavigationResult
			{
				NextUrl = UriHelper.BuildRelative(pathBase, "/Account/Login")
			});

		await signInManager.RefreshSignInAsync(user.Value).ConfigureAwait(false);
		var appRoot = UriHelper.BuildRelative(pathBase, "/");
		return Outcome<NavigationResult>.Ok(new NavigationResult
		{
			NextUrl = deferredCompletion.TryBuildUrl(appRoot) ?? appRoot
		});
	}
}
