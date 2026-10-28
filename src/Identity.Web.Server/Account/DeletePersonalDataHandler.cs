using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     Deletes the caller's account, the self-service front door to erasure (§5.6). An account with a password must
///     confirm it, and a wrong one answers this handler's one static <see cref="ErrorCategory.InvalidCredentials" />
///     instance with nothing shredded; a passwordless account proceeds on the always-present empty field. The shred
///     goes through <see cref="ErasureService.ShredWithRetriesAsync" />, since past the key's destruction the caller
///     gets no second request to retry from; a failure keeps its category, correlation id and any receipt and carries
///     the one user-facing line. Success signs the caller out and lands on the app root, through the
///     deferred-completion detour on a circuit. The fold's failures pass through unchanged.
/// </summary>
/// <param name="userManager">Loads the caller and checks the password.</param>
/// <param name="signInManager">Signs the caller out once the account is gone.</param>
/// <param name="principalAccessor">Reaches the caller's principal.</param>
/// <param name="erasure">Crypto-shreds the account, key first.</param>
/// <param name="deferredCompletion">Builds the completion detour for whatever the sign-out stashed.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
/// <param name="logger">Records every erasure and every shred that could not finish.</param>
sealed partial class DeletePersonalDataHandler(
	UserManager<NorseUser> userManager,
	SignInManager<NorseUser> signInManager,
	IPrincipalAccessor principalAccessor,
	ErasureService erasure,
	DeferredCompletion deferredCompletion,
	IHttpContextAccessor httpContextAccessor,
	ILogger<DeletePersonalDataHandler> logger)
	: IRequestHandler<DeletePersonalDataCommand, NavigationResult>
{
	/// <summary>How many shred runs one request makes before an operator must finish the erasure.</summary>
	internal const int ShredAttempts = 3;

	/// <summary>The one user-facing line every shred failure carries.</summary>
	internal const string ShredFailureMessage =
		"Your account could not be fully deleted. The failure has been logged for an administrator to finish.";

	static readonly Failed _incorrectPassword =
		new(Problem.ModelError(ErrorCategory.InvalidCredentials, "Incorrect password."));

	/// <summary>The one instance every wrong password answers, for reference-identity assertions.</summary>
	internal static Failed IncorrectPassword => _incorrectPassword;

	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(DeletePersonalDataCommand request,
		CancellationToken cancellationToken = default)
	{
		var principal = await principalAccessor.GetPrincipalAsync(cancellationToken).ConfigureAwait(false);
		var found = await userManager.Outcome.GetUserAsync(principal, cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> user);

		var wire = request.Request;
		if (await userManager.HasPasswordAsync(user.Value).ConfigureAwait(false) &&
			!await userManager.CheckPasswordAsync(user.Value, wire.Password).ConfigureAwait(false))
			return new(_incorrectPassword);

		var shred = await erasure.ShredWithRetriesAsync(user.Value.Id, ShredAttempts, cancellationToken)
			.ConfigureAwait(false);
		if (shred.TryGetValue(out Failed failed))
		{
			LogShredFailed(logger, user.Value.Id, failed.Problem.Category);
			return new(new Failed(failed.Problem with
			{
				Errors = new Dictionary<string, string[]> { [""] = [ShredFailureMessage] }
			}));
		}

		await signInManager.SignOutAsync().ConfigureAwait(false);
		LogSelfErasure(logger, user.Value.Id);
		var appRoot = UriHelper.BuildRelative(httpContextAccessor.HttpContext!.Request.PathBase, "/");
		return Outcome<NavigationResult>.Ok(new NavigationResult
		{
			NextUrl = deferredCompletion.TryBuildUrl(appRoot) ?? appRoot
		});
	}

	[LoggerMessage(Level = LogLevel.Error,
		Message = "User {UserId} could not finish deleting themselves: {Category}; an administrator must finish the erasure.")]
	static partial void LogShredFailed(ILogger logger, Guid userId, ErrorCategory category);

	[LoggerMessage(Level = LogLevel.Information, Message = "User {UserId} deleted themselves.")]
	static partial void LogSelfErasure(ILogger logger, Guid userId);
}
