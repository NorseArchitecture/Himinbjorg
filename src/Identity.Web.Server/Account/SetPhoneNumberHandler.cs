using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components.Shared;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;
using Norse.Primitives.Pii;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     Sets or clears the caller's phone number. A <see langword="null" /> stamp on the wire clears it; a parsed
///     number is stored in its canonical E.164 form. The change rotates the security stamp, so the sign-in is refreshed
///     and the answer is the Manage page with the <see cref="ManageStatus.PhoneUpdated" /> key, through the
///     deferred-completion detour on a circuit. A number equal to the stored one -- the same E.164 string, or no phone
///     on both sides, an empty stored value counting as none -- answers the same URL without writing anything (Ruling
///     47): the stock <c>SetPhoneNumberAsync</c> clears <c>PhoneNumberConfirmed</c> and rotates the security stamp
///     whether or not the number changed, so an interactive Save with no change would otherwise unconfirm a confirmed
///     phone, write a <c>users</c> history version, and sign the account out of every other session. Nothing rotated,
///     so nothing is refreshed and there is no detour to take. The fold failures pass through unchanged. A store
///     failure keeps its category and description but is regrouped onto the model-level key: the <c>.Outcome</c> view
///     keys errors by <c>IdentityError.Code</c> (<c>ConcurrencyFailure</c>, <c>IndeterminateOutcome</c>), the client
///     files each message under the field its key names, and the form binds only <c>Phone</c> and shows only the empty
///     key in its summary -- so a code-keyed failure, an indeterminate commit included, would render nowhere.
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Reads and stores the number.</param>
/// <param name="signInManager">Refreshes the caller's sign-in after the stamp rotation.</param>
/// <param name="deferredCompletion">Builds the completion detour for whatever the refresh stashed.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class SetPhoneNumberHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	SignInManager<NorseUser> signInManager,
	DeferredCompletion deferredCompletion,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<SetPhoneNumberCommand, NavigationResult>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(SetPhoneNumberCommand request,
		CancellationToken cancellationToken = default)
	{
		// A failed Result is never written to the wire (the buffer stamps null for empty input), so any Failure here
		// -- Empty included -- is a hostile caller or a misregistered validator: the tripwire, keyed to the same wire
		// field the client renders.
		string? phone = null;
		if (request.Request.Phone is { } stamped)
		{
			if (!stamped.TryGetValue(out Success<PhoneNumber> parsed))
				return Outcome<NavigationResult>.Err(ErrorCategory.Validation,
					new Dictionary<string, string[]>
					{
						[nameof(SetPhoneNumberRequest.Phone)] = ["Enter a valid phone number (+15551234567)."]
					});

			// WireValue is the deliberate plaintext egress -- Identity's store speaks canonical strings.
			phone = parsed.Value.WireValue;
		}

		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> user);

		var url = ManageUrls.Status(httpContextAccessor.HttpContext!.Request.PathBase, "/Account/Manage",
			ManageStatus.PhoneUpdated);
		// Ruling 47: the stock write unconfirms and rotates the stamp whatever the number, so an unchanged one never
		// reaches it. The store decrypts on read, so the stored value compares as the E.164 string the write would store.
		var stored = await userManager.GetPhoneNumberAsync(user.Value).ConfigureAwait(false);
		if (string.Equals(NullIfEmpty(stored), phone, StringComparison.Ordinal))
			return Outcome<NavigationResult>.Ok(new NavigationResult { NextUrl = url });

		var set = await userManager.Outcome.SetPhoneNumberAsync(user.Value, phone, cancellationToken)
			.ConfigureAwait(false);
		if (set.TryGetValue(out Failed failed))
			return new(new Failed(failed.Problem with
			{
				Errors = IdentityErrorFields.Regroup(failed.Problem.Errors, static _ => "")
			}));

		await signInManager.RefreshSignInAsync(user.Value).ConfigureAwait(false);
		return Outcome<NavigationResult>.Ok(new NavigationResult { NextUrl = deferredCompletion.TryBuildUrl(url) ?? url });
	}

	/// <summary>Folds an empty stored phone onto <see langword="null" />: both mean the account has none.</summary>
	/// <param name="value">The stored phone.</param>
	static string? NullIfEmpty(string? value) =>
		string.IsNullOrEmpty(value) ? null : value;
}
