namespace Norse.Identity.Web.Server;

/// <summary>
///     The one home of the landing's park on <see cref="NorseSignInManager.ReturnUrlItemName" />: a sign-in that may
///     answer a two-factor challenge parks its resolved landing for the challenge mint, which takes it into the token,
///     and the scope removes it on every exit, so no failure path leaks it onto the rest of the request (pre-flight D11).
///     Every site that parks -- password sign-in, passkey sign-in, the external-login callback -- goes through here.
/// </summary>
sealed class ParkedReturnUrl : IDisposable
{
	readonly IDictionary<object, object?> _items;

	ParkedReturnUrl(IDictionary<object, object?> items) =>
		_items = items;

	/// <summary>Parks <paramref name="landing" /> until the returned scope is disposed.</summary>
	/// <param name="context">The live request.</param>
	/// <param name="landing">The landing, already decided by <see cref="ReturnUrls.Resolve" />.</param>
	/// <returns>The scope; dispose it (<see langword="using" />) around the sign-in call.</returns>
	public static ParkedReturnUrl Park(HttpContext context, string landing)
	{
		context.Items[NorseSignInManager.ReturnUrlItemName] = landing;
		return new(context.Items);
	}

	/// <summary>Removes the parked landing; a no-op when the mint has already taken it.</summary>
	public void Dispose() =>
		_items.Remove(NorseSignInManager.ReturnUrlItemName);
}
