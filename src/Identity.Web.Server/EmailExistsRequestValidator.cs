using FluentValidation;
using Norse.AuthN.Services;
using Norse.Primitives;
using Norse.Primitives.Pii;

namespace Norse.Identity.Web.Server;

/// <summary>
///     The hostile-path gate for <see cref="EmailExistsRequest" /> — independently callable public
///     wire surface whose sanctioned caller (<c>RegisterRequestValidator</c>'s async rule) only
///     ever passes an already-proven stamp. Deserialization re-stamps, so the only stamps this
///     rule rejects are hostile or absent; the generated <c>CommandRequestValidator</c> adapter
///     converts the rejection to a failed outcome before the handler runs — a handler that is
///     executing holds only proven values. Registered by discovery like every other validator in
///     this assembly.
/// </summary>
sealed class EmailExistsRequestValidator : AbstractValidator<EmailExistsRequest>
{
	/// <summary>Initializes a new instance of the <see cref="EmailExistsRequestValidator"/> class.</summary>
	public EmailExistsRequestValidator() =>
		RuleFor(x => x.Email)
			.Must(static email => email.TryGetValue(out Success<EmailAddress> _))
			.WithMessage("Enter a valid email address (local@domain.tld).");
}
