using OpenIddict.Validation;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     Protocol errors carry the required <c>error</c> and nothing optional (2026-10-29 OpenIddict spec §5.7; Task 4.7):
///     one registration per stack, so no endpoint suppresses on its own.
/// </summary>
static class ErrorSuppressionExtensions
{
	/// <param name="builder">The server builder.</param>
	extension(OpenIddictServerBuilder builder)
	{
		/// <summary>
		///     Registers <see cref="SuppressErrorDetails{TContext}" /> on every response the server applies: authorization,
		///     token and revocation (the three this platform serves), and every other endpoint OpenIddict can answer
		///     (discovery and the key set answer by default), so an endpoint enabled later is covered without a change here.
		/// </summary>
		/// <returns>The same <paramref name="builder" /> for chaining.</returns>
		public OpenIddictServerBuilder AddNorseErrorSuppression() =>
			builder
				.AddEventHandler(SuppressErrorDetails<ApplyAuthorizationResponseContext>.Descriptor)
				.AddEventHandler(SuppressErrorDetails<ApplyTokenResponseContext>.Descriptor)
				.AddEventHandler(SuppressErrorDetails<ApplyRevocationResponseContext>.Descriptor)
				.AddEventHandler(SuppressErrorDetails<ApplyConfigurationResponseContext>.Descriptor)
				.AddEventHandler(SuppressErrorDetails<ApplyJsonWebKeySetResponseContext>.Descriptor)
				.AddEventHandler(SuppressErrorDetails<ApplyPushedAuthorizationResponseContext>.Descriptor)
				.AddEventHandler(SuppressErrorDetails<ApplyDeviceAuthorizationResponseContext>.Descriptor)
				.AddEventHandler(SuppressErrorDetails<ApplyEndUserVerificationResponseContext>.Descriptor)
				.AddEventHandler(SuppressErrorDetails<ApplyIntrospectionResponseContext>.Descriptor)
				.AddEventHandler(SuppressErrorDetails<ApplyEndSessionResponseContext>.Descriptor)
				.AddEventHandler(SuppressErrorDetails<ApplyUserInfoResponseContext>.Descriptor);
	}

	/// <param name="builder">The validation builder.</param>
	extension(OpenIddictValidationBuilder builder)
	{
		/// <summary>
		///     Registers <see cref="SuppressChallengeErrorDetails{TContext}" /> on both events whose response becomes the
		///     <c>WWW-Authenticate</c> header: a challenge or forbid through <c>Norse.Bearer</c>, and a rejected request.
		/// </summary>
		/// <returns>The same <paramref name="builder" /> for chaining.</returns>
		public OpenIddictValidationBuilder AddNorseErrorSuppression() =>
			builder
				.AddEventHandler(SuppressChallengeErrorDetails<OpenIddictValidationEvents.ProcessChallengeContext>.Descriptor)
				.AddEventHandler(SuppressChallengeErrorDetails<OpenIddictValidationEvents.ProcessErrorContext>.Descriptor);
	}
}
