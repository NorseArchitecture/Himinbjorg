using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Norse.Identity.Web.Server.Verification;

/// <summary>Composition-root wiring for the identity invariant verification.</summary>
public static class ServiceCollectionExtensions
{
	extension(IServiceCollection services)
	{
		/// <summary>
		///     Registers the stranded-account verification (T3-28): <see cref="IdentityVerificationOptions" /> from
		///     <c>Identity:Verification</c>, validated at startup (a <see cref="IdentityVerificationOptions.SampleSize" />
		///     out of range or an <see cref="IdentityVerificationOptions.Interval" /> that is not positive or exceeds
		///     <see cref="IdentityVerificationOptions.MaxInterval" /> fails the host before
		///     it serves), the scoped <see cref="IStrandedAccountsQuery" /> over
		///     the host's <see cref="Norse.Identity.EntityFramework.NorseIdentityDbContext" />, the system clock unless
		///     the host registered its own, and the hosted <see cref="IdentityInvariantVerificationService" />.
		/// </summary>
		/// <param name="configuration">The configuration the options bind from.</param>
		/// <returns>The same <see cref="IServiceCollection" /> for chaining.</returns>
		public IServiceCollection AddNorseIdentityInvariantVerification(IConfiguration configuration)
		{
			services.AddOptions<IdentityVerificationOptions>()
				.Bind(configuration.GetSection(IdentityVerificationOptions.Section))
				.ValidateDataAnnotations()
				.Validate(static options => options.Interval > TimeSpan.Zero,
					$"{IdentityVerificationOptions.Section}:{nameof(IdentityVerificationOptions.Interval)} must be positive.")
				.Validate(static options => options.Interval <= IdentityVerificationOptions.MaxInterval,
					$"{IdentityVerificationOptions.Section}:{nameof(IdentityVerificationOptions.Interval)} must be at most {IdentityVerificationOptions.MaxInterval}.")
				.ValidateOnStart();
			services.TryAddSingleton(TimeProvider.System);
			return services
				.AddScoped<IStrandedAccountsQuery, StrandedAccountsQuery>()
				.AddHostedService<IdentityInvariantVerificationService>();
		}
	}
}
