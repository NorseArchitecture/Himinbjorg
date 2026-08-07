using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

/// <summary>
/// Resolves <see cref="UserManager{TUser}"/> (and the <see cref="NorseIdentityDbContext"/> it wraps)
/// from a fresh <see cref="IServiceScopeFactory"/>-created scope per call, rather than taking the
/// circuit's ambient scoped instance directly. Load-bearing, not a style choice: Blazor Server's
/// injected services all resolve from ONE scope for the whole circuit's lifetime, and
/// <c>RegisterRequestValidator</c>'s email-exists check deliberately has no rule-set gating (ruled
/// 2026-08-06) -- it fires on the field's blur AND again on submit's re-validation, and Blazilla does
/// not cancel or await the blur-triggered call before submit starts its own. Two overlapping calls
/// sharing the circuit's single <c>DbContext</c> instance throw
/// <c>InvalidOperationException: A second operation was started on this context instance before a
/// previous operation completed</c> -- reproduced live, not theoretical. Mirrors the identical fix
/// already established in <see cref="IdentityRevalidatingAuthenticationStateProvider"/> for the same
/// root cause. Every other handler in this project is invoked once per genuine sign-in/registration
/// attempt and is not re-entered by design the way this one is -- this fix is scoped to the one
/// handler actually proven to race, not applied platform-wide speculatively.
/// </summary>
sealed class EmailExistsHandler(IServiceScopeFactory scopeFactory)
	: IRequestHandler<EmailExistsCommand, BoolResponse>
{
	public async ValueTask<Outcome<BoolResponse>> Handle(EmailExistsCommand request, CancellationToken cancellationToken = default)
	{
		var scope = scopeFactory.CreateAsyncScope();
		await using var _ = scope.ConfigureAwait(false);
		var userManager = scope.ServiceProvider.GetRequiredService<UserManager<NorseUser>>();
		var user = await userManager.FindByEmailAsync(request.Request.Email).ConfigureAwait(false);
		return Outcome<BoolResponse>.Ok(new BoolResponse { Value = user is not null });
	}
}
