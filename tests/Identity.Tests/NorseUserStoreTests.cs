using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Norse.Identity.Tests;

public sealed class NorseUserStoreTests
{
	[Fact]
	public async Task FindByIdAsync_returns_null_for_missing_user()
	{
		using var ctx = CreateContext();
		using NorseUserStore store = new(ctx, new IdentityErrorDescriber());

		var result = await store.FindByIdAsync(Guid.NewGuid().ToString(), TestContext.Current.CancellationToken);

		result.ShouldBeNull();
	}

	[Fact]
	public async Task FindByIdAsync_projects_required_fields()
	{
		using var ctx = CreateContext();
		var userId = Guid.NewGuid();
		ctx.Users.Add(new NorseUser
		{
			Id = userId,
			UserName = "test@example.com",
			Email = "test@example.com",
			NormalizedUserName = "TEST@EXAMPLE.COM",
			NormalizedEmail = "TEST@EXAMPLE.COM",
			SecurityStamp = Guid.NewGuid().ToString(),
			ConcurrencyStamp = Guid.NewGuid().ToString()
		});
		await ctx.SaveChangesAsync(TestContext.Current.CancellationToken);

		using NorseUserStore store = new(ctx, new IdentityErrorDescriber());
		var result = await store.FindByIdAsync(userId.ToString(), TestContext.Current.CancellationToken);

		result.ShouldNotBeNull();
		result.Id.ShouldBe(userId);
		result.UserName.ShouldBe("test@example.com");
		result.Email.ShouldBe("test@example.com");
	}

	static NorseIdentityDbContext CreateContext()
	{
		NorseIdentityDbContext ctx = new(
			new DbContextOptionsBuilder<NorseIdentityDbContext>()
				.UseSqlite($"Data Source={Guid.NewGuid()};Mode=Memory;Cache=Shared")
				.Options);
		// A shared-cache SQLite in-memory database is destroyed once its last open connection closes.
		// EnsureCreated() opens and closes its own connection, so the connection must be opened explicitly
		// first and kept open for the lifetime of the context (closed on dispose) to survive later queries.
		ctx.Database.OpenConnection();
		ctx.Database.EnsureCreated();
		return ctx;
	}
}
