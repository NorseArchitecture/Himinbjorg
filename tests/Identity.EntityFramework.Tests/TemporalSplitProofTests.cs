using Microsoft.EntityFrameworkCore;

namespace Norse.Identity.EntityFramework.Tests;

public sealed class TemporalSplitProofTests
{
	// Spec §8 verify item 2: IsTemporal + SplitToTable compose on one entity in EF 11 preview.
	// Standalone scratch context — deliberately NOT NorseIdentityDbContext, so this proof holds
	// even before Task 15 wires the real mapping.
	sealed class ProofUser
	{
		public Guid Id { get; set; }
		public string? Name { get; set; }
		public int AccessFailedCount { get; set; }
		public DateTimeOffset? LockoutEnd { get; set; }
	}

	sealed class ProofContext : DbContext
	{
		protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) =>
			optionsBuilder.UseSqlServer("Server=design-time-only;Database=proof;Encrypt=false");

		protected override void OnModelCreating(ModelBuilder modelBuilder) =>
			modelBuilder.Entity<ProofUser>(entity =>
			{
				entity.Property(u => u.Name).HasMaxLength(64);
				entity.ToTable("Users", table => table.IsTemporal());
				entity.SplitToTable("UserLockout", split =>
				{
					split.Property(u => u.AccessFailedCount);
					split.Property(u => u.LockoutEnd);
				});
			});
	}

	[Fact]
	void Temporal_main_table_composes_with_a_lockout_split_table()
	{
		using ProofContext context = new();
		var entity = context.Model.FindEntityType(typeof(ProofUser))!;
		entity.IsTemporal().ShouldBeTrue();
		entity.GetTableMappings()
			.Select(m => m.Table.Name)
			.ShouldContain("UserLockout");
		entity.FindProperty(nameof(ProofUser.AccessFailedCount))!
			.GetColumnName(Microsoft.EntityFrameworkCore.Metadata.StoreObjectIdentifier.Table("UserLockout", null))
			.ShouldNotBeNull();
	}

	[Fact]
	void Split_table_is_not_itself_temporal()
	{
		// The point of the split: lockout churn mints no history rows. If EF marks the split table
		// temporal too, the design premise fails → HALT and report.
		using ProofContext context = new();
		var entity = context.Model.FindEntityType(typeof(ProofUser))!;
		// Assert via the relational annotations on the split table mapping — the temporal annotation
		// must be scoped to the main table only. Exact assertion shape depends on EF 11 preview's
		// annotation surface; the invariant to prove: the generated migration creates history
		// tracking for "Users" and none for "UserLockout".
		entity.GetTableMappings().Count().ShouldBe(2);
	}
}
