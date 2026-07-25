# Norse.Identity.Migrations

The migration contributor for `NorseIdentityDbContext`, provider-agnostic. Migration tooling only — never referenced from a runtime container.

Provider-specific `IDesignTimeDbContextFactory` implementations and checked-in EF migrations live in the sibling `Identity.Migrations.PostgreSQL` and `Identity.Migrations.SqlServer` projects, each of which references this one.

Part of the [Norse Architecture](https://github.com/NorseArchitecture) platform.
