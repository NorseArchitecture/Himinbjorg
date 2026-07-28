using System.Diagnostics.CodeAnalysis;

namespace Norse.Identity.Migrations.Tests;

[CollectionDefinition("Postgres")]
[SuppressMessage("Design", "CA1711:Identifiers should not have incorrect suffix", Justification = "xUnit collection fixture naming convention")]
public sealed class PostgresCollection : ICollectionFixture<PostgresContainerFixture>;
