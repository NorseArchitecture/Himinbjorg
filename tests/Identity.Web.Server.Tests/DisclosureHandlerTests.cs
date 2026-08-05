using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.Web.Server.Disclosure;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
/// The disclosure surface's handler tests (2026-08-03 PII spec §6, real Postgres): self-disclosure
/// returns the full decrypted wire strings, masked disclosure returns the PII structs' own masks, an
/// unknown subject is <see cref="ErrorCategory.NotFound"/>, and a shredded subject is
/// <see cref="ErrorCategory.Erased"/> with the exact receipt -- proving the repository fold's
/// <see cref="KeyDestroyedException"/> catch survives a real EF materialization round trip, not a
/// hand-thrown stand-in (spec §8 verify item 11).
/// </summary>
public sealed class DisclosureHandlerTests(PostgresIdentityFixture fixture) : IClassFixture<PostgresIdentityFixture>
{
	[Fact]
	async Task Self_disclosure_returns_full_decrypted_wire_strings()
	{
		var (context, _) = await fixture.CreateScopeAsync();
		var user = await fixture.SeedUserAsync("me@example.com", phone: "+15551234567");
		GetMyPersonalDataHandler handler = new(context, FakePrincipal.For(user.Id));

		var outcome = await handler.Handle(new(new GetMyPersonalDataRequest()), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<PersonalDataResponse> success).ShouldBeTrue();
		success.Value.Email.ShouldBe("me@example.com");
		success.Value.PhoneNumber.ShouldBe("+15551234567");
	}

	[Fact]
	async Task Masked_disclosure_returns_the_structs_own_masks()
	{
		var (context, _) = await fixture.CreateScopeAsync();
		var user = await fixture.SeedUserAsync("jane@domain.com", phone: "+15551234567");
		GetMaskedPersonalDataHandler handler = new(context);

		var outcome = await handler.Handle(new(new GetMaskedPersonalDataRequest { SubjectId = user.Id }), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<MaskedPersonalDataResponse> success).ShouldBeTrue();
		success.Value.Email.ShouldBe("j***@d***.com");
		success.Value.PhoneNumber.ShouldBe("***4567");
	}

	[Fact]
	async Task Reading_a_shredded_subject_answers_erased_with_the_receipt()
	{
		var (context, keyStore) = await fixture.CreateScopeAsync();
		var user = await fixture.SeedUserAsync("gone@example.com");
		var shred = await new ErasureService(context, keyStore).ShredAsync(user.Id, TestContext.Current.CancellationToken);
		shred.TryGetValue(out Success<ErasureReceipt> receipt).ShouldBeTrue();

		GetMaskedPersonalDataHandler handler = new(context);
		var outcome = await handler.Handle(new(new GetMaskedPersonalDataRequest { SubjectId = user.Id }), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Erased);
		failed.Problem.Receipt.ShouldBe(receipt.Value); // spec §8 verify item 11: the typed exception crossed EF materialization intact
	}

	[Fact]
	async Task Unknown_subject_answers_not_found_not_erased()
	{
		var (context, _) = await fixture.CreateScopeAsync();
		GetMaskedPersonalDataHandler handler = new(context);

		var outcome = await handler.Handle(new(new GetMaskedPersonalDataRequest { SubjectId = Guid.NewGuid() }), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.NotFound);
	}
}
