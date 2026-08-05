using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
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
// Real-Postgres tests share exactly one PostgresIdentityFixture instance across the whole
// collection (see its own remark, and PostgresTestGroup) -- never a per-class IClassFixture.
[Collection(PostgresTestGroup.Name)]
public sealed class DisclosureHandlerTests(PostgresIdentityFixture fixture)
{
	[Fact]
	async Task Self_disclosure_returns_full_decrypted_wire_strings()
	{
		var (context, _) = await fixture.CreateScopeAsync();
		var user = await fixture.SeedUserAsync("me@example.com", phone: "+15551234567");
		GetMyPersonalDataHandler handler = new(context, FakePrincipal.For(user.Id), Options.Create(new IdentityOptions()));

		var outcome = await handler.Handle(new(new GetMyPersonalDataRequest()), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<PersonalDataResponse> success).ShouldBeTrue();
		success.Value.Email.ShouldBe("me@example.com");
		success.Value.PhoneNumber.ShouldBe("+15551234567");
	}

	[Fact]
	async Task Self_disclosure_with_no_user_id_claim_fails_loudly_naming_the_claim_type()
	{
		var (context, _) = await fixture.CreateScopeAsync();
		GetMyPersonalDataHandler handler = new(context, FakePrincipal.Empty(), Options.Create(new IdentityOptions()));

		var exception = await Should.ThrowAsync<InvalidOperationException>(
			async () => await handler.Handle(new(new GetMyPersonalDataRequest()), TestContext.Current.CancellationToken));

		exception.Message.ShouldContain(new IdentityOptions().ClaimsIdentity.UserIdClaimType); // names the missing claim type, not an opaque Guid.Parse(null) failure
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
	async Task Masked_disclosure_of_an_email_less_subject_answers_empty_string_not_a_fault()
	{
		// Email is nullable in the model -- only UserName is required (NorseUser.Configure) -- so a
		// legal row can carry no email at all. Seeded directly through UserManager rather than
		// fixture.SeedUserAsync, which always sets Email = the username argument.
		var (context, _) = await fixture.CreateScopeAsync();
		var userManager = fixture.CreateUserManager();
		NorseUser user = new() { UserName = "no-email-user" };
		(await userManager.CreateAsync(user)).Succeeded.ShouldBeTrue();

		GetMaskedPersonalDataHandler handler = new(context);
		var outcome = await handler.Handle(new(new GetMaskedPersonalDataRequest { SubjectId = user.Id }), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<MaskedPersonalDataResponse> success).ShouldBeTrue(); // not a Fault -- a legal row shape
		success.Value.Email.ShouldBe("");
		success.Value.PhoneNumber.ShouldBe("");
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
