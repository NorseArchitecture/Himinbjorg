using Microsoft.AspNetCore.Identity;

namespace Norse.Identity.EntityFramework.Tests;

public sealed class IdentitySeamPinningTests
{
	// Spec §8 verify item 1: which columns Identity's converter path claims ([ProtectedPersonalData]
	// strings) vs the store's lookup-protector path (Normalized* — deliberately unattributed).
	[Theory]
	[InlineData(nameof(IdentityUser.UserName))]
	[InlineData(nameof(IdentityUser.Email))]
	[InlineData(nameof(IdentityUser.PhoneNumber))]
	void Protected_personal_data_marks_the_payload_strings(string property) =>
		typeof(IdentityUser<Guid>).GetProperty(property)!
			.IsDefined(typeof(ProtectedPersonalDataAttribute), inherit: true).ShouldBeTrue();

	[Theory]
	[InlineData(nameof(IdentityUser.NormalizedUserName))]
	[InlineData(nameof(IdentityUser.NormalizedEmail))]
	void Normalized_columns_are_not_converter_protected(string property) =>
		typeof(IdentityUser<Guid>).GetProperty(property)!
			.IsDefined(typeof(ProtectedPersonalDataAttribute), inherit: true).ShouldBeFalse();
}
