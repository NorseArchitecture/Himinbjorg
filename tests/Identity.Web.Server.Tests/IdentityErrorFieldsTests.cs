namespace Norse.Identity.Web.Server.Tests;

public sealed class IdentityErrorFieldsTests
{
	[Fact]
	void ForPasswordChange_keys_mismatch_to_the_old_field_and_rules_to_the_new_one()
	{
		IdentityErrorFields.ForPasswordChange("PasswordMismatch").ShouldBe("OldPassword");
		string[] rules =
		[
			"PasswordTooShort", "PasswordRequiresUniqueChars", "PasswordRequiresNonAlphanumeric", "PasswordRequiresDigit",
			"PasswordRequiresLower", "PasswordRequiresUpper"
		];
		rules.ShouldAllBe(static code => IdentityErrorFields.ForPasswordChange(code) == "NewPassword");
		IdentityErrorFields.ForPasswordChange("ConcurrencyFailure").ShouldBe("");
	}

	[Fact]
	void Regroup_with_a_selector_merges_codes_onto_their_field()
	{
		Dictionary<string, string[]> errors = new()
		{
			["PasswordTooShort"] = ["a"],
			["PasswordRequiresDigit"] = ["b"],
			["PasswordMismatch"] = ["c"]
		};

		var regrouped = IdentityErrorFields.Regroup(errors, IdentityErrorFields.ForPasswordChange);

		regrouped.Count.ShouldBe(2);
		regrouped["NewPassword"].ShouldBe(["a", "b"]);
		regrouped["OldPassword"].ShouldBe(["c"]);
	}
}
