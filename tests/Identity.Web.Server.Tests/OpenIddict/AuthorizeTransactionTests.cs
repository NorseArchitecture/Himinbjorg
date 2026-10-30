using System.Security.Cryptography;
using Microsoft.Extensions.Primitives;
using Norse.Identity.Web.Server.OpenIddict;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     The canonical authorize transaction (spec §5.2, T4-10): order-independent by name, blind to the marker itself, and
///     structurally framed, so no two distinct parameter sets hash alike.
/// </summary>
public sealed class AuthorizeTransactionTests
{
	[Fact]
	void Canonical_hash_is_order_independent_by_name_and_excludes_the_marker()
	{
		var hash = Hash(("client_id", ["norse"]), ("state", ["s"]), ("scope", ["openid offline_access"]));

		Hash(("scope", ["openid offline_access"]), ("client_id", ["norse"]), ("state", ["s"])).ShouldBe(hash);
		Hash(("state", ["s"]), ("norse_reauth", ["a-marker"]), ("client_id", ["norse"]),
			("scope", ["openid offline_access"])).ShouldBe(hash);
		hash.Length.ShouldBe(32, "SHA-256");
	}

	[Fact]
	void Canonical_hash_keeps_the_values_received_order_and_case()
	{
		Hash(("state", ["s"])).ShouldNotBe(Hash(("state", ["S"])));
		Hash(("State", ["s"])).ShouldNotBe(Hash(("state", ["s"])));
		Hash(("Norse_Reauth", ["m"])).ShouldNotBe(Hash(), "only the exact marker name is excluded");
		Hash(("client_id", ["norse"]), ("norse_reauth", ["x"]))
			.ShouldNotBe(Hash(("client_id", ["norse"]), ("NORSE_REAUTH", ["x"])), "a variant spelling takes part");
	}

	[Fact]
	void Canonical_hash_is_injective_over_parameter_boundaries()
	{
		Hash(("a", ["bc"])).ShouldNotBe(Hash(("ab", ["c"])));
		Hash(("x", ["1", "2"])).ShouldNotBe(Hash(("x", ["12"])));
	}

	// The review's counterexample: a flat name-then-values stream reads both as a, b, c, d, e.
	[Fact]
	void Canonical_hash_distinguishes_parameter_groups() =>
		Hash(("a", ["b", "c"]), ("d", ["e"])).ShouldNotBe(Hash(("a", ["b"]), ("c", ["d", "e"])));

	[Fact]
	void Canonical_hash_frames_unknown_multi_valued_parameters()
	{
		Hash(("x", ["1", "2"])).ShouldNotBe(Hash(("x", ["2", "1"])));
		Hash(("x", [""])).ShouldNotBe(Hash());
		Hash(("x", [""])).ShouldNotBe(Hash(("x", ["", ""])));
	}

	// T4-10 byte for byte: the tags alone already make the stream self-delimiting, so only a known answer pins the counts.
	[Fact]
	void Canonical_hash_is_the_sha256_of_the_framed_serialization()
	{
		byte[] expected =
		[
			2, 0, 0, 0, // two parameters
			0x01, 1, 0, 0, 0, (byte)'a', 2, 0, 0, 0, // name a, two values
			0x02, 1, 0, 0, 0, (byte)'x', //   "x"
			0x02, 0, 0, 0, 0, //   ""
			0x01, 2, 0, 0, 0, (byte)'b', (byte)'b', 1, 0, 0, 0, // name bb, one value
			0x02, 2, 0, 0, 0, 0xC3, 0xA9 //   "é", UTF-8
		];

		Hash(("bb", ["é"]), ("norse_reauth", ["m"]), ("a", ["x", ""]))
			.ShouldBe(SHA256.HashData(expected));
	}

	static byte[] Hash(params (string Name, string[] Values)[] parameters) =>
		AuthorizeTransaction.Hash(parameters.Select(static parameter =>
			KeyValuePair.Create(parameter.Name, new StringValues(parameter.Values))));
}
