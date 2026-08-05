using System.Security.Cryptography;
using Norse.Abstractions.Backend.Keys;

namespace Norse.Identity.Web.Server.Tests;

public sealed class NorseLookupProtectorTests
{
	sealed class FakeRing : ILookupKeyRing
	{
		public byte[] Key { get; } = RandomNumberGenerator.GetBytes(32);
		public string CurrentKeyId => "k1";
		public IEnumerable<string> KeyIds => ["k1"];
		public byte[] GetKey(string keyId) => keyId == "k1" ? Key : throw new KeyNotFoundException(keyId);
	}

	[Fact]
	void Protect_is_a_deterministic_keyed_hmac_of_the_normalized_value()
	{
		FakeRing ring = new();
		NorseLookupProtector protector = new(ring);
		var first = protector.Protect("k1", "buvy@example.com");
		var second = protector.Protect("k1", "buvy@example.com");
		second.ShouldBe(first); // determinism IS the blind index
		using HMACSHA256 hmac = new(ring.Key);
		first.ShouldBe(Convert.ToBase64String(hmac.ComputeHash("buvy@example.com"u8.ToArray())));
	}

	[Fact]
	void Protect_passes_null_and_empty_through_unchanged()
	{
		NorseLookupProtector protector = new(new FakeRing());
		protector.Protect("k1", null).ShouldBeNull();
		protector.Protect("k1", "").ShouldBe("");
	}

	[Fact]
	void Unprotect_is_refused_because_a_blind_index_is_one_way()
	{
		NorseLookupProtector protector = new(new FakeRing());
		Should.Throw<NotSupportedException>(() => protector.Unprotect("k1", "hash"));
	}
}
