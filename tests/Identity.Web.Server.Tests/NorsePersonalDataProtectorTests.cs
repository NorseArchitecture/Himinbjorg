using System.Security.Cryptography;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;

namespace Norse.Identity.Web.Server.Tests;

public sealed class NorsePersonalDataProtectorTests
{
	// In-memory seam fake (three-state).
	sealed class FakeKeyStore : ISubjectKeyStore
	{
		readonly Dictionary<Guid, byte[]> _keys = [];
		readonly Dictionary<Guid, ErasureReceipt> _destroyed = [];

		public ValueTask<SubjectKeyResult> GetAsync(Guid subjectId, CancellationToken cancellationToken = default) =>
			ValueTask.FromResult(
				_keys.TryGetValue(subjectId, out var key) ? SubjectKeyResult.Available(key) :
				_destroyed.TryGetValue(subjectId, out var receipt) ? SubjectKeyResult.Destroyed(receipt) :
				SubjectKeyResult.Missing);

		public ValueTask<byte[]> GetOrCreateAsync(Guid subjectId, CancellationToken cancellationToken = default)
		{
			if (_destroyed.TryGetValue(subjectId, out var receipt))
				throw new KeyDestroyedException(receipt);
			if (!_keys.TryGetValue(subjectId, out var key))
			{
				key = new byte[32];
				RandomNumberGenerator.Fill(key);
				_keys[subjectId] = key;
			}
			return ValueTask.FromResult(key);
		}

		public ValueTask<ErasureReceipt> DestroyAsync(Guid subjectId, CancellationToken cancellationToken = default)
		{
			_keys.Remove(subjectId);
			if (!_destroyed.TryGetValue(subjectId, out var receipt))
			{
				receipt = new(Guid.NewGuid(), DateTimeOffset.UtcNow);
				_destroyed[subjectId] = receipt;
			}
			return ValueTask.FromResult(receipt);
		}
	}

	[Fact]
	void Protect_then_unprotect_round_trips_under_the_ambient_subject()
	{
		NorsePersonalDataProtector protector = new(new FakeKeyStore());
		var subject = Guid.NewGuid();
		string? protectedValue;
		using (SubjectCryptoScope.Begin(subject))
			protectedValue = protector.Protect("buvy@example.com");
		protectedValue.ShouldStartWith($"v1:{subject:D}:");
		protector.Unprotect(protectedValue).ShouldBe("buvy@example.com"); // no ambient needed — self-describing
	}

	[Fact]
	void Protect_fails_loudly_with_no_ambient_subject()
	{
		NorsePersonalDataProtector protector = new(new FakeKeyStore());
		Should.Throw<InvalidOperationException>(() => protector.Protect("data"));
	}

	[Fact]
	async Task Unprotect_throws_key_destroyed_with_the_receipt_when_the_subject_is_shredded()
	{
		FakeKeyStore store = new();
		NorsePersonalDataProtector protector = new(store);
		var subject = Guid.NewGuid();
		string? protectedValue;
		using (SubjectCryptoScope.Begin(subject))
			protectedValue = protector.Protect("buvy@example.com");
		// Async test method + real await here (unlike production's sync-over-async bridge) -- xUnit1031
		// forbids blocking task operations in test methods, so the fake store's async DestroyAsync is
		// awaited directly rather than mirroring the protector's own GetAwaiter().GetResult() bridge.
		var receipt = await store.DestroyAsync(subject, TestContext.Current.CancellationToken);
		var exception = Should.Throw<KeyDestroyedException>(() => protector.Unprotect(protectedValue));
		exception.Receipt.ShouldBe(receipt); // spec §8 verify item 8: Destroyed(receipt) vs Missing
	}

	[Fact]
	void Unprotect_throws_key_missing_when_no_key_and_no_receipt_exist()
	{
		NorsePersonalDataProtector protector = new(new FakeKeyStore());
		var orphan = $"v1:{Guid.NewGuid():D}:{Convert.ToBase64String(new byte[44])}";
		Should.Throw<KeyMissingException>(() => protector.Unprotect(orphan));
	}

	[Fact]
	void Tampered_ciphertext_fails_loudly()
	{
		NorsePersonalDataProtector protector = new(new FakeKeyStore());
		var subject = Guid.NewGuid();
		string? protectedValue;
		using (SubjectCryptoScope.Begin(subject))
			protectedValue = protector.Protect("buvy@example.com");
		var tampered = $"{protectedValue![..^4]}AAAA";
		Should.Throw<CryptographicException>(() => protector.Unprotect(tampered));
	}
}
