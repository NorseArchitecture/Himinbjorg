using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.Web.Server.Passkeys;

namespace Norse.Identity.Web.Server.Tests.Passkeys;

/// <summary>
///     <see cref="PasskeyService" /> is pure hydrate-and-send: every method and every command carries the account
///     policy (gRPC endpoint metadata reflects on the concrete type), and every method sends its own command around
///     the wire request.
/// </summary>
public sealed class PasskeyServiceTests
{
	static readonly Type[] _commands =
	[
		typeof(GetPasskeysCommand), typeof(GetPasskeyCommand), typeof(GetPasskeyCreationOptionsCommand),
		typeof(AddPasskeyCommand), typeof(RenamePasskeyCommand), typeof(RemovePasskeyCommand)
	];

	readonly ISender _sender = Substitute.For<ISender>();

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	PasskeyService Service => new(_sender);

	[Fact]
	void Every_operation_carries_its_policy()
	{
		var methods = typeof(PasskeyService).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

		methods.Select(static method => method.Name).ShouldBe(
			typeof(IPasskeyService).GetMethods().Select(static method => method.Name), true);
		methods.ShouldAllBe(static method => method.GetCustomAttribute<AuthorizeAttribute>()!.Policy == AuthNPolicies.Account);
		_commands.ShouldAllBe(static command => command.GetCustomAttribute<AuthorizeAttribute>()!.Policy == AuthNPolicies.Account);
	}

	[Fact]
	async Task GetPasskeys_sends_its_command()
	{
		await Service.GetPasskeys(Cancellation);

		await _sender.Received(1).Send(Arg.Any<GetPasskeysCommand>(), Cancellation);
	}

	[Fact]
	async Task GetPasskey_sends_its_command()
	{
		GetPasskeyRequest request = new() { CredentialId = "credential" };

		await Service.GetPasskey(request, Cancellation);

		await _sender.Received(1).Send(Arg.Is<GetPasskeyCommand>(c => ReferenceEquals(c.Request, request)), Cancellation);
	}

	[Fact]
	async Task GetPasskeyCreationOptions_sends_its_command()
	{
		await Service.GetPasskeyCreationOptions(Cancellation);

		await _sender.Received(1).Send(Arg.Any<GetPasskeyCreationOptionsCommand>(), Cancellation);
	}

	[Fact]
	async Task AddPasskey_sends_its_command()
	{
		AddPasskeyRequest request = new() { CredentialJson = "{}", AttestationState = "state" };

		await Service.AddPasskey(request, Cancellation);

		await _sender.Received(1).Send(Arg.Is<AddPasskeyCommand>(c => ReferenceEquals(c.Request, request)), Cancellation);
	}

	[Fact]
	async Task RenamePasskey_sends_its_command()
	{
		RenamePasskeyRequest request = new() { CredentialId = "credential", Name = "Laptop" };

		await Service.RenamePasskey(request, Cancellation);

		await _sender.Received(1).Send(Arg.Is<RenamePasskeyCommand>(c => ReferenceEquals(c.Request, request)),
			Cancellation);
	}

	[Fact]
	async Task RemovePasskey_sends_its_command()
	{
		RemovePasskeyRequest request = new() { CredentialId = "credential" };

		await Service.RemovePasskey(request, Cancellation);

		await _sender.Received(1).Send(Arg.Is<RemovePasskeyCommand>(c => ReferenceEquals(c.Request, request)),
			Cancellation);
	}
}
