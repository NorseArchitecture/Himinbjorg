using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Components.Authorization;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary>
///     <see cref="TwoFactorService" /> is pure hydrate-and-send: every method and every command carries the account
///     policy (gRPC endpoint metadata reflects on the concrete type), and every method sends its own command around
///     the wire request.
/// </summary>
public sealed class TwoFactorServiceTests
{
	static readonly Type[] _commands =
	[
		typeof(GetAuthenticatorSetupCommand), typeof(EnableAuthenticatorCommand), typeof(RevealRecoveryCodesCommand),
		typeof(ResetAuthenticatorCommand), typeof(DisableTwoFactorCommand), typeof(GenerateRecoveryCodesCommand),
		typeof(ForgetTwoFactorClientCommand)
	];

	readonly ISender _sender = Substitute.For<ISender>();

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	TwoFactorService Service => new(_sender);

	[Fact]
	void Every_operation_carries_its_policy()
	{
		var methods = typeof(TwoFactorService).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

		methods.Select(static method => method.Name).ShouldBe(
			typeof(ITwoFactorService).GetMethods().Select(static method => method.Name), true);
		methods.ShouldAllBe(static method => method.GetCustomAttribute<AuthorizeAttribute>()!.Policy == AuthNPolicies.Account);
		// The operation policy; the gated commands stack freshness beside it (CommandPolicyTests pins which).
		_commands.ShouldAllBe(static command => command.GetCustomAttributes<AuthorizeAttribute>()
			.Single(authorize => authorize.Policy != NorsePolicies.RecentAuthentication).Policy == AuthNPolicies.Account);
	}

	[Fact]
	async Task GetAuthenticatorSetup_sends_its_command()
	{
		await Service.GetAuthenticatorSetup(Cancellation);

		await _sender.Received(1).Send(Arg.Any<GetAuthenticatorSetupCommand>(), Cancellation);
	}

	[Fact]
	async Task EnableAuthenticator_sends_its_command()
	{
		EnableAuthenticatorRequest request = new() { Code = "123456" };

		await Service.EnableAuthenticator(request, Cancellation);

		await _sender.Received(1).Send(Arg.Is<EnableAuthenticatorCommand>(c => ReferenceEquals(c.Request, request)),
			Cancellation);
	}

	[Fact]
	async Task RevealRecoveryCodes_sends_its_command()
	{
		RevealRecoveryCodesRequest request = new() { Handoff = "handoff" };

		await Service.RevealRecoveryCodes(request, Cancellation);

		await _sender.Received(1).Send(Arg.Is<RevealRecoveryCodesCommand>(c => ReferenceEquals(c.Request, request)),
			Cancellation);
	}

	[Fact]
	async Task ResetAuthenticator_sends_its_command()
	{
		await Service.ResetAuthenticator(Cancellation);

		await _sender.Received(1).Send(Arg.Any<ResetAuthenticatorCommand>(), Cancellation);
	}

	[Fact]
	async Task DisableTwoFactor_sends_its_command()
	{
		await Service.DisableTwoFactor(Cancellation);

		await _sender.Received(1).Send(Arg.Any<DisableTwoFactorCommand>(), Cancellation);
	}

	[Fact]
	async Task GenerateRecoveryCodes_sends_its_command()
	{
		await Service.GenerateRecoveryCodes(Cancellation);

		await _sender.Received(1).Send(Arg.Any<GenerateRecoveryCodesCommand>(), Cancellation);
	}

	[Fact]
	async Task ForgetTwoFactorClient_sends_its_command()
	{
		await Service.ForgetTwoFactorClient(Cancellation);

		await _sender.Received(1).Send(Arg.Any<ForgetTwoFactorClientCommand>(), Cancellation);
	}
}
