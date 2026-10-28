using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.Web.Server.SignInMethods;

namespace Norse.Identity.Web.Server.Tests.SignInMethods;

/// <summary>
///     <see cref="SignInMethodsService" /> is pure hydrate-and-send: every method and every command carries the public
///     policy (gRPC endpoint metadata reflects on the concrete type), and every method sends its own command around
///     the wire request.
/// </summary>
public sealed class SignInMethodsServiceTests
{
	static readonly Type[] _commands =
	[
		typeof(GetSignInMethodsCommand), typeof(GetPasskeyRequestOptionsCommand), typeof(PasskeySignInCommand)
	];

	readonly ISender _sender = Substitute.For<ISender>();

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	SignInMethodsService Service => new(_sender);

	[Fact]
	void Every_operation_carries_its_policy()
	{
		var methods = typeof(SignInMethodsService).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

		methods.Select(static method => method.Name).ShouldBe(
			typeof(ISignInMethodsService).GetMethods().Select(static method => method.Name), true);
		methods.ShouldAllBe(static method => method.GetCustomAttribute<AuthorizeAttribute>()!.Policy == AuthNPolicies.Public);
		_commands.ShouldAllBe(static command => command.GetCustomAttribute<AuthorizeAttribute>()!.Policy == AuthNPolicies.Public);
	}

	[Fact]
	async Task GetSignInMethods_sends_its_command()
	{
		GetSignInMethodsRequest request = new() { ReturnUrl = "/counter" };

		await Service.GetSignInMethods(request, Cancellation);

		await _sender.Received(1).Send(Arg.Is<GetSignInMethodsCommand>(c => ReferenceEquals(c.Request, request)),
			Cancellation);
	}

	[Fact]
	async Task GetPasskeyRequestOptions_sends_its_command()
	{
		await Service.GetPasskeyRequestOptions(Cancellation);

		await _sender.Received(1).Send(Arg.Any<GetPasskeyRequestOptionsCommand>(), Cancellation);
	}

	[Fact]
	async Task PasskeySignIn_sends_its_command()
	{
		PasskeySignInRequest request = new() { CredentialJson = "{}", AssertionState = "state", ReturnUrl = "/counter" };

		await Service.PasskeySignIn(request, Cancellation);

		await _sender.Received(1).Send(Arg.Is<PasskeySignInCommand>(c => ReferenceEquals(c.Request, request)),
			Cancellation);
	}
}
