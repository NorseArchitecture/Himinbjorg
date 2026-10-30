using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.Web.Server.Account;

namespace Norse.Identity.Web.Server.Tests.Account;

/// <summary>
///     <see cref="AccountService" /> is pure hydrate-and-send: every method carries the account policy, the status read
///     <see cref="AuthNPolicies.AccountRead" /> (gRPC endpoint metadata reflects on the concrete type), and every method sends its own command around the wire request.
/// </summary>
public sealed class AccountServiceTests
{
	static readonly Type[] _commands =
	[
		typeof(GetAccountStatusCommand), typeof(SetPhoneNumberCommand), typeof(ChangePasswordCommand),
		typeof(SetPasswordCommand), typeof(ChangeEmailCommand), typeof(GetExternalLoginsCommand),
		typeof(RemoveExternalLoginCommand), typeof(DeletePersonalDataCommand)
	];

	readonly ISender _sender = Substitute.For<ISender>();

	public static TheoryData<string> Methods => [.. typeof(IAccountService).GetMethods().Select(static method => method.Name)];

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	void Every_method_carries_the_account_policy()
	{
		var methods = typeof(AccountService).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

		methods.Length.ShouldBe(8);
		methods.ShouldAllBe(static method =>
			method.GetCustomAttribute<AuthorizeAttribute>() != null &&
			method.GetCustomAttribute<AuthorizeAttribute>()!.Policy ==
			(method.Name == nameof(AccountService.GetAccountStatus) ? AuthNPolicies.AccountRead : AuthNPolicies.Account));
	}

	[Fact]
	void Every_command_carries_the_account_policy() =>
		_commands.ShouldAllBe(static command =>
			command.GetCustomAttribute<AuthorizeAttribute>() != null &&
			command.GetCustomAttribute<AuthorizeAttribute>()!.Policy ==
			(command == typeof(GetAccountStatusCommand) ? AuthNPolicies.AccountRead : AuthNPolicies.Account));

	[Theory]
	[MemberData(nameof(Methods))]
	async Task Every_method_sends_its_own_command(string method)
	{
		AccountService service = new(_sender);
		switch (method)
		{
			case nameof(IAccountService.GetAccountStatus):
				await service.GetAccountStatus(Cancellation);
				await _sender.Received(1).Send(Arg.Any<GetAccountStatusCommand>(), Cancellation);
				break;
			case nameof(IAccountService.SetPhoneNumber):
				SetPhoneNumberRequest phone = new() { PhoneInput = "+15551234567" };
				await service.SetPhoneNumber(phone, Cancellation);
				await _sender.Received(1).Send(Arg.Is<SetPhoneNumberCommand>(c => ReferenceEquals(c.Request, phone)),
					Cancellation);
				break;
			case nameof(IAccountService.ChangePassword):
				ChangePasswordRequest change = new() { OldPassword = "old", NewPassword = "new" };
				await service.ChangePassword(change, Cancellation);
				await _sender.Received(1).Send(Arg.Is<ChangePasswordCommand>(c => ReferenceEquals(c.Request, change)),
					Cancellation);
				break;
			case nameof(IAccountService.SetPassword):
				SetPasswordRequest set = new() { NewPassword = "new" };
				await service.SetPassword(set, Cancellation);
				await _sender.Received(1).Send(Arg.Is<SetPasswordCommand>(c => ReferenceEquals(c.Request, set)),
					Cancellation);
				break;
			case nameof(IAccountService.ChangeEmail):
				ChangeEmailRequest email = new() { NewEmailInput = "new@example.com" };
				await service.ChangeEmail(email, Cancellation);
				await _sender.Received(1).Send(Arg.Is<ChangeEmailCommand>(c => ReferenceEquals(c.Request, email)),
					Cancellation);
				break;
			case nameof(IAccountService.GetExternalLogins):
				await service.GetExternalLogins(Cancellation);
				await _sender.Received(1).Send(Arg.Any<GetExternalLoginsCommand>(), Cancellation);
				break;
			case nameof(IAccountService.RemoveExternalLogin):
				RemoveExternalLoginRequest remove = new() { LoginProvider = "Google", ProviderKey = "key" };
				await service.RemoveExternalLogin(remove, Cancellation);
				await _sender.Received(1).Send(Arg.Is<RemoveExternalLoginCommand>(c => ReferenceEquals(c.Request, remove)),
					Cancellation);
				break;
			case nameof(IAccountService.DeletePersonalData):
				DeletePersonalDataRequest delete = new() { Password = "secret" };
				await service.DeletePersonalData(delete, Cancellation);
				await _sender.Received(1).Send(Arg.Is<DeletePersonalDataCommand>(c => ReferenceEquals(c.Request, delete)),
					Cancellation);
				break;
			default:
				Assert.Fail($"No case for {method}.");
				break;
		}
	}
}
