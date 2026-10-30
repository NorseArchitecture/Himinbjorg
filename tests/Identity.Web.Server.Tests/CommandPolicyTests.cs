using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Components;
using Norse.Abstractions.Components.Authorization;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.Disclosure;
using Norse.Identity.Web.Server.Passkeys;
using Norse.Identity.Web.Server.SignInMethods;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The policies every command and every gRPC method of this assembly names, pinned at build time (2026-10-29 OpenIddict
///     spec §6.3, §7.5; plan rulings T4-3 and T4-4, PF7). Freshness rides the command alone, beside the operation's own
///     policy and with its landing, because an endpoint-edge freshness check would answer a bare 403 before the mediator
///     could author the hop; each gRPC method mirrors exactly its command's operation policies; and no service carries a
///     class-level <c>[Authorize]</c>, which would combine with every method's and narrow <c>GetAccountStatus</c> back to
///     the cookie lane.
/// </summary>
public sealed class CommandPolicyTests
{
	static readonly Type[] _services =
	[
		typeof(AuthenticationService), typeof(IdentityService), typeof(AccountService), typeof(TwoFactorService),
		typeof(PasskeyService), typeof(SignInMethodsService)
	];

	/// <summary>The one method whose command does not follow the <c>{Method}Command</c> name.</summary>
	static readonly Dictionary<string, Type> _unconventional = new(StringComparer.Ordinal)
	{
		[$"{nameof(IdentityService)}.{nameof(IdentityService.GetMaskedPersonalDataAsync)}"] = typeof(MaskedPersonalDataCommand)
	};

	static IEnumerable<Type> Commands =>
		typeof(LoginHandler).Assembly.GetTypes().Where(static type =>
			!type.IsAbstract && type.GetInterfaces().Any(static contract =>
				contract.IsGenericType && contract.GetGenericTypeDefinition() == typeof(IRequest<>)));

	static string[] Policies(MemberInfo member) =>
		[.. member.GetCustomAttributes<AuthorizeAttribute>().Select(static authorize => authorize.Policy!).Order(StringComparer.Ordinal)];

	static string[] OperationPolicies(MemberInfo member) =>
		[.. Policies(member).Where(static policy => policy != NorsePolicies.RecentAuthentication)];

	[Fact]
	void Every_command_naming_recent_authentication_declares_a_landing()
	{
		Type[] gated = [.. Commands.Where(static command => Policies(command).Contains(NorsePolicies.RecentAuthentication))];

		gated.ShouldNotBeEmpty();
		foreach (var command in gated)
		{
			var landing = command.GetCustomAttribute<ReauthenticationLandingAttribute>()
				.ShouldNotBeNull($"{command.Name} names {NorsePolicies.RecentAuthentication} without a landing");
			LocalNavigation.IsLocal(landing.Path).ShouldBeTrue(command.Name);
			OperationPolicies(command).ShouldNotBeEmpty($"{command.Name} stacks freshness on no operation policy");
		}
	}

	[Fact]
	void No_command_declares_a_landing_without_recent_authentication() =>
		Commands.Where(static command => command.GetCustomAttribute<ReauthenticationLandingAttribute>() is not null)
			.ShouldAllBe(static command => Policies(command).Contains(NorsePolicies.RecentAuthentication));

	// T4-4: the four operations, five commands, and the page each lands back on.
	[Fact]
	void The_gated_commands_are_the_five_with_their_landings()
	{
		var gated = Commands
			.Where(static command => Policies(command).Contains(NorsePolicies.RecentAuthentication))
			.ToDictionary(static command => command, static command =>
				command.GetCustomAttribute<ReauthenticationLandingAttribute>()!.Path);

		gated.ShouldBe(new Dictionary<Type, string>
		{
			[typeof(GetPasskeyCreationOptionsCommand)] = "/Account/Manage/Passkeys",
			[typeof(AddPasskeyCommand)] = "/Account/Manage/Passkeys",
			[typeof(DisableTwoFactorCommand)] = "/Account/Manage/Disable2fa",
			[typeof(GetAuthenticatorSetupCommand)] = "/Account/Manage/EnableAuthenticator",
			[typeof(ResetAuthenticatorCommand)] = "/Account/Manage/ResetAuthenticator"
		}, ignoreOrder: true);
		gated.Keys.ShouldAllBe(static command => OperationPolicies(command).SequenceEqual(new[] { AuthNPolicies.Account }));
	}

	// PF7 and T4-3: endpoint-edge authorization sees the class's attributes beside the method's, and would refuse a stale
	// caller with a bare 403 before the mediator could author the hop.
	[Fact]
	void No_grpc_service_carries_a_class_level_policy_or_names_recent_authentication()
	{
		_services.ShouldAllBe(static service => !service.GetCustomAttributes<AuthorizeAttribute>(true).Any());
		_services.SelectMany(static service => service.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
			.ShouldAllBe(static method => !Policies(method).Contains(NorsePolicies.RecentAuthentication));
	}

	[Fact]
	void Every_grpc_method_mirrors_its_commands_operation_policies()
	{
		var commands = Commands.ToDictionary(static command => command.Name, StringComparer.Ordinal);
		foreach (var service in _services)
		{
			foreach (var method in service.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
			{
				var key = $"{service.Name}.{method.Name}";
				var command = _unconventional.TryGetValue(key, out var named) ?
					named :
					commands.GetValueOrDefault($"{TrimAsync(method.Name)}Command").ShouldNotBeNull($"{key} has no command");
				Policies(method).ShouldBe(OperationPolicies(command), key);
			}
		}
	}

	// §7.5: the read-only account tier admits the cookie and a user bearer, and nothing narrows it back to Account.
	[Fact]
	void Get_account_status_is_admitted_by_account_read_alone()
	{
		Policies(typeof(GetAccountStatusCommand)).ShouldBe([AuthNPolicies.AccountRead]);
		Policies(typeof(AccountService).GetMethod(nameof(AccountService.GetAccountStatus))!).ShouldBe([AuthNPolicies.AccountRead]);
	}

	static string TrimAsync(string name) =>
		name.EndsWith("Async", StringComparison.Ordinal) ?
			name[..^"Async".Length] :
			name;
}
