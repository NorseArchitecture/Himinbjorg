using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Components.Authorization;
using Norse.Identity.EntityFramework;
using Norse.Identity.Migrations;
using Norse.Identity.Outcomes;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The Outcome surface's enforcement (2026-10-24 explicit-writes spec §4.12), standing in until banned-symbol
///     infrastructure exists: an IL scan of <c>Identity.Web.Server</c> and <c>Identity.Migrations</c> fails if any type
///     calls a raw <c>IdentityResult</c>-, <c>SignInResult</c>- or <see cref="ChallengeSignInResult" />-returning manager
///     method, a manager method banned by name, or any OpenIddict manager, instead of going through <c>.Outcome</c>.
///     <see cref="IRecoveryCodeReplacement" /> counts as a manager: a handler casting <c>UserManager&lt;NorseUser&gt;</c> to it would otherwise reach the raw
///     <c>(IdentityResult, string[])</c> of <c>ReplaceRecoveryCodesAsync</c> past the name check.
/// </summary>
/// <remarks>
///     Exempt: the managers themselves (<see cref="NorseUserManager" /> and <see cref="NorseSignInManager" />, whose
///     overrides call their base), the framework-boundary adapters (<see cref="NorseSignInManager" /> again, and
///     <see cref="IdentityRevalidatingAuthenticationStateProvider" />) and the <c>SignInManager</c> view. Nothing else is
///     exempt: the external-login callback page is scanned like any handler. Compiler-generated state machines and
///     closures are judged by the type that declares them.
/// </remarks>
public sealed class OutcomeSurfaceEnforcementTests
{
	static readonly ImmutableHashSet<string> _exempt =
	[
		typeof(NorseUserManager).FullName!,
		typeof(NorseSignInManager).FullName!,
		typeof(IdentityRevalidatingAuthenticationStateProvider).FullName!,
		typeof(SignInManagerOutcomeView).FullName!
	];

	static readonly ImmutableHashSet<string> _identityManagers =
	[
		"Microsoft.AspNetCore.Identity.UserManager`1",
		"Microsoft.AspNetCore.Identity.SignInManager`1",
		typeof(NorseUserManager).FullName!,
		typeof(NorseSignInManager).FullName!,
		typeof(IRecoveryCodeReplacement).FullName!,
		typeof(IAuthenticatorKeyProvisioning).FullName!
	];

	static readonly ImmutableHashSet<string> _rawResults =
	[
		"Microsoft.AspNetCore.Identity.IdentityResult",
		"Microsoft.AspNetCore.Identity.SignInResult",
		typeof(ChallengeSignInResult).FullName!
	];

	/// <summary>
	///     Manager methods banned whatever they return: <c>GenerateNewTwoFactorRecoveryCodesAsync</c> answers
	///     <see langword="null" /> for every failure, losing an indeterminate commit; Norse callers replace codes through
	///     <c>.Outcome.ReplaceRecoveryCodesAsync</c>. The five base passkey members (T3-15) park the ceremony state in
	///     the partial two-factor cookie, a write a circuit cannot make; Norse callers run the ceremonies through
	///     <see cref="NorseSignInManager" />'s own, distinctly named members, via <c>.Outcome</c>. <c>IsSignedIn</c> matches an
	///     identity by <c>AuthenticationType</c> against <c>IdentityConstants.ApplicationScheme</c>, and Midgard stamps every
	///     identity with its lane instead, so it answers <see langword="false" /> for every signed-in caller on the platform.
	/// </summary>
	static readonly ImmutableHashSet<string> _bannedByName =
	[
		"GenerateNewTwoFactorRecoveryCodesAsync",
		"IsSignedIn",
		"MakePasskeyCreationOptionsAsync",
		"PerformPasskeyAttestationAsync",
		"MakePasskeyRequestOptionsAsync",
		"PerformPasskeyAssertionAsync",
		"PasskeySignInAsync"
	];

	/// <summary>Every IL opcode, by value, for operand sizes.</summary>
	static readonly FrozenOpCodes _opCodes = new();

	[Fact]
	void No_handler_service_or_endpoint_calls_raw_Identity_or_OpenIddict_manager_methods()
	{
		string[] offenses =
		[
			.. Scan(typeof(LoginHandler).Assembly.Location),
			.. Scan(typeof(MachineClientSeedContributor).Assembly.Location)
		];

		offenses.ShouldBeEmpty(
			$"Reach Identity and OpenIddict through .Outcome instead:{Environment.NewLine}{string.Join(Environment.NewLine, offenses)}");
	}

	/// <summary>
	///     The scan is not vacuous for Train 4's doors (OpenIddict step-up spec §5.8): the authorize and exchange endpoints,
	///     the grant termination, the pruner and the external-login endpoints (the link start's freshness included) are
	///     scanned types of <c>Identity.Web.Server</c>, and each reaches Identity or OpenIddict through an <c>.Outcome</c> view,
	///     so the main scan's empty offense list covers them.
	/// </summary>
	[Fact]
	void The_scan_reaches_the_openiddict_endpoints_the_pruner_and_the_external_login_endpoints()
	{
		var viewCallers = OutcomeViewCallers(typeof(LoginHandler).Assembly.Location);

		string[] doors =
		[
			"Norse.Identity.Web.Server.OpenIddict.OpenIddictAuthorizeEndpoint",
			"Norse.Identity.Web.Server.OpenIddictExchangeEndpoint",
			"Norse.Identity.Web.Server.OpenIddict.GrantTermination",
			"Norse.Identity.Web.Server.OpenIddict.OpenIddictPruningService",
			"Microsoft.AspNetCore.Routing.ExternalLoginEndpointRouteBuilderExtensions"
		];
		doors.ShouldBeSubsetOf(viewCallers);
	}

	/// <summary>Every scanned owner whose IL calls a member of the <c>Norse.Identity.Outcomes</c> view surface.</summary>
	static ImmutableHashSet<string> OutcomeViewCallers(string assemblyPath)
	{
		using var stream = File.OpenRead(assemblyPath);
		using PEReader pe = new(stream);
		var reader = pe.GetMetadataReader();
		NameProvider names = new(reader);
		HashSet<string> callers = [];
		foreach (var typeHandle in reader.TypeDefinitions)
		{
			var type = reader.GetTypeDefinition(typeHandle);
			var ownerName = names.Of(Outermost(reader, type));
			foreach (var methodHandle in type.GetMethods())
			{
				var method = reader.GetMethodDefinition(methodHandle);
				if (method.RelativeVirtualAddress == 0)
					continue;
				if (Callees(pe.GetMethodBody(method.RelativeVirtualAddress).GetILReader())
					.Any(callee => Signature(reader, names, callee).DeclaringType
						.StartsWith("Norse.Identity.Outcomes.", StringComparison.Ordinal)))
					callers.Add(ownerName);
			}
		}

		return [.. callers];
	}

	/// <summary>
	///     Every Norse seam a manager implements is a manager to the scan: a cast to one would otherwise reach its raw
	///     <c>IdentityResult</c> past the declaring-type check (<see cref="IRecoveryCodeReplacement" />,
	///     <see cref="IAuthenticatorKeyProvisioning" />).
	/// </summary>
	[Fact]
	void The_manager_set_names_every_norse_identity_seam()
	{
		string[] seams =
		[
			.. typeof(NorseUserManager).GetInterfaces()
				.Concat(typeof(NorseSignInManager).GetInterfaces())
				.Where(static seam => seam.Namespace?.StartsWith("Norse.Identity", StringComparison.Ordinal) is true)
				.Select(static seam => seam.FullName!)
		];

		seams.ShouldNotBeEmpty();
		seams.ShouldBeSubsetOf(_identityManagers);
		_identityManagers.ShouldContain(typeof(IAuthenticatorKeyProvisioning).FullName!);
	}

	/// <summary>
	///     T3-15: the five base passkey members are banned by name, and each still names a real
	///     <c>SignInManager&lt;TUser&gt;</c> member, so a framework rename cannot make the ban vacuous.
	/// </summary>
	[Fact]
	void The_base_passkey_members_are_banned_by_name()
	{
		string[] passkeyMembers =
		[
			"MakePasskeyCreationOptionsAsync",
			"PerformPasskeyAttestationAsync",
			"MakePasskeyRequestOptionsAsync",
			"PerformPasskeyAssertionAsync",
			"PasskeySignInAsync"
		];

		passkeyMembers.ShouldAllBe(static name => typeof(SignInManager<NorseUser>).GetMethod(name) != null);
		passkeyMembers.ShouldBeSubsetOf(_bannedByName);
	}

	/// <summary>
	///     The controller's ruling (Task 2.2): <c>IsSignedIn</c> is banned by name, it still names a real
	///     <c>SignInManager&lt;TUser&gt;</c> member, and the reason holds: a lane-stamped identity cookie principal reads as
	///     signed out.
	/// </summary>
	[Fact]
	void IsSignedIn_is_banned_because_it_never_sees_a_lane_stamped_principal()
	{
		using var userManager = MockUserManager.Create();
		SignInManager<NorseUser> signInManager = new(userManager, new HttpContextAccessor(),
			Substitute.For<IUserClaimsPrincipalFactory<NorseUser>>(), Options.Create(new IdentityOptions()),
			NullLogger<SignInManager<NorseUser>>.Instance, Substitute.For<IAuthenticationSchemeProvider>(),
			Substitute.For<IUserConfirmation<NorseUser>>());
		ClaimsPrincipal stamped = new(new ClaimsIdentity([new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())],
			NorseLanes.Identity));

		typeof(SignInManager<NorseUser>).GetMethod(nameof(SignInManager<NorseUser>.IsSignedIn)).ShouldNotBeNull();
		_bannedByName.ShouldContain(nameof(SignInManager<NorseUser>.IsSignedIn));
		stamped.Identity!.IsAuthenticated.ShouldBeTrue();
		signInManager.IsSignedIn(stamped).ShouldBeFalse();
	}


	/// <summary>
	///     The controller's ruling (Task 2.2, widened in Task 4.4): no path signs a principal in from the request's ambient
	///     principal, which on the platform is Midgard's lane-stamped rebuild, not the cookie's ticket. Credential sign-ins
	///     build the principal from the claims factory and a refresh reads the ticket (<see cref="NorseSignInManagerTests" />
	///     pins both by behavior); structurally, no type that hands a <see cref="ClaimsPrincipal" /> to a sign-in
	///     (<c>SignInAsync</c>, <c>SignIn</c>, <c>StashSignIn</c>) reads one from an ambient source: <c>HttpContext.User</c>,
	///     <c>AuthenticationStateProvider.GetAuthenticationStateAsync</c>, a schemeless <c>AuthenticateAsync</c> (the default
	///     scheme, whatever a host makes it), an <c>AuthenticateAsync</c> whose scheme argument (the instruction just before
	///     the call) is not the Identity cookie's scheme (<see cref="IdentityConstants.ApplicationScheme" />, or the sign-in
	///     manager's own <c>AuthenticationScheme</c>, which is that constant), or a minimal-API handler's
	///     <see cref="ClaimsPrincipal" /> parameter (bound from <c>HttpContext.User</c>). Exactly one principal source is
	///     allowed: authenticating the Identity cookie by name, as the authorize endpoint and the sign-in manager's refresh do.
	///     The scan is not vacuous: the sign-in manager's stash and the authorize endpoint are found as signers, and
	///     <see cref="Every_ambient_principal_source_is_caught" /> proves each source is detected.
	/// </summary>
	[Fact]
	void No_type_that_signs_a_principal_in_reads_an_ambient_principal()
	{
		var (signers, offenders) = ScanPrincipalSignIns(typeof(LoginHandler).Assembly.Location);

		signers.ShouldContain(typeof(NorseSignInManager).FullName!);
		signers.ShouldContain("Norse.Identity.Web.Server.OpenIddict.OpenIddictAuthorizeEndpoint");
		offenders.ShouldBeEmpty(
			$"Build the principal from the claims factory or the ticket instead:{Environment.NewLine}{string.Join(Environment.NewLine, offenders)}");
	}

	/// <summary>The canaries (<c>PrincipalSourceCanaries</c>): every ambient source is caught, the allowed one is not.</summary>
	[Fact]
	void Every_ambient_principal_source_is_caught()
	{
		var (signers, offenders) = ScanPrincipalSignIns(typeof(PrincipalSourceCanaries.ReadsHttpContextUser).Assembly.Location);

		string[] canaries =
		[
			typeof(PrincipalSourceCanaries.ReadsHttpContextUser).FullName!,
			typeof(PrincipalSourceCanaries.ReadsAuthenticationState).FullName!,
			typeof(PrincipalSourceCanaries.AuthenticatesTheDefaultScheme).FullName!,
			typeof(PrincipalSourceCanaries.AuthenticatesAnotherScheme).FullName!,
			typeof(PrincipalSourceCanaries.AuthenticatesAnotherSchemeBesideTheConstant).FullName!,
			typeof(PrincipalSourceCanaries.BindsAMinimalApiPrincipal).FullName!
		];
		foreach (var canary in canaries)
			offenders.ShouldContain(canary);
		signers.ShouldContain(typeof(PrincipalSourceCanaries.AuthenticatesTheIdentityCookie).FullName!);
		offenders.ShouldNotContain(typeof(PrincipalSourceCanaries.AuthenticatesTheIdentityCookie).FullName!);
	}

	static readonly ImmutableHashSet<string> _principalSignIns = ["SignInAsync", "SignIn", "StashSignIn"];

	static readonly ImmutableHashSet<string> _minimalApiMaps =
		["Map", "MapGet", "MapPost", "MapPut", "MapDelete", "MapPatch", "MapMethods", "MapFallback"];

	const string Principal = "System.Security.Claims.ClaimsPrincipal";

	// Judged by the outermost type, like the main scan: a state machine's MoveNext reads what its method reads.
	static (ImmutableHashSet<string> Signers, string[] Offenders) ScanPrincipalSignIns(string assemblyPath)
	{
		using var stream = File.OpenRead(assemblyPath);
		using PEReader pe = new(stream);
		var reader = pe.GetMetadataReader();
		NameProvider names = new(reader);
		HashSet<string> signers = [];
		HashSet<string> readers = [];
		foreach (var typeHandle in reader.TypeDefinitions)
		{
			var type = reader.GetTypeDefinition(typeHandle);
			var ownerName = names.Of(Outermost(reader, type));
			foreach (var methodHandle in type.GetMethods())
			{
				var method = reader.GetMethodDefinition(methodHandle);
				if (method.RelativeVirtualAddress == 0)
					continue;
				var instructions = Instructions(pe.GetMethodBody(method.RelativeVirtualAddress).GetILReader());
				var maps = false;
				List<MethodDefinitionHandle> delegates = [];
				for (var index = 0; index < instructions.Count; index++)
				{
					var (opCode, handle) = instructions[index];
					if (opCode.OperandType != OperandType.InlineMethod)
						continue;
					var (declaringType, name, _, parameters) = Signature(reader, names, handle);
					if (_principalSignIns.Contains(name) && parameters.Contains(Principal))
						signers.Add(ownerName);
					if ((declaringType == "Microsoft.AspNetCore.Http.HttpContext" && name == "get_User")
						|| (declaringType == "Microsoft.AspNetCore.Components.Authorization.AuthenticationStateProvider"
							&& name == "GetAuthenticationStateAsync")
						|| (declaringType == "Microsoft.AspNetCore.Authentication.AuthenticationHttpContextExtensions"
							&& name == "AuthenticateAsync"
							&& (parameters.Length != 2 || ArgumentBefore(reader, names, instructions, index) is not { } scheme
								|| !IsIdentityCookieScheme(reader, names, scheme))))
						readers.Add(ownerName);
					if (declaringType.StartsWith("Microsoft.AspNetCore.Builder.", StringComparison.Ordinal) && _minimalApiMaps.Contains(name))
						maps = true;
					if ((opCode == OpCodes.Ldftn || opCode == OpCodes.Ldvirtftn) && handle.Kind == HandleKind.MethodDefinition)
						delegates.Add((MethodDefinitionHandle)handle);
				}

				// A minimal-API handler binds a ClaimsPrincipal parameter from HttpContext.User: its own type reads it.
				if (!maps)
					continue;
				foreach (var target in delegates)
				{
					var definition = reader.GetMethodDefinition(target);
					if (definition.DecodeSignature(names, null).ParameterTypes.Contains(Principal))
						readers.Add(names.Of(Outermost(reader, reader.GetTypeDefinition(definition.GetDeclaringType()))));
				}
			}
		}

		return ([.. signers], [.. signers.Intersect(readers, StringComparer.Ordinal).Order(StringComparer.Ordinal)]);
	}

	/// <summary>The declaring type and name of the field <paramref name="handle" /> names.</summary>
	static (string DeclaringType, string Name) Field(MetadataReader reader, NameProvider names, EntityHandle handle)
	{
		switch (handle.Kind)
		{
			case HandleKind.FieldDefinition:
				var field = reader.GetFieldDefinition((FieldDefinitionHandle)handle);
				return (names.Of(reader.GetTypeDefinition(field.GetDeclaringType())), reader.GetString(field.Name));
			case HandleKind.MemberReference:
				var member = reader.GetMemberReference((MemberReferenceHandle)handle);
				if (member.GetKind() != MemberReferenceKind.Field)
					return (string.Empty, string.Empty);
				var declaringType = member.Parent.Kind switch
				{
					HandleKind.TypeReference => names.GetTypeFromReference(reader, (TypeReferenceHandle)member.Parent, 0),
					HandleKind.TypeDefinition => names.GetTypeFromDefinition(reader, (TypeDefinitionHandle)member.Parent, 0),
					_ => string.Empty
				};
				return (declaringType, reader.GetString(member.Name));
			default:
				return (string.Empty, string.Empty);
		}
	}

	static IEnumerable<string> Scan(string assemblyPath)
	{
		using var stream = File.OpenRead(assemblyPath);
		using PEReader pe = new(stream);
		var reader = pe.GetMetadataReader();
		NameProvider names = new(reader);
		List<string> offenses = [];
		foreach (var typeHandle in reader.TypeDefinitions)
		{
			var type = reader.GetTypeDefinition(typeHandle);
			var owner = Outermost(reader, type);
			var ownerName = names.Of(owner);
			if (_exempt.Contains(ownerName))
				continue;

			foreach (var methodHandle in type.GetMethods())
			{
				var method = reader.GetMethodDefinition(methodHandle);
				if (method.RelativeVirtualAddress == 0)
					continue;
				var caller = $"{names.Of(type)}.{reader.GetString(method.Name)}";
				foreach (var callee in Callees(pe.GetMethodBody(method.RelativeVirtualAddress).GetILReader()))
					if (Describe(reader, names, callee) is { } banned)
						offenses.Add($"{caller} -> {banned}");
			}
		}

		return offenses.Distinct(StringComparer.Ordinal);
	}

	/// <summary>The method tokens an IL body references: <c>call</c>, <c>callvirt</c>, <c>newobj</c>, <c>ldftn</c> and kin.</summary>
	static List<EntityHandle> Callees(BlobReader il) =>
		[.. Instructions(il).Where(static instruction => instruction.OpCode.OperandType == OperandType.InlineMethod)
			.Select(static instruction => instruction.Handle)];

	/// <summary>
	///     Every instruction of an IL body, in order: its opcode and, for a method or field operand, that token (otherwise a
	///     nil handle).
	/// </summary>
	static List<(OpCode OpCode, EntityHandle Handle)> Instructions(BlobReader il)
	{
		List<(OpCode, EntityHandle)> instructions = [];
		while (il.RemainingBytes > 0)
		{
			var first = il.ReadByte();
			var value = first == 0xFE ?
				(short)(0xFE00 | il.ReadByte()) :
				first;
			var opCode = _opCodes[value];
			if (opCode.OperandType is OperandType.InlineMethod or OperandType.InlineField)
			{
				instructions.Add((opCode, MetadataTokens.EntityHandle(il.ReadInt32())));
				continue;
			}

			instructions.Add((opCode, default));
			// Computed before it is added: `il.Offset += …` reads Offset first, so the switch count ReadInt32 consumes
			// would be lost and the walk would land inside the jump table (an invalid opcode under Release IL).
			var operandBytes = opCode.OperandType switch
			{
				OperandType.InlineNone => 0,
				OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
				OperandType.InlineVar => 2,
				OperandType.InlineI8 or OperandType.InlineR => 8,
				OperandType.InlineSwitch => il.ReadInt32() * 4,
				_ => 4
			};
			il.Offset += operandBytes;
		}

		return instructions;
	}

	/// <summary>
	///     The instruction that pushes the last argument of the call at <paramref name="index" />: the one immediately before it,
	///     stepping back over a code-coverage hit probe (<c>ldsfld Tracker.Begin; ldc.i4 n; add; ldc.i4.1; stind.i1</c>), which
	///     the CI's static instrumentation writes into the very assembly this scan reads and which pushes nothing.
	/// </summary>
	static (OpCode OpCode, EntityHandle Handle)? ArgumentBefore(
		MetadataReader reader, NameProvider names, List<(OpCode OpCode, EntityHandle Handle)> instructions, int index)
	{
		var at = index - 1;
		if (at >= 4
			&& instructions[at].OpCode == OpCodes.Stind_I1
			&& instructions[at - 1].OpCode == OpCodes.Ldc_I4_1
			&& instructions[at - 2].OpCode == OpCodes.Add
			&& instructions[at - 3].OpCode == OpCodes.Ldc_I4
			&& instructions[at - 4].OpCode == OpCodes.Ldsfld
			&& Field(reader, names, instructions[at - 4].Handle).DeclaringType
				.StartsWith("Microsoft.CodeCoverage.Instrumentation.", StringComparison.Ordinal))
			at -= 5;
		return at >= 0 ?
			instructions[at] :
			null;
	}

	/// <summary>
	///     Whether <paramref name="instruction" />, the one immediately before an <c>AuthenticateAsync(HttpContext, string)</c>
	///     call (past any coverage probe) and so the instruction that pushes its scheme argument, loads the Identity cookie's scheme:
	///     <see cref="IdentityConstants.ApplicationScheme" />, or the sign-in manager's own <c>AuthenticationScheme</c>, which is
	///     that constant (the refresh reads the ticket it is re-issuing). Loading the constant anywhere else in the method
	///     allows nothing.
	/// </summary>
	static bool IsIdentityCookieScheme(MetadataReader reader, NameProvider names, (OpCode OpCode, EntityHandle Handle) instruction) =>
		(instruction.OpCode == OpCodes.Ldsfld
			&& Field(reader, names, instruction.Handle) is ("Microsoft.AspNetCore.Identity.IdentityConstants", "ApplicationScheme"))
		|| ((instruction.OpCode == OpCodes.Call || instruction.OpCode == OpCodes.Callvirt)
			&& Signature(reader, names, instruction.Handle) is var (declaring, member, _, _)
			&& declaring.StartsWith("Microsoft.AspNetCore.Identity.SignInManager`1", StringComparison.Ordinal)
			&& member == "get_AuthenticationScheme");

	/// <summary>The banned member <paramref name="callee" /> names, or <see langword="null" /> when it is allowed.</summary>
	static string? Describe(MetadataReader reader, NameProvider names, EntityHandle callee)
	{
		var (declaringType, name, returnType, _) = Signature(reader, names, callee);
		var genericType = declaringType.Split('<')[0];
		var banned = (_identityManagers.Contains(genericType)
				&& (_rawResults.Any(returnType.Contains) || _bannedByName.Contains(name)))
			|| IsOpenIddictManager(genericType);
		return banned ?
			$"{declaringType}::{name} : {returnType}" :
			null;
	}

	static bool IsOpenIddictManager(string type) =>
		(type.StartsWith("OpenIddict.Abstractions.IOpenIddict", StringComparison.Ordinal)
			|| type.StartsWith("OpenIddict.Core.OpenIddict", StringComparison.Ordinal))
		&& type.Split('`')[0].EndsWith("Manager", StringComparison.Ordinal);

	/// <summary>The declaring type, name, return type and parameter types of the method <paramref name="callee" /> names.</summary>
	static (string DeclaringType, string Name, string ReturnType, ImmutableArray<string> Parameters) Signature(
		MetadataReader reader, NameProvider names, EntityHandle callee)
	{
		if (callee.Kind == HandleKind.MethodSpecification)
			callee = reader.GetMethodSpecification((MethodSpecificationHandle)callee).Method;

		return callee.Kind switch
		{
			HandleKind.MethodDefinition => Definition(reader, names, (MethodDefinitionHandle)callee),
			HandleKind.MemberReference => Reference(reader, names, (MemberReferenceHandle)callee),
			_ => (string.Empty, string.Empty, string.Empty, [])
		};
	}

	static (string DeclaringType, string Name, string ReturnType, ImmutableArray<string> Parameters) Definition(
		MetadataReader reader, NameProvider names, MethodDefinitionHandle handle)
	{
		var method = reader.GetMethodDefinition(handle);
		var signature = method.DecodeSignature(names, null);
		return (names.Of(reader.GetTypeDefinition(method.GetDeclaringType())), reader.GetString(method.Name),
			signature.ReturnType, signature.ParameterTypes);
	}

	static (string DeclaringType, string Name, string ReturnType, ImmutableArray<string> Parameters) Reference(
		MetadataReader reader, NameProvider names, MemberReferenceHandle handle)
	{
		var member = reader.GetMemberReference(handle);
		if (member.GetKind() != MemberReferenceKind.Method)
			return (string.Empty, string.Empty, string.Empty, []);
		var parent = member.Parent;
		var declaringType = parent.Kind switch
		{
			HandleKind.TypeReference => names.GetTypeFromReference(reader, (TypeReferenceHandle)parent, 0),
			HandleKind.TypeDefinition => names.GetTypeFromDefinition(reader, (TypeDefinitionHandle)parent, 0),
			HandleKind.TypeSpecification => reader.GetTypeSpecification((TypeSpecificationHandle)parent)
				.DecodeSignature(names, null),
			_ => string.Empty
		};
		var signature = member.DecodeMethodSignature(names, null);
		return (declaringType, reader.GetString(member.Name), signature.ReturnType, signature.ParameterTypes);
	}

	static TypeDefinition Outermost(MetadataReader reader, TypeDefinition type)
	{
		while (type.GetDeclaringType() is { IsNil: false } declaring)
			type = reader.GetTypeDefinition(declaring);
		return type;
	}

	/// <summary>Full type names out of signatures: <c>Namespace.Name`1&lt;Arg&gt;</c>.</summary>
	sealed class NameProvider(MetadataReader reader) : ISignatureTypeProvider<string, object?>
	{
		public string Of(TypeDefinition type)
		{
			var name = reader.GetString(type.Name);
			if (type.GetDeclaringType() is { IsNil: false } declaring)
				return $"{Of(reader.GetTypeDefinition(declaring))}+{name}";
			var space = reader.GetString(type.Namespace);
			return space.Length == 0 ?
				name :
				$"{space}.{name}";
		}

		public string GetTypeFromDefinition(MetadataReader metadata, TypeDefinitionHandle handle, byte rawTypeKind) =>
			Of(metadata.GetTypeDefinition(handle));

		public string GetTypeFromReference(MetadataReader metadata, TypeReferenceHandle handle, byte rawTypeKind)
		{
			var type = metadata.GetTypeReference(handle);
			var name = metadata.GetString(type.Name);
			if (type.ResolutionScope.Kind == HandleKind.TypeReference)
				return $"{GetTypeFromReference(metadata, (TypeReferenceHandle)type.ResolutionScope, rawTypeKind)}+{name}";
			var space = metadata.GetString(type.Namespace);
			return space.Length == 0 ?
				name :
				$"{space}.{name}";
		}

		public string GetTypeFromSpecification(MetadataReader metadata, object? genericContext,
			TypeSpecificationHandle handle, byte rawTypeKind) =>
			metadata.GetTypeSpecification(handle).DecodeSignature(this, genericContext);

		public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) =>
			$"{genericType}<{string.Join(",", typeArguments)}>";

		public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode.ToString();
		public string GetSZArrayType(string elementType) => $"{elementType}[]";
		public string GetArrayType(string elementType, ArrayShape shape) => $"{elementType}[*]";
		public string GetByReferenceType(string elementType) => $"{elementType}&";
		public string GetPointerType(string elementType) => $"{elementType}*";
		public string GetPinnedType(string elementType) => elementType;
		public string GetGenericTypeParameter(object? genericContext, int index) => $"!{index}";
		public string GetGenericMethodParameter(object? genericContext, int index) => $"!!{index}";
		public string GetFunctionPointerType(MethodSignature<string> signature) => "fnptr";
		public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType;
	}

	/// <summary>Every <see cref="OpCode" /> <see cref="OpCodes" /> declares, by its value.</summary>
	sealed class FrozenOpCodes
	{
		readonly Dictionary<short, OpCode> _byValue = typeof(OpCodes)
			.GetFields(BindingFlags.Public | BindingFlags.Static)
			.Select(static field => (OpCode)field.GetValue(null)!)
			.ToDictionary(static opCode => opCode.Value);

		public OpCode this[short value] => _byValue[value];
	}
}
