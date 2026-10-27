using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using Norse.Identity.Migrations;
using Norse.Identity.Outcomes;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The Outcome surface's enforcement (2026-10-24 explicit-writes spec §4.12), standing in until banned-symbol
///     infrastructure exists: an IL scan of <c>Identity.Web.Server</c> and <c>Identity.Migrations</c> fails if any type
///     calls a raw <c>IdentityResult</c>- or <c>SignInResult</c>-returning manager method, a manager method banned by
///     name, or any OpenIddict manager, instead of going through <c>.Outcome</c>. <see cref="IRecoveryCodeReplacement" />
///     counts as a manager: a handler casting <c>UserManager&lt;NorseUser&gt;</c> to it would otherwise reach the raw
///     <c>(IdentityResult, string[])</c> of <c>ReplaceRecoveryCodesAsync</c> past the name check.
/// </summary>
/// <remarks>
///     Exempt: the managers themselves (<see cref="NorseUserManager" /> and <see cref="NorseSignInManager" />, whose
///     overrides call their base), the framework-boundary adapters (<see cref="NorseSignInManager" /> again, and
///     <see cref="IdentityRevalidatingAuthenticationStateProvider" />), the <c>SignInManager</c> view, and the scaffold
///     pages under <c>Components/</c> until #48 retires them. Compiler-generated state machines and closures are judged
///     by the type that declares them.
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

	const string ComponentsNamespace = "Norse.Identity.Web.Server.Components";

	static readonly ImmutableHashSet<string> _identityManagers =
	[
		"Microsoft.AspNetCore.Identity.UserManager`1",
		"Microsoft.AspNetCore.Identity.SignInManager`1",
		typeof(NorseUserManager).FullName!,
		typeof(NorseSignInManager).FullName!,
		typeof(IRecoveryCodeReplacement).FullName!
	];

	static readonly ImmutableHashSet<string> _rawResults =
	[
		"Microsoft.AspNetCore.Identity.IdentityResult",
		"Microsoft.AspNetCore.Identity.SignInResult"
	];

	/// <summary>
	///     Manager methods banned whatever they return: <c>GenerateNewTwoFactorRecoveryCodesAsync</c> answers
	///     <see langword="null" /> for every failure, losing an indeterminate commit; Norse callers replace codes through
	///     <c>.Outcome.ReplaceRecoveryCodesAsync</c>.
	/// </summary>
	static readonly ImmutableHashSet<string> _bannedByName =
	[
		"GenerateNewTwoFactorRecoveryCodesAsync"
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
			if (_exempt.Contains(ownerName) || ownerName.StartsWith(ComponentsNamespace, StringComparison.Ordinal))
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
	static List<EntityHandle> Callees(BlobReader il)
	{
		List<EntityHandle> callees = [];
		while (il.RemainingBytes > 0)
		{
			var first = il.ReadByte();
			var value = first == 0xFE ?
				(short)(0xFE00 | il.ReadByte()) :
				first;
			var opCode = _opCodes[value];
			if (opCode.OperandType == OperandType.InlineMethod)
			{
				callees.Add(MetadataTokens.EntityHandle(il.ReadInt32()));
				continue;
			}

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

		return callees;
	}

	/// <summary>The banned member <paramref name="callee" /> names, or <see langword="null" /> when it is allowed.</summary>
	static string? Describe(MetadataReader reader, NameProvider names, EntityHandle callee)
	{
		if (callee.Kind == HandleKind.MethodSpecification)
			callee = reader.GetMethodSpecification((MethodSpecificationHandle)callee).Method;

		var (declaringType, name, returnType) = callee.Kind switch
		{
			HandleKind.MethodDefinition => Definition(reader, names, (MethodDefinitionHandle)callee),
			HandleKind.MemberReference => Reference(reader, names, (MemberReferenceHandle)callee),
			_ => (string.Empty, string.Empty, string.Empty)
		};
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

	static (string DeclaringType, string Name, string ReturnType) Definition(MetadataReader reader, NameProvider names,
		MethodDefinitionHandle handle)
	{
		var method = reader.GetMethodDefinition(handle);
		var signature = method.DecodeSignature(names, null);
		return (names.Of(reader.GetTypeDefinition(method.GetDeclaringType())), reader.GetString(method.Name),
			signature.ReturnType);
	}

	static (string DeclaringType, string Name, string ReturnType) Reference(MetadataReader reader, NameProvider names,
		MemberReferenceHandle handle)
	{
		var member = reader.GetMemberReference(handle);
		if (member.GetKind() != MemberReferenceKind.Method)
			return (string.Empty, string.Empty, string.Empty);
		var parent = member.Parent;
		var declaringType = parent.Kind switch
		{
			HandleKind.TypeReference => names.GetTypeFromReference(reader, (TypeReferenceHandle)parent, 0),
			HandleKind.TypeDefinition => names.GetTypeFromDefinition(reader, (TypeDefinitionHandle)parent, 0),
			HandleKind.TypeSpecification => reader.GetTypeSpecification((TypeSpecificationHandle)parent)
				.DecodeSignature(names, null),
			_ => string.Empty
		};
		return (declaringType, reader.GetString(member.Name), member.DecodeMethodSignature(names, null).ReturnType);
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
