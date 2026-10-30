using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.ServiceModel;
using Google.Rpc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Norse.Abstractions.Components.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Facade;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.Disclosure;
using Norse.Identity.Web.Server.Passkeys;
using Norse.Identity.Web.Server.SignInMethods;
using Norse.Identity.Web.Server.Tests.OpenIddict;
using Norse.Identity.Web.Server.TwoFactor;
using Norse.Infrastructure.Web.Grpc;
using Norse.Infrastructure.Web.Server.Authentication;
using Norse.Infrastructure.Web.Server.Mediator;
using Norse.Infrastructure.Web.Server.Mediator.Grpc;
using OpenIddict.Abstractions;
using ProtoBuf.Meta;
using Status = Google.Rpc.Status;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     This realm's whole gRPC surface over the real pipeline, on a fixture's database: <see cref="AuthorizeHost" /> (the
///     production composition, the authorize and token endpoints, a controllable clock and a real password sign-in) with
///     what Yggdrasil's composition root adds on top: Midgard's lanes (<c>AddNorseAuthentication()</c>), the mediator
///     pipeline, the platform gRPC interceptor stack, every <c>[NorsePolicy]</c> declaration registered the way the
///     generated <c>AddNorsePolicies()</c> registers it (configure, then the default lane closure), the six gRPC services,
///     the external-login endpoints and one façade controller under the machine policy. Calls are raw HTTP/2 gRPC frames,
///     so a fact reads the status, the trailer and the <c>google.rpc.ErrorInfo</c> the client decoder would see.
/// </summary>
sealed class GrpcSurfaceHost : IAsyncDisposable
{
	/// <summary>The façade probe's route.</summary>
	public const string FacadePath = "/surface-probe";

	GrpcSurfaceHost(AuthorizeHost host, RecordingEmailSender emails)
	{
		Host = host;
		Emails = emails;
	}

	/// <summary>The underlying host: its clock, its sign-in and its OpenIddict endpoints.</summary>
	public AuthorizeHost Host { get; }

	/// <summary>Every email the host sent.</summary>
	public RecordingEmailSender Emails { get; }

	/// <summary>Starts a host on <paramref name="fixture" />'s database.</summary>
	/// <param name="fixture">The provider's fixture, already available.</param>
	/// <param name="pathBase">The <c>PathBase</c> to mount the host under.</param>
	public static async Task<GrpcSurfaceHost> StartAsync(IdentityFixture fixture, PathString pathBase = default)
	{
		RegisterWireModel();
		RecordingEmailSender emails = new();
		// Ownership of the underlying host moves to the returned one, which disposes it.
#pragma warning disable CA2000
		var host = await AuthorizeHost.StartAsync(fixture, pathBase, builder =>
		{
			builder.Services
				.Replace(ServiceDescriptor.Singleton<IEmailSender<NorseUser>>(emails))
				.AddNorsePipeline()
				.AddNorseCodeFirstGrpc()
				.AddNorseAuthentication();
			var policies = builder.Services.AddAuthorizationBuilder();
			foreach (var declaration in Declarations())
				policies.AddPolicy(declaration.Name, policy =>
				{
					declaration.Configure(policy);
					policy.CloseLaneByDefault();
				});
			builder.Services.AddControllers()
				.ConfigureApplicationPartManager(static manager =>
				{
					manager.ApplicationParts.Clear();
					manager.ApplicationParts.Add(new OneControllerPart());
					manager.FeatureProviders.Add(new OneControllerFeature());
				});
		}, static app =>
		{
			app.MapGrpcService<AuthenticationService>();
			app.MapGrpcService<IdentityService>();
			app.MapGrpcService<AccountService>();
			app.MapGrpcService<TwoFactorService>();
			app.MapGrpcService<PasskeyService>();
			app.MapGrpcService<SignInMethodsService>();
			app.MapNorseExternalLoginEndpoints();
			app.MapControllers();
		});
#pragma warning restore CA2000
		return new(host, emails);
	}

	/// <summary>A user with <see cref="AuthorizeHost.Password" /> and a confirmed email.</summary>
	/// <param name="fixture">The fixture whose database the host runs on.</param>
	public static async Task<NorseUser> SeedConfirmedUserAsync(IdentityFixture fixture)
	{
		var seeded = await AuthorizeHost.SeedUserAsync(fixture);
		var userManager = fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
		(await userManager.ConfirmEmailAsync(user, token)).Succeeded.ShouldBeTrue();
		return seeded;
	}

	/// <summary>A user access token (<c>aud = Norse.User</c>) for the holder of <paramref name="cookie" />, through the production code flow.</summary>
	/// <param name="cookie">A fresh identity cookie.</param>
	public async Task<string> MintUserTokenAsync(string cookie)
	{
		var request = AuthorizeRequest.Create();
		var code = await Host.IssueCodeAsync(request, cookie);
		using var response = await Host.RedeemAsync(code, request);
		return (await OpenIddictTestHost.ReadTokensAsync(response, TestContext.Current.CancellationToken)).AccessToken;
	}

	/// <summary>Seeds a fresh confidential client and mints its client-credentials (<c>aud = Norse.Facade</c>) access token.</summary>
	public async Task<string> MintMachineTokenAsync()
	{
		var clientId = $"surface-{Guid.NewGuid():N}";
		const string Secret = "surface-secret-value";
		await using (var scope = Host.Services.CreateAsyncScope())
		{
			await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(
				new OpenIddictApplicationDescriptor
				{
					ClientId = clientId,
					ClientSecret = Secret,
					ClientType = OpenIddictConstants.ClientTypes.Confidential,
					Permissions =
					{
						OpenIddictConstants.Permissions.Endpoints.Token,
						OpenIddictConstants.Permissions.GrantTypes.ClientCredentials
					}
				}, TestContext.Current.CancellationToken);
		}

		using var response = await Host.PostTokenAsync([
			new(OpenIddictConstants.Parameters.GrantType, OpenIddictConstants.GrantTypes.ClientCredentials),
			new(OpenIddictConstants.Parameters.ClientId, clientId),
			new(OpenIddictConstants.Parameters.ClientSecret, Secret)
		]);
		return (await OpenIddictTestHost.ReadTokensAsync(response, TestContext.Current.CancellationToken)).AccessToken;
	}

	/// <summary>A unary call to <paramref name="operation" /> carrying <paramref name="request" />, the cookie and the bearer when given.</summary>
	/// <param name="operation">The operation.</param>
	/// <param name="request">The wire request; none sends the empty message.</param>
	/// <param name="cookie">A raw <c>Cookie</c> header value, or none.</param>
	/// <param name="bearer">An access token to bear, or none.</param>
	public async Task<GrpcAnswer> CallAsync(GrpcOperation operation, object? request = null, string? cookie = null,
		string? bearer = null)
	{
		using MemoryStream payload = new();
		if (request is not null)
			RuntimeTypeModel.Default.Serialize(payload, request);
		var frame = new byte[5 + payload.Length];
		BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(1), (int)payload.Length);
		payload.ToArray().CopyTo(frame, 5);

		using ByteArrayContent content = new(frame);
		content.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
		using HttpRequestMessage message = new(HttpMethod.Post, new Uri(Host.PathBase + operation.Path, UriKind.Relative))
		{
			Content = content,
			Version = HttpVersion.Version20,
			VersionPolicy = HttpVersionPolicy.RequestVersionExact
		};
		if (cookie is not null)
			message.Headers.Add("Cookie", cookie);
		if (bearer is not null)
			message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
		using var response = await Host.SendAsync(message);
		var body = await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken);
		return new(response.StatusCode, Read(response, "grpc-status") is { } status ? int.Parse(status, System.Globalization.CultureInfo.InvariantCulture) : null,
			Read(response, "grpc-status-details-bin") is { } details ? Status.Parser.ParseFrom(FromBase64(details)) : null,
			body, response.Headers.Location?.OriginalString, [.. response.Headers.WwwAuthenticate]);
	}

	/// <summary>A GET to the façade probe, bearing <paramref name="token" />: its status.</summary>
	/// <param name="token">The access token.</param>
	public async Task<HttpStatusCode> GetFacadeAsync(string token) =>
		(await GetFacadeAnswerAsync(token)).Http;

	/// <summary>A GET to the façade probe, bearing <paramref name="token" />: its status, challenges and body.</summary>
	/// <param name="token">The access token.</param>
	public async Task<GrpcAnswer> GetFacadeAnswerAsync(string token)
	{
		using HttpRequestMessage request = new(HttpMethod.Get, new Uri(Host.PathBase + FacadePath, UriKind.Relative));
		request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
		using var response = await Host.SendAsync(request);
		return new(response.StatusCode, null, null, await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken),
			response.Headers.Location?.OriginalString, [.. response.Headers.WwwAuthenticate]);
	}

	/// <inheritdoc />
	public ValueTask DisposeAsync() =>
		Host.DisposeAsync();

	/// <summary>Every <c>[NorsePolicy]</c> declaration a Himinbjörg host composes: the platform's and Heimdall's.</summary>
	static IEnumerable<(string Name, Action<AuthorizationPolicyBuilder> Configure)> Declarations() =>
		new[] { typeof(NorsePlatformPolicies), typeof(AuthNPolicies), typeof(IdentityPolicies) }
			.SelectMany(static owner => owner.GetMethods(BindingFlags.Public | BindingFlags.Static))
			.Where(static method => method.GetCustomAttribute<NorsePolicyAttribute>() is not null)
			.Select(static method => (method.GetCustomAttribute<NorsePolicyAttribute>()!.Name,
				(Action<AuthorizationPolicyBuilder>)(policy => method.Invoke(null, [policy]))));

	/// <summary>
	///     The wire law the generated <c>MapNorseGrpcServices()</c> registers: the identifier and result serializers, and the
	///     <c>Outcome&lt;T&gt;</c> passthrough surrogate for every payload the six services answer.
	/// </summary>
	static void RegisterWireModel() =>
		RuntimeTypeModel.Default.EnsureRegistered(typeof(GrpcSurfaceHost), static () =>
		{
			var model = RuntimeTypeModel.Default;
			IdentifierSerializers.Register(model);
			ResultSerializers.Register(model);
			Type[] contracts =
			[
				typeof(IAuthenticationService), typeof(IIdentityService), typeof(IAccountService), typeof(ITwoFactorService),
				typeof(IPasskeyService), typeof(ISignInMethodsService)
			];
			foreach (var payload in contracts.SelectMany(static contract => contract.GetMethods())
				.Select(static method => method.ReturnType.GetGenericArguments()[0].GetGenericArguments()[0]).Distinct())
				if (!model.IsDefined(typeof(Outcome<>).MakeGenericType(payload)))
					model.Add(typeof(Outcome<>).MakeGenericType(payload), applyDefaultBehaviour: false).SetSurrogate(payload);
		});

	// gRPC writes grpc-status into the headers of a trailers-only response, into the trailers otherwise.
	static string? Read(HttpResponseMessage response, string name) =>
		response.TrailingHeaders.TryGetValues(name, out var trailers) ? trailers.Single() :
		response.Headers.TryGetValues(name, out var headers) ? headers.Single() :
		null;

	static byte[] FromBase64(string value) =>
		Convert.FromBase64String(value.PadRight(value.Length + ((4 - (value.Length % 4)) % 4), '='));

	/// <summary>Every email sent, by recipient.</summary>
	public sealed class RecordingEmailSender : IEmailSender<NorseUser>
	{
		readonly ConcurrentQueue<string> _sent = new();

		/// <summary>Every recipient, in send order.</summary>
		public IReadOnlyList<string> Sent => [.. _sent];

		public Task SendConfirmationLinkAsync(NorseUser user, string email, string confirmationLink)
		{
			_sent.Enqueue(email);
			return Task.CompletedTask;
		}

		public Task SendPasswordResetLinkAsync(NorseUser user, string email, string resetLink)
		{
			_sent.Enqueue(email);
			return Task.CompletedTask;
		}

		public Task SendPasswordResetCodeAsync(NorseUser user, string email, string resetCode)
		{
			_sent.Enqueue(email);
			return Task.CompletedTask;
		}
	}

	/// <summary>Exposes exactly the façade probe.</summary>
	sealed class OneControllerPart : ApplicationPart, IApplicationPartTypeProvider
	{
		public override string Name => nameof(SurfaceProbeController);

		public IEnumerable<TypeInfo> Types { get; } = [typeof(SurfaceProbeController).GetTypeInfo()];
	}

	sealed class OneControllerFeature : ControllerFeatureProvider
	{
		protected override bool IsController(TypeInfo typeInfo) =>
			typeInfo.AsType() == typeof(SurfaceProbeController);
	}

	/// <summary>A façade controller: <see cref="GrpcControllerBase" /> carries the machine policy, and the lane selector routes it to <c>Norse.Machine</c>.</summary>
	[Route(FacadePath)]
	sealed class SurfaceProbeController : GrpcControllerBase
	{
		[HttpGet]
		public IActionResult Get() =>
			Ok();
	}
}

/// <summary>One gRPC operation of this realm's surface, by its contract and method name.</summary>
/// <param name="Contract">The Heimdall service contract.</param>
/// <param name="Method">The contract's method name.</param>
sealed record GrpcOperation(Type Contract, string Method)
{
	/// <summary>The operation's route: <c>/{service}/{method}</c>, the method name without its <c>Async</c> suffix.</summary>
	public string Path =>
		$"/{Contract.GetCustomAttribute<ServiceContractAttribute>()!.Name}/{(Method.EndsWith("Async", StringComparison.Ordinal) ? Method[..^5] : Method)}";

	/// <inheritdoc />
	public override string ToString() =>
		$"{Contract.Name}.{Method}";
}

/// <summary>What a raw gRPC call answered.</summary>
/// <param name="Http">The HTTP status: anything but 200 is a refusal before the gRPC layer.</param>
/// <param name="Status">The <c>grpc-status</c>, when the gRPC layer answered.</param>
/// <param name="Details">The <c>grpc-status-details-bin</c> rich status, when there is one.</param>
/// <param name="Body">The response body, length-prefixed frames.</param>
/// <param name="Location">The <c>Location</c> header, if any.</param>
/// <param name="Challenges">Every <c>WWW-Authenticate</c> value.</param>
sealed record GrpcAnswer(HttpStatusCode Http, int? Status, Status? Details, byte[] Body, string? Location,
	IReadOnlyList<AuthenticationHeaderValue> Challenges)
{
	/// <summary>The rich status' <c>google.rpc.ErrorInfo</c>, when there is one.</summary>
	public ErrorInfo? Error =>
		Details?.Details.Where(static detail => detail.Is(ErrorInfo.Descriptor)).Select(static detail => detail.Unpack<ErrorInfo>())
			.SingleOrDefault();

	/// <summary>The one message a successful call answered.</summary>
	/// <typeparam name="T">The payload type.</typeparam>
	public T Read<T>()
	{
		Status.ShouldBe(0, "the call succeeded");
		return RuntimeTypeModel.Default.Deserialize<T>(Body.AsSpan(5));
	}
}
