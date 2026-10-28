using System.Buffers.Text;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.Passkeys;

/// <summary>
///     A passkey's identity on the wire: its credential id, base64url-encoded, the WebAuthn spelling. Every passkey
///     handler reads an id through <see cref="TryDecode" /> and answers <see cref="Invalid" /> for one that does not
///     decode and <see cref="NotFound" /> for one the caller does not have, and every entry it answers is built by
///     <see cref="Entry" />, rename URL included.
/// </summary>
static class CredentialIds
{
	const string RenameRoute = "/Account/Manage/RenamePasskey/";

	/// <summary>What an id that does not decode answers: <see cref="ErrorCategory.Validation" /> on <c>CredentialId</c>.</summary>
	public static readonly Failed Invalid = new(new Problem
	{
		Category = ErrorCategory.Validation,
		Errors = new Dictionary<string, string[]> { [nameof(GetPasskeyRequest.CredentialId)] = ["The passkey id is not valid."] }
	});

	/// <summary>What a passkey the caller does not have answers: <see cref="ErrorCategory.NotFound" />.</summary>
	public static readonly Failed NotFound = new(Problem.ModelError(ErrorCategory.NotFound, "The passkey was not found."));

	/// <summary>Encodes <paramref name="credentialId" /> for the wire.</summary>
	/// <param name="credentialId">The raw credential id.</param>
	/// <returns>The base64url id.</returns>
	public static string Encode(byte[] credentialId) =>
		Base64Url.EncodeToString(credentialId);

	/// <summary>Decodes a wire id; one that is not base64url answers <see langword="false" />, never throws.</summary>
	/// <param name="credentialId">The base64url id the client sent.</param>
	/// <param name="decoded">The raw credential id; empty when the id does not decode.</param>
	/// <returns><see langword="true" /> when <paramref name="decoded" /> holds the id.</returns>
	public static bool TryDecode(string credentialId, out byte[] decoded)
	{
		try
		{
			decoded = Base64Url.DecodeFromChars(credentialId);
			return true;
		}
		catch (FormatException)
		{
			decoded = [];
			return false;
		}
	}

	/// <summary>The server-authored rename page of the passkey <paramref name="credentialId" /> names.</summary>
	/// <param name="pathBase">The live request's <c>PathBase</c>.</param>
	/// <param name="credentialId">The base64url id.</param>
	/// <returns>The root-relative, PathBase-qualified URL.</returns>
	public static string RenameUrl(PathString pathBase, string credentialId) =>
		UriHelper.BuildRelative(pathBase, RenameRoute + credentialId);

	/// <summary>The wire entry for <paramref name="passkey" />; an unnamed passkey is named <c>""</c>.</summary>
	/// <param name="pathBase">The live request's <c>PathBase</c>.</param>
	/// <param name="passkey">The stored passkey.</param>
	/// <returns>The entry, with its rename URL.</returns>
	public static PasskeyEntry Entry(PathString pathBase, UserPasskeyInfo passkey)
	{
		var credentialId = Encode(passkey.CredentialId);
		return new()
		{
			CredentialId = credentialId,
			Name = passkey.Name ?? string.Empty,
			RenameUrl = RenameUrl(pathBase, credentialId)
		};
	}
}
